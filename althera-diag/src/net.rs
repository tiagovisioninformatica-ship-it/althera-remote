//! Conexão com o gateway (thread própria). Nada aqui obedece texto livre do gateway:
//! só mensagens do protocolo v1, revalidadas contra o catálogo local.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, TcpStream};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Error as WsError, Message, WebSocket};

use crate::{catalog, diag, policy, win};

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Limite próprio do agente, independente do que o gateway disser.
const AGENT_MAX_SESSION: Duration = Duration::from_secs(2 * 3600);

pub enum UiEvent {
    Log(String),
    Connected { technician: String, minutes: u64 },
    Approval { aid: String, text: String },
    Ended(String),
}

pub enum NetCmd {
    Revoke,
    Decision { aid: String, approved: bool },
}

/// Entrega eventos à thread da janela (lá vira chamada JS na página).
#[derive(Clone)]
pub struct UiSink {
    pub tx: Arc<dyn Fn(UiEvent) + Send + Sync>,
}

impl UiSink {
    fn push(&self, e: UiEvent) {
        (self.tx)(e);
    }
    fn log(&self, s: impl Into<String>) {
        self.push(UiEvent::Log(s.into()));
    }
}

/// wss:// sempre; ws:// (sem TLS) só para loopback ou rede Tailscale (100.64.0.0/10,
/// que já é criptografada pelo WireGuard).
pub fn check_server_url(url: &str) -> Result<(), String> {
    if url.starts_with("wss://") {
        return Ok(());
    }
    let rest = url.strip_prefix("ws://").ok_or("o endereço deve começar com wss://")?;
    let host = rest.split(['/', ':']).next().unwrap_or("");
    let ok = host == "localhost"
        || match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                let o = ip.octets();
                ip.is_loopback() || (o[0] == 100 && (o[1] & 0xC0) == 64)
            }
            Ok(IpAddr::V6(ip)) => ip.is_loopback(),
            Err(_) => false,
        };
    if ok { Ok(()) } else { Err("conexão sem criptografia recusada: use wss://".into()) }
}

fn set_timeout(ws: &WebSocket<MaybeTlsStream<TcpStream>>, d: Duration) {
    let tcp: Option<&TcpStream> = match ws.get_ref() {
        MaybeTlsStream::Plain(s) => Some(s),
        MaybeTlsStream::Rustls(s) => Some(s.get_ref()),
        _ => None,
    };
    if let Some(t) = tcp {
        let _ = t.set_read_timeout(Some(d));
    }
}

fn send(ws: &mut WebSocket<MaybeTlsStream<TcpStream>>, v: Value) -> Result<(), String> {
    ws.send(Message::text(v.to_string())).map_err(|e| e.to_string())
}

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// O que o cliente autorizou na tela.
pub struct Consent {
    pub tech_mode: bool,
    pub request: String,
    pub text: String,
}

pub fn run(server: String, code: String, consent: Consent, ui: UiSink, rx: Receiver<NetCmd>) {
    ui.log(format!("Conectando a {server} …"));
    let (mut ws, _) = match tungstenite::connect(server.as_str()) {
        Ok(x) => x,
        Err(e) => {
            ui.push(UiEvent::Ended(format!("Não foi possível conectar: {e}")));
            return;
        }
    };
    let hostname = sysinfo::System::host_name().unwrap_or_default();
    let hello = json!({
        "t": "hello", "v": 1, "code": code,
        "device": {
            "hostname": hostname,
            "os": sysinfo::System::long_os_version().unwrap_or_default(),
            "user": std::env::var("USERNAME").unwrap_or_default(),
            "machine_id_hash": win::machine_id_hash(),
            "agent_version": AGENT_VERSION,
            "admin": win::is_admin(),
        },
        "request": consent.request,
        "consent": {"accepted": true, "at": now_s(), "tech_mode": consent.tech_mode,
                    "text": consent.text,
                    "shown": ([catalog::READ_ONLY, catalog::CHANGES].concat())},
    });
    if let Err(e) = send(&mut ws, hello) {
        ui.push(UiEvent::Ended(format!("Falha ao enviar: {e}")));
        return;
    }
    set_timeout(&ws, Duration::from_millis(200));

    let start = Instant::now();
    let mut deadline = start + Duration::from_secs(20); // até chegar o welcome
    let mut connected = false;
    let mut tech_mode = false;
    let mut pending_approvals: HashMap<String, (String, Value)> = HashMap::new();
    let mut approved: HashMap<String, (String, Value)> = HashMap::new();
    let (res_tx, res_rx) = channel::<(String, diag::Outcome, u128)>();
    let mut busy = false;

    let end = |ws: &mut WebSocket<MaybeTlsStream<TcpStream>>, ui: &UiSink, why: String| {
        let _ = ws.close(None);
        let _ = ws.flush();
        ui.push(UiEvent::Ended(why));
    };

    loop {
        // 1. comandos da tela
        loop {
            match rx.try_recv() {
                Ok(NetCmd::Revoke) => {
                    let _ = send(&mut ws, json!({"t": "revoke", "why": "user"}));
                    end(&mut ws, &ui, "Você revogou o acesso. Nenhum comando pode mais ser executado.".into());
                    return;
                }
                Err(TryRecvError::Disconnected) => {
                    let _ = send(&mut ws, json!({"t": "revoke", "why": "ui_closed"}));
                    end(&mut ws, &ui, "Janela fechada: acesso encerrado.".into());
                    return;
                }
                Ok(NetCmd::Decision { aid, approved: yes }) => {
                    if let Some(p) = pending_approvals.remove(&aid) {
                        if yes {
                            approved.insert(aid.clone(), p);
                        }
                        ui.log(if yes { "Você APROVOU a alteração (vale uma vez)." }
                               else { "Você NEGOU a alteração." });
                        let _ = send(&mut ws, json!({"t": "approval_decision", "aid": aid, "approved": yes}));
                    }
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        // 2. resultados prontos
        while let Ok((rid, out, ms)) = res_rx.try_recv() {
            busy = false;
            ui.log(format!("  → concluído em {:.1}s{}", ms as f64 / 1000.0,
                           out.error.as_ref().map(|e| format!(" (erro: {e})")).unwrap_or_default()));
            let _ = send(&mut ws, json!({"t": "result", "rid": rid, "ok": out.ok,
                                         "output": out.output, "truncated": false,
                                         "ms": ms as u64, "error": out.error}));
        }
        // 3. prazo
        if Instant::now() > deadline {
            let why = if connected { "Tempo da sessão esgotado. Acesso encerrado." }
                      else { "O servidor não respondeu." };
            let _ = send(&mut ws, json!({"t": "revoke", "why": if connected { "deadline" } else { "no_welcome" }}));
            end(&mut ws, &ui, why.into());
            return;
        }
        // 4. mensagens do gateway
        let msg = match ws.read() {
            Ok(Message::Text(t)) => t.to_string(),
            Ok(Message::Close(_)) => {
                ui.push(UiEvent::Ended("O servidor encerrou a sessão.".into()));
                return;
            }
            Ok(_) => continue,
            Err(WsError::Io(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) => {
                ui.push(UiEvent::Ended(format!("Conexão perdida ({e}). Sessão encerrada.")));
                return;
            }
        };
        let m: Value = match serde_json::from_str(&msg) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let s = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        match s("t").as_str() {
            "welcome" if !connected => {
                connected = true;
                tech_mode = consent.tech_mode && m["tech_mode"].as_bool() == Some(true);
                let exp = m["expires_at"].as_u64().unwrap_or(0).saturating_sub(now_s());
                let lim = Duration::from_secs(exp).min(AGENT_MAX_SESSION);
                deadline = Instant::now() + lim;
                ui.push(UiEvent::Connected { technician: s("technician"), minutes: lim.as_secs() / 60 });
            }
            "error" => {
                end(&mut ws, &ui, format!("Recusado pelo servidor: {}", s("error")));
                return;
            }
            "end" => {
                end(&mut ws, &ui, format!("Sessão encerrada: {}", s("reason")));
                return;
            }
            "approval_request" if connected => {
                let aid = s("aid");
                let action = s("action");
                match catalog::validate(&action, &m["args"], true) {
                    Ok(args) => {
                        let reason: String = s("reason").chars().filter(|c| !c.is_control() || *c == '\n')
                            .take(300).collect();
                        let display = if action == "restart_service" {
                            let n = args["name"].as_str().unwrap_or("").to_ascii_lowercase();
                            win::list_services().ok().and_then(|rows| {
                                rows.into_iter().find(|r| r.name.to_ascii_lowercase() == n)
                                    .map(|r| r.display)
                            })
                        } else {
                            None
                        };
                        if action == "restart_service" && display.is_none() {
                            ui.log("Pedido de alteração RECUSADO automaticamente (serviço não existe).");
                            let _ = send(&mut ws, json!({"t": "approval_decision", "aid": aid, "approved": false}));
                            continue;
                        }
                        let text = format!(
                            "A equipe da Althera Tech pede sua permissão para fazer UM ajuste \
                             neste computador.\n\n{}\n\nO que o técnico disse:\n\"{}\"\n\n\
                             SIM = permitir este ajuste uma única vez.\n\
                             NÃO = nada será feito.",
                            catalog::explain_change(&action, &args, display.as_deref()), reason);
                        ui.log(format!("Pedido de alteração recebido: {}", catalog::describe(&action, &args)
                            .lines().next().unwrap_or("")));
                        pending_approvals.insert(aid.clone(), (action, args));
                        ui.push(UiEvent::Approval { aid, text });
                    }
                    Err(e) => {
                        ui.log(format!("Pedido de alteração RECUSADO automaticamente ({e})."));
                        let _ = send(&mut ws, json!({"t": "approval_decision", "aid": aid, "approved": false}));
                    }
                }
            }
            "run" if connected => {
                let rid = s("rid");
                let d = s("diag");
                let refuse = |ws: &mut WebSocket<MaybeTlsStream<TcpStream>>, why: String| {
                    let _ = send(ws, json!({"t": "result", "rid": rid, "ok": false, "output": "",
                                            "error": why, "ms": 0}));
                };
                if busy {
                    refuse(&mut ws, "agente ocupado com outro diagnóstico".into());
                    continue;
                }
                let is_change = catalog::CHANGES.contains(&d.as_str());
                let args = match catalog::validate(&d, &m["args"], is_change) {
                    Ok(a) => a,
                    Err(e) => {
                        ui.log(format!("Comando RECUSADO: {e}"));
                        refuse(&mut ws, e);
                        continue;
                    }
                };
                if is_change {
                    let aid = s("approval_id");
                    match approved.remove(&aid) {
                        Some((a, ar)) if a == d && ar == args => {}
                        _ => {
                            ui.log("Alteração RECUSADA: não foi aprovada por você nesta tela.");
                            refuse(&mut ws, "alteração não aprovada localmente pelo usuário".into());
                            continue;
                        }
                    }
                }
                ui.log(format!("Executando: {}", catalog::describe(&d, &args).lines().next().unwrap_or("")));
                busy = true;
                let tx = res_tx.clone();
                std::thread::spawn(move || {
                    let t0 = Instant::now();
                    let out = diag::execute(&d, &args);
                    let _ = tx.send((rid, out, t0.elapsed().as_millis()));
                });
            }
            "exec" if connected => {
                let rid = s("rid");
                let script = s("script");
                let reason: String = s("reason").chars().filter(|c| !c.is_control()).take(300).collect();
                let refuse = |ws: &mut WebSocket<MaybeTlsStream<TcpStream>>, ui: &UiSink, why: String| {
                    ui.log(format!("Comando RECUSADO ({why})."));
                    let _ = send(ws, json!({"t": "result", "rid": rid, "ok": false, "output": "",
                                            "error": why, "ms": 0}));
                };
                if !tech_mode {
                    refuse(&mut ws, &ui, "o cliente não autorizou correções nesta sessão".into());
                    continue;
                }
                if busy {
                    refuse(&mut ws, &ui, "agente ocupado com outro comando".into());
                    continue;
                }
                let approved_by = m["approved_by"].as_str().unwrap_or("").to_string();
                match policy::check(&script) {
                    Err(e) => {
                        refuse(&mut ws, &ui, e);
                        continue;
                    }
                    Ok(policy::Verdict::Sensitive(why)) if approved_by.is_empty() => {
                        refuse(&mut ws, &ui, format!("ação sensível sem aprovação de técnico ({})", why.join(", ")));
                        continue;
                    }
                    Ok(policy::Verdict::Sensitive(why)) => {
                        ui.log(format!("⚠ Ação sensível ({}) aprovada por {approved_by}.", why.join(", ")));
                    }
                    Ok(policy::Verdict::Free) => {}
                }
                let first = script.lines().next().unwrap_or("").chars().take(160).collect::<String>();
                let more = if script.lines().count() > 1 { " …" } else { "" };
                ui.log(format!("🔧 {reason}\n     > {first}{more}"));
                busy = true;
                let timeout = Duration::from_secs(m["timeout_s"].as_u64().unwrap_or(90).clamp(5, 3600));
                let tx = res_tx.clone();
                std::thread::spawn(move || {
                    let t0 = Instant::now();
                    let (code, output) = win::run_powershell(&script, timeout);
                    let out = diag::Outcome {
                        ok: code == Some(0),
                        output,
                        error: match code {
                            Some(0) => None,
                            Some(c) => Some(format!("o comando terminou com código {c}")),
                            None => Some("o comando foi interrompido".into()),
                        },
                    };
                    let _ = tx.send((rid, out, t0.elapsed().as_millis()));
                });
            }
            "pong" => {}
            _ => {}
        }
    }
}
