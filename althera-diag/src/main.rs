//! Althera Diagnóstico Remoto — módulo de diagnóstico do Althera Remote.
//!
//! Portátil: não instala, não cria serviço, não inicia com o Windows, não grava nada.
//! Só conecta depois que o usuário digita o código E marca o consentimento.
//! Interface em WebView2 (HTML embutido, sem navegação); a confirmação de alterações é
//! uma caixa NATIVA do Windows, com texto gerado aqui.
//!
//!   AltheraDiag.exe [--server wss://host/agent/ws]
#![windows_subsystem = "windows"]

mod catalog;
mod diag;
mod net;
mod win;

use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::platform::windows::WindowExtWindows;
use tao::window::WindowBuilder;
use wry::{WebView, WebViewBuilder};

use net::{NetCmd, UiEvent, UiSink};

/// Endereço de produção.
const DEFAULT_SERVER: &str = "wss://suporte.altheratech.com.br/diag/agent/ws";
const HTML: &str = include_str!("../assets/ui.html");
const HEADER_JPG: &[u8] = include_bytes!("../assets/header.jpg");
const APPROVAL_TITLE: &str = "Althera — confirmar alteração";

enum AppEvent {
    Net(UiEvent),
    Ipc(String),
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn server_from_args() -> String {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == "--server")
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| DEFAULT_SERVER.to_string())
}

fn js(webview: &WebView, ev: Value) {
    let _ = webview.evaluate_script(&format!("window.althera({ev})"));
}

fn host_of(url: &str) -> String {
    url.split("://").nth(1).unwrap_or(url).split(['/', ':']).next().unwrap_or("").to_string()
}

fn main() {
    // rustls 0.23 exige provedor de criptografia explícito (senão aborta no 1º wss://)
    let _ = rustls::crypto::ring::default_provider().install_default();
    std::panic::set_hook(Box::new(|info| {
        win::error_box(0, "AltheraDiag", &format!("Erro interno: {info}\nO acesso foi encerrado."));
    }));

    let server = server_from_args();
    let html = HTML.replace("__HEADER__", &format!("data:image/jpeg;base64,{}", b64(HEADER_JPG)));

    let event_loop = EventLoopBuilder::<AppEvent>::with_user_event().build();
    let window = match WindowBuilder::new()
        .with_title("Althera Diagnóstico Remoto")
        .with_inner_size(LogicalSize::new(1040.0, 700.0))
        .with_min_inner_size(LogicalSize::new(980.0, 660.0))
        .build(&event_loop)
    {
        Ok(w) => w,
        Err(e) => {
            win::error_box(0, "AltheraDiag", &format!("Não foi possível abrir a janela: {e}"));
            return;
        }
    };
    let hwnd = window.hwnd() as isize;
    win::set_window_icon(hwnd);

    let ipc_proxy = event_loop.create_proxy();
    let webview = match WebViewBuilder::new()
        .with_html(html)
        .with_devtools(false)
        // a página nunca sai do HTML embutido
        .with_navigation_handler(|url| {
            !(url.starts_with("http://") || url.starts_with("https://") || url.starts_with("file:"))
        })
        .with_new_window_req_handler(|_, _| wry::NewWindowResponse::Deny)
        .with_ipc_handler(move |req| {
            let _ = ipc_proxy.send_event(AppEvent::Ipc(req.body().clone()));
        })
        .build(&window)
    {
        Ok(w) => w,
        Err(e) => {
            win::error_box(hwnd, "AltheraDiag",
                &format!("Este computador precisa do Microsoft Edge WebView2 para abrir o \
                          Diagnóstico Althera.\n\nInstale em: https://go.microsoft.com/fwlink/p/?LinkId=2124703\n\n({e})"));
            return;
        }
    };

    let net_proxy = event_loop.create_proxy();
    let mut to_net: Option<Sender<NetCmd>> = None;
    let mut worker: Option<JoinHandle<()>> = None;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        let _ = &window;
        match event {
            Event::UserEvent(AppEvent::Ipc(body)) => {
                let m: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                match m["cmd"].as_str().unwrap_or("") {
                    "ready" => {
                        js(&webview, json!({"t": "server", "host": host_of(&server),
                            "text": format!("AltheraDiag {} — servidor: {}", net::AGENT_VERSION, server)}));
                        if let Err(e) = net::check_server_url(&server) {
                            js(&webview, json!({"t": "alert", "text": format!("ATENÇÃO: {e}")}));
                        }
                    }
                    "allow" if to_net.is_none() => {
                        let code: String = m["code"].as_str().unwrap_or("").chars()
                            .filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_uppercase();
                        if code.len() != 8 {
                            js(&webview, json!({"t": "alert",
                                "text": "Digite o código de 8 caracteres que o técnico informou (ex.: K7QM-4XPA)."}));
                            return;
                        }
                        if m["consent"].as_bool() != Some(true) {
                            js(&webview, json!({"t": "alert",
                                "text": "Marque \"Li e autorizo\" para continuar."}));
                            return;
                        }
                        if let Err(e) = net::check_server_url(&server) {
                            js(&webview, json!({"t": "alert", "text": e}));
                            return;
                        }
                        js(&webview, json!({"t": "starting"}));
                        let (tx, rx) = channel();
                        to_net = Some(tx);
                        let p = net_proxy.clone();
                        let sink = UiSink { tx: Arc::new(move |e| { let _ = p.send_event(AppEvent::Net(e)); }) };
                        let (srv, code) = (server.clone(), format!("{}-{}", &code[..4], &code[4..]));
                        worker = Some(std::thread::spawn(move || net::run(srv, code, sink, rx)));
                    }
                    "revoke" => {
                        if let Some(tx) = &to_net {
                            let _ = tx.send(NetCmd::Revoke);
                        }
                    }
                    "paste" => {
                        if let Some(t) = win::clipboard_text(hwnd) {
                            let t: String = t.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                                .take(9).collect();
                            js(&webview, json!({"t": "paste", "text": t}));
                        }
                    }
                    _ => {}
                }
            }
            Event::UserEvent(AppEvent::Net(ev)) => match ev {
                UiEvent::Log(s) => {
                    let cls = if s.contains("RECUSAD") || s.contains("NEGOU") { "bad" }
                              else if s.contains("APROVOU") || s.starts_with("  →") { "ok" } else { "" };
                    js(&webview, json!({"t": "log", "text": s, "cls": cls}));
                }
                UiEvent::Connected { technician, minutes } => {
                    js(&webview, json!({"t": "connected", "technician": technician, "minutes": minutes}));
                }
                UiEvent::Approval { aid, text } => {
                    let approved = win::confirm(hwnd, APPROVAL_TITLE, &text);
                    if let Some(tx) = &to_net {
                        let _ = tx.send(NetCmd::Decision { aid, approved });
                    }
                }
                UiEvent::Ended(why) => {
                    to_net = None;
                    js(&webview, json!({"t": "ended", "text": why}));
                }
            },
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                drop(to_net.take()); // canal fechado = "ui_closed" no gateway
                if let Some(h) = worker.take() {
                    let deadline = Instant::now() + Duration::from_secs(3);
                    while !h.is_finished() && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });
}
