//! Catálogo fechado — espelho de gateway/althera_remote_gw/catalog.py.
//! O agente revalida TUDO que chega do gateway; o que não estiver aqui não roda.

use serde_json::{json, Map, Value};
use std::net::IpAddr;

pub const READ_ONLY: &[&str] = &["system_info", "network_diagnostics", "list_services"];
pub const CHANGES: &[&str] = &["flush_dns", "restart_service"];

pub const PROTECTED_SERVICES: &[&str] = &[
    "windefend", "mpssvc", "wscsvc", "securityhealthservice", "sense", "wdnissvc",
    "eventlog", "rpcss", "dcomlaunch", "lsm", "samss", "winmgmt", "bfe",
    "cryptsvc", "keyiso", "vaultsvc", "wuauserv", "trustedinstaller",
];

fn obj(args: &Value) -> Result<&Map<String, Value>, String> {
    match args {
        Value::Object(m) => Ok(m),
        Value::Null => Err("args ausente".into()),
        _ => Err("args deve ser objeto".into()),
    }
}

fn no_extra(m: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    for k in m.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(format!("argumento não permitido: {k}"));
        }
    }
    Ok(())
}

pub fn valid_host(v: &str) -> bool {
    if v.parse::<IpAddr>().is_ok() {
        return true;
    }
    let h = v.strip_suffix('.').unwrap_or(v);
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    h.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    })
}

pub fn valid_service(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 80
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn valid_filter(v: &str) -> bool {
    v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b" _.-".contains(&b))
}

pub fn is_protected(name: &str) -> bool {
    PROTECTED_SERVICES.contains(&name.to_ascii_lowercase().as_str())
}

/// Valida e normaliza. `change` = ação que exige aprovação.
pub fn validate(diag: &str, args: &Value, change: bool) -> Result<Value, String> {
    let empty = Value::Object(Map::new());
    let args = if args.is_null() { &empty } else { args };
    let m = obj(args)?;
    match (diag, change) {
        ("system_info", false) | ("flush_dns", true) => {
            no_extra(m, &[])?;
            Ok(json!({}))
        }
        ("network_diagnostics", false) => {
            no_extra(m, &["target", "include_traceroute"])?;
            let target = m.get("target").and_then(Value::as_str).unwrap_or("8.8.8.8").trim();
            if !valid_host(target) {
                return Err("target inválido".into());
            }
            let tr = match m.get("include_traceroute") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(b)) => *b,
                _ => return Err("include_traceroute deve ser booleano".into()),
            };
            Ok(json!({"target": target, "include_traceroute": tr}))
        }
        ("list_services", false) => {
            no_extra(m, &["filter", "state"])?;
            let f = m.get("filter").and_then(Value::as_str).unwrap_or("");
            if !valid_filter(f) {
                return Err("filter inválido".into());
            }
            let s = m.get("state").and_then(Value::as_str).unwrap_or("all");
            if !["all", "running", "stopped"].contains(&s) {
                return Err("state inválido".into());
            }
            Ok(json!({"filter": f, "state": s}))
        }
        ("restart_service", true) => {
            no_extra(m, &["name"])?;
            let n = m.get("name").and_then(Value::as_str).unwrap_or("");
            if !valid_service(n) {
                return Err("nome de serviço inválido".into());
            }
            if is_protected(n) {
                return Err(format!("o serviço {n} é protegido"));
            }
            Ok(json!({"name": n}))
        }
        _ => Err(format!("'{diag}' não está no catálogo permitido")),
    }
}

/// Texto que o USUÁRIO vê — gerado aqui, nunca vindo do gateway.
pub fn describe(diag: &str, args: &Value) -> String {
    let s = |k: &str| args.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    match diag {
        "system_info" => "Ler informações do sistema (Windows, CPU, memória, discos)".into(),
        "network_diagnostics" => {
            let tr = args.get("include_traceroute").and_then(Value::as_bool).unwrap_or(false);
            format!("Testar a rede (ipconfig, rotas, ping e DNS para {}{})", s("target"),
                    if tr { ", tracert" } else { "" })
        }
        "list_services" => "Listar os serviços do Windows".into(),
        "flush_dns" => "Limpar o cache de DNS do Windows (ipconfig /flushdns).\n\
                        Nenhum arquivo é apagado; os nomes de sites são consultados de novo."
            .into(),
        "restart_service" => format!(
            "Reiniciar o serviço do Windows \"{}\".\n\
             O serviço para por alguns segundos e volta a funcionar.",
            s("name")
        ),
        other => format!("(desconhecido: {other})"),
    }
}

/// Nome amigável de serviços comuns (o que o cliente reconhece).
fn friendly_service(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        "spooler" => "Impressão (fila de impressão)",
        "dnscache" => "Localização de sites (Cliente DNS)",
        "dhcp" => "Endereço de rede automático (DHCP)",
        "audiosrv" | "audioendpointbuilder" => "Som do Windows",
        "wlansvc" => "Wi-Fi",
        "lanmanworkstation" => "Acesso a pastas e impressoras da rede",
        "lanmanserver" => "Compartilhamento de pastas deste computador",
        "bits" => "Downloads em segundo plano do Windows",
        "themes" => "Aparência do Windows (temas)",
        "wsearch" => "Pesquisa do Windows",
        "stisvc" => "Scanner e câmera",
        _ => return None,
    })
}

/// Explicação da ALTERAÇÃO para o cliente leigo: o que será feito, por que ajuda e o que
/// ele vai notar. Gerada aqui, a partir do catálogo — o gateway/IA não escrevem este texto.
pub fn explain_change(action: &str, args: &Value, display_name: Option<&str>) -> String {
    match action {
        "flush_dns" => "AJUSTE: renovar a forma como o computador encontra os sites\n\n\
            O que será feito: apagar a lista de endereços de internet que o Windows guarda \
            de memória, para ele buscar os endereços certos de novo.\n\n\
            Por que ajuda: resolve sites que não abrem, abrem errado ou ficaram \
            \"presos\" depois de uma mudança na rede ou no provedor.\n\n\
            O que você vai notar: praticamente nada. Nenhum arquivo, programa, \
            senha ou configuração sua é alterado."
            .into(),
        "restart_service" => {
            let name = args.get("name").and_then(Value::as_str).unwrap_or("");
            let label = friendly_service(name)
                .map(str::to_string)
                .or_else(|| display_name.map(str::to_string))
                .unwrap_or_else(|| name.to_string());
            format!(
                "AJUSTE: reiniciar a função \"{label}\" do Windows\n\n\
                 O que será feito: desligar e ligar de novo só esta parte do Windows \
                 (\"{name}\"), como quando se reinicia um aparelho travado.\n\n\
                 Por que ajuda: destrava essa função quando ela para de responder \
                 (por exemplo, impressões presas na fila).\n\n\
                 O que você vai notar: por alguns segundos essa função fica indisponível \
                 e volta sozinha. Seus arquivos e programas não são alterados."
            )
        }
        other => format!("(ação desconhecida: {other})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejeita_injecao() {
        for bad in ["-t", "8.8.8.8 & calc", "a;b", "..", "x".repeat(300).as_str(), "a b"] {
            assert!(validate("network_diagnostics", &json!({"target": bad}), false).is_err(), "{bad}");
        }
        assert!(validate("network_diagnostics", &json!({"target": "google.com"}), false).is_ok());
        assert!(validate("network_diagnostics", &json!({"target": "::1"}), false).is_ok());
    }

    #[test]
    fn mudanca_nao_passa_como_leitura() {
        assert!(validate("flush_dns", &json!({}), false).is_err());
        assert!(validate("system_info", &json!({}), true).is_err());
        assert!(validate("restart_service", &json!({"name": "WinDefend"}), true).is_err());
        assert!(validate("restart_service", &json!({"name": "Spooler"}), true).is_ok());
        assert!(validate("restart_service", &json!({"name": "Spooler", "x": 1}), true).is_err());
        assert!(validate("format", &json!({}), true).is_err());
    }
}
