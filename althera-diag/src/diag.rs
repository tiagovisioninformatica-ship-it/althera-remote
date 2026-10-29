//! Implementação de cada item do catálogo. Só é chamado depois de catalog::validate.

use serde_json::Value;
use std::fmt::Write as _;
use std::time::Duration;
use sysinfo::{Disks, System};

use crate::win;

pub const MAX_RESULT: usize = 60 * 1024;

pub struct Outcome {
    pub ok: bool,
    pub output: String,
    pub error: Option<String>,
}

fn gb(b: u64) -> f64 {
    b as f64 / 1_073_741_824.0
}

fn system_info() -> Outcome {
    let mut sys = System::new_all();
    std::thread::sleep(Duration::from_millis(300));
    sys.refresh_cpu_usage();
    let mut o = String::new();
    let up = System::uptime();
    let _ = writeln!(o, "Computador: {}", System::host_name().unwrap_or_default());
    let _ = writeln!(o, "Usuário: {}", std::env::var("USERNAME").unwrap_or_default());
    let _ = writeln!(o, "Sistema: {} (kernel {})", System::long_os_version().unwrap_or_default(),
                     System::kernel_version().unwrap_or_default());
    let _ = writeln!(o, "Ligado há: {}d {}h {}min", up / 86400, (up % 86400) / 3600, (up % 3600) / 60);
    if let Some(c) = sys.cpus().first() {
        let _ = writeln!(o, "CPU: {} ({} núcleos lógicos), uso {:.0}%", c.brand().trim(),
                         sys.cpus().len(), sys.global_cpu_usage());
    }
    let _ = writeln!(o, "Memória: {:.1} GB usada de {:.1} GB", gb(sys.used_memory()), gb(sys.total_memory()));
    let _ = writeln!(o, "\nDiscos:");
    for d in Disks::new_with_refreshed_list().list() {
        let total = d.total_space();
        let free = d.available_space();
        let pct = if total > 0 { 100.0 * free as f64 / total as f64 } else { 0.0 };
        let _ = writeln!(o, "  {} {:?} {}: {:.1} GB livres de {:.1} GB ({:.0}% livre){}",
                         d.mount_point().display(), d.kind(), d.file_system().to_string_lossy(),
                         gb(free), gb(total), pct, if pct < 10.0 { "  <-- POUCO ESPAÇO" } else { "" });
    }
    let mut procs: Vec<_> = sys.processes().values().collect();
    procs.sort_by_key(|p| std::cmp::Reverse(p.memory()));
    let _ = writeln!(o, "\nProcessos que mais usam memória:");
    for p in procs.iter().take(10) {
        let _ = writeln!(o, "  {:<32} {:>7.0} MB", p.name().to_string_lossy(), p.memory() as f64 / 1_048_576.0);
    }
    Outcome { ok: true, output: o, error: None }
}

fn network(args: &Value) -> Outcome {
    let target = args["target"].as_str().unwrap_or("8.8.8.8");
    let tr = args["include_traceroute"].as_bool().unwrap_or(false);
    let t = Duration::from_secs;
    let mut o = String::new();
    let mut sec = |title: &str, body: String| {
        let _ = writeln!(o, "===== {title} =====\n{}\n", body.trim());
    };
    sec("ipconfig /all", win::run_fixed("ipconfig.exe", &["/all"], t(15)));
    sec("rotas IPv4", win::run_fixed("route.exe", &["print", "-4"], t(15)));
    sec(&format!("ping {target}"), win::run_fixed("ping.exe", &["-n", "4", "-w", "1000", target], t(20)));
    sec(&format!("nslookup {target}"), win::run_fixed("nslookup.exe", &[target], t(15)));
    if tr {
        sec(&format!("tracert {target}"),
            win::run_fixed("tracert.exe", &["-d", "-h", "15", "-w", "800", target], t(60)));
    }
    Outcome { ok: true, output: o, error: None }
}

fn services(args: &Value) -> Outcome {
    let f = args["filter"].as_str().unwrap_or("").to_lowercase();
    let state = args["state"].as_str().unwrap_or("all");
    match win::list_services() {
        Err(e) => Outcome { ok: false, output: String::new(), error: Some(e) },
        Ok(rows) => {
            let mut o = String::from("NOME\tESTADO\tNOME DE EXIBIÇÃO\n");
            let mut n = 0;
            for r in rows {
                let st = win::state_name(r.state);
                let keep_state = match state {
                    "running" => st == "RUNNING",
                    "stopped" => st == "STOPPED",
                    _ => true,
                };
                let keep_f = f.is_empty() || r.name.to_lowercase().contains(&f)
                    || r.display.to_lowercase().contains(&f);
                if keep_state && keep_f {
                    let _ = writeln!(o, "{}\t{}\t{}", r.name, st, r.display);
                    n += 1;
                }
            }
            let _ = writeln!(o, "\n{n} serviço(s)");
            Outcome { ok: true, output: o, error: None }
        }
    }
}

pub fn execute(diag: &str, args: &Value) -> Outcome {
    let mut out = match diag {
        "system_info" => system_info(),
        "network_diagnostics" => network(args),
        "list_services" => services(args),
        "flush_dns" => Outcome {
            ok: true,
            output: win::run_fixed("ipconfig.exe", &["/flushdns"], Duration::from_secs(15)),
            error: None,
        },
        "restart_service" => match win::restart_service(args["name"].as_str().unwrap_or("")) {
            Ok(s) => Outcome { ok: true, output: s, error: None },
            Err(e) => Outcome { ok: false, output: String::new(), error: Some(e) },
        },
        _ => Outcome { ok: false, output: String::new(), error: Some("fora do catálogo".into()) },
    };
    if out.output.len() > MAX_RESULT {
        let mut cut = MAX_RESULT;
        while !out.output.is_char_boundary(cut) {
            cut -= 1;
        }
        out.output.truncate(cut);
        out.output.push_str("\n…[truncado no agente]");
    }
    out
}
