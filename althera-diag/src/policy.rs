//! Trava do "modo técnico": comandos bloqueados sempre, e comandos sensíveis que exigem
//! confirmação do cliente + aprovação de um técnico humano.
//! Espelho de gateway/althera_remote_gw/policy.py (mesmos arquivos de regras).

use regex::Regex;
use std::sync::OnceLock;

const DENYLIST: &str = include_str!("../assets/denylist.txt");
const DOWNLOAD_HOSTS: &str = include_str!("../assets/download_hosts.txt");
pub const MAX_SCRIPT: usize = 8000;

struct Rule {
    block: bool,
    reason: String,
    re: Regex,
    download: bool,
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// Pode rodar no modo técnico.
    Free,
    /// Só com confirmação do cliente + aprovação do técnico (motivos).
    Sensitive(Vec<String>),
}

fn rules() -> &'static Vec<Rule> {
    static R: OnceLock<Vec<Rule>> = OnceLock::new();
    R.get_or_init(|| {
        DENYLIST
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .filter_map(|l| {
                let mut it = l.splitn(3, '\t');
                Some((it.next()?, it.next()?, it.next()?))
            })
            .map(|(level, reason, pat)| Rule {
                block: level == "bloquear",
                reason: reason.to_string(),
                re: Regex::new(&format!("(?im){pat}")).expect("regra inválida em denylist.txt"),
                download: reason.starts_with("baixar de site"),
            })
            .collect()
    })
}

fn host_allowed(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    DOWNLOAD_HOSTS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .any(|d| h == d || h.ends_with(&format!(".{d}")))
}

/// Download só passa se houver URL literal https e TODAS forem de sites permitidos.
fn downloads_ok(script: &str) -> bool {
    static U: OnceLock<Regex> = OnceLock::new();
    let re = U.get_or_init(|| Regex::new(r"(?i)\b(https?)://([a-z0-9.-]+)").unwrap());
    let mut any = false;
    for c in re.captures_iter(script) {
        any = true;
        if !c[1].eq_ignore_ascii_case("https") || !host_allowed(&c[2]) {
            return false;
        }
    }
    any
}

/// `Err(motivo)` = bloqueado sempre; `Ok(Sensitive)` = precisa de confirmação + aprovação.
pub fn check(script: &str) -> Result<Verdict, String> {
    if script.trim().is_empty() {
        return Err("comando vazio".into());
    }
    if script.len() > MAX_SCRIPT {
        return Err(format!("comando grande demais (máx. {MAX_SCRIPT} caracteres)"));
    }
    let mut sensitive = Vec::new();
    for r in rules() {
        if !r.re.is_match(script) || (r.download && downloads_ok(script)) {
            continue;
        }
        if r.block {
            return Err(format!("bloqueado: {}", r.reason));
        }
        sensitive.push(r.reason.clone());
    }
    Ok(if sensitive.is_empty() { Verdict::Free } else { Verdict::Sensitive(sensitive) })
}

#[cfg(test)]
mod tests {
    use super::{check, Verdict};

    #[test]
    fn bloqueia_destrutivos() {
        for bad in [
            "Format-Volume -DriveLetter D",
            "vssadmin delete shadows /all",
            "Remove-Item C:\\Windows -Recurse -Force",
            "rd /s /q C:\\",
            "powershell -enc SQBFAFgA",
            "wevtutil cl Security",
            "reg save hklm\\sam c:\\x",
        ] {
            assert!(check(bad).is_err(), "deveria bloquear: {bad}");
        }
    }

    #[test]
    fn sensiveis_pedem_aprovacao() {
        for s in [
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "Add-MpPreference -ExclusionPath 'C:\\Fiscal'",
            "net user suporte 123 /add",
            "Invoke-WebRequest http://site.example/x.exe -OutFile x.exe",
            "schtasks /create /tn x /tr calc",
            "manage-bde -off C:",
            "Stop-Service WinDefend",
            "bcdedit /set {current} safeboot minimal",
            "Remove-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name App",
            "msiexec /x {1234-5678} /qn",
            "winget uninstall Zoom",
            "choco install vlc -y",
        ] {
            assert!(matches!(check(s), Ok(Verdict::Sensitive(_))), "deveria ser sensível: {s} -> {:?}", check(s));
        }
    }

    #[test]
    fn suporte_normal_livre() {
        for ok in [
            "Get-Printer | Select Name,PortName,DriverName",
            "Restart-Service Spooler -Force",
            "Remove-Item \"$env:SystemRoot\\System32\\spool\\PRINTERS\\*\" -Force",
            "Add-PrinterPort -Name IP_192.168.0.50 -PrinterHostAddress 192.168.0.50",
            "ipconfig /renew; ipconfig /flushdns",
            "Get-ChildItem $env:TEMP -Recurse | Measure-Object -Sum Length",
            "Invoke-WebRequest https://ftp.hp.com/pub/driver.exe -OutFile $env:TEMP\\d.exe",
            "Stop-Process -Name winword -Force",
            "sfc /scannow",
            "Get-CimInstance Win32_StartupCommand",
            "winget install --id Google.Chrome -e --silent --accept-package-agreements --accept-source-agreements",
            "msiexec /i \"$env:TEMP\\d.msi\" /qn",
        ] {
            assert_eq!(check(ok), Ok(Verdict::Free), "deveria ser livre: {ok}");
        }
    }
}
