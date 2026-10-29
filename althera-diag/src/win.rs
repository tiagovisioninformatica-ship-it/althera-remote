//! Chamadas Win32: comandos fixos do System32, decodificação OEM, MachineGuid, serviços.

use std::ffi::OsStr;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Globalization::{MultiByteToWideChar, CP_OEMCP};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const MAX_CMD_OUTPUT: usize = 24 * 1024;
pub const MAX_PS_OUTPUT: usize = 200 * 1024;

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

/// Caminho absoluto em System32 (evita executar um ping.exe plantado na pasta atual).
pub fn system32(exe: &str) -> PathBuf {
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let dir = if n == 0 || n >= buf.len() {
        "C:\\Windows\\System32".to_string()
    } else {
        String::from_utf16_lossy(&buf[..n])
    };
    PathBuf::from(dir).join(exe)
}

fn oem_to_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    unsafe {
        let n = MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), bytes.len() as i32,
                                    std::ptr::null_mut(), 0);
        if n <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut out = vec![0u16; n as usize];
        MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), bytes.len() as i32, out.as_mut_ptr(), n);
        String::from_utf16_lossy(&out)
    }
}

/// Roda um binário fixo do System32 com argv separado (sem shell), com tempo e tamanho limitados.
pub fn run_fixed(exe: &str, args: &[&str], timeout: Duration) -> String {
    let path = system32(exe);
    let mut child = match Command::new(&path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return format!("[falha ao iniciar {exe}: {e}]"),
    };
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut so).take(MAX_CMD_OUTPUT as u64 * 2).read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut se).take(8192).read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                timed_out = true;
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break,
        }
    }
    let mut text = oem_to_string(&t_out.join().unwrap_or_default());
    let err = oem_to_string(&t_err.join().unwrap_or_default());
    if !err.trim().is_empty() {
        text.push_str("\n[stderr] ");
        text.push_str(err.trim());
    }
    if text.len() > MAX_CMD_OUTPUT {
        let mut cut = MAX_CMD_OUTPUT;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str("\n…[truncado]");
    }
    if timed_out {
        text.push_str(&format!("\n[tempo limite de {}s atingido; processo encerrado]", timeout.as_secs()));
    }
    text.replace("\r\n", "\n")
}

/// Identificador do dispositivo: SHA-256 do MachineGuid (o GUID em si nunca sai da máquina).
pub fn machine_id_hash() -> String {
    let mut buf = [0u16; 128];
    let mut size = (buf.len() * 2) as u32;
    let key = wide("SOFTWARE\\Microsoft\\Cryptography");
    let val = wide("MachineGuid");
    let rc = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), val.as_ptr(), RRF_RT_REG_SZ,
                     std::ptr::null_mut(), buf.as_mut_ptr() as *mut _, &mut size)
    };
    let guid = if rc == ERROR_SUCCESS {
        let n = buf.iter().position(|&c| c == 0).unwrap_or(0);
        String::from_utf16_lossy(&buf[..n])
    } else {
        String::from("desconhecido")
    };
    hex::encode(Sha256::digest(format!("althera-diag:{guid}").as_bytes()))
}

pub struct ServiceRow {
    pub name: String,
    pub display: String,
    pub state: u32,
}

pub fn state_name(s: u32) -> &'static str {
    match s {
        SERVICE_STOPPED => "STOPPED",
        SERVICE_START_PENDING => "START_PENDING",
        SERVICE_STOP_PENDING => "STOP_PENDING",
        SERVICE_RUNNING => "RUNNING",
        SERVICE_CONTINUE_PENDING => "CONTINUE_PENDING",
        SERVICE_PAUSE_PENDING => "PAUSE_PENDING",
        SERVICE_PAUSED => "PAUSED",
        _ => "?",
    }
}

pub fn list_services() -> Result<Vec<ServiceRow>, String> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            return Err(format!("OpenSCManager falhou ({})", GetLastError()));
        }
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                              std::ptr::null_mut(), 0, &mut needed, &mut count, &mut resume,
                              std::ptr::null());
        // u64 garante alinhamento das structs dentro do buffer
        let mut buf = vec![0u64; (needed as usize + 8192) / 8];
        resume = 0;
        let ok = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                       buf.as_mut_ptr() as *mut u8, (buf.len() * 8) as u32,
                                       &mut needed, &mut count, &mut resume, std::ptr::null());
        let err = GetLastError();
        let mut rows = Vec::new();
        if ok != 0 || err == ERROR_MORE_DATA {
            let items = std::slice::from_raw_parts(
                buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
            for it in items {
                rows.push(ServiceRow {
                    name: from_wide_ptr(it.lpServiceName),
                    display: from_wide_ptr(it.lpDisplayName),
                    state: it.ServiceStatusProcess.dwCurrentState,
                });
            }
        }
        CloseServiceHandle(scm);
        if rows.is_empty() && ok == 0 {
            return Err(format!("EnumServicesStatusEx falhou ({err})"));
        }
        rows.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(rows)
    }
}

fn wait_state(h: SC_HANDLE, want: u32, limit: Duration) -> Result<(), String> {
    let start = Instant::now();
    loop {
        let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { QueryServiceStatus(h, &mut st) } == 0 {
            return Err(format!("QueryServiceStatus falhou ({})", unsafe { GetLastError() }));
        }
        if st.dwCurrentState == want {
            return Ok(());
        }
        if start.elapsed() > limit {
            return Err(format!("tempo esgotado; estado atual {}", state_name(st.dwCurrentState)));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn err_text(code: u32) -> String {
    match code {
        ERROR_ACCESS_DENIED => "acesso negado — esta ação precisa do AltheraDiag aberto como \
                                administrador (botão direito > Executar como administrador)".into(),
        ERROR_SERVICE_DOES_NOT_EXIST => "serviço não existe".into(),
        ERROR_DEPENDENT_SERVICES_RUNNING => "outros serviços dependem deste e estão rodando; \
                                             reinício recusado".into(),
        ERROR_SERVICE_DISABLED => "serviço está desabilitado".into(),
        c => format!("erro do Windows {c}"),
    }
}

pub fn restart_service(name: &str) -> Result<String, String> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(err_text(GetLastError()));
        }
        let wname = wide(name);
        let h = OpenServiceW(scm, wname.as_ptr(), SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
        if h.is_null() {
            let e = GetLastError();
            CloseServiceHandle(scm);
            return Err(err_text(e));
        }
        let mut log = String::new();
        let res = (|| {
            let mut st: SERVICE_STATUS = std::mem::zeroed();
            QueryServiceStatus(h, &mut st);
            if st.dwCurrentState != SERVICE_STOPPED {
                if ControlService(h, SERVICE_CONTROL_STOP, &mut st) == 0 {
                    return Err(err_text(GetLastError()));
                }
                wait_state(h, SERVICE_STOPPED, Duration::from_secs(30))?;
                log.push_str(&format!("{name}: parado\n"));
            } else {
                log.push_str(&format!("{name}: já estava parado\n"));
            }
            if StartServiceW(h, 0, std::ptr::null()) == 0 {
                return Err(err_text(GetLastError()));
            }
            wait_state(h, SERVICE_RUNNING, Duration::from_secs(30))?;
            log.push_str(&format!("{name}: iniciado (RUNNING)\n"));
            Ok(())
        })();
        CloseServiceHandle(h);
        CloseServiceHandle(scm);
        res.map(|_| log)
    }
}

// ---- janela: caixas nativas, ícone, área de transferência -----------------------------

use windows_sys::Win32::UI::WindowsAndMessaging as wm;

/// Caixa nativa SIM/NÃO (padrão = NÃO). Nativa de propósito: a página HTML não consegue imitá-la.
pub fn confirm(hwnd: isize, title: &str, text: &str) -> bool {
    let (t, c) = (wide(text), wide(title));
    let flags = wm::MB_YESNO | wm::MB_ICONWARNING | wm::MB_DEFBUTTON2 | wm::MB_TOPMOST | wm::MB_SETFOREGROUND;
    unsafe { wm::MessageBoxW(hwnd as _, t.as_ptr(), c.as_ptr(), flags) == wm::IDYES }
}

pub fn error_box(hwnd: isize, title: &str, text: &str) {
    let (t, c) = (wide(text), wide(title));
    unsafe { wm::MessageBoxW(hwnd as _, t.as_ptr(), c.as_ptr(), wm::MB_OK | wm::MB_ICONERROR | wm::MB_TOPMOST) };
}

/// Ícone Althera (recurso 1 do exe) na barra de título e de tarefas.
pub fn set_window_icon(hwnd: isize) {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        for (which, size) in [(wm::ICON_BIG, 32), (wm::ICON_SMALL, 16)] {
            let h = wm::LoadImageW(hinst, 1 as _, wm::IMAGE_ICON, size, size, wm::LR_DEFAULTCOLOR);
            if !h.is_null() {
                wm::SendMessageW(hwnd as _, wm::WM_SETICON, which as usize, h as isize);
            }
        }
    }
}

/// Texto da área de transferência (só para o botão "colar código").
pub fn clipboard_text(hwnd: isize) -> Option<String> {
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    const CF_UNICODETEXT: u32 = 13;
    unsafe {
        if OpenClipboard(hwnd as _) == 0 {
            return None;
        }
        let h = GetClipboardData(CF_UNICODETEXT);
        let out = if h.is_null() {
            None
        } else {
            let p = GlobalLock(h as _) as *const u16;
            let s = if p.is_null() { None } else { Some(from_wide_ptr(p)) };
            GlobalUnlock(h as _);
            s
        };
        CloseClipboard();
        out
    }
}

/// Texto -> bytes na code page OEM (caracteres fora dela viram '?').
fn to_oem(s: &str) -> Vec<u8> {
    use windows_sys::Win32::Globalization::WideCharToMultiByte;
    let w: Vec<u16> = s.encode_utf16().collect();
    if w.is_empty() {
        return Vec::new();
    }
    unsafe {
        let n = WideCharToMultiByte(CP_OEMCP, 0, w.as_ptr(), w.len() as i32, std::ptr::null_mut(), 0,
                                    std::ptr::null(), std::ptr::null_mut());
        if n <= 0 {
            return s.as_bytes().to_vec();
        }
        let mut out = vec![0u8; n as usize];
        WideCharToMultiByte(CP_OEMCP, 0, w.as_ptr(), w.len() as i32, out.as_mut_ptr(), n,
                            std::ptr::null(), std::ptr::null_mut());
        out
    }
}

/// O AltheraDiag está rodando como administrador?
pub fn is_admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

/// Reabre o próprio AltheraDiag pedindo elevação (UAC). Devolve true se o Windows aceitou.
pub fn relaunch_as_admin() -> bool {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let args: Vec<String> = std::env::args().skip(1).map(|a| format!("\"{a}\"")).collect();
    let (verb, file, params) = (wide("runas"), wide(&exe), wide(&args.join(" ")));
    let r = unsafe {
        ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), params.as_ptr(),
                      std::ptr::null(), wm::SW_SHOWNORMAL)
    };
    r as isize > 32
}

/// Modo técnico: roda um script PowerShell (texto pela entrada padrão, sem -EncodedCommand),
/// com saída UTF-8, tempo e tamanho limitados. Devolve (código de saída, saída).
pub fn run_powershell(script: &str, timeout: Duration) -> (Option<i32>, String) {
    use std::io::Write;
    let ps = system32("WindowsPowerShell\\v1.0\\powershell.exe");
    let mut child = match Command::new(&ps)
        .args(["-NoProfile", "-NonInteractive", "-NoLogo", "-Command", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (None, format!("[falha ao iniciar o PowerShell: {e}]")),
    };
    let prelude = "$ErrorActionPreference='Continue';$ProgressPreference='SilentlyContinue';\
                   [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);";
    if let Some(mut stdin) = child.stdin.take() {
        // linha em branco no fim encerra blocos de várias linhas no modo -Command -
        // o PowerShell lê a entrada padrão na code page OEM do Windows (ex.: 850)
        let _ = stdin.write_all(&to_oem(&format!("{prelude}\n{script}\n\n")));
    }
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut so).take(MAX_PS_OUTPUT as u64 + 1024).read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut se).take(32 * 1024).read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let mut code = None;
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                code = st.code();
                break;
            }
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                timed_out = true;
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break,
        }
    }
    let mut text = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    let err = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned();
    if !err.trim().is_empty() {
        text.push_str("\n[erros]\n");
        text.push_str(err.trim());
    }
    if text.len() > MAX_PS_OUTPUT {
        let mut cut = MAX_PS_OUTPUT;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str("\n…[truncado]");
    }
    if timed_out {
        text.push_str(&format!("\n[tempo limite de {}s atingido; comando encerrado]", timeout.as_secs()));
    }
    (code, text.replace("\r\n", "\n"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn decodifica_oem() {
        assert_eq!(super::oem_to_string(&[0x43, 0x87, 0xC6, 0x6F]), "Cção");
        let out = super::run_fixed("ipconfig.exe", &[], std::time::Duration::from_secs(10));
        let i = out.find("Configura").unwrap();
        let s: String = out[i..].chars().take(14).collect();
        println!("{s:?}");
        assert!(s.starts_with("Configuração"), "{s:?}");
    }

    #[test]
    fn powershell_multilinha_utf8() {
        let (code, out) = super::run_powershell(
            "$x = 0\nforeach ($i in 1..3) {\n  $x += $i\n}\n\"soma=$x ação\"",
            std::time::Duration::from_secs(60));
        assert_eq!(code, Some(0), "{out}");
        assert!(out.contains("soma=6 ação"), "{out:?}");
    }
}
