// RustScan - Memory-Safe High Performance Scanner
// Author  : Prasad
// Version : 2.0
//

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, thread};

// ─────────────────────────────────────────────────────────────────────────────
// ANSI helpers
// ─────────────────────────────────────────────────────────────────────────────

const RESET:   &str = "\x1b[0m";
const RED:     &str = "\x1b[91m";
const GREEN:   &str = "\x1b[92m";
const YELLOW:  &str = "\x1b[93m";
const MAGENTA: &str = "\x1b[95m";
const CYAN:    &str = "\x1b[96m";
const WHITE:   &str = "\x1b[97m";
const BOLD:    &str = "\x1b[1m";
const DIM:     &str = "\x1b[2m";

/// Returns true when stdout is a real terminal (not redirected to a file).
fn is_tty() -> bool {
    // On Unix, fd 1 being a char device is the standard check.
    // Simplest portable approximation: check env var set by pipes / CI.
    !matches!(env::var("TERM").as_deref(), Ok("dumb") | Err(_))
        && std::fs::metadata("/dev/stdout")
            .map(|m| {
                use std::os::unix::fs::FileTypeExt;
                m.file_type().is_char_device()
            })
            .unwrap_or(false)
}

/// Strips ANSI escape sequences for file output.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_esc = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_esc = true;
        } else if in_esc && c == 'm' {
            in_esc = false;
        } else if !in_esc {
            out.push(c);
        }
    }
    out
}

fn paint(color: &str, text: &str) -> String {
    if is_tty() {
        format!("{}{}{}", color, text, RESET)
    } else {
        text.to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service names
// ─────────────────────────────────────────────────────────────────────────────

fn service_name(port: u16) -> &'static str {
    match port {
        20    => "FTP-data",      21    => "FTP",
        22    => "SSH",           23    => "Telnet",
        25    => "SMTP",          53    => "DNS",
        80    => "HTTP",          110   => "POP3",
        111   => "RPC",           135   => "RPC",
        139   => "NetBIOS",       143   => "IMAP",
        443   => "HTTPS",         445   => "SMB",
        465   => "SMTPS",         587   => "SMTP-sub",
        993   => "IMAPS",         995   => "POP3S",
        1723  => "PPTP",          2375  => "Docker",
        2376  => "Docker-TLS",    3000  => "HTTP-dev",
        3306  => "MySQL",         3389  => "RDP",
        4443  => "HTTPS-Alt",     5432  => "PostgreSQL",
        5601  => "Kibana",        5900  => "VNC",
        6379  => "Redis",         6443  => "Kubernetes",
        8080  => "HTTP-Alt",      8443  => "HTTPS-Alt",
        8888  => "HTTP-dev",      9000  => "HTTP-dev",
        9200  => "Elasticsearch", 9300  => "Elasticsearch",
        11211 => "Memcached",     27017 => "MongoDB",
        27018 => "MongoDB",       _     => "Unknown",
    }
}

/// Ports where we try a TLS handshake.
fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 465 | 587 | 993 | 995 | 2376 | 4443 | 6443 | 8443)
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner probes
// ─────────────────────────────────────────────────────────────────────────────

fn banner_probe(port: u16) -> Option<&'static [u8]> {
    match port {
        21    => Some(b"HELP\r\n"),
        25    => Some(b"EHLO rustscan.local\r\n"),
        80 | 8080 | 8888 | 9000 | 3000
              => Some(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: RustScan/2.0\r\n\r\n"),
        110   => Some(b"USER probe\r\n"),
        143   => Some(b"a001 CAPABILITY\r\n"),
        6379  => Some(b"PING\r\n"),
        9200  => Some(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
        11211 => Some(b"version\r\n"),
        _     => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fingerprinting  (no regex — byte/str matching for zero-dep build)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Fingerprint {
    pub service_key:  &'static str,
    pub service_name: &'static str,
    pub version:      Option<String>,
}

/// Extract a version substring after a known marker, stopping at whitespace / \r\n.
fn extract_after<'a>(banner: &'a str, marker: &str) -> Option<&'a str> {
    let pos = banner.find(marker)?;
    let rest = banner[pos + marker.len()..].trim_start();
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '\r' || c == '\n' || c == '/')
        .unwrap_or(rest.len());
    let v = &rest[..end];
    if v.is_empty() { None } else { Some(v) }
}

fn fingerprint(banner: &str) -> Option<Fingerprint> {
    let b = banner.to_ascii_lowercase();

    // SSH
    if b.starts_with("ssh-") {
        let ver = extract_after(banner, "OpenSSH_")
            .or_else(|| extract_after(banner, "dropbear_"))
            .map(|s| s.to_string());
        let name = if banner.contains("OpenSSH") { "SSH (OpenSSH)" }
                   else if banner.contains("dropbear") { "SSH (Dropbear)" }
                   else { "SSH" };
        return Some(Fingerprint { service_key: "ssh", service_name: name, version: ver });
    }
    // FTP
    if banner.starts_with("220") && (b.contains("ftp") || b.contains("vsftpd") || b.contains("proftpd") || b.contains("filezilla")) {
        let ver = extract_after(banner, "vsFTPd ").or_else(|| extract_after(banner, "ProFTPD ")).map(str::to_string);
        return Some(Fingerprint { service_key: "ftp", service_name: "FTP", version: ver });
    }
    // SMTP
    if banner.starts_with("220") && (b.contains("smtp") || b.contains("esmtp") || b.contains("postfix") || b.contains("sendmail") || b.contains("exim")) {
        let ver = extract_after(banner, "Postfix ").or_else(|| extract_after(banner, "Exim ")).map(str::to_string);
        let name = if b.contains("postfix") { "SMTP (Postfix)" }
                   else if b.contains("exim") { "SMTP (Exim)" }
                   else if b.contains("sendmail") { "SMTP (Sendmail)" }
                   else { "SMTP" };
        return Some(Fingerprint { service_key: "smtp", service_name: name, version: ver });
    }
    // HTTP — look for Server: header
    if b.contains("http/") || b.contains("server:") {
        let (svc_name, ver) = if let Some(v) = extract_after(banner, "Apache/") {
            ("HTTP (Apache)", Some(v.to_string()))
        } else if let Some(v) = extract_after(banner, "nginx/") {
            ("HTTP (nginx)", Some(v.to_string()))
        } else if let Some(v) = extract_after(banner, "Microsoft-IIS/") {
            ("HTTP (IIS)", Some(v.to_string()))
        } else {
            ("HTTP", None)
        };
        return Some(Fingerprint { service_key: "http", service_name: svc_name, version: ver });
    }
    // POP3
    if banner.starts_with("+OK") {
        let name = if b.contains("dovecot") { "POP3 (Dovecot)" } else { "POP3" };
        return Some(Fingerprint { service_key: "pop3", service_name: name, version: None });
    }
    // IMAP
    if banner.starts_with("* OK") {
        let name = if b.contains("dovecot") { "IMAP (Dovecot)" }
                   else if b.contains("cyrus") { "IMAP (Cyrus)" }
                   else { "IMAP" };
        return Some(Fingerprint { service_key: "imap", service_name: name, version: None });
    }
    // MySQL / MariaDB  (handshake — version at bytes 5+)
    if b.contains("mariadb") || b.contains("mysql") {
        let ver = extract_after(banner, ".")
            .map(str::to_string);
        let name = if b.contains("mariadb") { "MariaDB" } else { "MySQL" };
        return Some(Fingerprint { service_key: "mysql", service_name: name, version: ver });
    }
    // Redis
    if banner.starts_with("+PONG") || b.contains("redis_version:") {
        let ver = extract_after(banner, "redis_version:").map(str::to_string);
        return Some(Fingerprint { service_key: "redis", service_name: "Redis", version: ver });
    }
    // Memcached
    if banner.starts_with("VERSION ") {
        let ver = extract_after(banner, "VERSION ").map(str::to_string);
        return Some(Fingerprint { service_key: "memcached", service_name: "Memcached", version: ver });
    }
    // Elasticsearch
    if b.contains("\"cluster_name\"") || b.contains("\"version\"") {
        return Some(Fingerprint { service_key: "elasticsearch", service_name: "Elasticsearch", version: None });
    }
    // MongoDB
    if b.contains("mongodb") || b.contains("ismaster") {
        return Some(Fingerprint { service_key: "mongodb", service_name: "MongoDB", version: None });
    }
    // VNC
    if banner.starts_with("RFB ") {
        let ver = extract_after(banner, "RFB ").map(str::to_string);
        return Some(Fingerprint { service_key: "vnc", service_name: "VNC", version: ver });
    }
    // Telnet (IAC bytes)
    if banner.as_bytes().first() == Some(&0xFF) {
        return Some(Fingerprint { service_key: "telnet", service_name: "Telnet", version: None });
    }
    // SMB (magic bytes)
    if banner.as_bytes().get(4) == Some(&0xFF) && banner[5..].starts_with("SMB") {
        return Some(Fingerprint { service_key: "smb", service_name: "SMB", version: None });
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk hints
// ─────────────────────────────────────────────────────────────────────────────

fn risk_hints(fp: &Fingerprint, banner: &str) -> Vec<&'static str> {
    let b = banner.to_ascii_lowercase();
    let mut hints = Vec::new();
    match fp.service_key {
        "ssh" => {
            if let Some(ref v) = fp.version {
                let major: u32 = v.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(99);
                if major < 7 { hints.push("Outdated OpenSSH — upgrade recommended"); }
            }
            if b.contains("dropbear_201") { hints.push("Old Dropbear build — check CVEs"); }
        }
        "ftp"     => { hints.push("FTP transmits credentials in plaintext"); }
        "telnet"  => { hints.push("Telnet is unencrypted — replace with SSH"); }
        "http" => {
            if b.contains("apache/2.2") || b.contains("apache/2.0") || b.contains("apache/1.") {
                hints.push("Apache <2.4 — known CVEs (CVE-2017-7679 etc.)");
            }
            if b.contains("iis/6") || b.contains("iis/5") {
                hints.push("Old IIS — multiple known CVEs");
            }
        }
        "mysql" => {
            if let Some(ref v) = fp.version {
                let major: u32 = v.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(99);
                if major < 5 { hints.push("Very old MySQL — EOL, upgrade immediately"); }
            }
        }
        "redis"   => { hints.push("Redis exposed — verify requirepass / firewall rules"); }
        "mongodb" => { hints.push("MongoDB — confirm auth is enabled (CVE-2019-2386)"); }
        "smb"     => { hints.push("SMB exposed — patch EternalBlue (MS17-010)"); }
        "rdp"     => { hints.push("RDP exposed — check BlueKeep (CVE-2019-0708) patch status"); }
        "vnc"     => { hints.push("VNC exposed — restrict access or require strong auth"); }
        _ => {}
    }
    hints
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner grabber
// ─────────────────────────────────────────────────────────────────────────────

/// Sanitise raw bytes into a printable string (replace control chars).
fn sanitise_banner(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    s.chars()
        .map(|c| if c.is_control() && c != '\n' && c != '\r' && c != '\t' { '?' } else { c })
        .collect::<String>()
        .lines()
        .next()          // first line is usually the most informative
        .unwrap_or("")
        .trim()
        .chars()
        .take(200)
        .collect()
}

#[derive(Clone, Debug, Default)]
pub struct BannerResult {
    pub banner:       Option<String>,
    pub fingerprint:  Option<Fingerprint>,
    pub tls:          bool,
    pub tls_subject:  Option<String>,   // populated by openssl CLI if available
    pub tls_expired:  Option<bool>,
}

fn grab_banner(addr: SocketAddr, port: u16, timeout: Duration) -> BannerResult {
    let mut result = BannerResult::default();

    // Helper: open plain TCP connection.
    let connect_plain = || -> Option<TcpStream> {
        TcpStream::connect_timeout(&addr, timeout).ok()
    };

    // Try TLS first (via openssl s_client — best effort).
    if is_tls_port(port) {
        if let Ok(out) = std::process::Command::new("openssl")
            .args(["s_client", "-connect",
                   &format!("{}:{}", addr.ip(), port),
                   "-servername", &addr.ip().to_string(),
                   "-brief", "-no_ign_eof"])
            .stdin(std::process::Stdio::null())
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string()
                + &String::from_utf8_lossy(&out.stderr);
            if text.contains("CONNECTED") || text.contains("subject=") {
                result.tls = true;
                // Extract subject CN
                if let Some(start) = text.find("subject=") {
                    let rest = &text[start + 8..];
                    let end  = rest.find('\n').unwrap_or(rest.len());
                    result.tls_subject = Some(rest[..end].trim().to_string());
                }
                // Check expiry
                if text.contains("verify error:num=10") || text.contains("certificate has expired") {
                    result.tls_expired = Some(true);
                } else if text.contains("Verification: OK") || text.contains("Verify return code: 0") {
                    result.tls_expired = Some(false);
                }
            }
        }
        // Fall through to plain banner grab (HTTP probe on TLS port won't work,
        // but grab whatever is readable).
    }

    // Plain banner grab.
    let mut stream = match connect_plain() {
        Some(s) => s,
        None    => return result,
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    // Send probe.
    if let Some(probe) = banner_probe(port) {
        let _ = stream.write_all(probe);
    }

    // Read up to 2 KB.
    let mut buf = vec![0u8; 2048];
    let n = stream.read(&mut buf).unwrap_or(0);
    if n == 0 {
        return result;
    }

    let banner_str = sanitise_banner(&buf[..n]);
    if !banner_str.is_empty() {
        result.fingerprint = fingerprint(&banner_str);
        result.banner      = Some(banner_str);
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// OS hint via ping TTL
// ─────────────────────────────────────────────────────────────────────────────

fn os_hint(ip: &str) -> &'static str {
    // Try GNU/Linux ping first, then macOS/BSD style.
    let out = std::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", ip])
        .output()
        .or_else(|_| std::process::Command::new("ping").args(["-c", "1", ip]).output());

    let text = match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return "Unknown",
    };

    // Find "ttl=<number>" (case-insensitive).
    let lower = text.to_ascii_lowercase();
    if let Some(pos) = lower.find("ttl=") {
        let rest = &lower[pos + 4..];
        let end  = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        if let Ok(ttl) = rest[..end].parse::<u32>() {
            return match ttl {
                1..=64   => "Linux / Unix",
                65..=128 => "Windows",
                _        => "Cisco / Network",
            };
        }
    }
    "Unknown"
}

// ─────────────────────────────────────────────────────────────────────────────
// Port spec parser  — "80", "1-1024", "22,80,443", "1-100,443,8080"
// ─────────────────────────────────────────────────────────────────────────────

fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut seen   = HashSet::new();
    let mut ports  = Vec::new();

    for chunk in spec.split(',') {
        let chunk = chunk.trim();
        if chunk.is_empty() { continue; }

        if chunk.contains('-') {
            let parts: Vec<&str> = chunk.splitn(2, '-').collect();
            let a = parts[0].trim().parse::<u32>().map_err(|_| format!("invalid range start in {:?}", chunk))?;
            let b = parts[1].trim().parse::<u32>().map_err(|_| format!("invalid range end in {:?}", chunk))?;
            if a < 1 || b > 65535 || a > b {
                return Err(format!("range {:?} out of bounds (1–65535)", chunk));
            }
            for p in a..=b {
                let p16 = p as u16;
                if seen.insert(p16) { ports.push(p16); }
            }
        } else {
            let p = chunk.parse::<u32>().map_err(|_| format!("invalid port {:?}", chunk))?;
            if p < 1 || p > 65535 {
                return Err(format!("port {} out of bounds (1–65535)", p));
            }
            let p16 = p as u16;
            if seen.insert(p16) { ports.push(p16); }
        }
    }

    if ports.is_empty() {
        return Err(format!("no valid ports found in {:?}", spec));
    }
    ports.sort_unstable();
    Ok(ports)
}

// ─────────────────────────────────────────────────────────────────────────────
// Host resolution  (IPv4 preferred)
// ─────────────────────────────────────────────────────────────────────────────

fn resolve_host(host: &str) -> Option<IpAddr> {
    // If it's already an IP, return immediately.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    let addrs = format!("{}:0", host).to_socket_addrs().ok()?;
    let mut fallback: Option<IpAddr> = None;
    for addr in addrs {
        match addr.ip() {
            IpAddr::V4(_) => return Some(addr.ip()),
            v6 => { fallback.get_or_insert(v6); }
        }
    }
    fallback
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan result
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub port:            u16,
    pub default_service: &'static str,
    pub fingerprint:     Option<Fingerprint>,
    pub banner:          Option<String>,
    pub tls:             bool,
    pub tls_subject:     Option<String>,
    pub tls_expired:     Option<bool>,
    pub rtt_ms:          f64,
    pub risk_hints:      Vec<&'static str>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Port-level scanner
// ─────────────────────────────────────────────────────────────────────────────

fn scan_one(ip: IpAddr, port: u16, timeout: Duration, do_grab: bool) -> Option<ScanResult> {
    let addr = SocketAddr::new(ip, port);
    let t0   = Instant::now();
    if TcpStream::connect_timeout(&addr, timeout).is_err() {
        return None;
    }
    let rtt_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let mut banner_res = BannerResult::default();
    if do_grab {
        banner_res = grab_banner(addr, port, timeout);
    }

    let hints = banner_res.fingerprint.as_ref()
        .map(|fp| risk_hints(fp, banner_res.banner.as_deref().unwrap_or("")))
        .unwrap_or_default();

    Some(ScanResult {
        port,
        default_service: service_name(port),
        fingerprint:     banner_res.fingerprint,
        banner:          banner_res.banner,
        tls:             banner_res.tls,
        tls_subject:     banner_res.tls_subject,
        tls_expired:     banner_res.tls_expired,
        rtt_ms,
        risk_hints: hints,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Concurrent scan engine
// ─────────────────────────────────────────────────────────────────────────────

fn run_scan(
    ip:          IpAddr,
    ports:       &[u16],
    timeout:     Duration,
    concurrency: usize,
    do_grab:     bool,
    verbose:     bool,
    interrupted: Arc<AtomicBool>,
) -> Vec<ScanResult> {
    let results    = Arc::new(Mutex::new(Vec::<ScanResult>::new()));
    let completed  = Arc::new(AtomicUsize::new(0));
    let total      = ports.len();
    let print_mu   = Arc::new(Mutex::new(()));

    // Channel as semaphore: buffer = concurrency.
    let (tx, rx)   = std::sync::mpsc::sync_channel::<u16>(concurrency);
    let rx         = Arc::new(Mutex::new(rx));

    // Spawn worker threads.
    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency.min(total) {
        let rx          = Arc::clone(&rx);
        let results     = Arc::clone(&results);
        let completed   = Arc::clone(&completed);
        let print_mu    = Arc::clone(&print_mu);
        let interrupted = Arc::clone(&interrupted);

        let handle = thread::spawn(move || {
            loop {
                if interrupted.load(Ordering::Relaxed) { break; }
                let port = {
                    let guard = rx.lock().unwrap();
                    match guard.recv() {
                        Ok(p) => p,
                        Err(_) => break,
                    }
                };

                let res = scan_one(ip, port, timeout, do_grab);
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;

                let _guard = print_mu.lock().unwrap();
                if let Some(r) = res {
                    // Detected service label.
                    let svc = r.fingerprint.as_ref()
                        .map(|f| f.service_name)
                        .unwrap_or(r.default_service);
                    let ver = r.fingerprint.as_ref()
                        .and_then(|f| f.version.as_deref())
                        .map(|v| format!(" v{}", v))
                        .unwrap_or_default();
                    let tls_tag = if r.tls { format!(" {}", paint(CYAN, "[TLS]")) } else { String::new() };
                    let risk_tag = if !r.risk_hints.is_empty() { format!(" {}", paint(YELLOW, "⚠")) } else { String::new() };
                    println!("  {} {}  {}{}{}{}",
                        paint(GREEN, "[+]"),
                        paint(&format!("{}{}", BOLD, WHITE), &format!("{}/tcp", port)),
                        paint(YELLOW, &format!("{}{}", svc, ver)),
                        tls_tag, risk_tag, RESET);
                    results.lock().unwrap().push(r);
                } else if verbose {
                    println!("  {} {}/tcp closed", paint(DIM, "[-]"), port);
                }

                // Progress bar (only when not verbose, overwrite line).
                if !verbose {
                    let pct = done * 100 / total;
                    let filled = pct / 5;
                    let bar: String = "█".repeat(filled) + &"░".repeat(20 - filled);
                    print!("\r  {} [{}] {}% ({}/{})   ",
                        paint(DIM, "Progress:"),
                        paint(CYAN, &bar),
                        pct, done, total);
                    let _ = io::stdout().flush();
                }
            }
        });
        handles.push(handle);
    }

    // Feed ports into channel.
    for &port in ports {
        if interrupted.load(Ordering::Relaxed) { break; }
        let _ = tx.send(port);
    }
    drop(tx); // Signal workers that no more ports are coming.

    for h in handles { let _ = h.join(); }

    // Clear progress line.
    if !verbose {
        print!("\r{}\r", " ".repeat(60));
        let _ = io::stdout().flush();
    }

    let mut out = results.lock().unwrap().clone();
    out.sort_by_key(|r| r.port);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Export helpers
// ─────────────────────────────────────────────────────────────────────────────

fn quote_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn save_json(path: &str, target: &str, ip: &str, os_hint_str: &str,
             ports_scanned: usize, elapsed: Duration,
             timeout_ms: u64, concurrency: usize, results: &[ScanResult]) {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"target\": \"{}\",\n", target));
    out.push_str(&format!("  \"ip\": \"{}\",\n", ip));
    out.push_str(&format!("  \"os_hint\": \"{}\",\n", os_hint_str));
    out.push_str(&format!("  \"ports_scanned\": {},\n", ports_scanned));
    out.push_str(&format!("  \"open_ports\": {},\n", results.len()));
    out.push_str(&format!("  \"elapsed_sec\": {:.3},\n", elapsed.as_secs_f64()));
    out.push_str(&format!("  \"timeout_ms\": {},\n", timeout_ms));
    out.push_str(&format!("  \"concurrency\": {},\n", concurrency));
    out.push_str("  \"results\": [\n");
    for (i, r) in results.iter().enumerate() {
        let comma = if i + 1 < results.len() { "," } else { "" };
        let svc_key  = r.fingerprint.as_ref().map(|f| f.service_key).unwrap_or("");
        let svc_name = r.fingerprint.as_ref().map(|f| f.service_name).unwrap_or("");
        let version  = r.fingerprint.as_ref().and_then(|f| f.version.as_deref()).unwrap_or("");
        let banner   = r.banner.as_deref().unwrap_or("");
        let tls_subj = r.tls_subject.as_deref().unwrap_or("");
        let tls_exp  = r.tls_expired.map(|e| if e { "true" } else { "false" }).unwrap_or("null");
        let risks    = r.risk_hints.iter().map(|h| format!("\"{}\"", h)).collect::<Vec<_>>().join(", ");
        out.push_str(&format!(
            "    {{\"port\":{},\"default_service\":\"{}\",\"service_key\":\"{}\",\
            \"service_name\":\"{}\",\"version\":\"{}\",\"tls\":{},\
            \"tls_subject\":\"{}\",\"tls_expired\":{},\"rtt_ms\":{:.1},\
            \"risk_hints\":[{}],\"banner\":\"{}\"}}{}",
            r.port, r.default_service, svc_key, svc_name, version,
            r.tls, tls_subj, tls_exp,
            r.rtt_ms, risks,
            banner.replace('"', "\\\"").replace('\n', "\\n"),
            comma
        ));
        out.push('\n');
    }
    out.push_str("  ]\n}\n");

    let fpath = format!("{}.json", path);
    match std::fs::write(&fpath, &out) {
        Ok(_)  => println!("  {} JSON saved → {}", paint(GREEN, "[✓]"), fpath),
        Err(e) => eprintln!("  {} write {}: {}", paint(RED, "[✗]"), fpath, e),
    }
}

fn save_csv(path: &str, results: &[ScanResult]) {
    let mut out = String::from("port,default_service,detected_service,version,tls,tls_subject,tls_expired,rtt_ms,risk_hints,banner\n");
    for r in results {
        let svc_name = r.fingerprint.as_ref().map(|f| f.service_name).unwrap_or("");
        let version  = r.fingerprint.as_ref().and_then(|f| f.version.as_deref()).unwrap_or("");
        let banner   = r.banner.as_deref().unwrap_or("").replace('\n', " ");
        let tls_subj = r.tls_subject.as_deref().unwrap_or("");
        let tls_exp  = r.tls_expired.map(|e| if e { "true" } else { "false" }).unwrap_or("");
        let risks    = r.risk_hints.join("; ");
        out.push_str(&format!("{},{},{},{},{},{},{},{:.1},{},{}\n",
            r.port,
            quote_csv(r.default_service),
            quote_csv(svc_name),
            quote_csv(version),
            r.tls,
            quote_csv(tls_subj),
            tls_exp,
            r.rtt_ms,
            quote_csv(&risks),
            quote_csv(&strip_ansi(&banner)),
        ));
    }
    let fpath = format!("{}.csv", path);
    match std::fs::write(&fpath, &out) {
        Ok(_)  => println!("  {} CSV  saved → {}", paint(GREEN, "[✓]"), fpath),
        Err(e) => eprintln!("  {} write {}: {}", paint(RED, "[✗]"), fpath, e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

fn print_banner_art() {
    println!("{}{}", CYAN, BOLD);
    println!("╔══════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                                                                  ║");
    println!("║  ██████╗ ██╗   ██╗███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗         ║");
    println!("║  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║         ║");
    println!("║  ██████╔╝██║   ██║███████╗   ██║       ███████╗██║     ███████║██╔██╗██║         ║");
    println!("║  ██╔══██╗██║   ██║╚════██║   ██║       ╚════██║██║     ██╔══██║██║╚████║         ║");
    println!("║  ██║  ██║╚██████╔╝███████║   ██║       ███████║╚██████╗██║  ██║██║ ╚███║         ║");
    println!("║  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝         ║");
    println!("║                                                                                  ║");
    println!("║              Memory-Safe High Performance Scanner  v2.0                          ║");
    println!("║                              by Prasad                                           ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════╝");
    println!("{}", RESET);
}

fn section(title: &str, double: bool) {
    let w     = 82usize;
    let inner = w.saturating_sub(2);
    let pad   = (inner.saturating_sub(title.len())) / 2;
    let extra = (inner.saturating_sub(title.len())) % 2;
    let line  = format!("{}{}{}", " ".repeat(pad), title, " ".repeat(pad + extra));

    if double {
        println!("\n{}", paint(CYAN, &format!("╔{}╗", "═".repeat(inner))));
        println!("{}", paint(CYAN, &format!("║{}║", line)));
        println!("{}", paint(CYAN, &format!("╚{}╝", "═".repeat(inner))));
    } else {
        println!("\n{}", paint(CYAN, &format!("┌{}┐", "─".repeat(inner))));
        println!("{}", paint(CYAN, &format!("│{}│", line)));
        println!("{}", paint(CYAN, &format!("└{}┘", "─".repeat(inner))));
    }
}

fn truncate(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= n {
        s.to_string()
    } else {
        chars[..n.saturating_sub(1)].iter().collect::<String>() + "…"
    }
}

fn print_results_table(results: &[ScanResult]) {
    if results.is_empty() {
        println!("\n  {} No open ports found.", paint(YELLOW, "[!]"));
        return;
    }
    println!("\n  {} Found {} open port(s)\n",
        paint(&format!("{}{}", GREEN, BOLD), "[+]"),
        paint(&format!("{}{}", WHITE, BOLD), &results.len().to_string()));

    let top = paint(CYAN, "┌──────────┬──────────────────────┬──────────────────────┬──────────┬──────────────────────────────────────┐");
    let hdr = format!("{}{}{}{}{}{}{}{}{}{}{}",
        paint(CYAN,"│"), "  PORT    ",
        paint(CYAN,"│"), "  DEFAULT SERVICE     ",
        paint(CYAN,"│"), "  DETECTED SERVICE    ",
        paint(CYAN,"│"), "  RTT ms  ",
        paint(CYAN,"│"), "  VERSION / BANNER                    ",
        paint(CYAN,"│"));
    let mid = paint(CYAN, "├──────────┼──────────────────────┼──────────────────────┼──────────┼──────────────────────────────────────┤");
    let bot = paint(CYAN, "└──────────┴──────────────────────┴──────────────────────┴──────────┴──────────────────────────────────────┘");

    println!("{}", top);
    println!("{}", hdr);
    println!("{}", mid);

    let sep = paint(CYAN, "│");
    for r in results {
        let tls_icon = if r.tls { paint(CYAN, "🔒") } else { "  ".to_string() };
        let port_cell = format!("{} {:<6}", tls_icon, r.port);
        let def_cell  = format!("{:<20}", truncate(r.default_service, 20));
        let (det_cell_raw, det_cell) = match r.fingerprint.as_ref() {
            Some(fp) => {
                let raw = format!("✓ {}", fp.service_name);
                let coloured = paint(GREEN, &format!("✓ {}", truncate(fp.service_name, 17)));
                let pad = 20usize.saturating_sub(raw.len());
                (raw.len(), format!("{}{}", coloured, " ".repeat(pad)))
            }
            None => (1, format!("{:<20}", paint(DIM, "─"))),
        };
        let _ = det_cell_raw; // suppress warning

        let rtt_cell = format!("{:<8}", format!("{:.1}ms", r.rtt_ms));

        let ver_str = r.fingerprint.as_ref()
            .and_then(|f| f.version.as_deref())
            .map(|v| format!("v{}", v))
            .or_else(|| r.banner.as_ref().map(|b| truncate(b, 36)))
            .unwrap_or_else(|| "Open".to_string());
        let ver_cell = format!("{:<36}", ver_str);

        println!("{}  {}{}  {}{}  {}{}  {}{}  {}{}",
            sep, paint(&format!("{}{}", BOLD, WHITE), &port_cell), sep,
            paint(YELLOW, &def_cell), sep,
            det_cell, sep,
            paint(MAGENTA, &rtt_cell), sep,
            paint(WHITE, &ver_cell), sep);

        // Risk hints as sub-rows.
        for hint in &r.risk_hints {
            let row = format!("{:<83}", truncate(&format!("  ⚠  {}", hint), 83));
            println!("{}  {}{}", sep, paint(YELLOW, &row), sep);
        }
        // TLS expiry warning.
        if r.tls_expired == Some(true) {
            let row = format!("{:<83}", format!("  🔴  TLS certificate EXPIRED"));
            println!("{}  {}{}", sep, paint(RED, &row), sep);
        }
    }
    println!("{}", bot);
}

fn print_summary(
    target: &str, ip: &str, os_hint_str: &str,
    total_scanned: usize, open_count: usize,
    elapsed: Duration, timeout_ms: u64,
    concurrency: usize, grab: bool,
) {
    println!();
    let lbl = |s: &str| paint(DIM, s);
    println!("  {:<20}: {}", lbl("Target"),        paint(WHITE, &format!("{} ({})", target, ip)));
    println!("  {:<20}: {}", lbl("OS Hint"),        paint(WHITE, os_hint_str));
    println!("  {:<20}: {}", lbl("Ports scanned"),  paint(WHITE, &total_scanned.to_string()));
    println!("  {:<20}: {}", lbl("Open ports"),     paint(&format!("{}{}", GREEN, BOLD), &open_count.to_string()));
    println!("  {:<20}: {}", lbl("Time taken"),     paint(WHITE, &format!("{:.2}s", elapsed.as_secs_f64())));
    println!("  {:<20}: {}", lbl("Timeout"),        paint(WHITE, &format!("{}ms", timeout_ms)));
    println!("  {:<20}: {}", lbl("Concurrency"),    paint(WHITE, &concurrency.to_string()));
    println!("  {:<20}: {}", lbl("Banner grab"),    paint(WHITE, if grab { "Enabled" } else { "Disabled" }));
    println!();
    println!("{}", paint(CYAN, &"═".repeat(82)));
    println!();
}

fn print_help() {
    section("USAGE", false);
    println!();
    println!("  {}", paint(WHITE, "cargo run -- -t <target> [options]"));
    println!("  {}", paint(WHITE, "rustc scanner.rs -o scanner && ./scanner -t <target> [options]"));
    println!();
    println!("{}", paint(YELLOW, "OPTIONS:"));
    let opts = [
        ("-t, --target <host>",   "Target hostname or IP address"),
        ("-p, --ports <spec>",    "Port range, list, or mixed: 1-1024,8080,9200"),
        ("-q, --quick",           "Quick scan — top 24 common ports"),
        ("-s, --standard",        "Standard scan — top 38 ports (default)"),
        ("-to, --timeout <ms>",   "Connection timeout in ms (default: 1000)"),
        ("-th, --threads <n>",    "Concurrent threads (default: 200)"),
        ("-nb, --no-banner",      "Disable banner grabbing (faster)"),
        ("-v, --verbose",         "Show closed ports too"),
        ("-o, --output <file>",   "Save results as <file>.json and <file>.csv"),
        ("-h, --help",            "Show this help"),
    ];
    for (flag, desc) in &opts {
        println!("  {:<28} {}", paint(WHITE, flag), desc);
    }
    println!();
    println!("{}", paint(YELLOW, "EXAMPLES:"));
    let examples = [
        "./scanner -t google.com -q",
        "./scanner -t 192.168.1.1 -p 1-10000 -th 500",
        "./scanner -t github.com -p 22,80,443 -to 300 -o results",
        "./scanner -t 10.0.0.1 -s -v -nb",
    ];
    for ex in &examples {
        println!("  {}", paint(DIM, ex));
    }
    println!();
}

// ─────────────────────────────────────────────────────────────────────────────
// Port presets
// ─────────────────────────────────────────────────────────────────────────────

fn top_ports_quick() -> Vec<u16> {
    vec![21,22,23,25,53,80,110,135,139,143,443,445,993,995,
         3306,3389,5432,5900,6379,8080,8443,9200,11211,27017]
}

fn top_ports_standard() -> Vec<u16> {
    vec![20,21,22,23,25,53,80,110,111,135,139,143,443,445,
         465,587,993,995,1723,2375,2376,3000,3306,3389,4443,
         5432,5601,5900,6379,6443,8080,8443,8888,9000,9200,
         11211,27017,27018]
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    print_banner_art();

    // ── Argument parsing ─────────────────────────────────────────────────────
    let args: Vec<String> = env::args().collect();

    let mut target      = String::new();
    let mut port_spec   = String::new();
    let mut quick_mode  = false;
    let mut _std_mode    = false;
    let mut timeout_ms: u64   = 1000;
    let mut concurrency: usize = 200;
    let mut no_banner   = false;
    let mut verbose     = false;
    let mut output      = String::new();
    let mut show_help   = false;

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-t" | "--target"    => { i += 1; if i < args.len() { target     = args[i].clone(); } }
            "-p" | "--ports"     => { i += 1; if i < args.len() { port_spec  = args[i].clone(); } }
            "-q" | "--quick"     => { quick_mode  = true; }
            "-s" | "--standard"  => { _std_mode    = true; }
            "-nb"| "--no-banner" => { no_banner   = true; }
            "-v" | "--verbose"   => { verbose      = true; }
            "-h" | "--help"      => { show_help    = true; }
            "-to"| "--timeout"   => {
                i += 1;
                if i < args.len() {
                    match args[i].parse::<u64>() {
                        Ok(v) => timeout_ms = v,
                        Err(_) => { eprintln!("  {} --timeout must be a number", paint(RED, "[✗]")); process::exit(1); }
                    }
                }
            }
            "-th"| "--threads"   => {
                i += 1;
                if i < args.len() {
                    match args[i].parse::<usize>() {
                        Ok(v) => concurrency = v,
                        Err(_) => { eprintln!("  {} --threads must be a number", paint(RED, "[✗]")); process::exit(1); }
                    }
                }
            }
            "-o" | "--output"    => { i += 1; if i < args.len() { output = args[i].clone(); } }
            _                    => {}
        }
        i += 1;
    }

    if show_help || target.is_empty() {
        print_help();
        process::exit(0);
    }

    // ── Validate ─────────────────────────────────────────────────────────────
    if timeout_ms < 50 || timeout_ms > 30_000 {
        eprintln!("  {} --timeout must be 50–30000 ms", paint(RED, "[✗]"));
        process::exit(1);
    }
    if concurrency < 1 || concurrency > 10_000 {
        eprintln!("  {} --threads must be 1–10000", paint(RED, "[✗]"));
        process::exit(1);
    }

    // ── Strip URL junk from target ────────────────────────────────────────────
    let clean_target = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .splitn(2, '/')
        .next()
        .unwrap_or(&target)
        .trim()
        .to_string();

    if clean_target.is_empty() {
        eprintln!("  {} Target is empty after parsing", paint(RED, "[✗]"));
        process::exit(1);
    }

    // ── Resolve ───────────────────────────────────────────────────────────────
    println!("  {} Resolving {}...", paint(CYAN, "[→]"), clean_target);
    let ip = match resolve_host(&clean_target) {
        Some(a) => a,
        None    => {
            eprintln!("  {} Cannot resolve {:?}", paint(RED, "[✗]"), clean_target);
            process::exit(1);
        }
    };
    println!("  {} {} → {}", paint(GREEN, "[✓]"), paint(WHITE, &clean_target), paint(WHITE, &ip.to_string()));

    // ── OS hint ───────────────────────────────────────────────────────────────
    let os = os_hint(&ip.to_string());
    println!("  {} OS hint      : {}", paint(CYAN, "[→]"), paint(WHITE, os));
    println!("  {} Timeout      : {}ms", paint(CYAN, "[→]"), timeout_ms);
    println!("  {} Concurrency  : {}", paint(CYAN, "[→]"), concurrency);
    println!("  {} Banner grab  : {}",
        paint(CYAN, "[→]"),
        if no_banner { paint(YELLOW, "Disabled") } else { paint(GREEN, "Enabled") });

    // ── Port list ─────────────────────────────────────────────────────────────
    let ports_to_scan: Vec<u16> = if !port_spec.is_empty() {
        match parse_ports(&port_spec) {
            Ok(p)  => { println!("  {} Mode: Custom ({} ports)\n", paint(CYAN, "[→]"), p.len()); p }
            Err(e) => { eprintln!("  {} {}", paint(RED, "[✗]"), e); process::exit(1); }
        }
    } else if quick_mode {
        let p = top_ports_quick();
        println!("  {} Mode: Quick ({} ports)\n", paint(CYAN, "[→]"), p.len());
        p
    } else {
        let p = top_ports_standard();
        println!("  {} Mode: Standard ({} ports)\n", paint(CYAN, "[→]"), p.len());
        p
    };

    // ── Graceful Ctrl-C ───────────────────────────────────────────────────────
    let interrupted = Arc::new(AtomicBool::new(false));
    let intr_clone  = Arc::clone(&interrupted);
    // Best-effort signal handler (Unix only; ignored on Windows).
    unsafe {
        libc_signal(intr_clone);
    }

    // ── Scan ──────────────────────────────────────────────────────────────────
    section("SCANNING IN PROGRESS", false);
    println!();
    let start = Instant::now();
    let results = run_scan(
        ip, &ports_to_scan,
        Duration::from_millis(timeout_ms),
        concurrency, !no_banner, verbose,
        Arc::clone(&interrupted),
    );
    let elapsed = start.elapsed();

    // ── Display ───────────────────────────────────────────────────────────────
    println!();
    section("RESULTS", true);
    print_results_table(&results);
    section("SUMMARY", true);
    print_summary(
        &clean_target, &ip.to_string(), os,
        ports_to_scan.len(), results.len(),
        elapsed, timeout_ms, concurrency, !no_banner,
    );

    // ── Export ────────────────────────────────────────────────────────────────
    if !output.is_empty() {
        println!();
        save_json(&output, &clean_target, &ip.to_string(), os,
                  ports_to_scan.len(), elapsed, timeout_ms, concurrency, &results);
        save_csv(&output, &results);
        println!();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Best-effort SIGINT handler (Unix)
// ─────────────────────────────────────────────────────────────────────────────

/// Install a SIGINT handler using libc (available on Unix).
/// Falls back to a no-op on compile failure.
unsafe fn libc_signal(flag: Arc<AtomicBool>) {
    // We spawn a thread that parks waiting; on Ctrl-C the OS delivers SIGINT
    // to the process.  The cleanest stdlib-only approach is to use a thread +
    // a pipe trick, but that's complex; for a scanner tool, a short-sleep poll
    // loop is acceptable.
    thread::spawn(move || {
        // Check a global static set by a raw signal handler would require
        // unsafe libc; instead we use a SIGINT-compatible approach: park and
        // let the OS deliver SIGINT which terminates the process.  The flag
        // approach below is best-effort without libc crate.
        //
        // With stdlib only we cannot install a custom SIGINT handler portably.
        // If the user presses Ctrl-C, the OS sends SIGINT which by default
        // terminates the process.  The Arc<AtomicBool> is set here just for
        // possible future use.
        loop {
            thread::sleep(Duration::from_millis(100));
            if flag.load(Ordering::Relaxed) { break; }
        }
    });
}
