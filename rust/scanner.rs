// SmartScan - Rust High Performance Scanner
// Author: Prasad

use std::net::TcpStream;
use std::time::Duration;
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::env;
use std::process;

// ANSI color codes
const RESET: &str = "\x1b[0m";
const RED: &str = "\x1b[91m";
const GREEN: &str = "\x1b[92m";
const YELLOW: &str = "\x1b[93m";
const BLUE: &str = "\x1b[94m";
const MAGENTA: &str = "\x1b[95m";
const CYAN: &str = "\x1b[96m";
const WHITE: &str = "\x1b[97m";
const BOLD: &str = "\x1b[1m";

fn print_banner() {
    println!("{}{}", CYAN, BOLD);
    println!("╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                                                                                                ║");
    println!("║     ██████╗ ██╗   ██╗███████╗████████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗         ║");
    println!("║     ██╔══██╗██║   ██║██╔════╝╚══██╔══╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗        ║");
    println!("║     ██████╔╝██║   ██║███████╗   ██║        ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝        ║");
    println!("║     ██╔══██╗██║   ██║╚════██║   ██║        ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗        ║");
    println!("║     ██║  ██║╚██████╔╝███████║   ██║        ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║        ║");
    println!("║     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝        ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝        ║");
    println!("║                                                                                                                ║");
    println!("║                                  Memory-Safe High Performance Scanner                                          ║");
    println!("║                                            by Prasad                                                           ║");
    println!("╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝");
    println!("{}", RESET);
}

// Common ports with service names
fn get_service_name(port: u16) -> &'static str {
    match port {
        20 => "FTP-data",    21 => "FTP",        22 => "SSH",
        23 => "Telnet",      25 => "SMTP",       53 => "DNS",
        80 => "HTTP",        110 => "POP3",      111 => "RPC",
        135 => "RPC",        139 => "NetBIOS",   143 => "IMAP",
        443 => "HTTPS",      445 => "SMB",       993 => "IMAPS",
        995 => "POP3S",      1723 => "PPTP",     3306 => "MySQL",
        3389 => "RDP",       5432 => "PostgreSQL", 5900 => "VNC",
        6379 => "Redis",     8080 => "HTTP-Alt", 8443 => "HTTPS-Alt",
        27017 => "MongoDB",  _ => "Unknown",
    }
}

fn scan_port(host: &str, port: u16, timeout: u64) -> bool {
    let address = format!("{}:{}", host, port);
    match TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_millis(timeout)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn print_scanning_header() {
    println!("{}", CYAN);
    println!("┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐");
    println!("│                                                 SCANNING IN PROGRESS...                                        │");
    println!("└────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘");
    println!("{}", RESET);
}

fn print_results_header() {
    println!("{}", CYAN);
    println!("╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                                  RESULTS                                                       ║");
    println!("╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝");
    println!("{}", RESET);
}

fn print_results_table(open_ports: &Vec<(u16, &'static str)>) {
    if open_ports.is_empty() {
        println!("\n{}[!] No open ports found.{}", YELLOW, RESET);
        return;
    }
    
    println!("\n{}[+] Found {} open port(s):{}", GREEN, open_ports.len(), RESET);
    println!("{}", CYAN);
    println!("┌──────────┬────────────────────┬────────────────────────────────────────────────────────────────────────────┐");
    println!("│   PORT   │      SERVICE       │                                    INFO                                    │");
    println!("├──────────┼────────────────────┼────────────────────────────────────────────────────────────────────────────┤");
    
    for (port, service) in open_ports {
        let service_color = if *service == "Unknown" { WHITE } else { YELLOW };
        println!("│  {:5}   │  {}{:<17}{} │  {:<76} │", 
            port, service_color, service, RESET, format!("Port {} is OPEN", port));
    }
    
    println!("└──────────┴────────────────────┴────────────────────────────────────────────────────────────────────────────┘");
    println!("{}", RESET);
}

fn print_summary_header() {
    println!("{}", CYAN);
    println!("╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                                  SUMMARY                                                       ║");
    println!("╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝");
    println!("{}", RESET);
}

fn print_summary(target: &str, ip: &str, total_scanned: usize, open_count: usize, elapsed_ms: u128, timeout: u64, threads: usize) {
    println!("{}", WHITE);
    println!("  Target IP     : {}", ip);
    println!("  Hostname      : {}", target);
    println!("  Ports scanned : {}", total_scanned);
    println!("  Open ports    : {}", open_count);
    println!("  Time taken    : {:.2} seconds", elapsed_ms as f64 / 1000.0);
    println!("  Timeout       : {} ms", timeout);
    println!("  Threads       : {}", threads);
    println!("{}", RESET);
    
    println!("{}", CYAN);
    println!("════════════════════════════════════════════════════════════════════════════════════════════════════════════════");
    println!("{}", RESET);
}

fn print_help() {
    println!("{}", CYAN);
    println!("┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐");
    println!("│                                                    USAGE                                                       │");
    println!("└────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘");
    println!("{}", RESET);
    println!("");
    println!("  cargo run -- -t <target> [options]");
    println!("  rustc scanner.rs && ./scanner -t <target> [options]");
    println!("");
    println!("{}OPTIONS:{}", YELLOW, RESET);
    println!("  -t, --target <host>     Target hostname or IP address");
    println!("  -p, --ports <ports>     Port range (1-1000) or list (22,80,443)");
    println!("  -q, --quick             Quick scan of top 24 common ports");
    println!("  -to, --timeout <ms>     Connection timeout in milliseconds (default: 1000)");
    println!("  -th, --threads <num>    Number of threads (default: 200)");
    println!("  -h, --help              Show this help message");
    println!("");
    println!("{}EXAMPLES:{}", YELLOW, RESET);
    println!("  ./scanner -t google.com -q");
    println!("  ./scanner -t 192.168.1.1 -p 1-1000");
    println!("  ./scanner -t github.com -p 22,80,443,3306 -to 500");
    println!("  ./scanner -t cloudflare.com -p 1-65535 -th 500");
    println!("");
}

fn get_top_ports() -> Vec<u16> {
    vec![21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
}

fn parse_ports(port_arg: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    
    if port_arg.contains('-') {
        let parts: Vec<&str> = port_arg.split('-').collect();
        if parts.len() == 2 {
            if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                if start > 0 && end <= 65535 && start <= end {
                    for p in start..=end {
                        ports.push(p);
                    }
                }
            }
        }
    } else if port_arg.contains(',') {
        for part in port_arg.split(',') {
            if let Ok(p) = part.trim().parse::<u16>() {
                if p > 0 && p <= 65535 {
                    ports.push(p);
                }
            }
        }
    } else {
        if let Ok(p) = port_arg.parse::<u16>() {
            if p > 0 && p <= 65535 {
                ports.push(p);
            }
        }
    }
    
    ports
}

fn main() {
    print_banner();
    
    let args: Vec<String> = env::args().collect();
    
    // Default values
    let mut target = String::new();
    let mut port_spec = String::new();
    let mut quick_mode = false;
    let mut timeout_ms: u64 = 1000;
    let mut threads: usize = 200;
    let mut show_help = false;
    
    // Parse arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-t" | "--target" => {
                if i + 1 < args.len() {
                    target = args[i + 1].clone();
                    i += 1;
                }
            }
            "-p" | "--ports" => {
                if i + 1 < args.len() {
                    port_spec = args[i + 1].clone();
                    i += 1;
                }
            }
            "-q" | "--quick" => {
                quick_mode = true;
            }
            "-to" | "--timeout" => {
                if i + 1 < args.len() {
                    if let Ok(t) = args[i + 1].parse::<u64>() {
                        timeout_ms = t;
                    }
                    i += 1;
                }
            }
            "-th" | "--threads" => {
                if i + 1 < args.len() {
                    if let Ok(t) = args[i + 1].parse::<usize>() {
                        threads = t;
                    }
                    i += 1;
                }
            }
            "-h" | "--help" => {
                show_help = true;
            }
            _ => {}
        }
        i += 1;
    }
    
    if show_help || target.is_empty() {
        print_help();
        process::exit(0);
    }
    
    // Clean target
    let mut clean_target = target.clone();
    clean_target = clean_target.replace("http://", "");
    clean_target = clean_target.replace("https://", "");
    if let Some(slash_pos) = clean_target.find('/') {
        clean_target = clean_target[..slash_pos].to_string();
    }
    
    println!("{}[✓] Target: {}{}", GREEN, WHITE, clean_target);
    println!("{}[→] Timeout: {}{} ms", GREEN, WHITE, timeout_ms);
    println!("{}[→] Threads: {}{}", GREEN, WHITE, threads);
    println!("{}", RESET);
    
    // Determine ports to scan
    let ports_to_scan: Vec<u16> = if quick_mode {
        println!("{}[→] Mode: Quick Scan (24 common ports){}", CYAN, RESET);
        get_top_ports()
    } else if !port_spec.is_empty() {
        let parsed = parse_ports(&port_spec);
        if parsed.is_empty() {
            println!("{}[!] Invalid port specification{}", RED, RESET);
            process::exit(1);
        }
        println!("{}[→] Mode: Custom Scan ({} ports){}", CYAN, parsed.len(), RESET);
        parsed
    } else {
        println!("{}[→] Mode: Default Scan (24 common ports){}", CYAN, RESET);
        println!("{}[→] Tip: Use -q or -p for custom ranges{}", YELLOW, RESET);
        get_top_ports()
    };
    
    // Resolve hostname
    use std::net::ToSocketAddrs;
    let ip = format!("{}:0", clean_target).to_socket_addrs();
    
    let ip_str = match ip {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                addr.ip().to_string()
            } else {
                println!("{}[!] Failed to resolve host{}", RED, RESET);
                process::exit(1);
            }
        }
        Err(_) => {
            println!("{}[!] Failed to resolve host{}", RED, RESET);
            process::exit(1);
        }
    };
    
    println!("{}[✓] Resolved: {} ({}){}", GREEN, WHITE, clean_target, ip_str);
    println!("{}", RESET);
    
    print_scanning_header();
    
    let start_time = std::time::Instant::now();
    
    // Shared results collection
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    
    // Create thread pool
    let mut handles = vec![];
    let ports_chunk_size = (ports_to_scan.len() + threads - 1) / threads;
    
    for chunk in ports_to_scan.chunks(ports_chunk_size) {
        let chunk_vec = chunk.to_vec();
        let open_ports_clone = Arc::clone(&open_ports);
        let target_clone = clean_target.clone();
        let timeout_clone = timeout_ms;
        
        let handle = thread::spawn(move || {
            let mut local_open = Vec::new();
            for port in chunk_vec {
                if scan_port(&target_clone, port, timeout_clone) {
                    let service = get_service_name(port);
                    local_open.push((port, service));
                    // Print open port immediately
                    println!("{}{}[+] Port {} is OPEN [{}]{}{}", 
                        GREEN, BOLD, port, service, RESET, GREEN);
                }
            }
            let mut guard = open_ports_clone.lock().unwrap();
            guard.extend(local_open);
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }
    
    let elapsed = start_time.elapsed();
    
    let mut final_results = open_ports.lock().unwrap().clone();
    final_results.sort_by_key(|(port, _)| *port);
    
    println!("{}", RESET);
    print_results_header();
    print_results_table(&final_results);
    print_summary_header();
    print_summary(&clean_target, &ip_str, ports_to_scan.len(), final_results.len(), elapsed.as_millis(), timeout_ms, threads);
}
