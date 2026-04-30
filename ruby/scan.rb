require 'socket'
require 'timeout'
require 'optparse'

# ANSI color codes
COLORS = {
  reset: "\033[0m",
  red: "\033[91m",
  green: "\033[92m",
  yellow: "\033[93m",
  blue: "\033[94m",
  magenta: "\033[95m",
  cyan: "\033[96m",
  white: "\033[97m",
  bold: "\033[1m"
}

def color(text, color)
  "#{COLORS[color]}#{text}#{COLORS[:reset]}"
end

def print_banner
  puts color("
╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                                ║
║     ██████╗ ██╗   ██╗██████╗ ██╗   ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗         ║
║     ██╔══██╗██║   ██║██╔══██╗╚██╗ ██╔╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗        ║
║     ██████╔╝██║   ██║██████╔╝ ╚████╔╝      ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝        ║
║     ██╔══██╗██║   ██║██╔══██╗  ╚██╔╝       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗        ║
║     ██║  ██║╚██████╔╝██████╔╝   ██║        ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║        ║
║     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝    ╚═╝        ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝        ║
║                                                                                                                ║
║                                    Service Detection Scanner                                                   ║
║                                            by Prasad                                                           ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
", :cyan)
end

# Service signatures for banner matching
SERVICE_SIGNATURES = {
  ssh: [/SSH-([0-9.]+)/, /OpenSSH_([0-9.]+)/, /dropbear_([0-9.]+)/],
  ftp: [/220(.*)FTP/, /vsFTPd/, /FileZilla/, /ProFTPD/],
  http: [/Server: (.*)/, /Apache\/([0-9.]+)/, /nginx\/([0-9.]+)/, /IIS\/([0-9.]+)/, /Express/],
  https: [/Server: (.*)/, /Apache/, /nginx/, /IIS/],
  mysql: [/mysql/, /MariaDB/, /\[([0-9.]+)\]/],
  postgres: [/PostgreSQL/, /postgres/],
  redis: [/redis_version/, /REDIS/],
  mongodb: [/MongoDB/, /wire version/],
  smtp: [/220 (.*) ESMTP/, /Postfix/, /Sendmail/, /Exchange/],
  pop3: [/POP3/, / Dovecot/, /Courier/],
  imap: [/IMAP/, / Dovecot/, /Courier/],
  rdp: [/RDP/, /Microsoft Terminal Services/],
  smb: [/SMB/, /Samba/, /Windows/],
  vnc: [/RFB/, /VNC/, /TightVNC/],
  telnet: [/Telnet/, /Microsoft Telnet/]
}

# Default probes for banner grabbing
BANNER_PROBES = {
  21 => "HELP\r\n",
  22 => "",
  25 => "HELP\r\n",
  80 => "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
  110 => "USER test\r\n",
  143 => "A001 CAPABILITY\r\n",
  443 => "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
  3306 => "",
  5432 => "",
  6379 => "INFO\r\n",
  27017 => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
}

# Common ports with default services
COMMON_PORTS = {
  20 => "FTP-data", 21 => "FTP", 22 => "SSH", 23 => "Telnet",
  25 => "SMTP", 53 => "DNS", 80 => "HTTP", 110 => "POP3",
  111 => "RPC", 135 => "RPC", 139 => "NetBIOS", 143 => "IMAP",
  443 => "HTTPS", 445 => "SMB", 993 => "IMAPS", 995 => "POP3S",
  1723 => "PPTP", 3306 => "MySQL", 3389 => "RDP", 5432 => "PostgreSQL",
  5900 => "VNC", 6379 => "Redis", 8080 => "HTTP-Alt", 8443 => "HTTPS-Alt",
  27017 => "MongoDB"
}

def get_service_name(port)
  COMMON_PORTS[port] || "Unknown"
end

def grab_banner(host, port, timeout_ms)
  banner = nil
  service_match = nil
  version = nil
  
  begin
    Timeout.timeout(timeout_ms / 1000.0) do
      sock = TCPSocket.new(host, port)
      
      # Send probe if available
      probe = BANNER_PROBES[port]
      if probe && !probe.empty?
        sock.print(probe)
      end
      
      # Read banner
      banner = sock.recv(1024)
      sock.close
      
      # Clean banner
      banner = banner.encode('UTF-8', 'binary', invalid: :replace, undef: :replace, replace: '')
      banner = banner.gsub(/[\x00-\x08\x0B\x0C\x0E-\x1F]/, ' ').strip
      banner = banner[0..200] if banner.length > 200
      
      # Detect service and version
      SERVICE_SIGNATURES.each do |service, patterns|
        patterns.each do |pattern|
          if banner.match(pattern)
            service_match = service.to_s.upcase
            if pattern.is_a?(Regexp) && banner.match(pattern)
              version = $1 if $1
            end
            break
          end
        end
        break if service_match
      end
    end
  rescue
    # Connection failed or timeout
  end
  
  { banner: banner, service: service_match, version: version }
end

def scan_port(host, port, timeout_ms, grab = true)
  start_time = Time.now
  result = {
    port: port,
    open: false,
    service: get_service_name(port),
    detected_service: nil,
    version: nil,
    banner: nil,
    time: nil
  }
  
  begin
    Timeout.timeout(timeout_ms / 1000.0) do
      sock = TCPSocket.new(host, port)
      result[:open] = true
      result[:time] = ((Time.now - start_time) * 1000).round(2)
      sock.close
      
      if grab && result[:open]
        banner_info = grab_banner(host, port, timeout_ms)
        result[:banner] = banner_info[:banner]
        result[:detected_service] = banner_info[:service] if banner_info[:service]
        result[:version] = banner_info[:version] if banner_info[:version]
      end
    end
  rescue
    # Port closed or timeout
  end
  
  result
end

def print_scanning_header
  puts color("\n┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐", :cyan)
  puts color("│                                             SCANNING IN PROGRESS...                                              │", :cyan)
  puts color("└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘", :cyan)
end

def print_results_header
  puts color("\n╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗", :cyan)
  puts color  ("║                                                  RESULTS                                                       ║", :cyan)
  puts color  ("╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝", :cyan)
end

def print_results_table(open_ports)
  if open_ports.empty?
    puts color("\n[!] No open ports found.", :yellow)
    return
  end
  
  puts color("\n[+] Found #{open_ports.length} open port(s):\n", :green)
  puts color("┌──────────┬────────────────────┬────────────────────┬────────────────────────────────────────────────────────┐", :cyan)
  puts color("│   PORT   │      SERVICE       │    DETECTED        │                      VERSION / BANNER                  │", :cyan)
  puts color("├──────────┼────────────────────┼────────────────────┼────────────────────────────────────────────────────────┤", :cyan)
  
  open_ports.each do |r|
    port_str = r[:port].to_s.center(8)
    service_str = (r[:detected_service] || r[:service])[0..18].to_s.ljust(18)
    detected_str = (r[:detected_service] ? "✓ #{r[:detected_service]}" : "─").ljust(18)
    
    version_str = if r[:version]
      "v#{r[:version]}"
    elsif r[:banner] && !r[:banner].empty?
      r[:banner][0..50]
    else
      "Open"
    end
    
    puts "│  #{port_str}   │  #{color(service_str, :yellow)} │  #{color(detected_str, :green)} │  #{color(version_str, :white)}#{' ' * (70 - version_str.length)} │"
  end
  
  puts color("└──────────┴────────────────────┴────────────────────┴────────────────────────────────────────────────────────┘", :cyan)
end

def print_summary_header
  puts color("\n╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗", :cyan)
  puts color  ("║                                                  SUMMARY                                                       ║", :cyan)
  puts color  ("╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝", :cyan)
end

def print_summary(host, ip, total_scanned, open_count, elapsed, timeout, threads)
  puts color("\n  Target IP     : #{ip}", :white)
  puts color("  Hostname      : #{host}", :white)
  puts color("  Ports scanned : #{total_scanned}", :white)
  puts color("  Open ports    : #{open_count}", :white)
  puts color("  Time taken    : #{elapsed.round(2)} seconds", :white)
  puts color("  Timeout       : #{timeout} ms", :white)
  puts color("  Threads       : #{threads}", :white)
  
  puts color("\n════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n", :cyan)
end

def print_help
  puts color("
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                    USAGE                                                       │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
", :cyan)
  puts "
  ruby scan.rb [options]

#{color("OPTIONS:", :yellow)}
  -t, --target HOST          Target hostname or IP address
  -p, --ports PORTS          Port range (1-1000) or list (22,80,443)
  -q, --quick                Quick scan of top 24 common ports
  -to, --timeout MS          Connection timeout in milliseconds (default: 1000)
  -th, --threads NUM         Number of threads (default: 50)
  -nb, --no-banner           Disable banner grabbing (faster)
  -h, --help                 Show this help message

#{color("EXAMPLES:", :yellow)}
  ruby scan.rb -t google.com -q
  ruby scan.rb -t 192.168.1.1 -p 1-1000
  ruby scan.rb -t github.com -p 22,80,443,3306 -to 500
  ruby scan.rb -t cloudflare.com -p 1-65535 -th 100 -nb
"
end

def parse_ports(port_spec)
  ports = []
  
  if port_spec.include?('-')
    parts = port_spec.split('-')
    if parts.length == 2
      start_p = parts[0].to_i
      end_p = parts[1].to_i
      (start_p..end_p).each { |p| ports << p if p > 0 && p <= 65535 }
    end
  elsif port_spec.include?(',')
    port_spec.split(',').each do |part|
      p = part.strip.to_i
      ports << p if p > 0 && p <= 65535
    end
  else
    p = port_spec.to_i
    ports << p if p > 0 && p <= 65535
  end
  
  ports
end

def get_top_ports
  [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
   993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
end

def resolve_host(host)
  begin
    ip = Socket.getaddrinfo(host, nil)[0][3]
    return ip
  rescue
    return nil
  end
end

def scan_port_range(host, ports, timeout_ms, threads, grab_banner)
  results = []
  queue = Queue.new
  ports.each { |p| queue << p }
  
  workers = (1..threads).map do
    Thread.new do
      while !queue.empty?
        port = queue.pop(true) rescue nil
        next unless port
        
        result = scan_port(host, port, timeout_ms, grab_banner)
        if result[:open]
          results << result
          service_info = result[:detected_service] ? "[#{result[:detected_service]}]" : ""
          version_info = result[:version] ? "v#{result[:version]}" : ""
          puts color("  [+] Port #{port} is OPEN #{service_info} #{version_info}", :green)
        end
      end
    end
  end
  
  workers.each(&:join)
  results.sort_by { |r| r[:port] }
end

# Main execution
print_banner

options = {
  target: nil,
  ports: nil,
  quick: false,
  timeout: 1000,
  threads: 50,
  no_banner: false,
  help: false
}

OptionParser.new do |opts|
  opts.on('-t', '--target HOST') { |v| options[:target] = v }
  opts.on('-p', '--ports PORTS') { |v| options[:ports] = v }
  opts.on('-q', '--quick') { options[:quick] = true }
  opts.on('-to', '--timeout MS') { |v| options[:timeout] = v.to_i }
  opts.on('-th', '--threads NUM') { |v| options[:threads] = v.to_i }
  opts.on('-nb', '--no-banner') { options[:no_banner] = true }
  opts.on('-h', '--help') { options[:help] = true }
end.parse!

if options[:help] || options[:target].nil?
  print_help
  exit
end

# Clean target
target = options[:target].gsub(/^https?:\/\//, '').split('/')[0]

# Resolve hostname
ip = resolve_host(target)
unless ip
  puts color("[!] Failed to resolve host: #{target}", :red)
  exit 1
end

puts color("[✓] Target resolved: #{target} (#{ip})", :green)
puts color("[→] Timeout: #{options[:timeout]}ms", :green)
puts color("[→] Threads: #{options[:threads]}", :green)
puts color("[→] Banner grabbing: #{options[:no_banner] ? 'Disabled' : 'Enabled'}", :green)

# Determine ports to scan
if options[:quick]
  ports_to_scan = get_top_ports
  puts color("[→] Mode: Quick Scan (#{ports_to_scan.length} common ports)", :cyan)
elsif options[:ports]
  ports_to_scan = parse_ports(options[:ports])
  if ports_to_scan.empty?
    puts color("[!] Invalid port specification", :red)
    exit 1
  end
  puts color("[→] Mode: Custom Scan (#{ports_to_scan.length} ports)", :cyan)
else
  ports_to_scan = get_top_ports
  puts color("[→] Mode: Default Scan (#{ports_to_scan.length} ports)", :cyan)
  puts color("[→] Tip: Use -q or -p for custom ranges", :yellow)
end

print_scanning_header
puts ""

start_time = Time.now
open_ports = scan_port_range(ip, ports_to_scan, options[:timeout], options[:threads], !options[:no_banner])
elapsed = Time.now - start_time

print_results_header
print_results_table(open_ports)
print_summary_header
print_summary(target, ip, ports_to_scan.length, open_ports.length, elapsed, options[:timeout], options[:threads])
