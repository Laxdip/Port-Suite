# =============================================================================
require 'socket'
require 'timeout'
require 'optparse'
require 'thread'
require 'resolv'
require 'json'
require 'csv'
require 'openssl'

# ─────────────────────────────────────────────────────────────────────────────
# ANSI helpers
# ─────────────────────────────────────────────────────────────────────────────
module C
  CODES = {
    reset: "\033[0m",   red:     "\033[91m", green:   "\033[92m",
    yellow:"\033[93m",  blue:    "\033[94m", magenta: "\033[95m",
    cyan:  "\033[96m",  white:   "\033[97m", bold:    "\033[1m",
    dim:   "\033[2m",   blink:   "\033[5m"
  }.freeze

  def self.paint(text, *attrs)
    return text.to_s unless $stdout.tty?
    attrs.map { |a| CODES[a] }.compact.join + text.to_s + CODES[:reset]
  end

  # Strip ANSI codes — used when writing to files
  def self.strip(text)
    text.to_s.gsub(/\033\[[0-9;]*m/, '')
  end
end

# ─────────────────────────────────────────────────────────────────────────────
# Service signatures  (ordered — first match wins)
# ─────────────────────────────────────────────────────────────────────────────
SERVICE_SIGNATURES = {
  ssh:        { patterns: [/SSH-(?<ver>[0-9.]+).*OpenSSH_(?<sub>[^\s]+)/,
                            /SSH-(?<ver>[0-9.]+)/,
                            /dropbear_(?<ver>[0-9.]+)/],
                name: 'SSH' },
  ftp:        { patterns: [/220[- ][^\r\n]*(?:vsFTPd|ProFTPD|FileZilla|Pure-FTPd)\s*(?<ver>[0-9.]+)?/i,
                            /220[- ]/],
                name: 'FTP' },
  smtp:       { patterns: [/220[^\r\n]*(?:Postfix|Sendmail|Exim|Exchange)[^\r\n]*(?<ver>[0-9.]+)?/i,
                            /220 .+ESMTP/],
                name: 'SMTP' },
  http:       { patterns: [/Server:\s*Apache\/(?<ver>[0-9.]+)/i,
                            /Server:\s*nginx\/(?<ver>[0-9.]+)/i,
                            /Server:\s*Microsoft-IIS\/(?<ver>[0-9.]+)/i,
                            /Server:\s*(?<ver>[^\r\n]+)/i,
                            /HTTP\/[0-9.]+\s+[0-9]+/],
                name: 'HTTP' },
  pop3:       { patterns: [/\+OK[^\r\n]*(?:Dovecot|Courier|UW POP3)[^\r\n]*(?<ver>[0-9.]+)?/i,
                            /\+OK/],
                name: 'POP3' },
  imap:       { patterns: [/\* OK[^\r\n]*(?:Dovecot|Courier|Cyrus)[^\r\n]*(?<ver>[0-9.]+)?/i,
                            /\* OK.*IMAP/],
                name: 'IMAP' },
  mysql:      { patterns: [/(?<ver>[0-9]+\.[0-9]+\.[0-9]+)[^\x00]*(?:MariaDB|mysql)/i,
                            /MariaDB/i, /mysql/i],
                name: 'MySQL/MariaDB' },
  postgres:   { patterns: [/PostgreSQL/i], name: 'PostgreSQL' },
  redis:      { patterns: [/redis_version:(?<ver>[0-9.]+)/i, /\+PONG/i], name: 'Redis' },
  mongodb:    { patterns: [/ismaster|MongoDB/i], name: 'MongoDB' },
  rdp:        { patterns: [/\x03\x00/, /RDP/], name: 'RDP' },
  vnc:        { patterns: [/RFB (?<ver>[0-9.]+)/], name: 'VNC' },
  telnet:     { patterns: [/\xff[\xfb-\xfe]/, /Telnet/i], name: 'Telnet' },
  smb:        { patterns: [/\xffSMB/, /SMB/i, /Samba/i], name: 'SMB' },
  memcached:  { patterns: [/VERSION (?<ver>[0-9.]+)/], name: 'Memcached' },
  elasticsearch: { patterns: [/"cluster_name"/, /"version"/], name: 'Elasticsearch' },
  docker:     { patterns: [/Docker-Distribution/, /application\/vnd\.docker/i], name: 'Docker Registry' },
  kubernetes: { patterns: [/k8s/, /kubernetes/i], name: 'Kubernetes' }
}.freeze

# ─────────────────────────────────────────────────────────────────────────────
# CVE / risk hints  { service_key => { version_constraint => hint } }
# These are informational nudges, NOT a full scanner.
# ─────────────────────────────────────────────────────────────────────────────
RISK_HINTS = {
  ssh:     { /OpenSSH [1-6]\./  => 'Outdated OpenSSH — upgrade recommended',
             /dropbear_20[01]/  => 'Old Dropbear build — check CVEs' },
  ftp:     { /.*/               => 'FTP transmits credentials in plaintext' },
  telnet:  { /.*/               => 'Telnet is unencrypted — use SSH instead' },
  http:    { /Apache\/2\.[0-3]/ => 'Apache <2.4 — known vulns (CVE-2017-7679, etc.)',
             /Apache\/2\.4\.(1[0-9]|[0-9])\b/ => 'Apache 2.4 <2.4.20 — check CVEs',
             /IIS\/[1-6]\./     => 'Old IIS — multiple known CVEs',
             /nginx\/1\.[0-9]\.[0-9]/  => 'Old nginx — check security advisories' },
  mysql:   { /[34]\.[0-9]/      => 'Very old MySQL — EOL, upgrade immediately',
             /5\.[0-6]\./       => 'MySQL 5.x approaching EOL' },
  redis:   { /.*/               => 'Redis without auth exposed? Check firewall / requirepass' },
  mongodb: { /.*/               => 'MongoDB — ensure auth is enabled (CVE-2019-2386 area)' },
  smb:     { /.*/               => 'SMB exposed — check for EternalBlue (MS17-010)' },
  rdp:     { /.*/               => 'RDP exposed — check BlueKeep (CVE-2019-0708) patch status' },
  vnc:     { /.*/               => 'VNC exposed — ensure strong auth or restrict access' }
}.freeze

# ─────────────────────────────────────────────────────────────────────────────
# Banner probes  (sent after connect to elicit a banner)
# ─────────────────────────────────────────────────────────────────────────────
BANNER_PROBES = {
   21  => "HELP\r\n",
   22  => nil,   # SSH sends banner automatically
   25  => "EHLO rubyscan.local\r\n",
   80  => "HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: RubyScan/2.0\r\n\r\n",
   110 => "USER probe\r\n",
   143 => "a001 CAPABILITY\r\n",
   443 => nil,   # TLS — handled separately
   3306=> nil,   # MySQL sends handshake automatically
   5432=> nil,   # Postgres sends handshake automatically
   6379=> "PING\r\n",
   9200=> "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",   # Elasticsearch
   11211 => "version\r\n",  # Memcached
   27017 => "\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00" \
            "\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff"    \
            "\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
}.freeze

# ─────────────────────────────────────────────────────────────────────────────
# Port → default service label
# ─────────────────────────────────────────────────────────────────────────────
COMMON_PORTS = {
  20 => 'FTP-data',  21 => 'FTP',        22 => 'SSH',       23 => 'Telnet',
  25 => 'SMTP',      53 => 'DNS',        80 => 'HTTP',      110 => 'POP3',
  111 => 'RPC',      135 => 'RPC',       139 => 'NetBIOS',  143 => 'IMAP',
  443 => 'HTTPS',    445 => 'SMB',       465 => 'SMTPS',    587 => 'SMTP-sub',
  993 => 'IMAPS',    995 => 'POP3S',     1723 => 'PPTP',    2375 => 'Docker',
  2376 => 'Docker-TLS', 3000 => 'HTTP-dev', 3306 => 'MySQL', 3389 => 'RDP',
  4443 => 'HTTPS-Alt', 5432 => 'PostgreSQL', 5601 => 'Kibana', 5900 => 'VNC',
  6379 => 'Redis',   6443 => 'Kubernetes', 8080 => 'HTTP-Alt', 8443 => 'HTTPS-Alt',
  8888 => 'HTTP-dev', 9000 => 'HTTP-dev', 9200 => 'Elasticsearch',
  9300 => 'Elasticsearch', 11211 => 'Memcached', 27017 => 'MongoDB',
  27018 => 'MongoDB', 50070 => 'HDFS'
}.freeze

# Ports to attempt TLS upgrade on
TLS_PORTS = [443, 465, 587, 993, 995, 2376, 4443, 6443, 8443].freeze

# ─────────────────────────────────────────────────────────────────────────────
# Top port lists
# ─────────────────────────────────────────────────────────────────────────────
TOP_PORTS = {
  quick:    [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
             993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017],
  standard: [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
             465, 587, 993, 995, 1723, 2375, 2376, 3000, 3306, 3389, 4443,
             5432, 5601, 5900, 6379, 6443, 8080, 8443, 8888, 9000, 9200,
             11211, 27017, 27018]
}.freeze

# ─────────────────────────────────────────────────────────────────────────────
# Banner grabber
# ─────────────────────────────────────────────────────────────────────────────
def grab_banner(host, port, timeout_sec)
  result = { banner: nil, service_key: nil, service_name: nil,
             version: nil, tls: false, tls_info: nil }

  begin
    Timeout.timeout(timeout_sec) do
      sock = TCPSocket.new(host, port)

      # Attempt TLS upgrade
      if TLS_PORTS.include?(port)
        begin
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
          tls_sock = OpenSSL::SSL::SSLSocket.new(sock, ctx)
          tls_sock.hostname = host
          tls_sock.connect
          result[:tls] = true
          cert = tls_sock.peer_cert
          if cert
            result[:tls_info] = {
              subject:    cert.subject.to_s,
              issuer:     cert.issuer.to_s,
              not_after:  cert.not_after.to_s,
              expired:    cert.not_after < Time.now
            }
          end
          sock = tls_sock   # swap to TLS socket for subsequent I/O
        rescue OpenSSL::SSL::SSLError, Errno::ECONNRESET
          # TLS failed — continue on plain socket (reopen)
          sock.close rescue nil
          sock = TCPSocket.new(host, port)
          result[:tls] = false
        end
      end

      # Send probe
      probe = BANNER_PROBES[port]
      sock.write(probe) if probe && !probe.empty?

      # Read banner (up to 2 KB, 2-second read window)
      raw = ''
      begin
        Timeout.timeout([timeout_sec, 2.0].min) do
          loop do
            chunk = sock.read_nonblock(2048) rescue nil
            break unless chunk && !chunk.empty?
            raw << chunk
            break if raw.length >= 2048
          end
        end
      rescue Timeout::Error, IO::EAGAINWaitReadable, Errno::ECONNRESET
        # Partial banner is fine
      end
      sock.close rescue nil

      # Sanitise
      banner = raw.encode('UTF-8', 'binary', invalid: :replace, undef: :replace, replace: '?')
                  .gsub(/[\x00-\x08\x0B\x0C\x0E-\x1F]/, ' ')
                  .strip
      banner = banner[0..300] unless banner.empty?
      result[:banner] = banner.empty? ? nil : banner

      # Fingerprint
      SERVICE_SIGNATURES.each do |key, sig|
        sig[:patterns].each do |pat|
          m = result[:banner]&.match(pat)
          next unless m
          result[:service_key]  = key
          result[:service_name] = sig[:name]
          # Named capture 'ver' or first capture group
          result[:version] = m[:ver] rescue (m[1] rescue nil)
          break
        end
        break if result[:service_key]
      end
    end
  rescue Timeout::Error, Errno::ECONNREFUSED, Errno::EHOSTUNREACH,
         Errno::ENETUNREACH, SocketError
    # Port closed / unreachable
  end

  result
end

# ─────────────────────────────────────────────────────────────────────────────
# Single port scan
# ─────────────────────────────────────────────────────────────────────────────
def scan_port(host, port, timeout_sec, do_grab)
  result = {
    port:           port,
    open:           false,
    default_service:COMMON_PORTS[port] || 'Unknown',
    service_key:    nil,
    service_name:   nil,
    version:        nil,
    banner:         nil,
    tls:            false,
    tls_info:       nil,
    rtt_ms:         nil,
    risk_hints:     []
  }

  t0 = Time.now
  begin
    Timeout.timeout(timeout_sec) do
      sock = TCPSocket.new(host, port)
      result[:open]   = true
      result[:rtt_ms] = ((Time.now - t0) * 1000).round(1)
      sock.close
    end
  rescue Timeout::Error, Errno::ECONNREFUSED, Errno::EHOSTUNREACH,
         Errno::ENETUNREACH, SocketError
    return result
  end

  # Banner grab only for open ports
  if do_grab
    info = grab_banner(host, port, timeout_sec)
    result.merge!(info.slice(:banner, :service_key, :service_name, :version,
                              :tls, :tls_info))
  end

  # Risk hints
  skey = result[:service_key]
  if skey && RISK_HINTS[skey]
    RISK_HINTS[skey].each do |pat, hint|
      probe_str = [result[:version], result[:banner]].compact.join(' ')
      result[:risk_hints] << hint if probe_str.match?(pat) || probe_str.empty?
    end
  end

  result
end

# ─────────────────────────────────────────────────────────────────────────────
# OS hint from TTL  (via system ping — optional, fails gracefully)
# ─────────────────────────────────────────────────────────────────────────────
def os_hint_from_ping(ip)
  out = `ping -c 1 -W 1 #{ip} 2>/dev/null` rescue ''
  ttl = out.match(/ttl=(\d+)/i)&.captures&.first.to_i
  return 'Unknown' if ttl.zero?

  case ttl
  when 1..64   then 'Linux / Unix'
  when 65..128 then 'Windows'
  when 129..255 then 'Cisco / Network'
  else 'Unknown'
  end
end

# ─────────────────────────────────────────────────────────────────────────────
# Thread-safe, bounded port scanner
# ─────────────────────────────────────────────────────────────────────────────
def scan_port_range(host, ports, timeout_sec, max_threads, do_grab, verbose)
  results    = []
  results_mu = Mutex.new
  queue      = Queue.new
  ports.each { |p| queue << p }

  print_mu   = Mutex.new
  completed  = 0
  total      = ports.size

  workers = Array.new([max_threads, ports.size].min) do
    Thread.new do
      loop do
        port = queue.pop(true) rescue break
        r    = scan_port(host, port, timeout_sec, do_grab)

        results_mu.synchronize { results << r } if r[:open]

        print_mu.synchronize do
          completed += 1
          if r[:open]
            svc   = r[:service_name] || r[:default_service]
            ver   = r[:version] ? " v#{r[:version]}" : ''
            tls   = r[:tls] ? C.paint(' [TLS]', :cyan) : ''
            risks = r[:risk_hints].any? ? C.paint(' ⚠', :yellow) : ''
            $stdout.print C.paint("  [+] ", :green) +
                          C.paint("#{port}/tcp", :white, :bold) +
                          C.paint("  #{svc}#{ver}", :yellow) +
                          tls + risks + "\n"
          elsif verbose
            $stdout.print C.paint("  [-] #{port}/tcp closed\n", :dim)
          end
          # Progress bar (overwrite same line only for non-verbose)
          unless verbose
            pct  = (completed * 100.0 / total).round
            bar  = ('█' * (pct / 5)).ljust(20)
            $stdout.print C.paint("\r  Progress: [#{bar}] #{pct}% (#{completed}/#{total})", :dim)
            $stdout.flush
          end
        end
      end
    end
  end

  workers.each(&:join)
  $stdout.print "\r#{' ' * 60}\r" unless verbose  # clear progress bar
  results.sort_by { |r| r[:port] }
end

# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────
def print_banner_art
  puts C.paint("
╔══════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                  ║
║   ██████╗ ██╗   ██╗██████╗ ██╗   ██╗    ███████╗ ██████╗ █████╗ ███╗  ██╗                       ║
║   ██╔══██╗██║   ██║██╔══██╗╚██╗ ██╔╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║                       ║
║   ██████╔╝██║   ██║██████╔╝ ╚████╔╝     ███████╗██║     ███████║██╔██╗██║                       ║
║   ██╔══██╗██║   ██║██╔══██╗  ╚██╔╝      ╚════██║██║     ██╔══██║██║╚████║                       ║
║   ██║  ██║╚██████╔╝██████╔╝   ██║       ███████║╚██████╗██║  ██║██║ ╚███║                       ║
║   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝    ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝                       ║
║                                                                                                  ║
║                          Service Detection Scanner  v2.0                                         ║
║                                    by Prasad                                                     ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════╝
", :cyan)
end

def section(title, style: :single)
  w = 96
  pad = title.length + 4
  rest = w - pad
  l, r = rest / 2, rest - rest / 2
  if style == :double
    puts C.paint("╔#{'═' * (w - 2)}╗", :cyan)
    puts C.paint("║#{' ' * l}  #{title}  #{' ' * r}║", :cyan)
    puts C.paint("╚#{'═' * (w - 2)}╝", :cyan)
  else
    puts C.paint("┌#{'─' * (w - 2)}┐", :cyan)
    puts C.paint("│#{' ' * l}  #{title}  #{' ' * r}│", :cyan)
    puts C.paint("└#{'─' * (w - 2)}┘", :cyan)
  end
end

def print_results_table(open_ports)
  if open_ports.empty?
    puts C.paint("\n  [!] No open ports found.\n", :yellow)
    return
  end

  puts C.paint("\n  [+] Found #{open_ports.size} open port(s)\n", :green, :bold)

  # ┌ header ┐
  puts C.paint('┌──────────┬──────────────────────┬──────────────────────┬──────────┬───────────────────────────────────────────┐', :cyan)
  puts C.paint('│  PORT    │  DEFAULT SERVICE     │  DETECTED SERVICE    │  RTT ms  │  VERSION / BANNER                         │', :cyan)
  puts C.paint('├──────────┼──────────────────────┼──────────────────────┼──────────┼───────────────────────────────────────────┤', :cyan)

  open_ports.each do |r|
    port_cell    = r[:port].to_s.ljust(6)
    tls_tag      = r[:tls] ? C.paint('🔒', :cyan) : '  '
    default_cell = (r[:default_service] || '?')[0..19].ljust(20)
    detected     = r[:service_name] ? C.paint("✓ #{r[:service_name]}", :green) : C.paint('─', :dim)
    detected_raw = r[:service_name] ? "✓ #{r[:service_name]}" : '─'
    detected_pad = detected + (' ' * [0, 20 - detected_raw.length].max)
    rtt_cell     = r[:rtt_ms] ? "#{r[:rtt_ms]}ms".ljust(8) : 'N/A'.ljust(8)
    ver_str      = if r[:version]
                     "v#{r[:version]}"
                   elsif r[:banner]
                     r[:banner].gsub(/\s+/, ' ')[0..48]
                   else
                     'Open'
                   end
    ver_cell = C.paint(ver_str, :white) + (' ' * [0, 41 - ver_str.length].max)

    puts "│  #{tls_tag} #{C.paint(port_cell, :white, :bold)}│  #{C.paint(default_cell, :yellow)}│  #{detected_pad}│  #{C.paint(rtt_cell, :magenta)}│  #{ver_cell}│"

    # Risk hints inline
    r[:risk_hints].each do |hint|
      puts "│  #{C.paint('  ⚠  RISK', :yellow, :bold)}  │  #{C.paint(hint[0..83].ljust(84), :yellow)}│"
    end

    # TLS cert expiry warning
    if r[:tls_info]&.fetch(:expired, false)
      puts "│  #{C.paint('  🔴 TLS CERT EXPIRED', :red, :bold)}  #{' ' * 68}│"
    end
  end

  puts C.paint('└──────────┴──────────────────────┴──────────────────────┴──────────┴───────────────────────────────────────────┘', :cyan)
end

def print_summary(host, ip, os_hint, total_scanned, open_count, elapsed, timeout_ms, threads, grab)
  puts ''
  puts C.paint("  Target        : #{host} (#{ip})", :white)
  puts C.paint("  OS Hint       : #{os_hint}", :white)
  puts C.paint("  Ports scanned : #{total_scanned}", :white)
  puts C.paint("  Open ports    : #{open_count}", :white)
  puts C.paint("  Time taken    : #{elapsed.round(2)}s", :white)
  puts C.paint("  Timeout       : #{timeout_ms}ms", :white)
  puts C.paint("  Threads       : #{threads}", :white)
  puts C.paint("  Banner grab   : #{grab ? 'Enabled' : 'Disabled'}", :white)
  puts ''
  puts C.paint('═' * 96, :cyan)
  puts ''
end

def print_help
  section 'USAGE'
  puts <<~HELP

    #{C.paint('  ruby rubyscan.rb [options]', :white)}

    #{C.paint('OPTIONS:', :yellow)}
      -t, --target HOST          Target hostname or IP address
      -p, --ports PORTS          Port range (1-1000) or comma list (22,80,443)
      -q, --quick                Quick scan — top 24 common ports
      -s, --standard             Standard scan — top 38 ports (default)
      -to, --timeout MS          Connection timeout in milliseconds (default: 1000)
      -th, --threads NUM         Max threads (default: 50)
      -nb, --no-banner           Disable banner grabbing (faster)
      -v, --verbose              Show closed ports too
      -o, --output FILE          Save results (auto-appends .json and .csv)
      -h, --help                 Show this help

    #{C.paint('EXAMPLES:', :yellow)}
      ruby rubyscan.rb -t 192.168.1.1 -q
      ruby rubyscan.rb -t example.com -p 1-10000 -th 100
      ruby rubyscan.rb -t github.com -p 22,80,443 -to 500 -o results
      ruby rubyscan.rb -t 10.0.0.1 -s -nb -v

  HELP
end

# ─────────────────────────────────────────────────────────────────────────────
# Export helpers
# ─────────────────────────────────────────────────────────────────────────────
def save_json(path, data)
  File.write("#{path}.json", JSON.pretty_generate(data))
  puts C.paint("  [✓] JSON saved → #{path}.json", :green)
rescue => e
  warn C.paint("  [!] JSON write failed: #{e.message}", :red)
end

def save_csv(path, open_ports)
  CSV.open("#{path}.csv", 'w') do |csv|
    csv << %w[port default_service detected_service version tls rtt_ms risk_hints banner]
    open_ports.each do |r|
      csv << [
        r[:port],
        r[:default_service],
        r[:service_name],
        r[:version],
        r[:tls],
        r[:rtt_ms],
        r[:risk_hints].join('; '),
        C.strip(r[:banner].to_s.gsub(/\s+/, ' ')[0..200])
      ]
    end
  end
  puts C.paint("  [✓] CSV  saved → #{path}.csv", :green)
rescue => e
  warn C.paint("  [!] CSV write failed: #{e.message}", :red)
end

# ─────────────────────────────────────────────────────────────────────────────
# Port spec parser  — handles "80", "22,80,443", "1-1024", "1-100,443,8080"
# ─────────────────────────────────────────────────────────────────────────────
def parse_ports(spec)
  ports = []
  spec.split(',').each do |chunk|
    chunk.strip!
    if chunk.include?('-')
      a, b = chunk.split('-').map(&:to_i)
      ports.concat((a..b).to_a) if a.positive? && b <= 65_535 && a <= b
    else
      p = chunk.to_i
      ports << p if p.positive? && p <= 65_535
    end
  end
  ports.uniq.sort
end

# ─────────────────────────────────────────────────────────────────────────────
# Host resolver  (IPv4 preferred)
# ─────────────────────────────────────────────────────────────────────────────
def resolve_host(host)
  Resolv.getaddresses(host)
        .select { |a| a.match?(/^\d{1,3}(\.\d{1,3}){3}$/) }
        .first || Socket.getaddrinfo(host, nil, Socket::AF_INET)[0][3]
rescue SocketError, Resolv::ResolvError
  nil
end

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
print_banner_art

options = {
  target:    nil,
  ports:     nil,
  quick:     false,
  standard:  false,
  timeout:   1000,
  threads:   50,
  no_banner: false,
  verbose:   false,
  output:    nil,
  help:      false
}

OptionParser.new do |opts|
  opts.on('-t', '--target HOST')    { |v| options[:target]   = v }
  opts.on('-p', '--ports PORTS')    { |v| options[:ports]    = v }
  opts.on('-q', '--quick')          {     options[:quick]    = true }
  opts.on('-s', '--standard')       {     options[:standard] = true }
  opts.on('-to', '--timeout MS')    { |v| options[:timeout]  = v.to_i }
  opts.on('-th', '--threads NUM')   { |v| options[:threads]  = v.to_i }
  opts.on('-nb', '--no-banner')     {     options[:no_banner]= true }
  opts.on('-v', '--verbose')        {     options[:verbose]  = true }
  opts.on('-o', '--output FILE')    { |v| options[:output]   = v }
  opts.on('-h', '--help')           {     options[:help]     = true }
end.parse!

if options[:help] || options[:target].nil?
  print_help
  exit
end

# Validate timeout / threads
if options[:timeout] < 100 || options[:timeout] > 30_000
  warn C.paint("[!] Timeout should be 100–30000 ms. Clamping.", :yellow)
  options[:timeout] = options[:timeout].clamp(100, 30_000)
end
if options[:threads] < 1 || options[:threads] > 500
  warn C.paint("[!] Threads should be 1–500. Clamping.", :yellow)
  options[:threads] = options[:threads].clamp(1, 500)
end

timeout_sec = options[:timeout] / 1000.0

# Strip protocol / path from target
target = options[:target].gsub(%r{^https?://}, '').split('/').first.to_s.strip

if target.empty?
  puts C.paint("[✗] Target is empty after parsing.", :red)
  exit 1
end

# Resolve
puts C.paint("[→] Resolving #{target}...", :cyan)
ip = resolve_host(target)
unless ip
  puts C.paint("[✗] Cannot resolve host: #{target}", :red)
  exit 1
end
puts C.paint("[✓] #{target} → #{ip}", :green)

# OS hint (best-effort)
os_hint = os_hint_from_ping(ip)

puts C.paint("[→] OS hint     : #{os_hint}", :cyan)
puts C.paint("[→] Timeout     : #{options[:timeout]} ms", :cyan)
puts C.paint("[→] Threads     : #{options[:threads]}", :cyan)
puts C.paint("[→] Banner grab : #{options[:no_banner] ? 'Disabled' : 'Enabled'}", :cyan)

# Determine port list
ports_to_scan =
  if options[:ports]
    parsed = parse_ports(options[:ports])
    if parsed.empty?
      puts C.paint("[✗] Invalid port specification: #{options[:ports]}", :red)
      exit 1
    end
    puts C.paint("[→] Mode: Custom (#{parsed.size} ports)", :cyan)
    parsed
  elsif options[:quick]
    puts C.paint("[→] Mode: Quick (#{TOP_PORTS[:quick].size} ports)", :cyan)
    TOP_PORTS[:quick]
  else
    puts C.paint("[→] Mode: Standard (#{TOP_PORTS[:standard].size} ports)", :cyan)
    TOP_PORTS[:standard]
  end

puts ''

# Graceful Ctrl-C
open_ports = []
begin
  section 'SCANNING IN PROGRESS'
  puts ''
  start_time = Time.now
  open_ports = scan_port_range(
    ip, ports_to_scan, timeout_sec,
    options[:threads], !options[:no_banner], options[:verbose]
  )
  elapsed = Time.now - start_time
rescue Interrupt
  puts C.paint("\n\n  [!] Interrupted by user — showing partial results...\n", :yellow)
  elapsed = Time.now - start_time
end

puts ''
section 'RESULTS', style: :double
print_results_table(open_ports)

section 'SUMMARY', style: :double
print_summary(
  target, ip, os_hint,
  ports_to_scan.size, open_ports.size, elapsed,
  options[:timeout], options[:threads], !options[:no_banner]
)

# Export
if options[:output]
  puts ''
  payload = {
    scan: {
      target: target, ip: ip, os_hint: os_hint,
      timestamp: Time.now.iso8601,
      ports_scanned: ports_to_scan.size,
      open_ports: open_ports.size,
      elapsed_sec: elapsed.round(3),
      timeout_ms: options[:timeout],
      threads: options[:threads]
    },
    results: open_ports.map { |r|
      r.merge(
        tls_info: r[:tls_info]&.transform_values(&:to_s),
        banner: C.strip(r[:banner].to_s)
      )
    }
  }
  save_json(options[:output], payload)
  save_csv(options[:output], open_ports)
  puts ''
end
