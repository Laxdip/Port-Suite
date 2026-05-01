// Usage:
//   go run fastscan.go -host <target> [options]

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

// ─────────────────────────────────────────────────────────────────────────────
// ANSI helpers
// ─────────────────────────────────────────────────────────────────────────────

const (
	reset   = "\033[0m"
	red     = "\033[91m"
	green   = "\033[92m"
	yellow  = "\033[93m"
	blue    = "\033[94m"
	magenta = "\033[95m"
	cyan    = "\033[96m"
	white   = "\033[97m"
	bold    = "\033[1m"
	dim     = "\033[2m"
)

// ansiRE strips ANSI escape sequences — used when writing plain-text files.
var ansiRE = regexp.MustCompile(`\033\[[0-9;]*m`)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

// isTTY returns true when stdout is a real terminal.
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func paint(color, text string) string {
	if !isTTY() {
		return text
	}
	return color + text + reset
}

// ─────────────────────────────────────────────────────────────────────────────
// Service registry
// ─────────────────────────────────────────────────────────────────────────────

var defaultService = map[int]string{
	20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
	25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
	111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
	443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-sub",
	993: "IMAPS", 995: "POP3S", 1723: "PPTP",
	2375: "Docker", 2376: "Docker-TLS", 3000: "HTTP-dev",
	3306: "MySQL", 3389: "RDP", 4443: "HTTPS-Alt",
	5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC",
	6379: "Redis", 6443: "Kubernetes", 8080: "HTTP-Alt",
	8443: "HTTPS-Alt", 8888: "HTTP-dev", 9000: "HTTP-dev",
	9200: "Elasticsearch", 9300: "Elasticsearch",
	11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
}

func svcName(port int) string {
	if s, ok := defaultService[port]; ok {
		return s
	}
	return "Unknown"
}

// TLS ports — attempt upgrade on these.
var tlsPorts = map[int]bool{
	443: true, 465: true, 587: true, 993: true,
	995: true, 2376: true, 4443: true, 6443: true, 8443: true,
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner probes  (sent right after TCP connect)
// ─────────────────────────────────────────────────────────────────────────────

var bannerProbes = map[int][]byte{
	21:    []byte("HELP\r\n"),
	25:    []byte("EHLO gofastscan.local\r\n"),
	80:    []byte("HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: GoFastScan/2.0\r\n\r\n"),
	110:   []byte("USER probe\r\n"),
	143:   []byte("a001 CAPABILITY\r\n"),
	6379:  []byte("PING\r\n"),
	9200:  []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
	11211: []byte("version\r\n"),
}

// ─────────────────────────────────────────────────────────────────────────────
// Fingerprint signatures  { key → (name, patterns) }
// First match wins.
// ─────────────────────────────────────────────────────────────────────────────

type sigEntry struct {
	name     string
	patterns []*regexp.Regexp
	verGroup int // capture group index for version (0 = no version)
}

var signatures = []struct {
	key string
	sigEntry
}{
	{"ssh", sigEntry{"SSH", []*regexp.Regexp{
		regexp.MustCompile(`SSH-[\d.]+ OpenSSH_([\d.]+\w*)`),
		regexp.MustCompile(`SSH-([\d.]+)`),
		regexp.MustCompile(`dropbear_([\d.]+)`),
	}, 1}},
	{"ftp", sigEntry{"FTP", []*regexp.Regexp{
		regexp.MustCompile(`(?i)220[- ].*(vsFTPd|ProFTPD|FileZilla|Pure-FTPd)\s*([\d.]*)`),
		regexp.MustCompile(`220[- ]`),
	}, 2}},
	{"smtp", sigEntry{"SMTP", []*regexp.Regexp{
		regexp.MustCompile(`(?i)220.*?(Postfix|Sendmail|Exim|Exchange).*?([\d.]+)`),
		regexp.MustCompile(`220 .+ESMTP`),
	}, 2}},
	{"http", sigEntry{"HTTP", []*regexp.Regexp{
		regexp.MustCompile(`(?i)Server:\s*Apache/([\d.]+)`),
		regexp.MustCompile(`(?i)Server:\s*nginx/([\d.]+)`),
		regexp.MustCompile(`(?i)Server:\s*Microsoft-IIS/([\d.]+)`),
		regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`),
		regexp.MustCompile(`HTTP/[\d.]+ \d+`),
	}, 1}},
	{"pop3", sigEntry{"POP3", []*regexp.Regexp{
		regexp.MustCompile(`(?i)\+OK[^\r\n]*(Dovecot|Courier)[^\r\n]*([\d.]*)`),
		regexp.MustCompile(`\+OK`),
	}, 2}},
	{"imap", sigEntry{"IMAP", []*regexp.Regexp{
		regexp.MustCompile(`(?i)\* OK[^\r\n]*(Dovecot|Courier|Cyrus)[^\r\n]*([\d.]*)`),
		regexp.MustCompile(`(?i)\* OK.*IMAP`),
	}, 2}},
	{"mysql", sigEntry{"MySQL/MariaDB", []*regexp.Regexp{
		regexp.MustCompile(`(?i)([\d]+\.[\d]+\.[\d]+)[^\x00]*(MariaDB|mysql)`),
		regexp.MustCompile(`(?i)MariaDB`),
	}, 1}},
	{"postgres", sigEntry{"PostgreSQL", []*regexp.Regexp{
		regexp.MustCompile(`(?i)PostgreSQL`),
	}, 0}},
	{"redis", sigEntry{"Redis", []*regexp.Regexp{
		regexp.MustCompile(`(?i)redis_version:([\d.]+)`),
		regexp.MustCompile(`\+PONG`),
	}, 1}},
	{"mongodb", sigEntry{"MongoDB", []*regexp.Regexp{
		regexp.MustCompile(`(?i)ismaster|MongoDB`),
	}, 0}},
	{"memcached", sigEntry{"Memcached", []*regexp.Regexp{
		regexp.MustCompile(`VERSION ([\d.]+)`),
	}, 1}},
	{"elasticsearch", sigEntry{"Elasticsearch", []*regexp.Regexp{
		regexp.MustCompile(`(?i)"cluster_name"|"version"`),
	}, 0}},
	{"vnc", sigEntry{"VNC", []*regexp.Regexp{
		regexp.MustCompile(`RFB ([\d.]+)`),
	}, 1}},
	{"rdp", sigEntry{"RDP", []*regexp.Regexp{
		regexp.MustCompile(`\x03\x00`),
	}, 0}},
	{"smb", sigEntry{"SMB", []*regexp.Regexp{
		regexp.MustCompile(`\xffSMB`),
	}, 0}},
	{"telnet", sigEntry{"Telnet", []*regexp.Regexp{
		regexp.MustCompile(`\xff[\xfb-\xfe]`),
	}, 0}},
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk hints
// ─────────────────────────────────────────────────────────────────────────────

var riskHints = map[string][]struct {
	pat  *regexp.Regexp
	hint string
}{
	"ssh": {
		{regexp.MustCompile(`OpenSSH_[1-6]\.`), "Outdated OpenSSH — upgrade recommended"},
		{regexp.MustCompile(`dropbear_20[01]`), "Old Dropbear — check CVEs"},
	},
	"ftp":     {{regexp.MustCompile(`.`), "FTP transmits credentials in plaintext"}},
	"telnet":  {{regexp.MustCompile(`.`), "Telnet is unencrypted — replace with SSH"}},
	"http": {
		{regexp.MustCompile(`Apache/2\.[0-3]\.`), "Apache <2.4 — known CVEs (CVE-2017-7679 etc.)"},
		{regexp.MustCompile(`IIS/[1-6]\.`), "Old IIS — multiple known CVEs"},
		{regexp.MustCompile(`nginx/1\.[0-9]\.`), "Old nginx — check security advisories"},
	},
	"mysql":   {{regexp.MustCompile(`[34]\.`), "Very old MySQL/MariaDB — EOL, upgrade immediately"}},
	"redis":   {{regexp.MustCompile(`.`), "Redis exposed — verify requirepass / firewall"}},
	"mongodb": {{regexp.MustCompile(`.`), "MongoDB — confirm auth enabled (CVE-2019-2386)"}},
	"smb":     {{regexp.MustCompile(`.`), "SMB exposed — patch EternalBlue (MS17-010)"}},
	"rdp":     {{regexp.MustCompile(`.`), "RDP exposed — check BlueKeep (CVE-2019-0708)"}},
	"vnc":     {{regexp.MustCompile(`.`), "VNC exposed — restrict or require strong auth"}},
}

// ─────────────────────────────────────────────────────────────────────────────
// Data structures
// ─────────────────────────────────────────────────────────────────────────────

// TLSInfo holds certificate metadata for an open TLS port.
type TLSInfo struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"`
	Expired  bool   `json:"expired"`
}

// ScanResult is the full record for one scanned port.
type ScanResult struct {
	Port           int      `json:"port"`
	Open           bool     `json:"open"`
	DefaultService string   `json:"default_service"`
	ServiceKey     string   `json:"service_key,omitempty"`
	ServiceName    string   `json:"service_name,omitempty"`
	Version        string   `json:"version,omitempty"`
	Banner         string   `json:"banner,omitempty"`
	TLS            bool     `json:"tls"`
	TLSInfo        *TLSInfo `json:"tls_info,omitempty"`
	RTTms          float64  `json:"rtt_ms,omitempty"`
	RiskHints      []string `json:"risk_hints,omitempty"`
}

// ScanMeta is the top-level JSON export envelope.
type ScanMeta struct {
	Target        string        `json:"target"`
	IP            string        `json:"ip"`
	OSHint        string        `json:"os_hint"`
	Timestamp     string        `json:"timestamp"`
	PortsScanned  int           `json:"ports_scanned"`
	OpenPorts     int           `json:"open_ports"`
	ElapsedSec    float64       `json:"elapsed_sec"`
	TimeoutMs     int           `json:"timeout_ms"`
	Concurrency   int           `json:"concurrency"`
	Results       []ScanResult  `json:"results"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner grabber
// ─────────────────────────────────────────────────────────────────────────────

func grabBanner(host string, port int, timeout time.Duration) (banner, serviceKey, serviceName, version string, isTLS bool, tlsInfo *TLSInfo) {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Helper: read up to 2 KB with a deadline.
	readBanner := func(conn net.Conn) string {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 2048)
		n, _ := bufio.NewReader(conn).Read(buf)
		if n == 0 {
			return ""
		}
		raw := buf[:n]
		// Sanitise to valid UTF-8, replace control chars except \t \n \r.
		s := strings.Map(func(r rune) rune {
			if r == '\t' || r == '\n' || r == '\r' {
				return ' '
			}
			if r < 0x20 || r == 0x7F {
				return '?'
			}
			return r
		}, string([]byte(raw)))
		if !utf8.ValidString(s) {
			s = strings.ToValidUTF8(s, "?")
		}
		s = strings.TrimSpace(s)
		if len(s) > 300 {
			s = s[:300]
		}
		return s
	}

	dialPlain := func() (net.Conn, error) {
		return net.DialTimeout("tcp", addr, timeout)
	}

	var conn net.Conn

	// Attempt TLS upgrade for known TLS ports.
	if tlsPorts[port] {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional — scanner
			ServerName:         host,
		}
		dialer := &net.Dialer{Timeout: timeout}
		if c, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg); err == nil {
			isTLS = true
			// Extract cert metadata.
			certs := c.ConnectionState().PeerCertificates
			if len(certs) > 0 {
				cert := certs[0]
				tlsInfo = &TLSInfo{
					Subject:  cert.Subject.CommonName,
					Issuer:   cert.Issuer.CommonName,
					NotAfter: cert.NotAfter.Format("2006-01-02"),
					Expired:  cert.NotAfter.Before(time.Now()),
				}
			}
			conn = c
		} else {
			// TLS failed — fall back to plain.
			if c2, err2 := dialPlain(); err2 == nil {
				conn = c2
			} else {
				return
			}
		}
	} else {
		var err error
		if conn, err = dialPlain(); err != nil {
			return
		}
	}
	defer conn.Close()

	// Send probe if available; otherwise just listen for a spontaneous banner.
	if probe, ok := bannerProbes[port]; ok {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		_, _ = conn.Write(probe)
	}

	banner = readBanner(conn)
	if banner == "" {
		return
	}

	// Fingerprint.
	for _, sig := range signatures {
		for _, pat := range sig.patterns {
			m := pat.FindStringSubmatch(banner)
			if m == nil {
				continue
			}
			serviceKey = sig.key
			serviceName = sig.name
			if sig.verGroup > 0 && sig.verGroup < len(m) {
				version = strings.TrimSpace(m[sig.verGroup])
			}
			return
		}
	}
	return
}

// ─────────────────────────────────────────────────────────────────────────────
// Single port scan
// ─────────────────────────────────────────────────────────────────────────────

func scanPort(host string, port int, timeout time.Duration, doGrab bool) ScanResult {
	r := ScanResult{
		Port:           port,
		DefaultService: svcName(port),
	}

	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return r
	}
	r.Open = true
	r.RTTms = float64(time.Since(t0).Microseconds()) / 1000.0
	conn.Close()

	if doGrab {
		r.Banner, r.ServiceKey, r.ServiceName, r.Version, r.TLS, r.TLSInfo =
			grabBanner(host, port, timeout)
	}

	// Risk hints.
	probe := r.Version + " " + r.Banner
	if hints, ok := riskHints[r.ServiceKey]; ok {
		for _, h := range hints {
			if h.pat.MatchString(probe) {
				r.RiskHints = append(r.RiskHints, h.hint)
			}
		}
	}

	return r
}

// ─────────────────────────────────────────────────────────────────────────────
// Concurrent scanner with semaphore + progress
// ─────────────────────────────────────────────────────────────────────────────

func scanPorts(
	ctx context.Context,
	host string,
	ports []int,
	timeout time.Duration,
	concurrency int,
	doGrab bool,
	verbose bool,
) []ScanResult {

	var (
		mu        sync.Mutex
		results   []ScanResult
		completed int64
		total     = int64(len(ports))
		sem       = make(chan struct{}, concurrency)
		wg        sync.WaitGroup
	)

	printMu := &sync.Mutex{}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer func() {
				<-sem
				wg.Done()
			}()

			r := scanPort(host, p, timeout, doGrab)
			done := atomic.AddInt64(&completed, 1)

			printMu.Lock()
			if r.Open {
				svc := r.ServiceName
				if svc == "" {
					svc = r.DefaultService
				}
				ver := ""
				if r.Version != "" {
					ver = " v" + r.Version
				}
				tlsTag := ""
				if r.TLS {
					tlsTag = paint(cyan, " [TLS]")
				}
				risk := ""
				if len(r.RiskHints) > 0 {
					risk = paint(yellow, " ⚠")
				}
				fmt.Printf("  %s %s  %s%s%s%s\n",
					paint(green, "[+]"),
					paint(bold+white, fmt.Sprintf("%d/tcp", p)),
					paint(yellow, svc+ver),
					tlsTag, risk, "")
			} else if verbose {
				fmt.Printf("  %s %d/tcp closed\n", paint(dim, "[-]"), p)
			}

			if !verbose {
				pct := int(done * 100 / total)
				bar := strings.Repeat("█", pct/5) + strings.Repeat("░", 20-pct/5)
				fmt.Printf("\r  %s [%s] %d%% (%d/%d)  ",
					paint(dim, "Progress:"),
					paint(cyan, bar), pct, done, total)
			}
			printMu.Unlock()

			if r.Open {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}(port)
	}

done:
	wg.Wait()

	if !verbose {
		fmt.Printf("\r%s\r", strings.Repeat(" ", 60)) // clear progress line
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	return results
}

// ─────────────────────────────────────────────────────────────────────────────
// OS hint from TTL  (best-effort; requires ping in $PATH)
// ─────────────────────────────────────────────────────────────────────────────

func osHint(ip string) string {
	out, err := exec.Command("ping", "-c", "1", "-W", "1", ip).Output()
	if err != nil {
		// Windows ping syntax
		out, err = exec.Command("ping", "-n", "1", "-w", "1000", ip).Output()
		if err != nil {
			return "Unknown"
		}
	}
	re := regexp.MustCompile(`(?i)ttl=(\d+)`)
	m := re.FindSubmatch(out)
	if m == nil {
		return "Unknown"
	}
	ttl, _ := strconv.Atoi(string(m[1]))
	switch {
	case ttl <= 64:
		return "Linux / Unix"
	case ttl <= 128:
		return "Windows"
	default:
		return "Cisco / Network"
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Port-spec parser  — handles "80", "1-1024", "22,80,443", "1-100,443,8080"
// ─────────────────────────────────────────────────────────────────────────────

func parsePorts(spec string) ([]int, error) {
	seen := map[int]bool{}
	var ports []int

	for _, chunk := range strings.Split(spec, ",") {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		if strings.Contains(chunk, "-") {
			parts := strings.SplitN(chunk, "-", 2)
			a, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("invalid range %q", chunk)
			}
			for p := a; p <= b; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(chunk)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port %q", chunk)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports in %q", spec)
	}
	sort.Ints(ports)
	return ports, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolve host — IPv4 preferred
// ─────────────────────────────────────────────────────────────────────────────

func resolveHost(host string) (string, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	// Prefer IPv4
	for _, a := range addrs {
		if net.ParseIP(a).To4() != nil {
			return a, nil
		}
	}
	return addrs[0], nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Export
// ─────────────────────────────────────────────────────────────────────────────

func saveJSON(path string, meta ScanMeta) {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		fmt.Printf("  %s JSON marshal: %v\n", paint(red, "[✗]"), err)
		return
	}
	if err := os.WriteFile(path+".json", data, 0o644); err != nil {
		fmt.Printf("  %s write %s.json: %v\n", paint(red, "[✗]"), path, err)
		return
	}
	fmt.Printf("  %s JSON saved → %s.json\n", paint(green, "[✓]"), path)
}

func saveCSV(path string, results []ScanResult) {
	f, err := os.Create(path + ".csv")
	if err != nil {
		fmt.Printf("  %s create %s.csv: %v\n", paint(red, "[✗]"), path, err)
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)
	_ = w.Write([]string{"port", "default_service", "detected_service",
		"version", "tls", "tls_subject", "tls_expiry", "tls_expired",
		"rtt_ms", "risk_hints", "banner"})

	for _, r := range results {
		tlsSubject, tlsExpiry, tlsExpired := "", "", ""
		if r.TLSInfo != nil {
			tlsSubject = r.TLSInfo.Subject
			tlsExpiry = r.TLSInfo.NotAfter
			tlsExpired = strconv.FormatBool(r.TLSInfo.Expired)
		}
		_ = w.Write([]string{
			strconv.Itoa(r.Port),
			r.DefaultService,
			r.ServiceName,
			r.Version,
			strconv.FormatBool(r.TLS),
			tlsSubject, tlsExpiry, tlsExpired,
			fmt.Sprintf("%.1f", r.RTTms),
			strings.Join(r.RiskHints, "; "),
			stripANSI(strings.ReplaceAll(r.Banner, "\n", " ")),
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fmt.Printf("  %s CSV flush: %v\n", paint(red, "[✗]"), err)
		return
	}
	fmt.Printf("  %s CSV  saved → %s.csv\n", paint(green, "[✓]"), path)
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

func printBanner() {
	fmt.Print(paint(cyan+bold, `
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║          ██████╗  ██████╗             ███████╗ █████╗ ███████╗████████╗          ║
║          ██╔════╝ ██╔═══██╗           ██╔════╝██╔══██╗██╔════╝╚══██╔══╝          ║
║          ██║  ███╗██║   ██║           █████╗  ███████║███████╗   ██║             ║
║          ██║   ██║██║   ██║           ██╔══╝  ██╔══██║╚════██║   ██║             ║
║          ╚██████╔╝╚██████╔╝           ██║     ██║  ██║███████║   ██║             ║
║           ╚═════╝  ╚═════╝            ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝             ║
║                                                                                  ║
║                       Ultra Fast Concurrent Scanner  v2.0                        ║
║                                   by Prasad                                      ║
╚══════════════════════════════════════════════════════════════════════════════════╝
`) + "\n")
}

func section(title string, double bool) {
	w := 82
	pad := (w - 2 - len(title)) / 2
	extra := (w - 2 - len(title)) % 2
	inner := strings.Repeat(" ", pad) + title + strings.Repeat(" ", pad+extra)
	if double {
		fmt.Printf("\n%s\n%s\n%s\n",
			paint(cyan, "╔"+strings.Repeat("═", w-2)+"╗"),
			paint(cyan, "║"+inner+"║"),
			paint(cyan, "╚"+strings.Repeat("═", w-2)+"╝"))
	} else {
		fmt.Printf("\n%s\n%s\n%s\n",
			paint(cyan, "┌"+strings.Repeat("─", w-2)+"┐"),
			paint(cyan, "│"+inner+"│"),
			paint(cyan, "└"+strings.Repeat("─", w-2)+"┘"))
	}
}

func printHelp() {
	section("USAGE", false)
	fmt.Printf(`
  %s

%s
  -host <target>      Target hostname or IP address
  -p    <ports>       Port range (1-1000), list (22,80,443), or mixed (1-100,443)
  -quick              Top-24 quick scan
  -standard           Top-38 standard scan (default when no -p / -quick)
  -timeout <ms>       Connection timeout in milliseconds (default: 500)
  -c    <n>           Max concurrent connections (default: 500)
  -nb                 Disable banner grabbing (faster)
  -v                  Verbose — show closed ports too
  -o    <file>        Save results (appends .json and .csv)
  -h                  Show this help

%s
  go run fastscan.go -host google.com -quick
  go run fastscan.go -host 192.168.1.1 -p 1-10000 -c 1000
  go run fastscan.go -host github.com  -p 22,80,443 -timeout 300 -o out
  go run fastscan.go -host 10.0.0.1    -standard -v -nb

`,
		paint(white, "go run fastscan.go -host <target> [options]"),
		paint(yellow, "OPTIONS:"),
		paint(yellow, "EXAMPLES:"))
}

func printResultsTable(results []ScanResult) {
	if len(results) == 0 {
		fmt.Printf("\n  %s No open ports found.\n", paint(yellow, "[!]"))
		return
	}
	fmt.Printf("\n  %s Found %s open port(s)\n\n",
		paint(green+bold, "[+]"),
		paint(white+bold, strconv.Itoa(len(results))))

	top := paint(cyan, "┌──────────┬──────────────────────┬──────────────────────┬──────────┬─────────────────────────────────────┐")
	hdr := paint(cyan, "│") + "  PORT    " +
		paint(cyan, "│") + "  DEFAULT SERVICE     " +
		paint(cyan, "│") + "  DETECTED SERVICE    " +
		paint(cyan, "│") + "  RTT ms  " +
		paint(cyan, "│") + "  VERSION / BANNER                   " +
		paint(cyan, "│")
	mid := paint(cyan, "├──────────┼──────────────────────┼──────────────────────┼──────────┼─────────────────────────────────────┤")
	bot := paint(cyan, "└──────────┴──────────────────────┴──────────────────────┴──────────┴─────────────────────────────────────┘")
	fmt.Println(top)
	fmt.Println(hdr)
	fmt.Println(mid)

	sep := paint(cyan, "│")
	for _, r := range results {
		tlsIcon := "  "
		if r.TLS {
			tlsIcon = paint(cyan, "🔒")
		}
		portCell := fmt.Sprintf("%s %-6d", tlsIcon, r.Port)
		defCell := fmt.Sprintf("%-20s", truncate(r.DefaultService, 20))
		detSvc := r.ServiceName
		detCell := ""
		if detSvc != "" {
			detCell = fmt.Sprintf("%-20s", truncate(paint(green, "✓ "+detSvc), 20))
		} else {
			detCell = fmt.Sprintf("%-20s", paint(dim, "─"))
		}
		rtt := "N/A     "
		if r.RTTms > 0 {
			rtt = fmt.Sprintf("%-8s", fmt.Sprintf("%.1fms", r.RTTms))
		}
		verStr := "Open"
		if r.Version != "" {
			verStr = "v" + r.Version
		} else if r.Banner != "" {
			verStr = truncate(r.Banner, 37)
		}
		verCell := fmt.Sprintf("%-37s", verStr)

		fmt.Printf("%s  %s %s  %s%s  %s%s  %s%s  %s%s  %s\n",
			sep, paint(white+bold, portCell), sep,
			paint(yellow, defCell), sep,
			detCell, sep,
			paint(magenta, rtt), sep,
			paint(white, verCell), sep, "")

		// Risk hints on sub-rows
		for _, h := range r.RiskHints {
			hintCell := fmt.Sprintf("%-83s", truncate("  ⚠  "+h, 83))
			fmt.Printf("%s  %s%s\n", sep, paint(yellow, hintCell), sep)
		}
		// TLS expiry warning
		if r.TLSInfo != nil && r.TLSInfo.Expired {
			expCell := fmt.Sprintf("%-83s", truncate("  🔴  TLS certificate EXPIRED ("+r.TLSInfo.NotAfter+")", 83))
			fmt.Printf("%s  %s%s\n", sep, paint(red+bold, expCell), sep)
		}
	}
	fmt.Println(bot)
}

func printSummary(target, ip, osHintStr string, totalScanned, openCount int, elapsed time.Duration, timeoutMs, concurrency int, grab bool) {
	fmt.Println()
	fmt.Printf("  %-18s : %s (%s)\n", paint(dim, "Target"), paint(white, target), paint(white, ip))
	fmt.Printf("  %-18s : %s\n", paint(dim, "OS Hint"), paint(white, osHintStr))
	fmt.Printf("  %-18s : %s\n", paint(dim, "Ports scanned"), paint(white, strconv.Itoa(totalScanned)))
	fmt.Printf("  %-18s : %s\n", paint(dim, "Open ports"), paint(green+bold, strconv.Itoa(openCount)))
	fmt.Printf("  %-18s : %s\n", paint(dim, "Time taken"), paint(white, fmt.Sprintf("%.2fs", elapsed.Seconds())))
	fmt.Printf("  %-18s : %s\n", paint(dim, "Timeout"), paint(white, fmt.Sprintf("%dms", timeoutMs)))
	fmt.Printf("  %-18s : %s\n", paint(dim, "Concurrency"), paint(white, strconv.Itoa(concurrency)))
	fmt.Printf("  %-18s : %s\n", paint(dim, "Banner grab"), paint(white, map[bool]string{true: "Enabled", false: "Disabled"}[grab]))
	fmt.Println()
	fmt.Println(paint(cyan, strings.Repeat("═", 82)))
	fmt.Println()
}

// truncate cuts s to at most n runes, appending "…" if cut.
func truncate(s string, n int) string {
	// Strip ANSI before measuring length, re-add colour after would be
	// complex; here we measure the *visible* portion only.
	visible := stripANSI(s)
	if len([]rune(visible)) <= n {
		return s
	}
	runes := []rune(visible)
	return string(runes[:n-1]) + "…"
}

// ─────────────────────────────────────────────────────────────────────────────
// Port lists
// ─────────────────────────────────────────────────────────────────────────────

var topPortsQuick = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
	443, 445, 993, 995, 3306, 3389, 5432, 5900,
	6379, 8080, 8443, 9200, 11211, 27017,
}

var topPortsStandard = []int{
	20, 21, 22, 23, 25, 53, 80, 110, 111, 135,
	139, 143, 443, 445, 465, 587, 993, 995, 1723,
	2375, 2376, 3000, 3306, 3389, 4443, 5432, 5601,
	5900, 6379, 6443, 8080, 8443, 8888, 9000, 9200,
	11211, 27017, 27018,
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	hostFlag    := flag.String("host", "", "Target hostname or IP")
	portsFlag   := flag.String("p", "", "Port spec: range, list, or mixed")
	quickFlag   := flag.Bool("quick", false, "Quick scan — top 24 ports")
	standardFlag:= flag.Bool("standard", false, "Standard scan — top 38 ports")
	timeoutFlag := flag.Int("timeout", 500, "Timeout in milliseconds")
	concurFlag  := flag.Int("c", 500, "Max concurrent connections")
	noBannerFlag:= flag.Bool("nb", false, "Disable banner grabbing")
	verboseFlag := flag.Bool("v", false, "Show closed ports")
	outputFlag  := flag.String("o", "", "Output file base path (no extension)")
	helpFlag    := flag.Bool("h", false, "Show help")
	flag.Parse()

	printBanner()

	if *helpFlag || *hostFlag == "" {
		printHelp()
		os.Exit(0)
	}

	// ── Validate inputs ──────────────────────────────────────────────────────
	if *timeoutFlag < 50 || *timeoutFlag > 30000 {
		fmt.Printf("  %s --timeout must be 50–30000 ms\n", paint(red, "[✗]"))
		os.Exit(1)
	}
	if *concurFlag < 1 || *concurFlag > 10000 {
		fmt.Printf("  %s -c must be 1–10000\n", paint(red, "[✗]"))
		os.Exit(1)
	}

	// ── Strip URL junk from target ───────────────────────────────────────────
	target := *hostFlag
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.SplitN(target, "/", 2)[0]
	target = strings.TrimSpace(target)
	if target == "" {
		fmt.Printf("  %s Target is empty after parsing.\n", paint(red, "[✗]"))
		os.Exit(1)
	}

	// ── Resolve ───────────────────────────────────────────────────────────────
	fmt.Printf("  %s Resolving %s...\n", paint(cyan, "[→]"), target)
	ip, err := resolveHost(target)
	if err != nil {
		fmt.Printf("  %s Cannot resolve %q: %v\n", paint(red, "[✗]"), target, err)
		os.Exit(1)
	}
	fmt.Printf("  %s %s → %s\n", paint(green, "[✓]"), paint(white, target), paint(white, ip))

	// ── OS hint ───────────────────────────────────────────────────────────────
	hint := osHint(ip)
	fmt.Printf("  %s OS hint      : %s\n", paint(cyan, "[→]"), paint(white, hint))
	fmt.Printf("  %s Timeout      : %s\n", paint(cyan, "[→]"), paint(white, fmt.Sprintf("%dms", *timeoutFlag)))
	fmt.Printf("  %s Concurrency  : %s\n", paint(cyan, "[→]"), paint(white, strconv.Itoa(*concurFlag)))
	fmt.Printf("  %s Banner grab  : %s\n", paint(cyan, "[→]"), paint(white, map[bool]string{true: "Disabled", false: "Enabled"}[*noBannerFlag]))

	// ── Determine port list ───────────────────────────────────────────────────
	var portsToScan []int
	switch {
	case *portsFlag != "":
		portsToScan, err = parsePorts(*portsFlag)
		if err != nil {
			fmt.Printf("  %s Invalid port spec: %v\n", paint(red, "[✗]"), err)
			os.Exit(1)
		}
		fmt.Printf("  %s Mode: Custom (%d ports)\n\n", paint(cyan, "[→]"), len(portsToScan))
	case *quickFlag:
		portsToScan = topPortsQuick
		fmt.Printf("  %s Mode: Quick (%d ports)\n\n", paint(cyan, "[→]"), len(portsToScan))
	default:
		portsToScan = topPortsStandard
		fmt.Printf("  %s Mode: Standard (%d ports)\n\n", paint(cyan, "[→]"), len(portsToScan))
	}

	// ── Graceful Ctrl-C ───────────────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n\n  %s Interrupted — showing partial results...\n",
			paint(yellow, "[!]"))
		cancel()
	}()

	// ── Scan ──────────────────────────────────────────────────────────────────
	section("SCANNING IN PROGRESS", false)
	fmt.Println()
	start := time.Now()
	results := scanPorts(ctx, ip, portsToScan,
		time.Duration(*timeoutFlag)*time.Millisecond,
		*concurFlag, !*noBannerFlag, *verboseFlag)
	elapsed := time.Since(start)

	// ── Display ───────────────────────────────────────────────────────────────
	fmt.Println()
	section("RESULTS", true)
	printResultsTable(results)

	section("SUMMARY", true)
	printSummary(target, ip, hint,
		len(portsToScan), len(results),
		elapsed, *timeoutFlag, *concurFlag, !*noBannerFlag)

	// ── Export ────────────────────────────────────────────────────────────────
	if *outputFlag != "" {
		fmt.Println()
		meta := ScanMeta{
			Target:       target,
			IP:           ip,
			OSHint:       hint,
			Timestamp:    time.Now().Format(time.RFC3339),
			PortsScanned: len(portsToScan),
			OpenPorts:    len(results),
			ElapsedSec:   elapsed.Seconds(),
			TimeoutMs:    *timeoutFlag,
			Concurrency:  *concurFlag,
			Results:      results,
		}
		saveJSON(*outputFlag, meta)
		saveCSV(*outputFlag, results)
		fmt.Println()
	}
}
