package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ANSI color codes
const (
	Reset   = "\033[0m"
	Red     = "\033[91m"
	Green   = "\033[92m"
	Yellow  = "\033[93m"
	Blue    = "\033[94m"
	Magenta = "\033[95m"
	Cyan    = "\033[96m"
	White   = "\033[97m"
	Bold    = "\033[1m"
)

func printBanner() {
	fmt.Print(Cyan + Bold + `
╔════════════════════════════════════════════════════════════════════════════════╗
║                                                                                ║
║      ██████╗  ██████╗     ███████╗ █████╗ ███████╗████████╗ ██████╗ █████╗     ║
║     ██╔════╝ ██╔═══██╗    ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗    ║
║     ██║  ███╗██║   ██║    █████╗  ███████║███████╗   ██║   ██║     ██║  ██║    ║
║     ██║   ██║██║   ██║    ██╔══╝  ██╔══██║╚════██║   ██║   ██║     ██║  ██║    ║
║     ╚██████╔╝╚██████╔╝    ██║     ██║  ██║███████║   ██║   ╚██████╗███████║    ║
║      ╚═════╝  ╚═════╝     ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝╚══════╝    ║
║                                                                                ║
║                         Ultra-Fast Concurrent Scanner                          ║
║                                  by Prasad                                     ║
╚════════════════════════════════════════════════════════════════════════════════╝
` + Reset + "\n")
}

// Common ports with service names
var commonPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	111:  "RPC",
	135:  "RPC",
	139:  "NetBIOS",
	143:  "IMAP",
	443:  "HTTPS",
	445:  "SMB",
	993:  "IMAPS",
	995:  "POP3S",
	1723: "PPTP",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	6379: "Redis",
	8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
	27017: "MongoDB",
}

func getServiceName(port int) string {
	if name, exists := commonPorts[port]; exists {
		return name
	}
	return "Unknown"
}

type ScanResult struct {
	Port    int
	Open    bool
	Service string
}

func scanPort(host string, port int, timeout time.Duration) ScanResult {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	
	if err != nil {
		return ScanResult{Port: port, Open: false, Service: ""}
	}
	conn.Close()
	
	return ScanResult{
		Port:    port,
		Open:    true,
		Service: getServiceName(port),
	}
}

func scanPortsConcurrent(host string, ports []int, timeout time.Duration, concurrency int) []ScanResult {
	var wg sync.WaitGroup
	results := make([]ScanResult, 0)
	resultsChan := make(chan ScanResult, len(ports))
	semaphore := make(chan struct{}, concurrency)
	
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			result := scanPort(host, p, timeout)
			<-semaphore
			resultsChan <- result
		}(port)
	}
	
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	
	for result := range resultsChan {
		if result.Open {
			results = append(results, result)
		}
	}
	
	return results
}

func parsePorts(portArg string) []int {
	var ports []int
	
	if strings.Contains(portArg, "-") {
		// Range like 1-1000
		parts := strings.Split(portArg, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(parts[0])
			end, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil && start > 0 && end <= 65535 && start <= end {
				for p := start; p <= end; p++ {
					ports = append(ports, p)
				}
			}
		}
	} else if strings.Contains(portArg, ",") {
		// List like 22,80,443
		parts := strings.Split(portArg, ",")
		for _, part := range parts {
			if p, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
		}
	} else {
		// Single port
		if p, err := strconv.Atoi(portArg); err == nil && p > 0 && p <= 65535 {
			ports = append(ports, p)
		}
	}
	
	return ports
}

func getTopPorts() []int {
	return []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017}
}

func main() {
	// Command line flags
	host := flag.String("host", "", "Target hostname or IP address")
	ports := flag.String("p", "", "Ports to scan (e.g., 1-1000, 22,80,443)")
	quick := flag.Bool("quick", false, "Quick scan of top 24 common ports")
	timeoutMs := flag.Int("timeout", 500, "Connection timeout in milliseconds")
	concurrency := flag.Int("c", 500, "Number of concurrent connections")
	showHelp := flag.Bool("h", false, "Show help")
	
	flag.Parse()
	
	printBanner()
	
	if *showHelp || *host == "" {
		fmt.Print(Cyan + `
USAGE:
  go run fastscan.go -host <target> [options]

OPTIONS:
  -host <target>     Target hostname or IP address
  -p <ports>         Port range (1-1000) or list (22,80,443)
  -quick             Quick scan of top 24 common ports
  -timeout <ms>      Connection timeout in milliseconds (default: 500)
  -c <number>        Concurrent connections (default: 500)
  -h                 Show this help

EXAMPLES:
  go run fastscan.go -host google.com -quick
  go run fastscan.go -host 192.168.1.1 -p 1-1000
  go run fastscan.go -host github.com -p 22,80,443,3306 -c 1000
  go run fastscan.go -host cloudflare.com -p 1-65535 -timeout 300

` + Reset)
		os.Exit(0)
	}
	
	// Remove protocol if present
	target := *host
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.Split(target, "/")[0]
	
	// Resolve hostname to IP
	ips, err := net.LookupIP(target)
	if err != nil {
		fmt.Printf(Red+"[!] Failed to resolve host: %v"+Reset+"\n", err)
		os.Exit(1)
	}
	
	ip := ips[0].String()
	timeout := time.Duration(*timeoutMs) * time.Millisecond
	
	fmt.Printf(Cyan+"[✓] Target resolved: "+White+"%s (%s)"+Reset+"\n", target, ip)
	fmt.Printf(Cyan+"[→] Timeout: "+White+"%dms"+Reset+"\n", *timeoutMs)
	fmt.Printf(Cyan+"[→] Concurrency: "+White+"%d"+Reset+"\n\n", *concurrency)
	
	// Determine ports to scan
	var portsToScan []int
	if *quick {
		portsToScan = getTopPorts()
		fmt.Printf(Cyan+"[→] Mode: "+White+"Quick Scan (%d common ports)"+Reset+"\n\n", len(portsToScan))
	} else if *ports != "" {
		portsToScan = parsePorts(*ports)
		if len(portsToScan) == 0 {
			fmt.Printf(Red+"[!] Invalid port specification"+Reset+"\n")
			os.Exit(1)
		}
		fmt.Printf(Cyan+"[→] Mode: "+White+"Custom Scan (%d ports)"+Reset+"\n\n", len(portsToScan))
	} else {
		// Default: top ports
		portsToScan = getTopPorts()
		fmt.Printf(Cyan+"[→] Mode: "+White+"Default Scan (%d common ports)"+Reset+"\n", len(portsToScan))
		fmt.Print(Yellow + "[→] Tip: Use -quick or -p for custom ranges" + Reset + "\n\n")
	}
	
	// Start scanning
	fmt.Print(Cyan + "┌────────────────────────────────────────────────────────────────────────────────────┐\n")
	fmt.Print("│                              Scanning in progress...                               │\n")
	fmt.Print("└────────────────────────────────────────────────────────────────────────────────────┘\n" + Reset)
	
	startTime := time.Now()
	results := scanPortsConcurrent(ip, portsToScan, timeout, *concurrency)
	elapsed := time.Since(startTime)
	
	// Sort results by port number
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	
	// Display results
	fmt.Print(Cyan + "\n╔════════════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Print("║                                    RESULTS                                        ║\n")
	fmt.Print("╚════════════════════════════════════════════════════════════════════════════════╝\n" + Reset)
	
	if len(results) == 0 {
		fmt.Print(Yellow + "\n[!] No open ports found.\n" + Reset)
	} else {
		fmt.Printf("\n" + Green + "[+] Found %d open port(s):\n" + Reset, len(results))
		fmt.Print(Cyan + "\n┌──────────┬────────────────────┬────────────────────────────────────────┐\n")
		fmt.Print("│   PORT   │      SERVICE       │                    INFO                     │\n")
		fmt.Print("├──────────┼────────────────────┼────────────────────────────────────────┤\n" + Reset)
		
		for _, r := range results {
			serviceColor := Yellow
			if r.Service == "Unknown" {
				serviceColor = White
			}
			fmt.Printf("│  %-5d   │  %s%-17s%s  │  %-38s  │\n", 
				r.Port, serviceColor, r.Service, Reset, "Open")
		}
		fmt.Print(Cyan + "└──────────┴────────────────────┴────────────────────────────────────────┘\n" + Reset)
	}
	
	// Summary
	fmt.Print(Cyan + "\n╔════════════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Print("║                                    SUMMARY                                        ║\n")
	fmt.Print("╚════════════════════════════════════════════════════════════════════════════════╝\n" + Reset)
	
	fmt.Printf(White+"\n  Target IP     : %s\n", ip)
	fmt.Printf("  Ports scanned : %d\n", len(portsToScan))
	fmt.Printf("  Open ports    : %d\n", len(results))
	fmt.Printf("  Time taken    : %.2f seconds\n", elapsed.Seconds())
	fmt.Printf("  Concurrency   : %d\n", *concurrency)
	fmt.Printf("  Timeout       : %dms\n"+Reset, *timeoutMs)
	
	fmt.Print(Cyan + "\n════════════════════════════════════════════════════════════════════════════════\n" + Reset)
}