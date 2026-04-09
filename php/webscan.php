#!/usr/bin/env php
<?php
/**
 * SmartScan - Web-Based Port Scanner
 * Author: Prasad
 * Features: CLI + Web interface, Service detection, Multi-threaded scanning
 */

// ANSI colors for CLI mode
definee('RESET', "\033[0m");
define('RED', "\033[91m");
define('GREEN', "\033[92m");
define('YELLOW', "\033[93m");
define('BLUE', "\033[94m");
define('MAGENTA', "\033[95m");
define('CYAN', "\033[96m");
define('WHITE', "\033[97m");
define('BOLD', "\033[1m");

function print_banner_cli() {
    echo CYAN . BOLD;
    echo "\n";
    echo "╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    echo "║                                                                                                                ║\n";
    echo "║     ██████╗ ██╗  ██╗██████╗     ██╗    ██╗███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗   ║\n";
    echo "║     ██╔══██╗██║  ██║██╔══██╗    ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗  ║\n";
    echo "║     ██████╔╝███████║██████╔╝    ██║ █╗ ██║█████╗  ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝  ║\n";
    echo "║     ██╔═══╝ ██╔══██║██╔═══╝     ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗  ║\n";
    echo "║     ██║     ██║  ██║██║         ╚███╔███╔╝███████╗██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║  ║\n";
    echo "║     ╚═╝     ╚═╝  ╚═╝╚═╝          ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝  ║\n";
    echo "║                                                                                                                ║\n";
    echo "║                                    Web-Based Port Scanner                                                      ║\n";
    echo "║                                            by Prasad                                                          ║\n";
    echo "╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    echo RESET;
}

function print_help() {
    echo CYAN;
    echo "┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐\n";
    echo "│                                                    USAGE                                                       │\n";
    echo "└────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘\n";
    echo RESET;
    echo "\n";
    echo "  php webscan.php [options]\n";
    echo "  Or access via web browser: http://localhost/webscan.php\n";
    echo "\n";
    echo YELLOW . "OPTIONS:" . RESET . "\n";
    echo "  -t, --target <host>     Target hostname or IP address\n";
    echo "  -p, --ports <ports>     Port range (1-1000) or list (22,80,443)\n";
    echo "  -q, --quick             Quick scan of top 24 common ports\n";
    echo "  -to, --timeout <ms>     Connection timeout in milliseconds (default: 1000)\n";
    echo "  -h, --help              Show this help message\n";
    echo "  --web                   Start in web server mode\n";
    echo "\n";
    echo YELLOW . "EXAMPLES:" . RESET . "\n";
    echo "  php webscan.php -t google.com -q\n";
    echo "  php webscan.php -t 192.168.1.1 -p 1-1000\n";
    echo "  php webscan.php -t github.com -p 22,80,443,3306 -to 500\n";
    echo "  php -S localhost:8080 webscan.php --web\n";
    echo "\n";
}

// Service names for common ports
function get_service_name($port) {
    $services = [
        20 => "FTP-data", 21 => "FTP", 22 => "SSH", 23 => "Telnet",
        25 => "SMTP", 53 => "DNS", 80 => "HTTP", 110 => "POP3",
        111 => "RPC", 135 => "RPC", 139 => "NetBIOS", 143 => "IMAP",
        443 => "HTTPS", 445 => "SMB", 993 => "IMAPS", 995 => "POP3S",
        1723 => "PPTP", 3306 => "MySQL", 3389 => "RDP", 5432 => "PostgreSQL",
        5900 => "VNC", 6379 => "Redis", 8080 => "HTTP-Alt", 8443 => "HTTPS-Alt",
        27017 => "MongoDB"
    ];
    return isset($services[$port]) ? $services[$port] : "Unknown";
}

// Scan a single port
function scan_port($host, $port, $timeout) {
    $start = microtime(true);
    $socket = @fsockopen($host, $port, $errno, $errstr, $timeout / 1000);
    $end = microtime(true);
    
    if ($socket) {
        fclose($socket);
        $response_time = round(($end - $start) * 1000, 2);
        return ['open' => true, 'time' => $response_time];
    }
    return ['open' => false, 'time' => null];
}

// Get top common ports
function get_top_ports() {
    return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017];
}

// Parse port specification
function parse_ports($port_spec) {
    $ports = [];
    
    if (strpos($port_spec, '-') !== false) {
        $range = explode('-', $port_spec);
        if (count($range) == 2) {
            $start = intval($range[0]);
            $end = intval($range[1]);
            for ($i = $start; $i <= $end; $i++) {
                if ($i > 0 && $i <= 65535) $ports[] = $i;
            }
        }
    } elseif (strpos($port_spec, ',') !== false) {
        $parts = explode(',', $port_spec);
        foreach ($parts as $part) {
            $port = intval(trim($part));
            if ($port > 0 && $port <= 65535) $ports[] = $port;
        }
    } else {
        $port = intval($port_spec);
        if ($port > 0 && $port <= 65535) $ports[] = $port;
    }
    
    return $ports;
}

// CLI scan function
function scan_cli($target, $ports_to_scan, $timeout_ms) {
    $open_ports = [];
    $total = count($ports_to_scan);
    $current = 0;
    
    echo CYAN . "\n┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐\n";
    echo "│                                                 SCANNING IN PROGRESS...                                          │\n";
    echo "└────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘\n" . RESET;
    echo "\n";
    
    foreach ($ports_to_scan as $port) {
        $current++;
        $result = scan_port($target, $port, $timeout_ms);
        
        if ($result['open']) {
            $service = get_service_name($port);
            $open_ports[] = ['port' => $port, 'service' => $service, 'time' => $result['time']];
            echo GREEN . "[+] Port $port is OPEN [" . YELLOW . "$service" . GREEN . "] - {$result['time']}ms" . RESET . "\n";
        } else {
            // Silent for closed ports in CLI mode
        }
        
        // Show progress
        $percent = round(($current / $total) * 100);
        echo "\r" . CYAN . "[→] Progress: $percent% ($current/$total ports)" . RESET;
    }
    
    echo "\n\n";
    return $open_ports;
}

// Web interface HTML
function web_interface() {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SmartScan - Web Port Scanner</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                background: #0a0e27;
                font-family: 'Courier New', monospace;
                color: #c9d1d9;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            .banner {
                background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
                border: 1px solid #30363d;
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 30px;
                text-align: center;
            }
            .banner pre {
                color: #58a6ff;
                font-size: 10px;
                line-height: 1.2;
                margin: 0;
                overflow-x: auto;
            }
            .card {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 10px;
                padding: 25px;
                margin-bottom: 20px;
            }
            .card h2 {
                color: #58a6ff;
                margin-bottom: 20px;
                border-bottom: 1px solid #30363d;
                padding-bottom: 10px;
            }
            input, select {
                background: #0d1117;
                border: 1px solid #30363d;
                color: #c9d1d9;
                padding: 12px;
                font-family: monospace;
                font-size: 14px;
                border-radius: 6px;
                width: 100%;
                margin-bottom: 15px;
            }
            button {
                background: #238636;
                border: none;
                color: white;
                padding: 12px 24px;
                font-family: monospace;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
                cursor: pointer;
                transition: background 0.3s;
            }
            button:hover {
                background: #2ea043;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }
            th, td {
                border: 1px solid #30363d;
                padding: 10px;
                text-align: left;
            }
            th {
                background: #0d1117;
                color: #58a6ff;
            }
            .open {
                color: #3fb950;
                font-weight: bold;
            }
            .closed {
                color: #f85149;
            }
            .status-box {
                background: #0d1117;
                border-left: 4px solid #58a6ff;
                padding: 15px;
                margin-top: 20px;
                border-radius: 6px;
            }
            .progress {
                background: #0d1117;
                border-radius: 6px;
                height: 20px;
                overflow: hidden;
                margin-top: 10px;
            }
            .progress-bar {
                background: #58a6ff;
                height: 100%;
                width: 0%;
                transition: width 0.3s;
            }
            hr {
                border-color: #30363d;
                margin: 20px 0;
            }
            .footer {
                text-align: center;
                padding: 20px;
                color: #8b949e;
                font-size: 12px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="banner">
                <pre>
╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                                ║
║     ██████╗ ██╗  ██╗██████╗     ██╗    ██╗███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗   ║
║     ██╔══██╗██║  ██║██╔══██╗    ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗  ║
║     ██████╔╝███████║██████╔╝    ██║ █╗ ██║█████╗  ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝  ║
║     ██╔═══╝ ██╔══██║██╔═══╝     ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗  ║
║     ██║     ██║  ██║██║         ╚███╔███╔╝███████╗██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║  ║
║     ╚═╝     ╚═╝  ╚═╝╚═╝          ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝  ║
║                                                                                                                ║
║                                    Web-Based Port Scanner                                                      ║
║                                            by Prasad                                                          ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
                </pre>
            </div>

            <div class="card">
                <h2>🎯 Scan Target</h2>
                <form method="GET" action="">
                    <input type="text" name="target" placeholder="Target IP or Hostname (e.g., google.com, 192.168.1.1)" value="<?php echo isset($_GET['target']) ? htmlspecialchars($_GET['target']) : ''; ?>">
                    <input type="text" name="ports" placeholder="Ports (e.g., 1-1000, 22,80,443, or leave empty for quick scan)" value="<?php echo isset($_GET['ports']) ? htmlspecialchars($_GET['ports']) : ''; ?>">
                    <input type="number" name="timeout" placeholder="Timeout (ms)" value="<?php echo isset($_GET['timeout']) ? intval($_GET['timeout']) : 1000; ?>" step="100" min="100">
                    <button type="submit" name="scan" value="1">🚀 START SCAN</button>
                </form>
            </div>

            <?php if (isset($_GET['scan']) && isset($_GET['target']) && !empty($_GET['target'])): 
                $target = $_GET['target'];
                $port_spec = isset($_GET['ports']) && !empty($_GET['ports']) ? $_GET['ports'] : '';
                $timeout_ms = isset($_GET['timeout']) ? intval($_GET['timeout']) : 1000;
                
                // Clean target
                $target = preg_replace('#^https?://#', '', $target);
                $target = explode('/', $target)[0];
                
                // Resolve hostname
                $ip = gethostbyname($target);
                $is_resolved = ($ip !== $target);
                
                // Determine ports to scan
                if (!empty($port_spec)) {
                    $ports_to_scan = parse_ports($port_spec);
                    $scan_mode = "Custom Scan";
                } else {
                    $ports_to_scan = get_top_ports();
                    $scan_mode = "Quick Scan (Top 24 ports)";
                }
                
                $start_time = microtime(true);
                $open_ports = [];
                $total = count($ports_to_scan);
                $current = 0;
            ?>
                <div class="card">
                    <h2>📡 Scan Results</h2>
                    <div class="status-box">
                        <strong>Target:</strong> <?php echo htmlspecialchars($target); ?><br>
                        <strong>IP Address:</strong> <?php echo $is_resolved ? htmlspecialchars($ip) : 'Failed to resolve'; ?><br>
                        <strong>Mode:</strong> <?php echo $scan_mode; ?><br>
                        <strong>Timeout:</strong> <?php echo $timeout_ms; ?> ms<br>
                        <strong>Ports to scan:</strong> <?php echo $total; ?>
                    </div>
                    
                    <div class="progress">
                        <div class="progress-bar" id="progressBar"></div>
                    </div>
                    
                    <div id="scanStatus" style="margin-top: 10px; color: #8b949e;">Scanning...</div>
                    
                    <div id="results">
                        <table style="display: none;" id="resultsTable">
                            <thead>
                                <tr><th>Port</th><th>Service</th><th>Status</th><th>Response Time</th></tr>
                            </thead>
                            <tbody id="resultsBody"></tbody>
                        </table>
                    </div>
                </div>
                
                <script>
                    const ports = <?php echo json_encode($ports_to_scan); ?>;
                    const target = '<?php echo addslashes($target); ?>';
                    const timeout = <?php echo $timeout_ms; ?>;
                    let current = 0;
                    let openPorts = [];
                    
                    async function scanPort(port) {
                        const start = performance.now();
                        try {
                            const controller = new AbortController();
                            const timeoutId = setTimeout(() => controller.abort(), timeout);
                            const response = await fetch(`/check_port.php?target=${encodeURIComponent(target)}&port=${port}`, {
                                signal: controller.signal
                            });
                            clearTimeout(timeoutId);
                            const end = performance.now();
                            const responseTime = (end - start).toFixed(2);
                            
                            if (response.ok) {
                                const data = await response.json();
                                if (data.open) {
                                    openPorts.push({port, service: data.service, time: responseTime});
                                    addResultRow(port, data.service, 'OPEN', responseTime + 'ms');
                                }
                            }
                        } catch(e) {
                            // Port closed or error
                        }
                        current++;
                        const percent = (current / ports.length) * 100;
                        document.getElementById('progressBar').style.width = percent + '%';
                        document.getElementById('scanStatus').innerHTML = `Scanning: ${current}/${ports.length} ports (${Math.round(percent)}%) - Open ports found: ${openPorts.length}`;
                        
                        if (current === ports.length) {
                            document.getElementById('scanStatus').innerHTML = `✅ Scan complete! Found ${openPorts.length} open port(s).`;
                            if (openPorts.length === 0) {
                                document.getElementById('resultsTable').style.display = 'table';
                                document.getElementById('resultsBody').innerHTML = '<tr><td colspan="4" style="text-align:center;">No open ports found</td></tr>';
                            }
                        }
                    }
                    
                    function addResultRow(port, service, status, time) {
                        const table = document.getElementById('resultsTable');
                        const tbody = document.getElementById('resultsBody');
                        table.style.display = 'table';
                        const row = tbody.insertRow();
                        row.innerHTML = `
                            <td>${port}</td>
                            <td>${service}</td>
                            <td class="open">${status}</td>
                            <td>${time}</td>
                        `;
                    }
                    
                    async function startScan() {
                        for (const port of ports) {
                            await scanPort(port);
                            await new Promise(resolve => setTimeout(resolve, 10));
                        }
                    }
                    
                    startScan();
                </script>
            <?php endif; ?>
            
            <div class="footer">
                SmartScan v1.0 | by Prasad | Web-Based Port Scanner
            </div>
        </div>
    </body>
    </html>
    <?php
}

// Check port endpoint for AJAX
function check_port_endpoint() {
    if (isset($_GET['target']) && isset($_GET['port'])) {
        header('Content-Type: application/json');
        $target = $_GET['target'];
        $port = intval($_GET['port']);
        $timeout = isset($_GET['timeout']) ? intval($_GET['timeout']) : 1000;
        
        $socket = @fsockopen($target, $port, $errno, $errstr, $timeout / 1000);
        if ($socket) {
            fclose($socket);
            echo json_encode(['open' => true, 'service' => get_service_name($port)]);
        } else {
            echo json_encode(['open' => false, 'service' => null]);
        }
        exit;
    }
}

// Main execution
$args = array_slice($argv, 1);

if (php_sapi_name() === 'cli') {
    // CLI Mode
    $target = null;
    $port_spec = null;
    $quick_mode = false;
    $timeout_ms = 1000;
    $web_mode = false;
    
    for ($i = 0; $i < count($args); $i++) {
        switch ($args[$i]) {
            case '-t': case '--target':
                $target = $args[++$i];
                break;
            case '-p': case '--ports':
                $port_spec = $args[++$i];
                break;
            case '-q': case '--quick':
                $quick_mode = true;
                break;
            case '-to': case '--timeout':
                $timeout_ms = intval($args[++$i]);
                break;
            case '--web':
                $web_mode = true;
                break;
            case '-h': case '--help':
                print_banner_cli();
                print_help();
                exit(0);
        }
    }
    
    if ($web_mode) {
        // Web server mode
        echo CYAN . "[✓] Starting web server on http://localhost:8080" . RESET . "\n";
        echo CYAN . "[→] Press Ctrl+C to stop" . RESET . "\n";
        return;
    }
    
    if (!$target) {
        print_banner_cli();
        print_help();
        exit(1);
    }
    
    // Clean target
    $target = preg_replace('#^https?://#', '', $target);
    $target = explode('/', $target)[0];
    
    // Resolve IP
    $ip = gethostbyname($target);
    
    print_banner_cli();
    
    echo CYAN . "[✓] Target: " . WHITE . $target . RESET . "\n";
    echo CYAN . "[✓] Resolved: " . WHITE . $ip . RESET . "\n";
    echo CYAN . "[→] Timeout: " . WHITE . $timeout_ms . "ms" . RESET . "\n";
    
    // Determine ports
    if ($quick_mode) {
        $ports_to_scan = get_top_ports();
        echo CYAN . "[→] Mode: " . WHITE . "Quick Scan (" . count($ports_to_scan) . " ports)" . RESET . "\n";
    } elseif ($port_spec) {
        $ports_to_scan = parse_ports($port_spec);
        echo CYAN . "[→] Mode: " . WHITE . "Custom Scan (" . count($ports_to_scan) . " ports)" . RESET . "\n";
    } else {
        $ports_to_scan = get_top_ports();
        echo CYAN . "[→] Mode: " . WHITE . "Default Scan (" . count($ports_to_scan) . " ports)" . RESET . "\n";
    }
    
    $start_time = microtime(true);
    $open_ports = scan_cli($ip, $ports_to_scan, $timeout_ms);
    $end_time = microtime(true);
    $elapsed = round($end_time - $start_time, 2);
    
    // Print results table
    echo CYAN . "╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    echo "║                                                  RESULTS                                                       ║\n";
    echo "╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n" . RESET;
    
    if (count($open_ports) == 0) {
        echo YELLOW . "\n[!] No open ports found.\n" . RESET;
    } else {
        echo "\n" . GREEN . "[+] Found " . count($open_ports) . " open port(s):\n" . RESET;
        echo CYAN . "\n┌──────────┬────────────────────┬────────────────────────────────────────────────────────────────────────────┐\n";
        echo "│   PORT   │      SERVICE       │                                    INFO                                     │\n";
        echo "├──────────┼────────────────────┼────────────────────────────────────────────────────────────────────────────┤\n" . RESET;
        
        foreach ($open_ports as $p) {
            $service_color = ($p['service'] == 'Unknown') ? WHITE : YELLOW;
            echo "│  " . str_pad($p['port'], 5) . "   │  " . $service_color . str_pad($p['service'], 17) . RESET . " │  " . WHITE . "Port " . $p['port'] . " is OPEN (" . $p['time'] . "ms)" . str_pad('', 30) . RESET . " │\n";
        }
        
        echo CYAN . "└──────────┴────────────────────┴────────────────────────────────────────────────────────────────────────────┘\n" . RESET;
    }
    
    // Summary
    echo CYAN . "\n╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    echo "║                                                  SUMMARY                                                      ║\n";
    echo "╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n" . RESET;
    
    echo WHITE . "\n  Target IP     : $ip\n";
    echo "  Hostname      : $target\n";
    echo "  Ports scanned : " . count($ports_to_scan) . "\n";
    echo "  Open ports    : " . count($open_ports) . "\n";
    echo "  Time taken    : " . $elapsed . " seconds\n";
    echo "  Timeout       : " . $timeout_ms . "ms\n" . RESET;
    
    echo CYAN . "\n════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n" . RESET;
    
} else {
    // Web Mode
    if (isset($_GET['check_port'])) {
        check_port_endpoint();
    } else {
        web_interface();
    }
}
?>
