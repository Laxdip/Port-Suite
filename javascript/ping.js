#!/usr/bin/env node
/**
 * SmartScan - Real-time Ping Monitor
 * Author: Prasad
 * Features: Live latency tracking, packet loss monitoring, colorful graphs
 */

const { exec } = require('child_process');
const readline = require('readline');
const os = require('os');

// Colors for terminal output
const colors = {
    red: '\x1b[91m',
    green: '\x1b[92m',
    yellow: '\x1b[93m',
    blue: '\x1b[94m',
    magenta: '\x1b[95m',
    cyan: '\x1b[96m',
    white: '\x1b[97m',
    gray: '\x1b[90m',
    bold: '\x1b[1m',
    reset: '\x1b[0m',
    clear: '\x1b[2J\x1b[H'
};

function printBanner() {
    console.log(colors.clear + colors.cyan + colors.bold);
    console.log('╔══════════════════════════════════════════════════════════════════════════╗');
    console.log('║                                                                          ║');
    console.log('║      ██████╗ ██╗███╗   ██╗ ██████╗     ███╗   ███╗ ██████╗ ███╗   ██╗    ║');
    console.log('║      ██╔══██╗██║████╗  ██║██╔════╝     ████╗ ████║██╔═══██╗████╗  ██║    ║');
    console.log('║      ██████╔╝██║██╔██╗ ██║██║  ███╗    ██╔████╔██║██║   ██║██╔██╗ ██║    ║');
    console.log('║      ██╔═══╝ ██║██║╚██╗██║██║   ██║    ██║╚██╔╝██║██║   ██║██║╚██╗██║    ║');
    console.log('║      ██║     ██║██║ ╚████║╚██████╔╝    ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║    ║');
    console.log('║      ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝     ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝    ║');
    console.log('║                                                                          ║');
    console.log('║                      Real-time Ping Monitor                              ║');
    console.log('║                             by Prasad                                    ║');
    console.log('║                                                                          ║');
    console.log('╚══════════════════════════════════════════════════════════════════════════╝');
    console.log(colors.reset);
}
class PingMonitor {
    constructor(target, interval = 1000, alerts = true) {
        this.target = target;
        this.interval = interval;
        this.alerts = alerts;
        this.running = true;
        this.results = [];
        this.lossCount = 0;
        this.totalSent = 0;
        this.latencies = [];
        this.alertThreshold = 200; // ms
        this.isWindows = os.platform() === 'win32';
    }

    getColorForLatency(latency) {
        if (latency === null) return colors.red;
        if (latency < 50) return colors.green;
        if (latency < 100) return colors.yellow;
        if (latency < 200) return colors.magenta;
        return colors.red;
    }

    drawGraph() {
        const maxWidth = 50;
        const recentResults = this.results.slice(-maxWidth);
        console.log(colors.gray + '\n┌──────────────────────────────────────────────────────────────┐');
                        console.log('│                          Latency Graph                       │');
                        console.log('├──────────────────────────────────────────────────────────────┤' + colors.reset);
        
        let graphLine = '';
        for (let i = 0; i < recentResults.length; i++) {
            const latency = recentResults[i];
            if (latency === null) {
                graphLine += colors.red + '█' + colors.reset;
            } else if (latency < 50) {
                graphLine += colors.green + '█' + colors.reset;
            } else if (latency < 100) {
                graphLine += colors.yellow + '█' + colors.reset;
            } else if (latency < 200) {
                graphLine += colors.magenta + '█' + colors.reset;
            } else {
                graphLine += colors.red + '█' + colors.reset;
            }
        }
        console.log('│ ' + graphLine.padEnd(maxWidth) + ' │');
        
        console.log(colors.gray + '└──────────────────────────────────────────────────┘' + colors.reset);
        
        // Legend
        console.log(colors.gray + '  ' + colors.green + '█ <50ms  ' + colors.yellow + '█ 50-100ms  ' + 
                   colors.magenta + '█ 100-200ms  ' + colors.red + '█ >200ms  ' + colors.red + '█ Loss' + colors.reset);
    }

    drawStats() {
        const total = this.results.length;
        if (total === 0) return;
        
        const successful = this.results.filter(r => r !== null).length;
        const lossPercent = ((this.totalSent - successful) / this.totalSent * 100).toFixed(1);
        
        const validLatencies = this.results.filter(r => r !== null);
        const avgLatency = validLatencies.length > 0 
            ? (validLatencies.reduce((a, b) => a + b, 0) / validLatencies.length).toFixed(1)
            : 'N/A';
        
        const minLatency = validLatencies.length > 0 ? Math.min(...validLatencies).toFixed(1) : 'N/A';
        const maxLatency = validLatencies.length > 0 ? Math.max(...validLatencies).toFixed(1) : 'N/A';
        
        console.log(colors.cyan + '\n╔════════════════════════════════════════════════════╗');
        console.log('║                    Statistics                        ║');
        console.log('╠════════════════════════════════════════════════════╣');
        console.log(`║  ${colors.white}Target:${colors.reset} ${this.target.padEnd(40)}${colors.cyan}║`);
        console.log(`║  ${colors.white}Sent:${colors.reset} ${this.totalSent}     ${colors.white}Lost:${colors.reset} ${this.lossCount} (${lossPercent}%)        ${colors.cyan}║`);
        console.log(`║  ${colors.white}Avg:${colors.reset} ${String(avgLatency).padEnd(5)}ms    ${colors.white}Min:${colors.reset} ${String(minLatency).padEnd(5)}ms    ${colors.white}Max:${colors.reset} ${String(maxLatency).padEnd(5)}ms  ${colors.cyan}║`);
        console.log('╚════════════════════════════════════════════════════╝' + colors.reset);
    }

    checkAlert(latency) {
        if (!this.alerts) return;
        
        if (latency === null) {
            console.log(colors.red + colors.bold + `\n⚠️  ALERT: Packet loss detected! ⚠️` + colors.reset);
            this.lossCount++;
        } else if (latency > this.alertThreshold) {
            console.log(colors.yellow + colors.bold + `\n⚠️  ALERT: High latency detected! (${latency}ms) ⚠️` + colors.reset);
        }
    }

    async ping() {
        return new Promise((resolve) => {
            let command;
            if (this.isWindows) {
                command = `ping -n 1 ${this.target}`;
            } else {
                command = `ping -c 1 ${this.target}`;
            }
            
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    resolve(null);
                    return;
                }
                
                let latency = null;
                if (this.isWindows) {
                    const match = stdout.match(/time[=<](\d+)ms/);
                    if (match) latency = parseInt(match[1]);
                } else {
                    const match = stdout.match(/time[= ](\d+(?:\.\d+)?) ms/);
                    if (match) latency = parseFloat(match[1]);
                }
                
                resolve(latency);
            });
        });
    }

    async start() {
        printBanner();
        
        console.log(colors.green + `[✓] Monitoring started` + colors.reset);
        console.log(colors.cyan + `[→] Target: ${colors.white}${this.target}${colors.reset}`);
        console.log(colors.cyan + `[→] Interval: ${colors.white}${this.interval}ms${colors.reset}`);
        console.log(colors.cyan + `[→] Alert threshold: ${colors.white}${this.alertThreshold}ms${colors.reset}`);
        console.log(colors.gray + `[→] Press ${colors.yellow}Ctrl+C${colors.gray} to stop${colors.reset}\n`);
        
        console.log(colors.gray + '─'.repeat(60) + colors.reset);
        
        while (this.running) {
            const latency = await this.ping();
            this.totalSent++;
            this.results.push(latency);
            
            // Keep only last 1000 results
            if (this.results.length > 1000) {
                this.results.shift();
            }
            
            const color = this.getColorForLatency(latency);
            const latencyStr = latency === null ? 'LOSS' : `${latency}ms`;
            
            // Clear previous line and print new status
            readline.cursorTo(process.stdout, 0);
            readline.clearLine(process.stdout, 0);
            
            const timestamp = new Date().toLocaleTimeString();
            process.stdout.write(`${colors.gray}[${timestamp}]${colors.reset} ${color}${latencyStr.padEnd(8)}${colors.reset}`);
            
            // Draw graph and stats every 10 pings
            if (this.totalSent % 10 === 0) {
                console.log('');
                this.drawStats();
                this.drawGraph();
                console.log(colors.gray + '─'.repeat(60) + colors.reset);
            }
            
            this.checkAlert(latency);
            
            await new Promise(resolve => setTimeout(resolve, this.interval));
        }
    }

    stop() {
        this.running = false;
        console.log(colors.yellow + `\n\n[!] Monitoring stopped` + colors.reset);
        
        // Final statistics
        console.log(colors.cyan + '\n╔════════════════════════════════════════════════════╗');
                        console.log('║                  Final Report                      ║');
                        console.log('╠════════════════════════════════════════════════════╣');
        
        const total = this.results.length;
        const successful = this.results.filter(r => r !== null).length;
        const lossPercent = total > 0 ? ((total - successful) / total * 100).toFixed(1) : '0';
        
        console.log(`║  Total pings: ${this.totalSent}`);
        console.log(`║  Packet loss: ${lossPercent}%`);
        
        const validLatencies = this.results.filter(r => r !== null);
        if (validLatencies.length > 0) {
            const avg = (validLatencies.reduce((a, b) => a + b, 0) / validLatencies.length).toFixed(1);
            const min = Math.min(...validLatencies).toFixed(1);
            const max = Math.max(...validLatencies).toFixed(1);
            console.log(`║  Average latency: ${avg}ms`);
            console.log(`║  Min latency: ${min}ms`);
            console.log(`║  Max latency: ${max}ms`);
        }
        console.log('╚════════════════════════════════════════════════════╝' + colors.reset);
        
        process.exit(0);
    }
}

// Parse command line arguments
function parseArgs() {
    const args = process.argv.slice(2);
    let target = '8.8.8.8';
    let interval = 1000;
    let alerts = true;
    let noAlerts = false;
    
    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '-t':
            case '--target':
                target = args[++i];
                break;
            case '-i':
            case '--interval':
                interval = parseInt(args[++i]);
                if (isNaN(interval) || interval < 100) {
                    console.log(colors.red + 'Invalid interval. Using 1000ms' + colors.reset);
                    interval = 1000;
                }
                break;
            case '--no-alerts':
                noAlerts = true;
                break;
            case '-h':
            case '--help':
                console.log(`
${colors.cyan}SmartScan - Real-time Ping Monitor${colors.reset}

Usage: node ping.js [options]

Options:
  -t, --target <host>    Target host or IP (default: 8.8.8.8)
  -i, --interval <ms>    Ping interval in milliseconds (default: 1000, min: 100)
  --no-alerts            Disable alert notifications
  -h, --help             Show this help message

Examples:
  node ping.js -t google.com
  node ping.js -t 192.168.1.1 -i 500
  node ping.js -t cloudflare.com --no-alerts
`);
                process.exit(0);
                break;
            default:
                if (!target || target === '8.8.8.8') {
                    target = args[i];
                }
        }
    }
    
    return { target, interval, alerts: !noAlerts };
}

// Main execution
const { target, interval, alerts } = parseArgs();
const monitor = new PingMonitor(target, interval, alerts);

// Handle graceful shutdown
process.on('SIGINT', () => {
    monitor.stop();
});

// Start monitoring
monitor.start().catch(err => {
    console.error(colors.red + `\n[!] Error: ${err.message}` + colors.reset);
    process.exit(1);
});