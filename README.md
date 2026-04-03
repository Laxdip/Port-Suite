# 🔍 Port-Suite

**Port-Suite** is a network port scanning suite. Each implementation is optimized for a specific use case from speed to accuracy to usability.

---

##  Features

| Feature | Description |
|--------|-------------|
| 🚀 **Fast** | Multi-threaded / concurrent scanning |
| 🎯 **Accurate** | Service detection and banner grabbing |
| 💻 **Cross-platform** | Works on Windows, Linux, macOS |
| 🎨 **Beautiful UI** | Terminal colors + Windows GUI app |
| 📊 **Detailed output** | Port, service, status, response time |
| 💾 **Export results** | Save scans to file |

---

## 📁 Versions & Purpose

| Version | File | Best For |
|--------|------|----------|
| 🐍 Python | `python/scanner.py` | Full features, OS detection, banner grabbing |
| 🟨 JavaScript | `javascript/ping.js` | Real-time latency monitoring |
| 🔵 Go | `go/fastscan.go` | Blazing fast scanning |
| 🦀 Rust | `rust/scanner.rs` | Memory-safe, high performance |
| 🐚 Bash | `bash/netscan.sh` | Local network discovery |
| 🐘 PHP | `php/webscan.php` | Web + CLI scanning |
| 🪟 C# | `csharp/PortScanner.cs` | Windows GUI application |
| 💎 Ruby | `ruby/scan.rb` | Service fingerprinting |

---

## 🚀 Quick Start

```
### 🐍 Python
cd python  
python scanner.py -t google.com -q  
```
### 🟨 JavaScript (Node.js)
cd javascript  
node ping.js -t google.com  
```
### 🔵 Go
cd go  
go run fastscan.go -host google.com -quick  
```
### 🦀 Rust
cd rust  
rustc scanner.rs  
./scanner -t google.com -q  
```
### 🐚 Bash
cd bash  
chmod +x netscan.sh  
./netscan.sh -n 192.168.1.0/24  
```
### 🐘 PHP
cd php  
php webscan.php -t google.com -q  
```
### 🪟 C# (Windows)
cd csharp  
csc /target:winexe /reference:System.Windows.Forms.dll PortScanner.cs  
PortScanner.exe  
```
### 💎 Ruby
cd ruby  
ruby scan.rb -t google.com -q  
```
---

## 📖 Usage Examples

Scan common ports  
python scanner.py github.com -q  

Scan specific range  
go run fastscan.go -host 192.168.1.1 -p 1-1000  

Service detection  
ruby scan.rb -t cloudflare.com -p 22,80,443 -to 500  

Real-time ping  
node ping.js -t google.com -i 500  

Network discovery  
sudo ./netscan.sh -a  

Start web scanner (PHP)  
php -S localhost:8080 webscan.php --web  
Open http://localhost:8080  

---

## 📊 Output Example

╔════════════════════════════════════════════════════════════════════════════════╗  
║                                    RESULTS                                     ║  
╚════════════════════════════════════════════════════════════════════════════════╝  

[+] Found 3 open port(s):  

┌──────────┬────────────────────┬────────────────────────────────────────┐  
│   PORT   │      SERVICE       │                    INFO                │  
├──────────┼────────────────────┼────────────────────────────────────────┤  
│   22     │  SSH               │  Open                                  │  
│   80     │  HTTP              │  Open                                  │  
│   443    │  HTTPS             │  Open                                  │  
└──────────┴────────────────────┴────────────────────────────────────────┘  

╔════════════════════════════════════════════════════════════════════════════════╗  
║                                    SUMMARY                                     ║  
╚════════════════════════════════════════════════════════════════════════════════╝  

Target IP     : 142.250.185.46  
Hostname      : google.com  
Ports scanned : 24  
Open ports    : 3  
Time taken    : 0.31 seconds  

---

## 🛠️ Requirements

| Version | Requirement |
|--------|------------|
| Python | Python 3.6+ |
| JavaScript | Node.js 14+ |
| Go | Go 1.16+ |
| Rust | Rust 1.60+ |
| Bash | Linux/macOS or WSL |
| PHP | PHP 7.4+ |
| C# | .NET Framework / .NET Core |
| Ruby | Ruby 2.5+ |

---

## 📁 Project Structure

Port-Suite/  
├── README.md  
├── python/  
│   └── scanner.py  
├── javascript/  
│   └── ping.js  
├── go/  
│   └── fastscan.go  
├── rust/  
│   └── scanner.rs  
├── bash/  
│   └── netscan.sh  
├── php/  
│   ├── webscan.php  
│   └── check_port.php  
├── csharp/  
│   └── PortScanner.cs  
└── ruby/  
    └── scan.rb  

---

## ⚠️ Disclaimer

This tool is for educational purposes and authorized testing only.  
Only scan systems you own or have permission to test.

---

## 📄 License

MIT License  

---

## Author

Prasad
