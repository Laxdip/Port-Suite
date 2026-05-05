# Port Suite

**Port-Suite** is a network port scanning suite. Each implementation is optimized for a specific use case from speed to accuracy to usability.

---

## Features

- **Fast** – Multi threaded concurrent scanning
- **Accurate** – Service detection + banner grabbing
- **Cross-platform** – Windows, Linux, macOS
- **Detailed output** – Port, service, status, response time
- **Export results** – Save scans to file
---

## Screenshots

### Python Scanner
![Python](screenshots/python.png)

### Go Scanner
![Go](screenshots/Go.png)

### JavaScript Ping Monitor
![JavaScript](screenshots/js.png)

### PHP Web Scanner
![PHP](screenshots/php.png)

### Ruby Scanner
![Ruby](screenshots/ruby.png)

---

## Versions & Purpose

- **Python** – Full features + banner grabbing
- **Go** – Blazing fast
- **Rust** – Memory-safe performance
- **Bash** – Local network discovery
- **JavaScript** – Real-time ping
- **PHP** – Web + CLI scanning
- **C#** – Windows GUI app
- **Ruby** – Service fingerprinting

---

## Quick Start

### Python
```
cd python  
python scanner.py -t google.com -q  
```
### JavaScript (Node.js)
```
cd javascript  
node ping.js -t google.com  
```
### Go
```
cd go  
go run fastscan.go -host google.com -quick  
```
### Rust
```
cd rust  
rustc scanner.rs  
./scanner -t google.com -q  
```
### Bash
```
cd bash  
chmod +x netscan.sh  
./netscan.sh -n 192.168.1.0/24  
```
### PHP
```
cd php  
php webscan.php -t google.com -q  
```
### C# (Windows)
```
cd csharp  
csc /target:winexe /reference:System.Windows.Forms.dll PortScanner.cs  
PortScanner.exe  
```
### Ruby
```
cd ruby  
ruby scan.rb -t google.com -q  
```
---

## Usage Examples

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

## Requirements
Python 3.6+, Node.js 14+, Go 1.16+, Rust 1.60+, PHP 7.4+, Ruby 2.5+, or .NET (C#)

---

## ⚠️ Disclaimer

This tool is for educational purposes and authorized testing only.  
Only scan systems you own or have permission to test.

---

## License

MIT License  

---

## Author

Prasad
