# 🌐 Web Discovery Scanner - Enhanced Version

A powerful, feature-rich web service discovery and analysis tool designed for security professionals, penetration testers, and network administrators. This tool provides comprehensive web service enumeration with advanced features like SSL certificate analysis, subdomain discovery, path fuzzing, and automated screenshot capture.

## 🚀 Features

- **🌐 Web Service Discovery**: Automatically detects and analyzes web services on specified targets
- **🔐 SSL/TLS Certificate Analysis**: Validates certificates, checks expiry dates, and extracts SANs
- **📸 Automated Screenshots**: Captures high-quality screenshots of discovered web services
- **🔗 Subdomain Enumeration**: Active and passive subdomain discovery from certificates
- **🔍 Path Fuzzing**: Discovers hidden paths and files using customizable wordlists
- **🔑 Credential Testing**: Tests default credentials with intelligent false-positive detection
- **📊 Live HTML Reports**: Real-time HTML reports with interactive tables and collapsible sections
- **🎯 DNS Resolution**: Reverse DNS lookup for IP addresses
- **⚡ Performance Optimized**: Fast scanning with configurable threading and timeouts
- **🎨 Beautiful UI**: Colored console output with emojis and progress bars

## 📋 Requirements

- Python 3.8 or higher
- Windows, macOS, or Linux
- Internet connection for initial setup

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/web-discovery-scanner.git
cd web-discovery-scanner
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Install Playwright Browsers

```bash
playwright install chromium
```

### 4. Verify Installation

```bash
python web_discovery_scan.py --help
```

## 📖 Usage Examples

### Basic Usage

#### Scan a Single Target
```bash
python web_discovery_scan.py --input example.com --ports 80,443
```

#### Scan Multiple Targets
```bash
python web_discovery_scan.py --input 192.168.1.1,192.168.1.2 --ports 80,443,8080
```

#### Scan a Subnet
```bash
python web_discovery_scan.py --input 192.168.1.0/24 --ports 80,443
```

#### Scan from File
```bash
python web_discovery_scan.py --input-file targets.txt --ports 80,443
```

### Advanced Usage

#### Full Feature Scan
```bash
python web_discovery_scan.py \
  --input example.com \
  --ports 80,443,8080,8443 \
  --enable-fuzzing \
  --creds-check \
  --threads 10 \
  --timeout 10
```

#### Custom Wordlist for Path Fuzzing
```bash
python web_discovery_scan.py \
  --input example.com \
  --enable-fuzzing \
  --fuzz-wordlist custom_paths.txt
```

#### Disable Screenshots (Faster)
```bash
python web_discovery_scan.py \
  --input example.com \
  --no-screenshots
```

#### Custom Output Directory
```bash
python web_discovery_scan.py \
  --input example.com \
  --output my_scan_results
```

## 🔧 Command Line Options

### Input Options
- `--input`: Single IP/hostname/CIDR range
- `--input-file`: File containing targets (one per line)

### Port Configuration
- `--ports`: Comma-separated list of ports (default: 80,443,8080,8000,8443,8888,81,82,7000,9443)

### Performance Options
- `--threads`: Number of concurrent threads (default: 30)
- `--timeout`: Connection timeout in seconds (default: 5)

### Feature Flags
- `--enable-fuzzing`: Enable path fuzzing discovery
- `--fuzz-wordlist`: Custom wordlist file for path fuzzing
- `--creds-check`: Enable default credential testing
- `--creds-file`: Custom credentials file (username:password format)
- `--subdomain-enum`: Enable active subdomain enumeration (enabled by default)
- `--no-subdomain-enum`: Disable active subdomain enumeration
- `--no-recursive`: Disable recursive scanning of discovered subdomains

### Output Options
- `--output`: Output directory (default: outputs)
- `--no-screenshots`: Disable screenshot capture
- `--no-html`: Disable HTML report generation

## 📁 Output Structure

```
outputs/
├── report.html          # Interactive HTML report
├── found_web.csv        # CSV export of results
└── screenshots/         # Captured screenshots
    ├── target1_443_https.png
    ├── target2_80_http.png
    └── ...
```

## 📊 HTML Report Features

The generated HTML report includes:

- **📈 Summary Statistics**: Total services, HTTPS count, service types
- **🎯 Target Information**: Original scan targets and discovered subdomains
- **🔑 Credential Findings**: Default credentials discovered during scan
- **📋 Interactive Tables**: Sortable and searchable results
- **🖼️ Screenshot Gallery**: Click to enlarge screenshots
- **📄 Detailed Information**: Headers, cookies, certificates, discovered paths
- **🔍 Collapsible Sections**: Organized information display

## 🔍 Path Fuzzing

The tool includes a comprehensive default wordlist covering:

- **Admin Panels**: `/admin`, `/login`, `/auth`, `/management`
- **API Endpoints**: `/api`, `/api/v1`, `/api/v2`, `/rest`
- **Common Files**: `/robots.txt`, `/sitemap.xml`, `/.env`
- **Backup Files**: `/backup`, `/backups`, `/bak`, `/old`
- **Development**: `/dev`, `/test`, `/staging`, `/debug`

## 🔑 Credential Testing

Tests common default credentials:

- `admin:admin`
- `admin:password`
- `root:root`
- `user:user`
- `guest:guest`
- And more...

Uses intelligent detection to minimize false positives by comparing responses with and without credentials.

## 🛡️ Security Features

- **SSL Certificate Validation**: Checks expiry dates and validity
- **Server Information Disclosure**: Identifies exposed server banners
- **Missing Security Headers**: Detects common security misconfigurations
- **Default Credential Detection**: Tests for common weak credentials

## 📝 Example Output

```
======================================================================
🚀 WEB DISCOVERY SCANNER - ENHANCED VERSION
======================================================================
🔍 Features:
  🌐 Web service discovery and analysis
  🔐 SSL/TLS certificate validation
  📸 Automated screenshots
  🔗 Subdomain enumeration
  🔍 Path fuzzing and discovery
  📊 Live HTML reports
  🎯 CI/CD and lateral movement detection
======================================================================

🎯 Starting scan of 3 targets
🚀 Starting Web Discovery Scanner
📊 Targets: 3 | Ports: 1 | Total Tasks: 3
⏱️  Estimated time: 9s
⌨️  Press 's' to skip current website scan

🔍 Scanning: 100%|██████████| 3/3 [00:15<00:00, 5.12s/target:port]

✅ Scan completed!

============================================================
📊 SCAN SUMMARY
============================================================
✅ Total Services Found: 3
🔗 Subdomain Services: 1
🔐 HTTPS Services: 3

🔍 Service Types Found:
  🌐 Web: 3

💾 Results saved to: outputs
📄 HTML Report: outputs/report.html
📊 CSV Report: outputs/found_web.csv
============================================================
```

## 🚨 Important Notes

- **Legal Use Only**: This tool is for authorized security testing only
- **Rate Limiting**: Be respectful of target systems and implement appropriate delays
- **SSL Warnings**: The tool ignores SSL certificate errors for comprehensive scanning
- **Resource Usage**: Screenshot capture can be resource-intensive

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The authors are not responsible for any misuse of this tool.

## 🆘 Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: Check the inline help with `python web_discovery_scan.py --help`
- **Examples**: See the usage examples above

---

**Made with ❤️ for the security community** 