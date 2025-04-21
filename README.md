# 🔍 Backup File Finder

🛡️ A Python tool to scan domains for backup files, unreferenced files, and potentially sensitive content.

## ✨ Features

- 🔬 Scans for common backup file extensions (.bak, .old, .tmp, etc.)
- 🔎 Checks for unreferenced paths (.git, .env, etc.)
- 🕰️ Integrates with Wayback Machine for historical URLs
- 🔑 Supports custom keyword searching in file content
- ⚡ Multi-threaded scanning with configurable concurrency
- 🛡️ WAF (Web Application Firewall) detection
- 🎯 Custom 404 page detection
- 📂 Directory listing detection
- ⭐ File content scoring system
- 📊 JSON report generation
- 🌐 Subdomain scanning support

## 📥 Installation

```bash
pip install -r requirements.txt
```

📦 Required packages:
- 🌐 requests
- 🎨 colorama
- 📊 tqdm
- 🔍 dnspython

## 🚀 Usage

Basic usage:
```bash
python find_backup_files.py example.com
```

⚡ Advanced usage with options:
```bash
python find_backup_files.py example.com \
    -o output.txt \
    -s "200,403,401" \
    -c 20 \
    -v \
    -k "password,secret,database" \
    -l downloads \
    -d 0.5 \
    -w "blocked" \
    -j report.json \
    --subdomains "dev,staging,test"
```

### 🛠️ Arguments

- 🌐 `domain`: Target domain to scan
- 📝 `-o, --output`: Output file to write found URLs
- 🔢 `-s, --status-codes`: Comma-separated status codes to filter (default: 200,403,200-404)
- ⚡ `-c, --concurrency`: Number of concurrent threads (default: 10)
- 📢 `-v, --verbose`: Enable verbose output
- 🔑 `-k, --keywords`: Comma-separated keywords to search in content
- 📂 `-l, --loot-directory`: Directory to save downloaded files
- ⏰ `-d, --delay`: Delay between requests in seconds (default: 0)
- 🛡️ `-w, --waf-string`: String to detect WAF blocking
- 📊 `-j, --json-output`: JSON report output file
- 🔍 `--subdomains`: Comma-separated list of subdomain prefixes to check

## 🎯 10 Example Use Cases

### 1. 🔒 Basic Security Scan
```bash
python find_backup_files.py target.com -o basic_scan.txt
```
Performs a standard security assessment with default settings, saving results to file.

### 2. 🚀 High-Speed Corporate Scan
```bash
python find_backup_files.py company.com \
    -c 50 \
    -s "200,403,401" \
    --subdomains "dev,staging,test,prod" \
    -j report.json
```
Fast multi-threaded scan of corporate environments with JSON reporting.

### 3. 🕵️ Stealth Mode Scan
```bash
python find_backup_files.py sensitive-target.com \
    -d 2.0 \
    -c 5 \
    -w "blocked,forbidden" \
    -v
```
Slow, careful scanning to avoid detection with WAF monitoring.

### 4. 📊 Database Backup Hunt
```bash
python find_backup_files.py db.target.com \
    -k "mysql,dump,backup,sql,database" \
    -s "200" \
    -l database_files
```
Specifically searching for exposed database backups and dumps.

### 5. 🌐 Full Domain Analysis
```bash
python find_backup_files.py main-site.com \
    -o full_analysis.txt \
    -s "200-499" \
    -c 30 \
    -k "password,token,secret,key" \
    --subdomains "www,api,admin,portal" \
    -j full_report.json
```
Comprehensive domain analysis including all subdomains.

### 6. 🔍 Development Environment Check
```bash
python find_backup_files.py dev.company.com \
    -k "DEBUG,test,beta,staging" \
    -l dev_files \
    -v
```
Focusing on development environment exposures.

### 7. 📁 Git Repository Search
```bash
python find_backup_files.py code.target.com \
    -k ".git,config,HEAD,index" \
    -s "200,403" \
    -l git_files
```
Searching for exposed Git repositories and configuration.

### 8. ⚡ Quick Vulnerability Assessment
```bash
python find_backup_files.py quick-check.com \
    -c 100 \
    -s "200" \
    --subdomains "dev,staging" \
    -o quick_results.txt
```
Rapid assessment with maximum threads for initial testing.

### 9. 🔐 WordPress Site Audit
```bash
python find_backup_files.py wordpress-site.com \
    -k "wp-config,wp-content,backup,admin" \
    -l wordpress_files \
    -d 1.0 \
    -v
```
Specialized scan for WordPress installations.

### 10. 🛡️ WAF Testing Mode
```bash
python find_backup_files.py secured-site.com \
    -w "blocked,waf,protection" \
    -s "403,406,429,502" \
    -d 1.5 \
    -v \
    -o waf_analysis.txt
```
Testing and analyzing WAF responses and protection mechanisms.

## ⚠️ Note

🚨 Use responsibly and only on domains you have permission to test. The tool is meant for security research and penetration testing purposes.
