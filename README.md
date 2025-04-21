# Backup File Finder

A Python tool to scan domains for backup files, unreferenced files, and potentially sensitive content.

## Features

- Scans for common backup file extensions (.bak, .old, .tmp, etc.)
- Checks for unreferenced paths (.git, .env, etc.)
- Integrates with Wayback Machine for historical URLs
- Supports custom keyword searching in file content
- Multi-threaded scanning with configurable concurrency
- WAF (Web Application Firewall) detection
- Custom 404 page detection
- Directory listing detection
- File content scoring system
- JSON report generation
- Subdomain scanning support

## Installation

```bash
pip install -r requirements.txt
```

Required packages:
- requests
- colorama
- tqdm
- dnspython

## Usage

Basic usage:
```bash
python find_backup_files.py example.com
```

Advanced usage with options:
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

### Arguments

- `domain`: Target domain to scan
- `-o, --output`: Output file to write found URLs
- `-s, --status-codes`: Comma-separated status codes to filter (default: 200,403,200-404)
- `-c, --concurrency`: Number of concurrent threads (default: 10)
- `-v, --verbose`: Enable verbose output
- `-k, --keywords`: Comma-separated keywords to search in content (default: SQL,CREATE TABLE,gzip,PK)
- `-l, --loot-directory`: Directory to save downloaded files
- `-d, --delay`: Delay between requests in seconds (default: 0)
- `-w, --waf-string`: String to detect WAF blocking
- `-j, --json-output`: JSON report output file
- `--subdomains`: Comma-separated list of subdomain prefixes to check

## Example

```bash
python find_backup_files.py example.com -o results.txt -s "200,403" -k "password,api_key" -l downloads
```

This will:
1. Scan example.com for backup files
2. Save found URLs to results.txt
3. Only show responses with status codes 200 or 403
4. Look for "password" and "api_key" in file contents
5. Download found files to the "downloads" directory

## Note

Use responsibly and only on domains you have permission to test. The tool is meant for security research and penetration testing purposes.
