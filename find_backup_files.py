import requests
import re
import sys
import argparse
import concurrent.futures
import colorama
import time
import os
import json
from tqdm import tqdm
from urllib.parse import urljoin
import socket
import dns.resolver
import traceback
import hashlib

colorama.init()

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
HEADERS = {'User-Agent': USER_AGENT}

def crawl_homepage(domain):
    try:
        response = requests.get(f"http://{domain}", headers=HEADERS, timeout=10)
        response.raise_for_status()
        content = response.text
        backup_files = re.findall(r'href=["\']?([^"\'>]*?\.(?:bak|zip|tar\.gz|sql\.backup|backup|save|orig|swp|rar|7z|gz))["\']?', content)
        return [urljoin(f"http://{domain}", file) for file in backup_files]
    except requests.exceptions.RequestException as e:
        print(f"{colorama.Fore.RED}Error crawling homepage: {e}{colorama.Style.RESET_ALL}")
        return []

def heuristic_scoring(url, content):
    score = 0
    if ".sql" in url or "database" in content.lower():
        score += 5
    if ".bak" in url or "backup" in url:
        score += 3
    if "password" in content.lower() or "secret" in content.lower():
        score += 4
    return score

BACKUP_EXTENSIONS = [
    ".bak", ".old", ".tmp", ".zip", ".tar.gz", ".sql.backup", ".backup", ".save", ".orig", ".swp",
    ".rar", ".7z", ".gz", "~", ".swp", ".tar", ".tar.bz2", ".bak1", ".backup.sql", ".bck", ".dat",
    ".sql", ".db", ".sqlite", ".mdb", ".Access", ".log", ".txt", ".conf", ".ini", ".yaml", ".yml",
    ".json", ".xml", ".csv", ".xls", ".xlsx", ".docx", ".doc", ".rtf", ".odt", ".wpd", ".psd", ".ai",
    ".indd", ".ppt", ".pptx", ".key", ".pdf", ".js", ".css", ".html", ".htm", ".php", ".aspx", ".jsp",
    ".py", ".rb", ".java", ".class", ".jar", ".war", ".ear", ".dll", ".exe", ".sh", ".bat", ".ps1"
]
UNREFERENCED_PATHS = [
    ".git/", ".svn/", "WEB-INF/web.xml", "config.php.dist", "CHANGELOG.txt", ".env", "backup/", "backups/", "db_dumps/",
    "readme.txt", "install.txt", "config.ini", "application.yml", "database.sql", "dump.sql", "wp-config.php",
    "server.conf", ".htaccess", ".htpasswd", "error_log", "access_log",
    "/aws.bak", ".s3cfg", ".azure-pipelines.yml", "firebase.json",
    "index.php~", ".index.php.swp", ".DS_Store", ".project", ".idea/", "Thumbs.db",
    ".gitlab-ci.yml", ".travis.yml", ".circleci/config.yml"
]

def get_wayback_urls(domain):
    wayback_url = f"http://archive.org/wayback/available?url={domain}"
    try:
        response = requests.get(wayback_url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        if data and data["archived_snapshots"]:
            return [data["archived_snapshots"]["closest"]["url"]]
        else:
            return []
    except requests.exceptions.RequestException as e:
        print(f"{colorama.Fore.RED}Error querying Wayback Machine: {e}{colorama.Style.RESET_ALL}")
        return []

def is_waf_blocked(url, waf_string):
    try:
        response = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        if waf_string in response.text:
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        return False

def is_custom_404(url):
    """
    Enhanced custom 404 detection using multiple methods:
    1. Content hash comparison
    2. Content length analysis
    3. Common error patterns
    4. Title comparison
    """
    try:
        # Test with multiple random strings
        random_paths = [
            "/404_test_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
            "/not_found_" + hashlib.md5(str(time.time() + 1).encode()).hexdigest()[:8],
            "/error_page_" + hashlib.md5(str(time.time() + 2).encode()).hexdigest()[:8]
        ]
        
        responses = []
        content_lengths = []
        content_hashes = []
        titles = []
        
        for path in random_paths:
            test_url = url.rstrip('/') + path
            response = requests.get(test_url, headers=HEADERS, timeout=10)
            responses.append(response)
            content_lengths.append(len(response.content))
            content_hashes.append(hashlib.sha256(response.content).hexdigest())
            
            # Extract title if HTML
            title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
            titles.append(title_match.group(1) if title_match else '')

        # Check if it's a wildcard response (all responses are identical)
        if len(set(content_hashes)) == 1:
            return True

        # Check if content lengths are similar (within 10% variance)
        length_variance = max(content_lengths) - min(content_lengths)
        if length_variance <= min(content_lengths) * 0.1:
            return True

        # Check if titles are identical and contain error-related terms
        error_patterns = ['404', 'not found', 'error', 'does not exist', 'missing']
        if len(set(titles)) == 1 and any(pattern in titles[0].lower() for pattern in error_patterns):
            return True

        # Check for common custom 404 patterns in content
        error_indicators = [
            'page not found',
            'file not found',
            '404',
            'error',
            'does not exist',
            'could not be found',
            'not available',
            'no longer available'
        ]
        
        content_lower = responses[0].text.lower()
        if any(indicator in content_lower for indicator in error_indicators):
            # Verify if this pattern appears in all responses
            if all(all(indicator in r.text.lower() for indicator in error_indicators) for r in responses):
                return True

        return False

    except requests.exceptions.RequestException:
        return False

STATUS_CODES_TO_CHECK = [200, 403, 401]  # User can customize this

def check_url(url, output_file, status_codes_filter, keywords, loot_directory, delay, waf_string):
    start_time = time.time()
    try:
        # HEAD request optimization
        try:
            head_response = requests.head(url, headers=HEADERS, timeout=10, allow_redirects=True)
            if head_response.status_code in status_codes_filter:
                response = head_response  # Use HEAD response if it's successful
            else:
                response = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        except requests.exceptions.RequestException:
            response = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)

        time.sleep(delay)  # Rate limiting

        if is_waf_blocked(url, waf_string):
            print(f"{colorama.Fore.RED}WAF Blocked: {url}{colorama.Style.RESET_ALL}")
            return None

        if response.history:
            print(f"{colorama.Fore.MAGENTA}Redirected to: {response.url} from {url}{colorama.Style.RESET_ALL}")

        if response.status_code in status_codes_filter:
            base_url = url.rsplit('/', 1)[0]
            if is_custom_404(base_url):
                if args.verbose:
                    print(f"{colorama.Fore.YELLOW}Detected custom 404 page: {url}{colorama.Style.RESET_ALL}")
                return None

            status_color = colorama.Fore.GREEN if response.status_code == 200 else colorama.Fore.YELLOW
            output = f"{status_color}Status {response.status_code}: {url}{colorama.Style.RESET_ALL}"

            # Directory Listing Detection
            if "Index of /" in response.text:
                output += f" {colorama.Fore.YELLOW}[Directory Listing]{colorama.Style.RESET_ALL}"

            # File Content Indicators
            content = response.text
            for keyword in keywords:
                if keyword.lower() in content.lower():
                    output += f" {colorama.Fore.RED}[Keyword: {keyword}]{colorama.Style.RESET_ALL}"
                    break  # Only show one keyword match
            
            # Heuristic Scoring
            try:
                score = heuristic_scoring(url, content)
                output += f" {colorama.Fore.MAGENTA}[Score: {score}]{colorama.Style.RESET_ALL}"
            except Exception:
                output += f" {colorama.Fore.MAGENTA}[Score: N/A]{colorama.Style.RESET_ALL}"

            # Download Discovered Files
            if loot_directory and response.status_code == 200:
                filename = os.path.basename(url)
                filepath = os.path.join(loot_directory, filename)
                try:
                    with open(filepath, "wb") as f:
                        f.write(response.content)
                    output += f" {colorama.Fore.GREEN}[Downloaded to: {filepath}]{colorama.Style.RESET_ALL}"
                except Exception as e:
                    output += f" {colorama.Fore.RED}[Error downloading: {e}]{colorama.Style.RESET_ALL}"

            end_time = time.time()
            elapsed_time = end_time - start_time
            output += f" {colorama.Fore.CYAN}[Time: {elapsed_time:.2f}s]{colorama.Style.RESET_ALL}"

            print(output)
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"Status {response.status_code}: {url}\n")
            return url if response.status_code == 200 else None
        elif args.verbose:
            print(f"{colorama.Fore.BLUE}Status {response.status_code}: {url}{colorama.Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        end_time = time.time()
        elapsed_time = end_time - start_time
        if args.verbose:
            print(f"{colorama.Fore.RED}Error checking {url}: {e} [Time: {elapsed_time:.2f}s]{colorama.Style.RESET_ALL}")
    return None

def main(domain, output_file, status_codes_filter, concurrency, json_output, subdomains):
    # Handle Wildcard Domains / Virtual Hosts
    domains = [domain]
    try:
        if subdomains:
            resolver = dns.resolver.Resolver()
            subdomain_list = [s.strip() + "." + domain for s in subdomains.split(",")]
            for subdomain in subdomain_list:
                try:
                    resolver.resolve(subdomain)
                    print(f"{colorama.Fore.GREEN}Subdomain found: {subdomain}{colorama.Style.RESET_ALL}")
                    domains.append(subdomain)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    print(f"{colorama.Fore.RED}Subdomain not found: {subdomain}{colorama.Style.RESET_ALL}")
    except Exception as e:
        print(f"{colorama.Fore.RED}Error resolving subdomains: {e}{colorama.Style.RESET_ALL}")
    except Exception as e:
        print(f"{colorama.Fore.RED}Error during subdomain handling: {e}{colorama.Style.RESET_ALL}")

    potential_files = []

    # Crawler Integration
    try:
        homepage_files = crawl_homepage(domain)
        potential_files.extend(homepage_files)
    except Exception as e:
        print(f"{colorama.Fore.RED}Error during crawling: {e}{colorama.Style.RESET_ALL}")

    for ext in BACKUP_EXTENSIONS:
        potential_files.extend([
            f"/.index{ext}", f"/index{ext}", f"/backup{ext}", f"/{domain}{ext}",
            f"/{domain}.com{ext}", f"/{domain}.net{ext}", f"/{domain}.org{ext}",
            f"/{domain}-backup{ext}", f"/db_backup{ext}", f"/sql_backup{ext}"
        ])
    for path in UNREFERENCED_PATHS:
        potential_files.append(f"/{path}")

    # Wayback Machine integration
    wayback_urls = get_wayback_urls(domain)
    for url in wayback_urls:
        potential_files.append(url.replace("http://", "/").replace("https://", "/"))

    all_urls = []
    for dom in domains:
        schemes = ["http", "https"]
        for file_path in potential_files:
            all_urls.append(f"{scheme}://{dom}{file_path}")

    found_files = []

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        keywords = [k.strip() for k in args.keywords.split(",")]
        loot_directory = args.loot_directory
        delay = args.delay
        waf_string = args.waf_string

        if loot_directory:
            os.makedirs(loot_directory, exist_ok=True)  # Create directory if it doesn't exist

        with tqdm(total=len(all_urls), desc="Scanning", unit="url") as pbar:
            future_to_url = {}
            for url in all_urls:
                future = executor.submit(check_url, url, output_file, status_codes_filter, keywords, loot_directory, delay, waf_string)
                future_to_url[future] = url
                pbar.update(1)

        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                data = future.result()
                if data:
                    found_files.append(data)
                    results.append({"url": url, "status": "found", "score": heuristic_scoring(url, data)})
                else:
                    results.append({"url": url, "status": "not_found", "score": 0})
            except Exception as exc:
                print(f"{colorama.Fore.RED}url generated an exception: {exc}{colorama.Style.RESET_ALL}")
                results.append({"url": url, "status": "error", "exception": str(exc), "score": 0})

    if found_files:
        print(f"\n{colorama.Fore.CYAN}Potential backup/unreferenced files found:{colorama.Style.RESET_ALL}")
        for file in found_files:
            print(file)
    else:
        print(f"\n{colorama.Fore.GREEN}No potential backup/unreferenced files found.{colorama.Style.RESET_ALL}")

    # JSON Report Output
    if json_output:
        with open(json_output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"\n{colorama.Fore.CYAN}Results exported to JSON: {json_output}{colorama.Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for backup and unreferenced files on a domain.")
    parser.add_argument("domain", help="Domain to check")
    parser.add_argument("-o", "--output", help="Output file to write found URLs")
    parser.add_argument("-s", "--status-codes", default="200", help="Comma-separated status codes to filter (default: 200,403,200-404)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrency level (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-k", "--keywords", default="SQL,CREATE TABLE,gzip,PK", help="Comma-separated keywords to search for in file content")
    parser.add_argument("-l", "--loot-directory", help="Directory to save downloaded files")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay in seconds between requests (default: 0)")
    parser.add_argument("-w", "--waf-string", default="", help="String to detect WAF blocking (default: empty)")
    parser.add_argument("-j", "--json-output", help="Output file for JSON report")
    parser.add_argument("--subdomains", default="", help="Comma-separated list of subdomain prefixes to check")

    args = parser.parse_args()

    status_codes_filter_list = []
    for code_range in args.status_codes.split(','):
        if '-' in code_range:
            start, end = map(int, code_range.split('-'))
            status_codes_filter_list.extend(range(start, end + 1))
        else:
            status_codes_filter_list.append(int(code_range))
    status_codes_filter = set(status_codes_filter_list)

    main(args.domain, args.output, status_codes_filter, args.concurrency, args.json_output, args.subdomains)
