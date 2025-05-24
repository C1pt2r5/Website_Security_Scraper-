import requests
from bs4 import BeautifulSoup
import re
import urllib.parse

# --- Configuration ---
# User-Agent header to mimic a web browser. Some sites block requests without it.
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Common paths to check for admin panels or login pages
ADMIN_PATHS = [
    '/admin', '/administrator', '/login', '/wp-admin', '/dashboard',
    '/cpanel', '/phpmyadmin', '/webmail', '/user/login', '/panel'
]

# --- Helper Functions ---

def fetch_url_content(url):
    """
    Fetches the content of a given URL.
    Returns the response object if successful, None otherwise.
    """
    try:
        print(f"[*] Fetching: {url}")
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        return response
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching {url}: {e}")
        return None

def check_open_directory(response):
    """
    Checks if the response content indicates an open directory listing.
    Looks for common patterns like "Index of /" in the title or body.
    """
    if not response:
        return False

    soup = BeautifulSoup(response.text, 'html.parser')

    # Check title tag
    if soup.title and "index of /" in soup.title.get_text().lower():
        return True

    # Check for common directory listing elements (e.g., <pre>, <table>)
    # This is a heuristic and might have false positives/negatives
    if soup.find(string=re.compile(r"Index of /", re.IGNORECASE)) or \
       soup.find('pre', string=re.compile(r"Name\s+Last modified\s+Size\s+Description", re.IGNORECASE)):
        return True

    return False

def check_outdated_software(soup):
    """
    Attempts to identify signs of outdated software versions.
    This is highly heuristic and depends on common patterns.
    Examples: "Powered by WordPress X.Y.Z", specific meta tags.
    """
    findings = []

    # Check for generator meta tag (common for CMS like WordPress, Joomla, Drupal)
    meta_generator = soup.find('meta', attrs={'name': 'generator'})
    if meta_generator and 'content' in meta_generator.attrs:
        generator_info = meta_generator['content']
        findings.append(f"Potential software identified via meta tag: {generator_info}")

    # Check for common footer text patterns
    footer_text_patterns = [
        r"powered by (wordpress|joomla|drupal|magento) v?(\d+\.\d+(\.\d+)?(\.\d+)?)",
        r"version (\d+\.\d+(\.\d+)?(\.\d+)?)",
        r"apache/(\d+\.\d+(\.\d+)?)", # Check for server headers if available (less common in HTML)
    ]
    for pattern in footer_text_patterns:
        match = re.search(pattern, soup.get_text(), re.IGNORECASE)
        if match:
            findings.append(f"Potential software version found in text: {match.group(0)}")

    # Check for specific script/CSS file paths that might reveal versions
    for link in soup.find_all(['script', 'link']):
        src = link.get('src') or link.get('href')
        if src:
            # Example: /wp-includes/css/dashicons.min.css?ver=5.8.1
            match = re.search(r'ver=(\d+\.\d+(\.\d+)?)', src)
            if match:
                findings.append(f"Potential version parameter in resource URL: {src} (version: {match.group(1)})")

    return findings

def check_exposed_admin_panels(base_url):
    """
    Checks common admin panel paths for a given base URL.
    Returns a list of accessible admin panel URLs.
    """
    accessible_panels = []
    for path in ADMIN_PATHS:
        full_url = urllib.parse.urljoin(base_url, path)
        print(f"[*] Checking for admin panel: {full_url}")
        response = fetch_url_content(full_url)
        if response and response.status_code == 200:
            # A 200 OK status indicates the page exists.
            # Further analysis would be needed to confirm it's an actual login page.
            accessible_panels.append(full_url)
    return accessible_panels

# --- Main Scraper Function ---

def security_scan_website(target_url):
    """
    Performs a basic security scan on the target website.
    """
    print(f"\n--- Starting Security Scan for: {target_url} ---")
    results = {
        "target_url": target_url,
        "status": "Incomplete",
        "findings": {
            "open_directory": False,
            "outdated_software_indicators": [],
            "exposed_admin_panels": [],
            "general_info": []
        },
        "errors": []
    }

    # 1. Fetch the main page content
    main_response = fetch_url_content(target_url)
    if not main_response:
        results["errors"].append(f"Could not fetch main URL: {target_url}")
        results["status"] = "Failed"
        return results

    soup = BeautifulSoup(main_response.text, 'html.parser')
    results["findings"]["general_info"].append(f"Title: {soup.title.get_text() if soup.title else 'N/A'}")
    results["findings"]["general_info"].append(f"HTTP Status Code: {main_response.status_code}")

    # 2. Check for Open Directory on the main URL
    if check_open_directory(main_response):
        results["findings"]["open_directory"] = True
        results["findings"]["general_info"].append("Detected potential open directory listing on main URL.")

    # 3. Check for Outdated Software Indicators
    outdated_software_indicators = check_outdated_software(soup)
    if outdated_software_indicators:
        results["findings"]["outdated_software_indicators"].extend(outdated_software_indicators)

    # 4. Check for Exposed Admin Panels
    exposed_admin_panels = check_exposed_admin_panels(target_url)
    if exposed_admin_panels:
        results["findings"]["exposed_admin_panels"].extend(exposed_admin_panels)

    results["status"] = "Completed"
    return results

# --- Main Execution Block ---
if __name__ == "__main__":
    print("Welcome to the Basic Website Security Scraper!")
    print("Note: This is a simple tool for educational purposes and provides basic indicators.")
    print("It does not perform deep vulnerability scanning.")

    while True:
        url_input = input("\nEnter the URL to scan (e.g., https://example.com) or 'exit' to quit: ").strip()
        if url_input.lower() == 'exit':
            break
        if not url_input:
            print("Please enter a URL.")
            continue

        # Ensure the URL has a scheme
        if not (url_input.startswith('http://') or url_input.startswith('https://')):
            print("Warning: URL missing scheme (http:// or https://). Attempting with https://")
            url_input = "https://" + url_input

        scan_results = security_scan_website(url_input)

        print("\n--- Scan Results ---")
        print(f"Target URL: {scan_results['target_url']}")
        print(f"Scan Status: {scan_results['status']}")

        print("\n[+] General Information:")
        for info in scan_results['findings']['general_info']:
            print(f"    - {info}")

        print("\n[+] Potential Vulnerability Indicators:")
        if scan_results['findings']['open_directory']:
            print("    - **OPEN DIRECTORY DETECTED!** This could expose sensitive files.")
        else:
            print("    - No obvious open directory listing detected on main URL.")

        if scan_results['findings']['outdated_software_indicators']:
            print("    - **OUTDATED SOFTWARE INDICATORS FOUND:**")
            for indicator in scan_results['findings']['outdated_software_indicators']:
                print(f"        - {indicator}")
            print("      (Outdated software can lead to known vulnerabilities.)")
        else:
            print("    - No clear outdated software indicators found.")

        if scan_results['findings']['exposed_admin_panels']:
            print("    - **EXPOSED ADMIN PANELS/LOGIN PAGES FOUND:**")
            for panel_url in scan_results['findings']['exposed_admin_panels']:
                print(f"        - {panel_url}")
            print("      (Publicly accessible admin panels increase attack surface.)")
        else:
            print("    - No common admin panel paths found to be directly accessible.")

        if scan_results['errors']:
            print("\n[!] Errors during scan:")
            for error in scan_results['errors']:
                print(f"    - {error}")

        print("\n--- Scan Complete ---")
