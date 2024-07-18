import requests
from bs4 import BeautifulSoup
import tldextract
import json

# Subdomain Enumeration
def get_subdomains(domain):
    subdomains = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        for entry in data:
            subdomain = entry['name_value'].split('\n')
            for sub in subdomain:
                if sub not in subdomains:
                    subdomains.append(sub)
    return subdomains

# Web Crawling
def crawl_url(url):
    urls = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and href.startswith('http'):
                urls.append(href)
    except requests.RequestException as e:
        print(f"Error crawling {url}: {e}")
    return urls

# SQL Injection Testing
def test_sql_injection(url):
    payloads = ["' OR '1'='1", "' OR '1'='1' --"]
    params = extract_params(url)
    vulnerable = False
    for param in params:
        for payload in payloads:
            test_params = params.copy()
            test_params[param] = payload
            try:
                response = requests.get(url, params=test_params)
                if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
                    print(f"Vulnerable: {url} with payload: {payload}")
                    vulnerable = True
                    break
            except requests.RequestException as e:
                print(f"Error testing {url}: {e}")
        if vulnerable:
            break
    return vulnerable

def extract_params(url):
    parsed_url = requests.utils.urlparse(url)
    query_params = requests.utils.parse_qs(parsed_url.query)
    return query_params

# Main function to run the tool
def main(domain):
    subdomains = get_subdomains(domain)
    all_urls = []

    # Crawl main domain and subdomains
    for subdomain in subdomains:
        urls = crawl_url(f"http://{subdomain}")
        all_urls.extend(urls)

    # Test each URL for SQL Injection
    for url in all_urls:
        if test_sql_injection(url):
            print(f"Vulnerable URL found: {url}")

if __name__ == "__main__":
    domain = input("Enter the domain to scan: ")
    main(domain)
