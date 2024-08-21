import requests
from bs4 import BeautifulSoup
import re
import socket
import ssl
import subprocess
import configparser
import base64
import hmac
import hashlib
import urllib.parse
import time
import dns.resolver
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp

# Utility function to make requests
def fetch_url(url):
    try:
        response = requests.get(url, verify=False)
        return response.text, response.status_code
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return "", None

# Function to get title
def get_title(url):
    data, _ = fetch_url(url)
    soup = BeautifulSoup(data, 'html.parser')
    title = soup.title.string if soup.title else "No Title Found"
    return title

# Function to detect CMS
def detect_cms(url):
    data, _ = fetch_url(url)
    if '/wp-content/' in data:
        return "WordPress"
    elif 'Joomla' in data:
        return "Joomla"
    elif 'Drupal' in fetch_url(url + "/misc/drupal.js")[0]:
        return "Drupal"
    elif '/skin/frontend/' in data:
        return "Magento"
    elif 'content="WordPress' in data:
        return "WordPress"
    return "Could Not Detect"

# Function to check robots.txt
def check_robots_txt(url):
    robots_url = f"{url}/robots.txt"
    data, status_code = fetch_url(robots_url)
    if status_code == 200:
        if data.strip() == "":
            print("Found But Empty!")
        else:
            print("Found:\n", data)
    else:
        print("Could NOT Find robots.txt!")

# Function to get HTTP headers
def get_http_headers(url):
    response = requests.head(url, verify=False)
    for header, value in response.headers.items():
        print(f"{header}: {value}")

# Function to extract social links
def extract_social_links(source_code):
    soup = BeautifulSoup(source_code, 'html.parser')
    links = soup.find_all('a', href=True)
    
    social_links = {
        'facebook': [],
        'twitter': [],
        'instagram': [],
        'youtube': [],
        'google_plus': [],
        'pinterest': [],
        'github': []
    }
    
    for link in links:
        href = link['href']
        if 'facebook.com/' in href:
            social_links['facebook'].append(href)
        elif 'twitter.com/' in href:
            social_links['twitter'].append(href)
        elif 'instagram.com/' in href:
            social_links['instagram'].append(href)
        elif 'youtube.com/' in href:
            social_links['youtube'].append(href)
        elif 'plus.google.com/' in href:
            social_links['google_plus'].append(href)
        elif 'github.com/' in href:
            social_links['github'].append(href)
        elif 'pinterest.com/' in href:
            social_links['pinterest'].append(href)

    return social_links

# Function to detect Cloudflare
def detect_cloudflare(url):
    headers = requests.get(f"http://api.hackertarget.com/httpheaders/?q={url}", verify=False).text
    if 'cloudflare' in headers:
        print("Detected Cloudflare")
    else:
        print("Not Detected")

# Function to get MX record
def mx_lookup(domain):
    mx_records = dns.resolver.resolve(domain, 'MX')
    for mx_record in mx_records:
        mx_host = str(mx_record.exchange)
        mx_ip = socket.gethostbyname(mx_host)
        mx_hostname = socket.gethostbyaddr(mx_ip)[0]
        return f"IP: {mx_ip}, Hostname: {mx_hostname}"
    return "No MX records found"

# Function to get Alexa rank
def get_alexa_rank(url):
    xml = requests.get(f"http://data.alexa.com/data?cli=10&url={url}").text
    soup = BeautifulSoup(xml, 'xml')
    popularity = soup.find('POPULARITY')
    if popularity:
        return popularity['TEXT']
    return "No Alexa rank available"

# Function to get MOZ info
def get_moz_info(url):
    config = configparser.ConfigParser()
    config.read('config.ini')
    access_id = config['MOZ']['AccessID']
    secret_key = config['MOZ']['SecretKey']

    expires = int(time.time()) + 300
    string_to_sign = f"{access_id}\n{expires}"
    binary_signature = hmac.new(secret_key.encode(), string_to_sign.encode(), hashlib.sha1).digest()
    signature = base64.b64encode(binary_signature).decode()
    
    url_encoded = urllib.parse.quote_plus(url)
    request_url = f"http://lsapi.seomoz.com/linkscape/url-metrics/{url_encoded}?Cols=103079231492&AccessID={access_id}&Expires={expires}&Signature={signature}"
    
    response = requests.get(request_url)
    if response.ok:
        data = response.json()
        return f"Moz Rank: {data['umrp']}, Domain Authority: {data['pda']}, Page Authority: {data['upa']}"
    else:
        return "Failed to get MOZ info"

# Function to run Nmap scan
def run_nmap_scan(target):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-p-')
    return nm.csv()

# Function to run Masscan scan
def run_masscan_scan(target):
    try:
        result = subprocess.run(['masscan', target, '-p0-65535', '--rate=1000'], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "Masscan is not installed or not found in the system path."

# Function to run OpenVAS scan
def run_openvas_scan(target):
    try:
        connection = TLSConnection(hostname='localhost', port=9390)
        gmp = Gmp(connection)
        gmp.authenticate(username='admin', password='admin')

        # Create a new task
        task = gmp.create_task(name='Scan Task', target=target)

        # Start the task
        gmp.start_task(task.id)

        # Wait for the task to complete
        time.sleep(30)  # Adjust as needed

        # Retrieve the results
        results = gmp.get_results(task.id)
        return results
    except Exception as e:
        return f"OpenVAS error: {e}"

# Main function
if __name__ == "__main__":
    target_url = input("Enter the target URL: ").strip()

    # Information Gathering
    print("Title:", get_title(target_url))
    print("CMS Detection:", detect_cms(target_url))
    check_robots_txt(target_url)
    get_http_headers(target_url)
    
    source_code, _ = fetch_url(target_url)
    social_links = extract_social_links(source_code)
    for platform, links in social_links.items():
        print(f"Social Links ({platform}): {', '.join(links)}")
    
    detect_cloudflare(target_url)
    print(mx_lookup(socket.gethostbyname(target_url)))
    print("Alexa Rank:", get_alexa_rank(target_url))
    print(get_moz_info(target_url))
    
    # Port Scanning
    print("Nmap Scan Results:\n", run_nmap_scan(target_url))
    print("Masscan Results:\n", run_masscan_scan(target_url))
    
    # Vulnerability Scanning
    print("OpenVAS Scan Results:\n", run_openvas_scan(target_url))
