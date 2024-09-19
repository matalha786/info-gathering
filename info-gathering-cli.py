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
from gvm.transforms import EtreeTransform
from gvm.protocols.gmp import Gmp
import nmap
import json
import logging
import argparse
from lxml import EtreeTransform



# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class ReconTool:
    def __init__(self, targets, options, fast_scan=False):
        self.targets = targets
        self.options = options
        self.fast_scan = fast_scan
        self.nm = nmap.PortScanner()
        self.report = {
            "targets": [],
            "ports": {},
            "vulnerabilities": {},
            "os": {},
            "details": {
                "Target Specification": self.options.get("target_spec", ""),
                "Hostnames": self.options.get("hostnames", ""),
                "IP Addresses": self.options.get("ip_addresses", ""),
                "Networks": self.options.get("networks", ""),
                "Input File": self.options.get("input_file", ""),
                "Random Targets": self.options.get("random_targets", ""),
                "Exclude Hosts": self.options.get("exclude_hosts", ""),
                "Exclude File": self.options.get("exclude_file", ""),
                "Host Discovery": self.options.get("host_discovery", ""),
                "Scan Techniques": self.options.get("scan_techniques", ""),
                "Port Specification": self.options.get("ports", ""),
                "Exclude Ports": self.options.get("exclude_ports", ""),
                "Service Detection": self.options.get("service_detection", ""),
                "Version Detection": self.options.get("version_detection", ""),
                "Script Scan": self.options.get("script_scan", ""),
                "OS Detection": self.options.get("os_detection", ""),
                "Timing and Performance": self.options.get("timing_template", ""),
                "Firewall/IDS Evasion": self.options.get("firewall_evasion", ""),
                "Output": self.options.get("output_format", ""),
                "Miscellaneous": {
                    "IPv6": self.options.get("ipv6", ""),
                    "Data Directory": self.options.get("data_directory", ""),
                    "Raw Frames": self.options.get("raw_frames", ""),
                    "Privileged": self.options.get("privileged", ""),
                    "Unprivileged": self.options.get("unprivileged", ""),
                    "Version Number": self.options.get("version_number", ""),
                    "Help Summary": self.options.get("help_summary", "")
                }
            }
        }

    # Utility function to make requests
    def fetch_url(self, url):
        try:
            response = requests.get(url, verify=False)
            return response.text, response.status_code
        except requests.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return "", None

    def extract_ip(self, target):
        if re.match(r'^https?://', target):
            parsed_url = urllib.parse.urlparse(target)
            hostname = parsed_url.hostname
            return socket.gethostbyname(hostname)
        return target
    
    def parse_target_list(self):
        parsed_targets = []
        for target in self.targets:
            if re.match(r'^https?://', target):
                parsed_targets.append(self.extract_ip(target))
            else:
                parsed_targets.append(target)
        return parsed_targets

    def port_scan_nmap(self):
        logging.info("Starting Nmap scan...")
        print("Starting Nmap scan...")
        for target in self.parse_target_list():
            self.report["targets"].append(target)
            nmap_args = ""
            
            # Target Specification
            if "target_spec" in self.options:
                nmap_args += f"{self.options['target_spec']} "
            
            # Host Discovery
            if "host_discovery" in self.options:
                nmap_args += f"-s{self.options['host_discovery']} "
            
            # Scan Techniques
            if "scan_techniques" in self.options:
                nmap_args += f"-s{self.options['scan_techniques']} "
            
            # Port Specification
            if "ports" in self.options:
                nmap_args += f"-p {self.options['ports']} "
            
            # Exclude Ports
            if "exclude_ports" in self.options:
                nmap_args += f"--exclude-ports {self.options['exclude_ports']} "
            
            # Service/Version Detection
            if "version_detection" in self.options:
                nmap_args += f"-sV --version-intensity={self.options.get('version_intensity', 5)} "
            
            # Script Scan
            if "script_scan" in self.options:
                nmap_args += f"--script={self.options['script_scan']} "
            
            # OS Detection
            if "os_detection" in self.options:
                nmap_args += f"-O "
            
            # Timing and Performance
            if "timing_template" in self.options:
                nmap_args += f"-T{self.options['timing_template']} "
            
            # Firewall/IDS Evasion
            if "firewall_evasion" in self.options:
                nmap_args += f"{self.options['firewall_evasion']} "
            
            # Output
            if "output_format" in self.options:
                nmap_args += f"-o{self.options['output_format']} {self.options.get('output_file', 'nmap_scan')} "
            
            self.nm.scan(target, arguments=nmap_args.strip())
            for host in self.nm.all_hosts():
                self.report["ports"][host] = []
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        service = self.nm[host][proto][port]
                        self.report["ports"][host].append({
                            "port": port,
                            "name": service.get("name", "N/A"),
                            "product": service.get("product", "N/A"),
                            "version": service.get("version", "N/A"),
                            "extrainfo": service.get("extrainfo", "N/A"),
                            "state": service.get("state", "N/A")
                        })
                # OS Detection
                if "osclass" in self.nm[host]:
                    self.report["os"][host] = {
                        "os_name": self.nm[host]["osclass"][0].get("osfamily", "N/A"),
                        "os_version": self.nm[host]["osclass"][0].get("osgen", "N/A")
                    }
        logging.info("Nmap scan completed.")
        print("Nmap scan completed.")
    
    def port_scan_masscan(self):
        logging.info("Starting Masscan scan...")
        print("Starting Masscan scan...")
        rate = '1000' if not self.fast_scan else '10000'
        for target in self.parse_target_list():
            masscan_command = f"masscan {target} -p{self.options.get('masscan_ports', '1-65535')} --rate={rate}"
            result = subprocess.run(masscan_command.split(), capture_output=True, text=True)
            masscan_output = result.stdout
            
            for line in masscan_output.splitlines():
                if line.startswith("Discovered open port"):
                    parts = line.split()
                    port = parts[3]
                    ip = parts[5]
                    if ip not in self.report["ports"]:
                        self.report["ports"][ip] = []
                    self.report["ports"][ip].append({"port": port, "state": "open"})
        logging.info("Masscan scan completed.")
        print("Masscan scan completed.")
    
    def vulnerability_scan_openvas(self):
        logging.info("Starting OpenVAS scan...")
        print("Starting OpenVAS scan...")
        try:
            connection = TLSConnection(hostname='localhost')
            with Gmp(connection) as gmp:
                gmp.authenticate('admin', 'admin')  # Change these credentials as needed
                
                for target in self.parse_target_list():
                    target_id = gmp.create_target(name=target, hosts=[self.extract_ip(target)])['id']
                    task_id = gmp.create_task(name=f'Task for {target}', target_id=target_id, config_id='daba56c8-73ec-11df-a475-002264764cea')['id']
                    report_id = gmp.start_task(task_id)['report_id']
                    
                    status = 'Running'
                    while status == 'Running':
                        status = gmp.get_task_status(task_id)['status']
                    
                    report = gmp.get_report(report_id, transform=EtreeTransform())
                    vulnerabilities = []
                    for vuln in report.xpath('//report/item'):
                        vulnerabilities.append({
                            "name": vuln.find('name').text,
                            "description": vuln.find('description').text,
                            "solution": vuln.find('solution').text,
                            "severity": vuln.find('severity').text,
                            "cvss_score": vuln.find('cvss_base_score').text
                        })
                    self.report["vulnerabilities"].update({target: vulnerabilities})
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        logging.info("OpenVAS scan completed.")
        print("OpenVAS scan completed.")
    
    def get_title(self, url):
        data, _ = self.fetch_url(url)
        soup = BeautifulSoup(data, 'html.parser')
        title = soup.title.string if soup.title else "No Title Found"
        return title

    def detect_cms(self, url):
        data, _ = self.fetch_url(url)
        if '/wp-content/' in data:
            return "WordPress"
        elif 'Joomla' in data:
            return "Joomla"
        elif 'Drupal' in self.fetch_url(url + "/misc/drupal.js")[0]:
            return "Drupal"
        elif '/skin/frontend/' in data:
            return "Magento"
        elif 'content="WordPress' in data:
            return "WordPress"
        return "Could Not Detect"

    def check_robots_txt(self, url):
        robots_url = f"{url}/robots.txt"
        data, status_code = self.fetch_url(robots_url)
        if status_code == 200:
            if data.strip() == "":
                print("Found But Empty!")
            else:
                print("Found:\n", data)
        else:
            print("Could NOT Find robots.txt!")

    def get_http_headers(self, url):
        response = requests.head(url, verify=False)
        for header, value in response.headers.items():
            print(f"{header}: {value}")

    def extract_social_links(self, source_code):
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

    def detect_cloudflare(self, url):
        headers = requests.get(f"http://api.hackertarget.com/httpheaders/?q={url}", verify=False).text
        if 'cloudflare' in headers:
            print("Detected Cloudflare")
        else:
            print("Not Detected")

    def mx_lookup(self, domain):
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx_record in mx_records:
            mx_host = str(mx_record.exchange)
            mx_ip = socket.gethostbyname(mx_host)
            mx_hostname = socket.gethostbyaddr(mx_ip)[0]
            return f"IP: {mx_ip}, Hostname: {mx_hostname}"
        return "No MX records found"

    def get_alexa_rank(self, url):
        xml = requests.get(f"http://data.alexa.com/data?cli=10&url={url}").text
        soup = BeautifulSoup(xml, 'xml')
        popularity = soup.find('POPULARITY')
        if popularity:
            return popularity['TEXT']
        return "No Alexa rank available"

    def get_moz_info(self, url):
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

    def run_nmap_scan(self):
        logging.info("Running Nmap scan...")
        print("Running Nmap scan...")
        for target in self.parse_target_list():
            self.nm.scan(target, arguments='-p-')
            self.report["ports"][target] = []
            for proto in self.nm[target].all_protocols():
                lport = self.nm[target][proto].keys()
                for port in lport:
                    service = self.nm[target][proto][port]
                    self.report["ports"][target].append({
                        "port": port,
                        "name": service.get("name", "N/A"),
                        "product": service.get("product", "N/A"),
                        "version": service.get("version", "N/A"),
                        "extrainfo": service.get("extrainfo", "N/A"),
                        "state": service.get("state", "N/A")
                    })
            if "osclass" in self.nm[target]:
                self.report["os"][target] = {
                    "os_name": self.nm[target]["osclass"][0].get("osfamily", "N/A"),
                    "os_version": self.nm[target]["osclass"][0].get("osgen", "N/A")
                }
        logging.info("Nmap scan completed.")
        print("Nmap scan completed.")

    def run_masscan_scan(self):
        logging.info("Running Masscan scan...")
        print("Running Masscan scan...")
        try:
            result = subprocess.run(['masscan', ' '.join(self.parse_target_list()), '-p0-65535', '--rate=1000'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.startswith("Discovered open port"):
                    parts = line.split()
                    port = parts[3]
                    ip = parts[5]
                    if ip not in self.report["ports"]:
                        self.report["ports"][ip] = []
                    self.report["ports"][ip].append({"port": port, "state": "open"})
        except FileNotFoundError:
            print("Masscan is not installed or not found in the system path.")
        logging.info("Masscan scan completed.")
        print("Masscan scan completed.")

    def run_openvas_scan(self):
        logging.info("Running OpenVAS scan...")
        print("Running OpenVAS scan...")
        try:
            connection = TLSConnection(hostname='localhost', port=9390)
            gmp = Gmp(connection)
            gmp.authenticate(username='admin', password='admin')

            for target in self.parse_target_list():
                task = gmp.create_task(name='Scan Task', target=target)
                gmp.start_task(task.id)
                time.sleep(30)  # Wait for the task to complete
                results = gmp.get_results(task.id)
                self.report["vulnerabilities"][target] = []
                for result in results:
                    self.report["vulnerabilities"][target].append({
                        "name": result.get("name", "N/A"),
                        "description": result.get("description", "N/A"),
                        "solution": result.get("solution", "N/A"),
                        "severity": result.get("severity", "N/A"),
                        "cvss_score": result.get("cvss_score", "N/A")
                    })
        except Exception as e:
            logging.error(f"OpenVAS error: {e}")
        logging.info("OpenVAS scan completed.")
        print("OpenVAS scan completed.")

def main():
    parser = argparse.ArgumentParser(description='Recon Tool for Scanning and Information Gathering.')
    parser.add_argument('targets', nargs='+', help='List of target URLs or IPs')
    parser.add_argument('--config', type=str, default='config.ini', help='Path to the configuration file')
    parser.add_argument('--fast-scan', action='store_true', help='Enable fast scanning for Masscan')
    args = parser.parse_args()

    # Load configuration
    config = configparser.ConfigParser()
    config.read(args.config)
    options = {key: value for key, value in config.items('DEFAULT')}

    recon_tool = ReconTool(targets=args.targets, options=options, fast_scan=args.fast_scan)
    
    # Information Gathering
    for target in args.targets:
        print(f"Target: {target}")
        print("Title:", recon_tool.get_title(target))
        print("CMS Detection:", recon_tool.detect_cms(target))
        recon_tool.check_robots_txt(target)
        recon_tool.get_http_headers(target)
        
        source_code, _ = recon_tool.fetch_url(target)
        social_links = recon_tool.extract_social_links(source_code)
        for platform, links in social_links.items():
            print(f"Social Links ({platform}): {', '.join(links)}")
        
        recon_tool.detect_cloudflare(target)
        print(recon_tool.mx_lookup(recon_tool.extract_ip(target)))
        print("Alexa Rank:", recon_tool.get_alexa_rank(target))
        print(recon_tool.get_moz_info(target))

    # Port Scanning
    recon_tool.run_nmap_scan()
    recon_tool.run_masscan_scan()
    
    # Vulnerability Scanning
    recon_tool.run_openvas_scan()

if __name__ == "__main__":
    main()
