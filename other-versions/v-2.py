import nmap
import subprocess
import json
import re
import socket
import logging
import argparse
from urllib.parse import urlparse
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

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
    
    def extract_ip(self, target):
        if re.match(r'^https?://', target):
            parsed_url = urlparse(target)
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
    
    def sanitize_filename(self, filename):
        return ''.join(c for c in filename if c.isalnum() or c in (' ', '_', '-')).rstrip()
    
    def generate_text_report(self):
        logging.info("Generating text report...")
        print("Generating text report...")
        report_lines = []

        # Scan Details
        report_lines.append("Scan Details:")
        for section, details in self.report["details"].items():
            report_lines.append(f"{section}: {details}")
        report_lines.append("\n")

        # Port Scanning Results
        report_lines.append("Port Scanning Results:")
        for target in self.report["targets"]:
            report_lines.append(f"Target: {target}")
            if target in self.report["ports"]:
                ports = self.report["ports"][target]
                for port_info in ports:
                    report_lines.append(
                        f'    "port": {port_info["port"]}, "name": "{port_info["name"]}", "product": "{port_info["product"]}", '
                        f'"version": "{port_info["version"]}", "extrainfo": "{port_info["extrainfo"]}", "state": "{port_info["state"]}"'
                    )
            report_lines.append("\n")

        # OS Detection Results
        report_lines.append("OS Detection Results:")
        for target in self.report["os"]:
            os_info = self.report["os"][target]
            report_lines.append(f'Target: {target}\n    "os_name": "{os_info["os_name"]}", "os_version": "{os_info["os_version"]}"')
        report_lines.append("\n")

        # Vulnerability Scanning Results
        report_lines.append("Vulnerability Scanning Results:")
        for target, vulnerabilities in self.report["vulnerabilities"].items():
            report_lines.append(f"Target: {target}")
            for vuln in vulnerabilities:
                report_lines.append(
                    f'    "name": "{vuln["name"]}", "description": "{vuln["description"]}", "solution": "{vuln["solution"]}", '
                    f'"severity": "{vuln["severity"]}", "cvss_score": "{vuln["cvss_score"]}"'
                )
            report_lines.append("\n")

        # Save to file
        text_file = self.sanitize_filename("scan_report.txt")
        with open(text_file, 'w') as f:
            f.write("\n".join(report_lines))
        logging.info(f"Text report saved as {text_file}.")
        print(f"Text report saved as {text_file}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Recon Tool')
    parser.add_argument('-t', '--targets', metavar='T', type=str, nargs='+', required=True, help='List of targets (IP addresses or URLs)')
    parser.add_argument('-f', '--fast', action='store_true', help='Enable fast scan mode')
    parser.add_argument('--options', type=json.loads, default='{}', help='JSON string of scan options')
    args = parser.parse_args()
    
    recon_tool = ReconTool(targets=args.targets, options=args.options, fast_scan=args.fast)
    recon_tool.port_scan_nmap()
    recon_tool.port_scan_masscan()
    recon_tool.vulnerability_scan_openvas()
    recon_tool.generate_text_report()
