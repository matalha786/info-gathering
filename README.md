# info-gathering
It is a comprehensive network reconnaissance and vulnerability scanning tool designed to streamline the process of gathering information about targets, performing port scanning, vulnerability scanning, and retrieving relevant data about the target network or website.

## Features
- **Nmap Scan**: Perform detailed Nmap scans, including port scanning, OS detection, service and version detection, and firewall/IDS evasion.
- **Masscan**: Fast network-wide port scanning using Masscan.
- **OpenVAS Scan**: Vulnerability scanning using OpenVAS with detailed vulnerability reporting.
- **URL Reconnaissance**: Detect CMS platforms, HTTP headers, social media links, Cloudflare protection, and Alexa ranking.
- **DNS and MX Lookup**: Perform DNS and MX record lookups for target domains.
- **SEO Metrics**: Fetch Moz metrics such as Domain Authority and Page Authority.
- **Detailed Reporting**: Gather detailed reports including open ports, OS details, and vulnerabilities.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/matalha786/info-gathering
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Ensure you have **Nmap**, **Masscan**, and **OpenVAS** installed and available in your system's PATH.

4. Modify any configuration parameters such as OpenVAS credentials in the code where required.

## Usage

### Command-Line Interface

The `ReconTool` provides various methods to perform reconnaissance and vulnerability scanning. Here's a quick overview of its core functionalities.

#### Basic Nmap Scan

```python
from recon_tool import ReconTool

targets = ["example.com", "192.168.1.1"]
options = {"ports": "80,443", "version_detection": True}

tool = ReconTool(targets, options)
tool.port_scan_nmap()
```

#### Masscan Scan

```python
tool.port_scan_masscan()
```

#### OpenVAS Vulnerability Scan

```python
tool.vulnerability_scan_openvas()
```

#### CMS Detection and HTTP Header Analysis

```python
url = "http://example.com"
cms = tool.detect_cms(url)
headers = tool.get_http_headers(url)
```

### Available Scanning Options
- **Target Specification**: Specify target hostnames, IP addresses, or networks.
- **Port Specification**: Define specific ports to scan.
- **OS and Version Detection**: Enable OS detection and version detection for services.
- **Firewall/IDS Evasion**: Evade firewalls or IDS systems during scanning.
- **Output Formats**: Output scan results in various formats (e.g., XML, JSON).
- **Timing and Performance**: Set Nmap timing templates (e.g., `-T4` for faster scans).
  
### Example Execution

```bash
python recon_tool.py --targets example.com --ports 80,443 --version-detection --os-detection
```

## Logging and Output

- Logging is enabled to help track the execution of the scans. Logs are saved in the following format:

  ```plaintext
  YYYY-MM-DD HH:MM:SS,LEVEL, Message
  ```

- Scan results are stored in a structured dictionary format, which can be easily converted to JSON for reporting.

## Requirements
- **Python 3.x**
- **Requests**
- **BeautifulSoup**
- **Nmap**
- **Masscan**
- **OpenVAS**
- **lxml**
- **dnspython**

Install required dependencies via:

```bash
pip install -r requirements.txt
```

## Contributing

1. Fork the repository.
2. Create a new feature branch.
3. Submit a pull request detailing your changes.

## License

This project is licensed under the GLP License.

