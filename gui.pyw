#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox
import nmap
import subprocess
import re
import socket
import os
import logging
from urllib.parse import urlparse
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from fpdf import FPDF
import concurrent.futures
import threading
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ReconToolGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Recon Tool")
        self.geometry("800x600")
        self.create_widgets()
        self.running = False
        self.thread = None
        self.protocol("WM_DELETE_WINDOW", self.on_closing)  # Handle window close

    def create_widgets(self):
        # Configure grid rows and columns
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=3)
        self.rowconfigure(0, weight=0)
        self.rowconfigure(1, weight=0)
        self.rowconfigure(2, weight=0)
        self.rowconfigure(3, weight=0)
        self.rowconfigure(4, weight=1)
        self.rowconfigure(5, weight=0)

        # Target URL or IP
        self.target_label = tk.Label(self, text="Target URL or IP:")
        self.target_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.target_entry = tk.Entry(self, width=50)
        self.target_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W+tk.E)
        
        # Context Menu for Target Entry
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Cut", command=self.cut_text)
        self.context_menu.add_command(label="Copy", command=self.copy_text)
        self.context_menu.add_command(label="Paste", command=self.paste_text)
        self.context_menu.add_command(label="Select All", command=self.select_all_text)
        
        self.target_entry.bind("<Button-3>", self.show_context_menu)

        # Fast Scan Checkbox
        self.fast_scan_var = tk.BooleanVar()
        self.fast_scan_checkbox = tk.Checkbutton(self, text="Enable Fast Scan", variable=self.fast_scan_var)
        self.fast_scan_checkbox.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Start Scan Button
        self.start_button = tk.Button(self, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        
        # Stop Scan Button
        self.stop_button = tk.Button(self, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)

        # Progress Log
        self.progress_text = tk.Text(self, wrap='word')
        self.progress_text.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W+tk.E+tk.N+tk.S)
        
        # Progress Bar
        self.progress_bar = ttk.Progressbar(self, orient='horizontal', mode='indeterminate')
        self.progress_bar.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W+tk.E)

        # Debug Checkbox
        self.debug_var = tk.BooleanVar()
        self.debug_checkbox = tk.Checkbutton(self, text="Enable Debug Logging", variable=self.debug_var)
        self.debug_checkbox.grid(row=3, column=1, padx=10, pady=5, sticky=tk.W)

    def append_log(self, message):
        self.progress_text.insert(tk.END, message + '\n')
        self.progress_text.yview(tk.END)
    
    def start_scan(self):
        target = self.target_entry.get()
        fast_scan = self.fast_scan_var.get()
        debug_mode = self.debug_var.get()
        
        if not target:
            messagebox.showerror("Input Error", "Please enter a target URL or IP.")
            return
        
        # Set logging level
        logging.getLogger().setLevel(logging.DEBUG if debug_mode else logging.INFO)
        
        self.append_log(f"Starting scan for target: {target}")
        
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        self.tool = ReconTool(target, fast_scan)
        self.tool.set_log_function(self.append_log)
        self.tool.set_progress_function(self.update_progress)
        self.tool.set_stop_function(self.stop_scanning)
        self.tool.set_progress_bar(self.progress_bar)
        
        self.thread = threading.Thread(target=self.run_scans)
        self.thread.start()

    def run_scans(self):
        self.tool.run()
        self.stop_scan()

    def stop_scan(self):
        if self.running:
            self.append_log("Stopping scan...")
            self.running = False
            if self.thread:
                self.thread.join(timeout=10)  # Wait up to 10 seconds for the thread to stop
            self.progress_bar.stop()
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.append_log("Scan stopped.")

    def update_progress(self, message, progress=None):
        def update():
            self.append_log(message)
            if progress is not None:
                self.progress_bar['value'] = progress
            else:
                self.progress_bar.start()
                self.animate_progress_bar()
            self.update_idletasks()
        self.after(0, update)

    def animate_progress_bar(self):
        if not self.running:
            return
        
        current_value = self.progress_bar['value']
        if current_value < 100:
            self.progress_bar['value'] = (current_value + 1) % 100
        else:
            self.progress_bar['value'] = 0
        
        self.after(100, self.animate_progress_bar)

    def stop_scanning(self):
        self.running = False

    def on_closing(self):
        if self.running:
            if messagebox.askokcancel("Quit", "The scan is still running. Are you sure you want to quit?"):
                self.stop_scan()
                self.destroy()
        else:
            self.destroy()

    def show_context_menu(self, event):
        self.context_menu.post(event.x_root, event.y_root)

    def cut_text(self):
        self.target_entry.event_generate('<<Cut>>')

    def copy_text(self):
        self.target_entry.event_generate('<<Copy>>')

    def paste_text(self):
        self.target_entry.event_generate('<<Paste>>')

    def select_all_text(self):
        self.target_entry.event_generate('<<SelectAll>>')

class ReconTool:
    def __init__(self, target, fast_scan=False):
        self.target = target
        self.ip = self.extract_ip(target)
        self.fast_scan = fast_scan
        self.nm = nmap.PortScanner()
        self.report = {"target": target, "ip": self.ip, "ports": {}, "vulnerabilities": {}}
        self.log_function = None
        self.progress_function = None
        self.stop_function = None
        self.progress_bar = None
        self.running = True
    
    def set_log_function(self, log_function):
        self.log_function = log_function
    
    def set_progress_function(self, progress_function):
        self.progress_function = progress_function
    
    def set_stop_function(self, stop_function):
        self.stop_function = stop_function

    def set_progress_bar(self, progress_bar):
        self.progress_bar = progress_bar

    def extract_ip(self, target):
        if re.match(r'^https?://', target):
            parsed_url = urlparse(target)
            hostname = parsed_url.hostname
            return socket.gethostbyname(hostname)
        return target
    
    def log(self, message):
        if self.log_function:
            self.log_function(message)
    
    def update_progress(self, message, progress=None):
        if self.progress_function:
            self.progress_function(message, progress)
    
    def stop_scanning(self):
        if self.stop_function:
            self.stop_function()
    
    def port_scan_nmap(self):
        if not self.running:
            return
        self.update_progress("Starting Nmap scan...", 0)
        nm = self.nm
        nm.scan(self.ip, arguments='-sS -sV')
        for host in nm.all_hosts():
            self.report["ports"][host] = []
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    service = nm[host][proto][port]
                    self.report["ports"][host].append({
                        "port": port,
                        "name": service.get("name", "N/A"),
                        "product": service.get("product", "N/A"),
                        "version": service.get("version", "N/A"),
                        "extrainfo": service.get("extrainfo", "N/A"),
                        "state": service.get("state", "N/A")
                    })
        self.update_progress("Nmap scan completed.", 100)
    
    def port_scan_masscan(self):
        if not self.running:
            return
        self.update_progress("Starting Masscan scan...", 0)
        rate = '1000' if not self.fast_scan else '10000'
        masscan_command = f"masscan {self.ip} -p1-65535 --rate={rate}"
        result = subprocess.run(masscan_command.split(), capture_output=True, text=True)
        masscan_output = result.stdout
        
        for line in masscan_output.splitlines():
            if not self.running:
                return
            if line.startswith("Discovered open port"):
                parts = line.split()
                port = parts[3]
                ip = parts[5]
                if ip not in self.report["ports"]:
                    self.report["ports"][ip] = []
                self.report["ports"][ip].append({"port": port, "state": "open"})
        self.update_progress("Masscan scan completed.", 100)
    
    def vulnerability_scan_openvas(self):
        if not self.running:
            return
        self.update_progress("Starting OpenVAS scan...", 0)
        try:
            connection = TLSConnection(hostname='localhost')
            with Gmp(connection) as gmp:
                gmp.authenticate('admin', 'admin')  # Change these credentials as needed
                
                target_id = gmp.create_target(name=self.target, hosts=[self.ip])['id']
                task_id = gmp.create_task(name=f'Task for {self.target}', target_id=target_id, config_id='daba56c8-73ec-11df-a475-002264764cea')['id']
                
                gmp.start_task(task_id)
                
                # Poll for task completion
                while True:
                    status = gmp.get_task(task_id)['status']
                    if status in ['Done', 'Failed']:
                        break
                    self.update_progress("OpenVAS scan in progress...", None)
                    time.sleep(10)
                
                results = gmp.get_results(task_id)
                self.report["vulnerabilities"] = results
        except Exception as e:
            self.log(f"OpenVAS scan failed: {str(e)}")
        self.update_progress("OpenVAS scan completed.", 100)
    
    def sanitize_filename(self, filename):
        return re.sub(r'[<>:"/\\|?*\x00-\x1F]', '_', filename)
    
    def generate_pdf_report(self):
        self.log("Generating PDF report...")
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Report Title
        pdf.cell(200, 10, txt=f"Scan Report for {self.report['target']}", ln=True, align="C")

        # Port Scanning Results
        for host, ports in self.report["ports"].items():
            pdf.cell(200, 10, txt=f"Host: {host}", ln=True, align="L")

            columns = ["Port", "State"]
            if any(port.get("name") for port in ports):
                columns.append("Service")
            if any(port.get("product") for port in ports):
                columns.append("Product")
            if any(port.get("version") for port in ports):
                columns.append("Version")

            pdf.set_fill_color(200, 220, 255)
            col_width = 0
            for col in columns:
                col_width = max(col_width, pdf.get_string_width(col))
            for col in columns:
                pdf.cell(col_width, 10, txt=col, border=1, fill=True)
            pdf.ln()

            for port in ports:
                pdf.cell(col_width, 10, txt=str(port.get("port", "N/A")), border=1)
                pdf.cell(col_width, 10, txt=port.get("state", "N/A"), border=1)
                if "Service" in columns:
                    pdf.cell(col_width, 10, txt=port.get("name", "N/A"), border=1)
                if "Product" in columns:
                    pdf.cell(col_width, 10, txt=port.get("product", "N/A"), border=1)
                if "Version" in columns:
                    pdf.cell(col_width, 10, txt=port.get("version", "N/A"), border=1)
                pdf.ln()

        # Vulnerability Scanning Results
        pdf.add_page()
        pdf.cell(200, 10, txt="Vulnerability Report", ln=True, align="C")

        if not self.report["vulnerabilities"]:
            pdf.cell(200, 10, txt="No vulnerabilities found.", ln=True, align="L")
        else:
            for item in self.report["vulnerabilities"]:
                pdf.cell(200, 10, txt=str(item), ln=True, align="L")

        # Ensure results directory exists
        result_folder = "results"
        if not os.path.exists(result_folder):
            os.makedirs(result_folder)

        # Sanitize filename
        base_filename = os.path.join(result_folder, f"{self.sanitize_filename(self.report['target'])}_report")
        filename = base_filename + ".pdf"
        counter = 1
        while os.path.exists(filename):
            filename = f"{base_filename}_{counter}.pdf"
            counter += 1

        pdf.output(filename)
        self.log(f"PDF report saved as {filename}")

    def run(self):
        # Print and log target and resolved IP
        self.log(f"Target URL: {self.target}")
        self.log(f"Resolved IP: {self.ip}")

        # Execute scans sequentially with progress tracking
        scans = [
            ("Nmap", self.port_scan_nmap),
            ("Masscan", self.port_scan_masscan),
            ("OpenVAS", self.vulnerability_scan_openvas)
        ]

        total_scans = len(scans)
        for i, (scan_name, scan_func) in enumerate(scans):
            if not self.running:
                self.log("Scan halted.")
                break
            progress = (i / total_scans) * 100
            self.update_progress(f"Starting {scan_name} scan...", progress)
            scan_func()
            self.update_progress(f"{scan_name} scan completed.", ((i + 1) / total_scans) * 100)

        self.generate_pdf_report()
        self.update_progress("All scans completed and report generated.", 100)
        self.stop_scanning()

if __name__ == "__main__":
    app = ReconToolGUI()
    app.mainloop()
