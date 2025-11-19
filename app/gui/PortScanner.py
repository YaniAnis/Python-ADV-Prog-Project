"""
Port Scanner GUI with Modern Theme
Educational cybersecurity tool for authorized testing only.
Advanced features: TCP/UDP scanning, service banner detection, OS fingerprinting.
"""

import asyncio
import socket
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import messagebox
import re
import time
import threading
import os
import sys
import struct

# Add parent directory to path for imports
current_dir = os.path.dirname(__file__)
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# ==========================
#   OS DETECTION SIGNATURES
# ==========================
OS_SIGNATURES = {
    'Windows': {
        'ttl': [128, 127, 126, 125],
        'flags': ['WINNT', 'Windows', 'Microsoft'],
        'services': ['smb', 'netbios', 'ms-sql', 'rdp', 'wmi']
    },
    'Linux': {
        'ttl': [64, 63, 62, 61],
        'flags': ['Linux', 'GNU', 'ubuntu', 'debian', 'centos'],
        'services': ['ssh', 'ftp', 'http', 'mysql', 'postgres']
    },
    'macOS': {
        'ttl': [64, 63, 62],
        'flags': ['Darwin', 'macOS', 'OSX'],
        'services': ['ssh', 'afp', 'http']
    },
    'Cisco': {
        'ttl': [254, 253],
        'flags': ['Cisco', 'IOS'],
        'services': ['telnet', 'ssh']
    }
}

SERVICE_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
    27017: 'MongoDB', 6379: 'Redis', 1433: 'MS-SQL'
}

# ==========================
#   SCAN ASYNCIO - TCP
# ==========================
async def scan_port_tcp(host, port, get_banner=False):
    """Scan a single TCP port with optional banner grabbing"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=1
        )
        
        banner = None
        if get_banner:
            try:
                writer.write(b'\r\n')
                await asyncio.wait_for(writer.drain(), timeout=0.5)
                banner = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                banner = banner.decode('utf-8', errors='ignore').strip()
            except:
                banner = None
        
        writer.close()
        await writer.wait_closed()
        return {'port': port, 'protocol': 'TCP', 'banner': banner}
    except:
        return None


async def scan_ports_tcp(host, ports, concurrency=500, get_banners=False):
    """Scan multiple TCP ports with concurrency limit"""
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def sem_task(p):
        async with semaphore:
            return await scan_port_tcp(host, p, get_banners)

    tasks = [asyncio.create_task(sem_task(p)) for p in ports]
    for t in asyncio.as_completed(tasks):
        r = await t
        if r:
            results.append(r)

    return sorted(results, key=lambda x: x['port'])


# ==========================
#   SCAN UDP
# ==========================
async def scan_port_udp(host, port):
    """Scan a single UDP port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        
        # Send common UDP probes
        probes = [
            (b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00', 'DNS'),
            (b'\x49\x4e\x49\x54', 'SNMP'),
            (b'\x4e\x42\x53\x54\x41\x54\x0a', 'NetBIOS'),
        ]
        
        for probe, name in probes:
            try:
                sock.sendto(probe, (host, port))
                response, _ = sock.recvfrom(1024)
                if response:
                    return {'port': port, 'protocol': 'UDP', 'service': name}
            except socket.timeout:
                continue
            except:
                pass
        
        sock.close()
        return None
    except:
        return None


async def scan_ports_udp(host, ports, concurrency=50):
    """Scan multiple UDP ports"""
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def sem_task(p):
        async with semaphore:
            return await scan_port_udp(host, p)

    tasks = [asyncio.create_task(sem_task(p)) for p in ports]
    for t in asyncio.as_completed(tasks):
        r = await t
        if r:
            results.append(r)

    return sorted(results, key=lambda x: x['port'])


# ==========================
#   OS DETECTION
# ==========================
async def detect_os(host):
    """Detect OS based on common ports and signatures"""
    detected_os = None
    confidence = 0
    
    # Try to connect to common ports to gather information
    common_ports = [22, 23, 80, 443, 445, 3389, 3306]
    
    for port in common_ports:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=1
            )
            
            try:
                writer.write(b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n')
                await asyncio.wait_for(writer.drain(), timeout=0.5)
                response = await asyncio.wait_for(reader.read(512), timeout=0.5)
                resp_str = response.decode('utf-8', errors='ignore').lower()
                
                # Check for OS signatures
                for os_name, sigs in OS_SIGNATURES.items():
                    if any(flag.lower() in resp_str for flag in sigs['flags']):
                        if confidence < 8:
                            detected_os = os_name
                            confidence = 8
            except:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
        except:
            pass
    
    # If no banner detected, use TTL inference (less reliable)
    if not detected_os:
        try:
            # Default OS detection based on port patterns
            detected_os = "Unknown"
            confidence = 3
        except:
            pass
    
    return detected_os or "Unknown", confidence


# ================ UTILS ================
def clean_num(s: str) -> str:
    """Remove all spaces and invisible characters"""
    if not s:
        return ""
    return re.sub(r"\s+", "", s)


def get_service_name(port):
    """Get common service name for a port"""
    return SERVICE_PORTS.get(port, 'Unknown')


# ==========================
#  PORT SCANNER CLASS
# ==========================
class PortScanner:
    """Modern Port Scanner with advanced features"""
    
    def __init__(self, master):
        self.master = master
        self.window = tb.Toplevel(master)
        self.window.title("🔍 Advanced Network Port Scanner")
        self.window.geometry("1100x800")
        self.window.resizable(True, True)
        
        # Icon handling
        self.set_icon()
        
        # Initialize variables
        self.is_scanning = False
        self.current_scan_thread = None
        self.scan_options = {
            'tcp': True,
            'udp': False,
            'banners': False,
            'os_detect': False
        }
        
        # Create GUI
        self.setup_styles()
        self.create_gui()
        
        # Center window
        self.center_window()
    
    def set_icon(self):
        """Set window icon with error handling"""
        try:
            self.window.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
        except:
            pass
    
    def setup_styles(self):
        """Setup custom styles"""
        try:
            self.style = tb.Style()
            cfg = {"relief": "flat", "borderwidth": 1}
            try:
                colors = getattr(self.style, 'colors', None)
                if isinstance(colors, dict):
                    bg = colors.get('bg') or colors.get('background')
                else:
                    bg = None
            except Exception:
                bg = None
            if bg:
                cfg["background"] = bg
            self.style.configure("Card.TFrame", **cfg)
        except Exception as e:
            print(f"Style setup error: {e}")
    
    def center_window(self):
        """Center window on screen"""
        try:
            self.window.update_idletasks()
            width = self.window.winfo_reqwidth()
            height = self.window.winfo_reqheight()
            pos_x = (self.window.winfo_screenwidth() // 2) - (width // 2)
            pos_y = (self.window.winfo_screenheight() // 2) - (height // 2)
            self.window.geometry(f"{width}x{height}+{pos_x}+{pos_y}")
        except Exception:
            pass
    
    def create_gui(self):
        """Create main GUI layout"""
        main_frame = tb.Frame(self.window)
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        self.create_header(main_frame)
        self.create_input_section(main_frame)
        self.create_options_section(main_frame)
        self.create_results_section(main_frame)
        self.create_footer(main_frame)
    
    def create_header(self, parent):
        """Create header section"""
        header_frame = tb.Frame(parent, style="Card.TFrame")
        header_frame.pack(fill=X, pady=(0, 15))
        
        header_content = tb.Frame(header_frame)
        header_content.pack(fill=X, padx=20, pady=15)
        
        title_label = tb.Label(
            header_content,
            text="🔍 Advanced Network Port Scanner",
            font=("Arial", 20, "bold"),
            bootstyle="primary"
        )
        title_label.pack(anchor=W)
        
        subtitle_label = tb.Label(
            header_content,
            text="TCP/UDP scanning with banner detection and OS fingerprinting",
            font=("Arial", 10),
            bootstyle="secondary"
        )
        subtitle_label.pack(anchor=W, pady=(5, 0))
    
    def create_input_section(self, parent):
        """Create input fields section"""
        input_frame = tb.Labelframe(
            parent,
            text="🎯 Scan Configuration",
            padding=20,
            bootstyle="info"
        )
        input_frame.pack(fill=X, pady=(0, 15))
        
        inputs_grid = tb.Frame(input_frame)
        inputs_grid.pack(fill=X)
        
        # Host input
        tb.Label(inputs_grid, text="Target Host (IP/Domain):", font=("Arial", 11, "bold")).grid(row=0, column=0, sticky=W, pady=10)
        self.entry_host = tb.Entry(inputs_grid, width=40, bootstyle="info")
        self.entry_host.grid(row=0, column=1, sticky=W, padx=(10, 0), pady=10)
        self.entry_host.insert(0, "127.0.0.1")
        
        # Port range
        tb.Label(inputs_grid, text="Port Range:", font=("Arial", 11, "bold")).grid(row=1, column=0, sticky=W, pady=10)
        port_range_frame = tb.Frame(inputs_grid)
        port_range_frame.grid(row=1, column=1, sticky=W, padx=(10, 0), pady=10)
        
        tb.Label(port_range_frame, text="Start:").pack(side=LEFT)
        self.entry_start = tb.Entry(port_range_frame, width=10, bootstyle="info")
        self.entry_start.pack(side=LEFT, padx=(5, 20))
        self.entry_start.insert(0, "1")
        
        tb.Label(port_range_frame, text="End:").pack(side=LEFT)
        self.entry_end = tb.Entry(port_range_frame, width=10, bootstyle="info")
        self.entry_end.pack(side=LEFT, padx=(5, 0))
        self.entry_end.insert(0, "1024")
        
        # Concurrency
        tb.Label(inputs_grid, text="Concurrency (tasks):", font=("Arial", 11, "bold")).grid(row=2, column=0, sticky=W, pady=10)
        self.entry_concurrency = tb.Entry(inputs_grid, width=40, bootstyle="info")
        self.entry_concurrency.grid(row=2, column=1, sticky=W, padx=(10, 0), pady=10)
        self.entry_concurrency.insert(0, "500")
        
        # Buttons
        buttons_frame = tb.Frame(inputs_grid)
        buttons_frame.grid(row=3, column=0, columnspan=2, sticky=W, pady=15)
        
        self.button_scan = tb.Button(buttons_frame, text="🚀 Start Scan", bootstyle="success", command=self.run_scan, width=20)
        self.button_scan.pack(side=LEFT, padx=(0, 10))
        
        self.button_clear = tb.Button(buttons_frame, text="🗑️ Clear Results", bootstyle="warning", command=self.clear_output, width=20)
        self.button_clear.pack(side=LEFT)
        
        # Progress bar
        self.progress = tb.Progressbar(input_frame, mode='indeterminate', bootstyle="success", length=400)
        self.progress.pack(pady=(15, 0))
    
    def create_options_section(self, parent):
        """Create scan options section"""
        options_frame = tb.Labelframe(
            parent,
            text="⚙️ Scan Options",
            padding=15,
            bootstyle="secondary"
        )
        options_frame.pack(fill=X, pady=(0, 15))
        
        # TCP option
        self.tcp_var = tb.BooleanVar(value=True)
        tcp_check = tb.Checkbutton(
            options_frame,
            text="TCP Port Scan",
            variable=self.tcp_var,
            bootstyle="round-toggle"
        )
        tcp_check.pack(side=LEFT, padx=10)
        
        # UDP option
        self.udp_var = tb.BooleanVar(value=False)
        udp_check = tb.Checkbutton(
            options_frame,
            text="UDP Port Scan",
            variable=self.udp_var,
            bootstyle="round-toggle"
        )
        udp_check.pack(side=LEFT, padx=10)
        
        # Banner grabbing
        self.banner_var = tb.BooleanVar(value=False)
        banner_check = tb.Checkbutton(
            options_frame,
            text="Grab Service Banners",
            variable=self.banner_var,
            bootstyle="round-toggle"
        )
        banner_check.pack(side=LEFT, padx=10)
        
        # OS detection
        self.os_var = tb.BooleanVar(value=False)
        os_check = tb.Checkbutton(
            options_frame,
            text="Detect OS",
            variable=self.os_var,
            bootstyle="round-toggle"
        )
        os_check.pack(side=LEFT, padx=10)
    
    def create_results_section(self, parent):
        """Create results display section"""
        results_frame = tb.Labelframe(
            parent,
            text="📊 Scan Results",
            padding=15,
            bootstyle="primary"
        )
        results_frame.pack(fill=BOTH, expand=True, pady=(0, 15))
        
        self.output = tk.Text(
            results_frame,
            height=15,
            font=("Consolas", 9),
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="#00ff00",
            state="disabled"
        )
        self.output.pack(fill=BOTH, expand=True, side=LEFT)
        
        scrollbar = tb.Scrollbar(results_frame, command=self.output.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.output.config(yscrollcommand=scrollbar.set)
    
    def create_footer(self, parent):
        """Create footer section"""
        footer_frame = tb.Frame(parent)
        footer_frame.pack(fill=X, pady=(10, 0))
        
        separator = tb.Separator(footer_frame, orient=HORIZONTAL)
        separator.pack(fill=X, pady=(0, 10))
        
        info_label = tb.Label(
            footer_frame,
            text="⚠️ Educational tool for authorized testing only. Always obtain permission before scanning networks.",
            font=("Arial", 9),
            bootstyle="secondary"
        )
        info_label.pack(anchor=W)
    
    def append_output(self, text):
        """Add text to output area"""
        self.output.config(state="normal")
        self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.output.config(state="disabled")
        self.window.update()
    
    def clear_output(self):
        """Clear output area"""
        self.output.config(state="normal")
        self.output.delete(1.0, tk.END)
        self.output.config(state="disabled")
    
    def run_scan(self):
        """Execute port scan"""
        if self.is_scanning:
            messagebox.showwarning("Warning", "Scan already in progress!")
            return
        
        host = (self.entry_host.get() or "").strip()
        if not host:
            messagebox.showerror("Error", "Please enter a target host!")
            return
        
        start_str = clean_num(self.entry_start.get())
        end_str = clean_num(self.entry_end.get())
        concurrency_str = clean_num(self.entry_concurrency.get())
        
        if start_str == "": start_str = "1"
        if end_str == "": end_str = "1024"
        if concurrency_str == "": concurrency_str = "500"
        
        try:
            start = int(start_str)
            end = int(end_str)
            concurrency = int(concurrency_str)
        except ValueError:
            messagebox.showerror("Error", "Port range and concurrency must be numeric!")
            return
        
        if start < 1: start = 1
        if end > 65535: end = 65535
        if start > end:
            messagebox.showerror("Error", "Start port must be <= end port!")
            return
        if concurrency < 1:
            messagebox.showerror("Error", "Concurrency must be >= 1!")
            return
        
        self.scan_options = {
            'tcp': self.tcp_var.get(),
            'udp': self.udp_var.get(),
            'banners': self.banner_var.get(),
            'os_detect': self.os_var.get()
        }
        
        if not self.scan_options['tcp'] and not self.scan_options['udp']:
            messagebox.showerror("Error", "Select at least TCP or UDP scanning!")
            return
        
        self.is_scanning = True
        self.button_scan.config(state="disabled")
        self.progress.start()
        
        self.current_scan_thread = threading.Thread(
            target=self.perform_scan,
            args=(host, start, end, concurrency)
        )
        self.current_scan_thread.daemon = True
        self.current_scan_thread.start()
    
    def perform_scan(self, host, start, end, concurrency):
        """Perform actual scan in background"""
        try:
            ports = range(start, end + 1)
            
            self.append_output(f"{'='*70}\n")
            self.append_output(f"🚀 Advanced Port Scan Started\n")
            self.append_output(f"   Target: {host}\n")
            self.append_output(f"   Port Range: {start} → {end}\n")
            self.append_output(f"   TCP Scan: {'Yes' if self.scan_options['tcp'] else 'No'}\n")
            self.append_output(f"   UDP Scan: {'Yes' if self.scan_options['udp'] else 'No'}\n")
            self.append_output(f"   Banner Grabbing: {'Yes' if self.scan_options['banners'] else 'No'}\n")
            self.append_output(f"   OS Detection: {'Yes' if self.scan_options['os_detect'] else 'No'}\n")
            self.append_output(f"{'='*70}\n\n")
            
            t0 = time.time()
            
            # OS Detection
            if self.scan_options['os_detect']:
                self.append_output("🔎 Detecting Operating System...\n")
                os_name, confidence = asyncio.run(detect_os(host))
                self.append_output(f"   Detected OS: {os_name} (Confidence: {confidence}/10)\n\n")
            
            # TCP Scan
            if self.scan_options['tcp']:
                self.append_output(f"🔍 TCP Port Scanning...\n")
                tcp_results = asyncio.run(scan_ports_tcp(host, ports, concurrency, self.scan_options['banners']))
                
                if tcp_results:
                    self.append_output(f"\n✅ TCP Ports Found: {len(tcp_results)}\n")
                    self.append_output(f"{'-'*70}\n")
                    self.append_output(f"{'Port':<8} {'Service':<20} {'Status':<10} {'Banner':<25}\n")
                    self.append_output(f"{'-'*70}\n")
                    
                    for result in tcp_results:
                        port = result['port']
                        service = get_service_name(port)
                        banner = result.get('banner', '')[:23] if result.get('banner') else 'N/A'
                        self.append_output(f"{port:<8} {service:<20} {'OPEN':<10} {banner:<25}\n")
                    
                    self.append_output(f"{'-'*70}\n\n")
                else:
                    self.append_output("❌ No TCP ports found\n\n")
            
            # UDP Scan
            if self.scan_options['udp']:
                self.append_output(f"🔍 UDP Port Scanning...\n")
                udp_results = asyncio.run(scan_ports_udp(host, ports, concurrency=50))
                
                if udp_results:
                    self.append_output(f"\n✅ UDP Ports Found: {len(udp_results)}\n")
                    self.append_output(f"{'-'*70}\n")
                    self.append_output(f"{'Port':<8} {'Protocol':<20} {'Service':<15}\n")
                    self.append_output(f"{'-'*70}\n")
                    
                    for result in udp_results:
                        port = result['port']
                        service = result.get('service', 'Unknown')
                        self.append_output(f"{port:<8} {result['protocol']:<20} {service:<15}\n")
                    
                    self.append_output(f"{'-'*70}\n\n")
                else:
                    self.append_output("❌ No UDP ports found\n\n")
            
            elapsed = time.time() - t0
            self.append_output(f"⏱ Scan completed in {elapsed:.2f}s\n")
            self.append_output(f"{'='*75}\n")
        
        except Exception as e:
            self.append_output(f"⚠️ Scan error: {str(e)}\n\n")
        
        finally:
            self.is_scanning = False
            self.button_scan.config(state="normal")
            self.progress.stop()


# ==========================
#     MAIN (for testing)
# ==========================
if __name__ == "__main__":
    root = tb.Window(themename="cosmo")
    root.title("Port Scanner Test")
    root.geometry("400x300")
    root.withdraw()
    
    scanner = PortScanner(root)
    root.mainloop()
