"""
Port Scanner GUI with Modern Theme
Educational cybersecurity tool for authorized testing only.
Real-time port enumeration and service detection.
"""

import asyncio
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import messagebox
import re
import time
import threading
import os
import sys

# Add parent directory to path for imports
current_dir = os.path.dirname(__file__)
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# ==========================
#   SCAN ASYNCIO
# ==========================
async def scan_port(host, port):
    """Scan a single port with timeout"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=1
        )
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None


async def scan_ports(host, ports, concurrency=500):
    """Scan multiple ports with concurrency limit"""
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def sem_task(p):
        async with semaphore:
            return await scan_port(host, p)

    tasks = [asyncio.create_task(sem_task(p)) for p in ports]
    for t in asyncio.as_completed(tasks):
        r = await t
        if r:
            results.append(r)

    return sorted(results)


# ================ UTILS ================
def clean_num(s: str) -> str:
    """Remove all spaces and invisible characters"""
    if not s:
        return ""
    return re.sub(r"\s+", "", s)


# ==========================
#  PORT SCANNER CLASS
# ==========================
class PortScanner:
    """Modern Port Scanner with ttkbootstrap theme"""
    
    def __init__(self, master):
        self.master = master
        self.window = tb.Toplevel(master)
        self.window.title("🔍 Network Port Scanner")
        self.window.geometry("1000x700")
        self.window.resizable(True, True)
        
        # Icon handling
        self.set_icon()
        
        # Initialize variables
        self.is_scanning = False
        self.current_scan_thread = None
        
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
            
            # Card style - do not force a light background so it adapts to the active theme
            # Some themes (dark) will look wrong if we hardcode a white background here.
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
        # Main container
        main_frame = tb.Frame(self.window)
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        # Header
        self.create_header(main_frame)
        
        # Input section
        self.create_input_section(main_frame)
        
        # Results section
        self.create_results_section(main_frame)
        
        # Footer
        self.create_footer(main_frame)
    
    def create_header(self, parent):
        """Create header section"""
        header_frame = tb.Frame(parent, style="Card.TFrame")
        header_frame.pack(fill=X, pady=(0, 20))
        
        header_content = tb.Frame(header_frame)
        header_content.pack(fill=X, padx=20, pady=15)
        
        title_label = tb.Label(
            header_content,
            text="🔍 Network Port Scanner",
            font=("Arial", 20, "bold"),
            bootstyle="primary"
        )
        title_label.pack(anchor=W)
        
        subtitle_label = tb.Label(
            header_content,
            text="Asynchronous port scanning with concurrent connections",
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
        input_frame.pack(fill=X, pady=(0, 20))
        
        # Create grid for inputs
        inputs_grid = tb.Frame(input_frame)
        inputs_grid.pack(fill=X)
        
        # Host input
        host_label = tb.Label(
            inputs_grid,
            text="Target Host (IP/Domain):",
            font=("Arial", 11, "bold")
        )
        host_label.grid(row=0, column=0, sticky=W, pady=10)
        
        self.entry_host = tb.Entry(inputs_grid, width=40, bootstyle="info")
        self.entry_host.grid(row=0, column=1, sticky=W, padx=(10, 0), pady=10)
        self.entry_host.insert(0, "127.0.0.1")
        
        # Port range inputs
        port_label = tb.Label(
            inputs_grid,
            text="Port Range:",
            font=("Arial", 11, "bold")
        )
        port_label.grid(row=1, column=0, sticky=W, pady=10)
        
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
        
        # Concurrency input
        concurrency_label = tb.Label(
            inputs_grid,
            text="Concurrency (simultaneous tasks):",
            font=("Arial", 11, "bold")
        )
        concurrency_label.grid(row=2, column=0, sticky=W, pady=10)
        
        self.entry_concurrency = tb.Entry(inputs_grid, width=40, bootstyle="info")
        self.entry_concurrency.grid(row=2, column=1, sticky=W, padx=(10, 0), pady=10)
        self.entry_concurrency.insert(0, "500")
        
        # Buttons frame
        buttons_frame = tb.Frame(inputs_grid)
        buttons_frame.grid(row=3, column=0, columnspan=2, sticky=W, pady=15)
        
        self.button_scan = tb.Button(
            buttons_frame,
            text="🚀 Start Scan",
            bootstyle="success",
            command=self.run_scan,
            width=20
        )
        self.button_scan.pack(side=LEFT, padx=(0, 10))
        
        self.button_clear = tb.Button(
            buttons_frame,
            text="🗑️ Clear Results",
            bootstyle="warning",
            command=self.clear_output,
            width=20
        )
        self.button_clear.pack(side=LEFT)
        
        # Progress bar
        self.progress = tb.Progressbar(
            input_frame,
            mode='indeterminate',
            bootstyle="success",
            length=400
        )
        self.progress.pack(pady=(15, 0))
    
    def create_results_section(self, parent):
        """Create results display section"""
        results_frame = tb.Labelframe(
            parent,
            text="📊 Scan Results",
            padding=15,
            bootstyle="primary"
        )
        results_frame.pack(fill=BOTH, expand=True, pady=(0, 20))
        
        # Output text area
        self.output = tk.Text(
            results_frame,
            height=20,
            font=("Consolas", 10),
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="#00ff00",
            state="disabled"
        )
        self.output.pack(fill=BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = tb.Scrollbar(results_frame, command=self.output.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.output.config(yscrollcommand=scrollbar.set)
    
    def create_footer(self, parent):
        """Create footer section"""
        footer_frame = tb.Frame(parent)
        footer_frame.pack(fill=X, pady=(10, 0))
        
        # Separator
        separator = tb.Separator(footer_frame, orient=HORIZONTAL)
        separator.pack(fill=X, pady=(0, 10))
        
        # Info label
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
        
        # Default values
        if start_str == "": start_str = "1"
        if end_str == "": end_str = "1024"
        if concurrency_str == "": concurrency_str = "500"
        
        # Validation
        try:
            start = int(start_str)
            end = int(end_str)
            concurrency = int(concurrency_str)
        except ValueError:
            messagebox.showerror("Error", "Port range and concurrency must be numeric values!")
            return
        
        # Bounds checking
        if start < 1: start = 1
        if end > 65535: end = 65535
        if start > end:
            messagebox.showerror("Error", "Start port must be less than or equal to end port!")
            return
        if concurrency < 1:
            messagebox.showerror("Error", "Concurrency must be at least 1!")
            return
        
        # Start scan in background thread
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
            
            self.append_output(f"{'='*60}\n")
            self.append_output(f"🚀 Starting scan on {host}\n")
            self.append_output(f"   Port range: {start} → {end}\n")
            self.append_output(f"   Concurrency: {concurrency}\n")
            self.append_output(f"{'='*60}\n\n")
            
            t0 = time.time()
            
            # Run async scan
            result = asyncio.run(scan_ports(host, ports, concurrency))
            
            elapsed = time.time() - t0
            
            self.append_output(f"✅ Scan completed in {elapsed:.2f}s\n\n")
            
            if result:
                self.append_output(f"📌 Open Ports Found: {len(result)}\n")
                self.append_output(f"{'-'*60}\n")
                for port in result:
                    self.append_output(f"   Port {port:5d} : OPEN\n")
                self.append_output(f"{'-'*60}\n\n")
            else:
                self.append_output("❌ No open ports found\n\n")
        
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
    root.withdraw()  # Hide main window
    
    scanner = PortScanner(root)
    root.mainloop()
