"""
Subdomain Finder GUI
Professional subdomain enumeration interface
"""

import ttkbootstrap as tb
from ttkbootstrap.constants import *
import threading
import sys
import os
from tkinter import messagebox, filedialog
from datetime import datetime
import time

# Add utils to path
utils_path = os.path.join(os.path.dirname(__file__), '..', 'utils')
if utils_path not in sys.path:
    sys.path.insert(0, utils_path)

try:
    from subdomain_finder import SubdomainFinder
except ImportError as e:
    print(f"Error importing SubdomainFinder: {e}")
    raise


class SubdomainFinderGUI:
    def __init__(self, master):
        self.window = tb.Toplevel(master)
        self.window.title("🌐 Subdomain Finder")
        self.window.geometry("1200x800")
        try:
            self.window.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
        except Exception:
            pass
        self.window.resizable(True, True)
        
        # Get ExportManager from parent if available
        export_manager = None
        if hasattr(master, 'export_manager'):
            export_manager = master.export_manager
        
        # Initialize core with ExportManager
        self.core = SubdomainFinder(export_manager=export_manager)
        self.scan_thread = None
        self.start_time = None
        self.current_results = {}
        
        self.setup_ui()
        self.load_wordlists()

    def setup_ui(self):
        """Setup the user interface"""
        # Title and close button
        title_frame = tb.Frame(self.window)
        title_frame.pack(fill=X, padx=10, pady=5)
        
        tb.Label(
            title_frame,
            text="🌐 Subdomain Finder",
            font=("Helvetica", 16, "bold"),
            bootstyle="info"
        ).pack(side=LEFT)
        
        tb.Button(
            title_frame,
            text="❌ Close",
            bootstyle="danger-outline",
            command=self.window.destroy
        ).pack(side=RIGHT)

        # Main container
        main_frame = tb.Frame(self.window)
        main_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)

        # Left panel - Configuration
        config_frame = tb.LabelFrame(main_frame, text="⚙️ Configuration", padding=10)
        config_frame.pack(side=LEFT, fill=Y, padx=(0, 5))

        # Domain input
        domain_frame = tb.Frame(config_frame)
        domain_frame.pack(fill=X, pady=(0, 10))

        tb.Label(domain_frame, text="🎯 Target Domain:", font=("Helvetica", 10, "bold")).pack(anchor=W)
        self.domain_var = tb.StringVar()
        domain_entry = tb.Entry(
            domain_frame,
            textvariable=self.domain_var,
            width=35,
            font=("Consolas", 10)
        )
        domain_entry.pack(fill=X, pady=(5, 0))
        domain_entry.bind('<Return>', self.start_scan)

        # Wordlists selection
        wordlist_frame = tb.Frame(config_frame)
        wordlist_frame.pack(fill=X, pady=(0, 10))

        tb.Label(wordlist_frame, text="📝 Wordlists:", font=("Helvetica", 10, "bold")).pack(anchor=W)
        
        # Wordlist checkboxes frame with scrollbar
        wordlist_scroll_frame = tb.Frame(wordlist_frame)
        wordlist_scroll_frame.pack(fill=X, pady=(5, 0))
        
        self.wordlist_vars = {}
        self.wordlist_checkboxes = tb.Frame(wordlist_scroll_frame)
        self.wordlist_checkboxes.pack(fill=X)

        # Techniques selection
        techniques_frame = tb.Frame(config_frame)
        techniques_frame.pack(fill=X, pady=(0, 10))

        tb.Label(techniques_frame, text="🔍 Techniques:", font=("Helvetica", 10, "bold")).pack(anchor=W)
        
        self.technique_vars = {
            "dns_bruteforce": tb.BooleanVar(value=True),
            "certificate_transparency": tb.BooleanVar(value=True),
            "search_engines": tb.BooleanVar(value=False),
            "zone_transfer": tb.BooleanVar(value=True),
            "web_crawler": tb.BooleanVar(value=False)
        }
        
        technique_descriptions = {
            "dns_bruteforce": "DNS Bruteforce",
            "certificate_transparency": "Certificate Transparency",
            "search_engines": "Search Engine Enumeration",
            "zone_transfer": "DNS Zone Transfer",
            "web_crawler": "Web Crawler"
        }
        
        for technique, var in self.technique_vars.items():
            cb = tb.Checkbutton(
                techniques_frame,
                text=technique_descriptions[technique],
                variable=var,
                bootstyle="info"
            )
            cb.pack(anchor=W, pady=2)

        # Advanced options
        advanced_frame = tb.Frame(config_frame)
        advanced_frame.pack(fill=X, pady=(0, 10))

        tb.Label(advanced_frame, text="⚡ Advanced Options:", font=("Helvetica", 10, "bold")).pack(anchor=W)

        # Threads
        threads_frame = tb.Frame(advanced_frame)
        threads_frame.pack(fill=X, pady=2)
        tb.Label(threads_frame, text="Threads:").pack(side=LEFT)
        self.threads_var = tb.IntVar(value=50)
        threads_spin = tb.Spinbox(
            threads_frame,
            from_=1,
            to=200,
            textvariable=self.threads_var,
            width=8
        )
        threads_spin.pack(side=RIGHT)

        # Max pages for crawler
        pages_frame = tb.Frame(advanced_frame)
        pages_frame.pack(fill=X, pady=2)
        tb.Label(pages_frame, text="Max Pages:").pack(side=LEFT)
        self.pages_var = tb.IntVar(value=50)
        pages_spin = tb.Spinbox(
            pages_frame,
            from_=10,
            to=200,
            textvariable=self.pages_var,
            width=8
        )
        pages_spin.pack(side=RIGHT)

        # Control buttons
        control_frame = tb.Frame(config_frame)
        control_frame.pack(fill=X, pady=10)

        self.scan_btn = tb.Button(
            control_frame,
            text="🚀 Start Scan",
            bootstyle="success",
            command=self.start_scan
        )
        self.scan_btn.pack(fill=X, pady=(0, 5))

        self.stop_btn = tb.Button(
            control_frame,
            text="⏹️ Stop Scan",
            bootstyle="danger",
            command=self.stop_scan,
            state=DISABLED
        )
        self.stop_btn.pack(fill=X, pady=(0, 5))

        tb.Button(
            control_frame,
            text="📂 Load Wordlist",
            bootstyle="info-outline",
            command=self.load_custom_wordlist
        ).pack(fill=X, pady=(0, 5))

        tb.Button(
            control_frame,
            text="📊 View Statistics",
            bootstyle="secondary-outline",
            command=self.show_statistics
        ).pack(fill=X)

        # Right panel - Results
        results_frame = tb.Frame(main_frame)
        results_frame.pack(side=RIGHT, fill=BOTH, expand=True)

        # Progress and statistics
        progress_frame = tb.LabelFrame(results_frame, text="📈 Progress & Statistics", padding=5)
        progress_frame.pack(fill=X, pady=(0, 5))

        # Progress bar
        self.progress_var = tb.DoubleVar()
        self.progress_bar = tb.Progressbar(
            progress_frame,
            variable=self.progress_var,
            mode="determinate"
        )
        self.progress_bar.pack(fill=X, pady=(0, 5))

        # Progress label
        self.progress_label_var = tb.StringVar(value="Ready to scan")
        tb.Label(
            progress_frame,
            textvariable=self.progress_label_var,
            font=("Consolas", 9)
        ).pack(fill=X)

        # Statistics frame
        stats_frame = tb.Frame(progress_frame)
        stats_frame.pack(fill=X, pady=5)

        self.stats_vars = {
            "total": tb.StringVar(value="0"),
            "active": tb.StringVar(value="0"),
            "elapsed": tb.StringVar(value="00:00:00")
        }

        tb.Label(stats_frame, text="Found:").grid(row=0, column=0, sticky=W)
        tb.Label(stats_frame, textvariable=self.stats_vars["total"], 
                font=("Consolas", 10, "bold")).grid(row=0, column=1, sticky=W, padx=5)

        tb.Label(stats_frame, text="Active:").grid(row=0, column=2, sticky=W, padx=(20, 0))
        tb.Label(stats_frame, textvariable=self.stats_vars["active"], 
                font=("Consolas", 10, "bold")).grid(row=0, column=3, sticky=W, padx=5)

        tb.Label(stats_frame, text="Time:").grid(row=0, column=4, sticky=W, padx=(20, 0))
        tb.Label(stats_frame, textvariable=self.stats_vars["elapsed"], 
                font=("Consolas", 10, "bold")).grid(row=0, column=5, sticky=W, padx=5)

        # Results display
        results_display_frame = tb.LabelFrame(results_frame, text="🎯 Discovered Subdomains", padding=5)
        results_display_frame.pack(fill=BOTH, expand=True)

        # Results treeview
        columns = ("Subdomain", "Status", "IP Address", "Method", "Timestamp")
        self.results_tree = tb.Treeview(
            results_display_frame,
            columns=columns,
            show="headings",
            height=20
        )

        # Configure columns
        self.results_tree.heading("Subdomain", text="Subdomain")
        self.results_tree.heading("Status", text="Status")
        self.results_tree.heading("IP Address", text="IP Address")
        self.results_tree.heading("Method", text="Method")
        self.results_tree.heading("Timestamp", text="Timestamp")

        self.results_tree.column("Subdomain", width=250)
        self.results_tree.column("Status", width=80)
        self.results_tree.column("IP Address", width=120)
        self.results_tree.column("Method", width=150)
        self.results_tree.column("Timestamp", width=130)

        # Scrollbars
        v_scroll = tb.Scrollbar(results_display_frame, orient=VERTICAL, command=self.results_tree.yview)
        h_scroll = tb.Scrollbar(results_display_frame, orient=HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        # Pack treeview and scrollbars
        self.results_tree.pack(side=LEFT, fill=BOTH, expand=True)
        v_scroll.pack(side=RIGHT, fill=Y)
        h_scroll.pack(side=BOTTOM, fill=X)

        # Configure row colors
        self.results_tree.tag_configure("active", background="#e8f5e8")
        self.results_tree.tag_configure("discovered", background="#fff3cd")

        # Context menu for results
        self.results_tree.bind("<Button-3>", self.show_context_menu)

        # Export buttons
        export_frame = tb.Frame(results_frame)
        export_frame.pack(fill=X, pady=5)

        tb.Button(
            export_frame,
            text="💾 Export JSON",
            bootstyle="info-outline",
            command=lambda: self.export_results("json")
        ).pack(side=LEFT, padx=(0, 5))

        tb.Button(
            export_frame,
            text="📄 Export TXT",
            bootstyle="secondary-outline",
            command=lambda: self.export_results("txt")
        ).pack(side=LEFT, padx=(0, 5))

        tb.Button(
            export_frame,
            text="📊 Export CSV",
            bootstyle="warning-outline",
            command=lambda: self.export_results("csv")
        ).pack(side=LEFT, padx=(0, 5))

        tb.Button(
            export_frame,
            text="🗑️ Clear Results",
            bootstyle="danger-outline",
            command=self.clear_results
        ).pack(side=RIGHT)

        # Status bar
        self.status_var = tb.StringVar(value="Ready")
        status_bar = tb.Label(
            self.window,
            textvariable=self.status_var,
            relief=SUNKEN,
            anchor=W
        )
        status_bar.pack(side=BOTTOM, fill=X)

    def load_wordlists(self):
        """Load available wordlists"""
        wordlists = self.core.get_wordlists()
        
        # Clear existing checkboxes
        for widget in self.wordlist_checkboxes.winfo_children():
            widget.destroy()
        
        self.wordlist_vars.clear()
        
        # Create checkboxes for each wordlist
        for wordlist in wordlists:
            var = tb.BooleanVar(value=True if wordlist == "common.txt" else False)
            self.wordlist_vars[wordlist] = var
            
            cb = tb.Checkbutton(
                self.wordlist_checkboxes,
                text=wordlist.replace('.txt', '').title(),
                variable=var,
                bootstyle="info"
            )
            cb.pack(anchor=W, pady=1)

    def load_custom_wordlist(self):
        """Load custom wordlist file"""
        file_path = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Copy to wordlists directory
                import shutil
                filename = os.path.basename(file_path)
                destination = os.path.join(self.core.wordlists_dir, filename)
                shutil.copy2(file_path, destination)
                
                messagebox.showinfo("Success", f"Wordlist '{filename}' loaded successfully!")
                self.load_wordlists()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load wordlist: {e}")

    def start_scan(self, event=None):
        """Start subdomain enumeration"""
        domain = self.domain_var.get().strip()
        
        if not domain:
            messagebox.showwarning("Invalid Domain", "Please enter a target domain")
            return
        
        # Validate domain format
        if not self.validate_domain_format(domain):
            messagebox.showwarning("Invalid Domain", 
                                 "Please enter a valid domain (e.g., example.com)")
            return
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
        
        # Remove trailing slash and path
        domain = domain.split('/')[0].strip()
        
        # Get selected wordlists
        selected_wordlists = [name for name, var in self.wordlist_vars.items() if var.get()]
        
        # Get selected techniques
        selected_techniques = [name for name, var in self.technique_vars.items() if var.get()]
        
        if not selected_techniques:
            messagebox.showwarning("No Techniques", "Please select at least one enumeration technique")
            return
        
        # Check if DNS bruteforce is selected but no wordlists
        if "dns_bruteforce" in selected_techniques and not selected_wordlists:
            result = messagebox.askyesno("No Wordlists", 
                                       "DNS bruteforce is selected but no wordlists are chosen.\n" +
                                       "Do you want to continue with other techniques only?")
            if not result:
                return
            # Remove DNS bruteforce if no wordlists
            selected_techniques.remove("dns_bruteforce")
            if not selected_techniques:
                messagebox.showwarning("No Techniques", "No valid techniques remaining")
                return
        
        # Clear previous results
        self.clear_results()
        
        # Update UI
        self.scan_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.status_var.set(f"Starting scan for {domain}...")
        self.start_time = time.time()
        
        # Start scan thread
        def scan_worker():
            try:
                def progress_callback(current, total, message):
                    def update_ui():
                        try:
                            # Update progress
                            progress = min((current / total) * 100 if total > 0 else 0, 100)
                            self.progress_var.set(progress)
                            self.progress_label_var.set(str(message)[:100])  # Limit message length
                            
                            # Update statistics
                            stats = self.core.get_scan_statistics()
                            self.stats_vars["total"].set(str(stats["total_found"]))
                            
                            # Count active subdomains from current results
                            active_count = len([s for s in stats.get("found_subdomains", []) 
                                             if any(r.get("status") == "active" and r.get("subdomain") == s 
                                                   for r in self.current_results.get("results", []))])
                            self.stats_vars["active"].set(str(active_count))
                            
                            # Update elapsed time
                            if self.start_time:
                                elapsed = time.time() - self.start_time
                                hours, remainder = divmod(elapsed, 3600)
                                minutes, seconds = divmod(remainder, 60)
                                self.stats_vars["elapsed"].set(f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
                        except Exception as e:
                            print(f"Progress update error: {e}")
                    
                    try:
                        self.window.after(0, update_ui)
                    except Exception as e:
                        print(f"UI update error: {e}")
                
                # Run comprehensive scan
                results = self.core.comprehensive_scan(
                    domain=domain,
                    wordlist_files=selected_wordlists,
                    techniques=selected_techniques,
                    threads=min(self.threads_var.get(), 100),  # Limit threads
                    max_pages=min(self.pages_var.get(), 100),  # Limit pages
                    progress_callback=progress_callback
                )
                
                # Update UI with results
                self.window.after(0, lambda: self.scan_completed(results))
                
            except Exception as e:
                print(f"Scan worker error: {e}")
                self.window.after(0, lambda: self.scan_error(str(e)))
        
        self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self.scan_thread.start()
        
        # Start timer update
        self.update_timer()

    def validate_domain_format(self, domain: str) -> bool:
        """Validate domain format"""
        import re
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
        
        # Remove path and port
        domain = domain.split('/')[0].split(':')[0]
        
        # Basic domain validation
        if not domain or len(domain) > 255:
            return False
        
        # Check for valid domain pattern
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        
        return bool(re.match(domain_pattern, domain))

    def update_timer(self):
        """Update elapsed time display"""
        if self.start_time and self.core.is_running:
            elapsed = time.time() - self.start_time
            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.stats_vars["elapsed"].set(f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
            
            # Schedule next update
            self.window.after(1000, self.update_timer)

    def stop_scan(self):
        """Stop the current scan"""
        self.core.stop_scan()
        self.scan_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.status_var.set("Scan stopped by user")
        self.progress_label_var.set("Scan interrupted")

    def scan_completed(self, results):
        """Handle scan completion"""
        self.current_results = results
        
        # Update UI
        self.scan_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.progress_var.set(100)
        self.progress_label_var.set("Scan completed")
        
        # Update final statistics
        total_found = results.get("total_found", 0)
        active_count = results.get("active_subdomains", 0)
        
        self.stats_vars["total"].set(str(total_found))
        self.stats_vars["active"].set(str(active_count))
        
        # Populate results tree
        for result in results.get("results", []):
            status_tag = result["status"]
            ip_addresses = ", ".join(result["ip_addresses"]) if result["ip_addresses"] else "N/A"
            
            self.results_tree.insert(
                "",
                "end",
                values=(
                    result["subdomain"],
                    result["status"].title(),
                    ip_addresses,
                    result["method"],
                    result["timestamp"]
                ),
                tags=(status_tag,)
            )
        
        self.status_var.set(f"Scan completed: {total_found} subdomains found ({active_count} active)")
        
        # Show completion message
        messagebox.showinfo(
            "Scan Complete",
            f"Subdomain enumeration completed!\n\n"
            f"Domain: {results.get('domain', 'Unknown')}\n"
            f"Total found: {total_found}\n"
            f"Active: {active_count}\n"
            f"Techniques used: {len(results.get('techniques_used', []))}"
        )

    def scan_error(self, error_msg):
        """Handle scan error"""
        self.scan_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.status_var.set("Scan error occurred")
        self.progress_label_var.set("Error occurred")
        
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_msg}")

    def show_context_menu(self, event):
        """Show context menu for results"""
        item = self.results_tree.selection()[0] if self.results_tree.selection() else None
        
        if item:
            menu = tb.Menu(self.window, tearoff=0)
            
            values = self.results_tree.item(item, 'values')
            subdomain = values[0] if values else ""
            
            menu.add_command(
                label=f"Copy {subdomain}",
                command=lambda: self.copy_to_clipboard(subdomain)
            )
            
            menu.add_command(
                label="Copy IP Address",
                command=lambda: self.copy_to_clipboard(values[2] if len(values) > 2 else "")
            )
            
            menu.add_separator()
            
            menu.add_command(
                label="Open in Browser",
                command=lambda: self.open_in_browser(subdomain)
            )
            
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        try:
            self.window.clipboard_clear()
            self.window.clipboard_append(text)
            self.status_var.set(f"Copied to clipboard: {text}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {e}")

    def open_in_browser(self, subdomain):
        """Open subdomain in browser"""
        import webbrowser
        try:
            url = f"http://{subdomain}"
            webbrowser.open(url)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open browser: {e}")

    def show_statistics(self):
        """Show detailed statistics"""
        if not self.current_results:
            messagebox.showinfo("No Results", "No scan results available")
            return
        
        stats_window = tb.Toplevel(self.window)
        stats_window.title("Scan Statistics")
        stats_window.geometry("500x400")
        
        # Statistics content
        stats_text = tb.Text(stats_window, wrap=WORD, font=("Consolas", 10))
        stats_scroll = tb.Scrollbar(stats_window, orient=VERTICAL, command=stats_text.yview)
        stats_text.configure(yscrollcommand=stats_scroll.set)
        
        # Generate statistics
        results = self.current_results
        stats_content = f"""SUBDOMAIN ENUMERATION STATISTICS
{'='*50}

Domain: {results.get('domain', 'Unknown')}
Scan Date: {results.get('timestamp', 'Unknown')}
Total Subdomains Found: {results.get('total_found', 0)}
Active Subdomains: {results.get('active_subdomains', 0)}

TECHNIQUES USED:
{'-'*20}
"""
        
        for technique in results.get('techniques_used', []):
            stats_content += f"• {technique.replace('_', ' ').title()}\n"
        
        stats_content += f"\nMETHOD BREAKDOWN:\n{'-'*20}\n"
        
        # Count by method
        method_counts = {}
        for result in results.get('results', []):
            method = result['method']
            method_counts[method] = method_counts.get(method, 0) + 1
        
        for method, count in method_counts.items():
            stats_content += f"• {method}: {count}\n"
        
        stats_content += f"\nSTATUS BREAKDOWN:\n{'-'*20}\n"
        
        # Count by status
        status_counts = {}
        for result in results.get('results', []):
            status = result['status']
            status_counts[status] = status_counts.get(status, 0) + 1
        
        for status, count in status_counts.items():
            stats_content += f"• {status.title()}: {count}\n"
        
        stats_text.insert(1.0, stats_content)
        stats_text.config(state=DISABLED)
        
        stats_text.pack(side=LEFT, fill=BOTH, expand=True)
        stats_scroll.pack(side=RIGHT, fill=Y)
        
        # Close button
        tb.Button(
            stats_window,
            text="Close",
            bootstyle="primary",
            command=stats_window.destroy
        ).pack(pady=10)

    def export_results(self, format_type):
        """Export scan results"""
        if not self.current_results:
            messagebox.showwarning("No Results", "No scan results to export")
            return
        
        try:
            filename = self.core.save_results(self.current_results, format_type)
            messagebox.showinfo("Export Complete", f"Results exported to:\n{filename}")
            self.status_var.set(f"Results exported: {os.path.basename(filename)}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {e}")

    def clear_results(self):
        """Clear all results"""
        # Clear treeview
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Reset statistics
        self.stats_vars["total"].set("0")
        self.stats_vars["active"].set("0")
        self.stats_vars["elapsed"].set("00:00:00")
        
        # Reset progress
        self.progress_var.set(0)
        self.progress_label_var.set("Ready to scan")
        
        # Clear results
        self.current_results = {}
        self.core.found_subdomains.clear()
        
        self.status_var.set("Results cleared")