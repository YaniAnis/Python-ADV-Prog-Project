import ttkbootstrap as tb
from ttkbootstrap.constants import *
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import sys
import os
import webbrowser

# Add the utils directory to the path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils'))
from directory_fuzzer import DirectoryFuzzerEngine, get_wordlist


class DirectoryFuzzer:
    def __init__(self, master):
        self.window = tb.Toplevel(master)
        self.window.title("Directory Fuzzer")
        self.window.geometry("1000x700")
        try:
            self.window.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
        except Exception:
            pass
        self.window.resizable(False, False)
        
        # Initialize fuzzer
        self.fuzzer = None
        self.fuzzing_thread = None
        self.is_fuzzing = False
        
        self.setup_ui()

    def setup_ui(self):
        """Setup the user interface"""
        
        # Header
        header_frame = tb.Frame(self.window)
        header_frame.pack(fill=X, padx=10, pady=5)
        
        tb.Label(
            header_frame,
            text="🎯 Directory Fuzzer",
            font=("Helvetica", 16, "bold"),
            bootstyle="primary"
        ).pack(side=LEFT)
        
        tb.Button(
            header_frame,
            text="✕ Close",
            bootstyle="danger-outline",
            command=self.window.destroy
        ).pack(side=RIGHT)
        
        # Configuration Frame
        config_frame = tb.LabelFrame(self.window, text="Configuration", padding=10)
        config_frame.pack(fill=X, padx=10, pady=5)
        
        # Target URL
        url_frame = tb.Frame(config_frame)
        url_frame.pack(fill=X, pady=2)
        
        tb.Label(url_frame, text="Target URL:", width=15).pack(side=LEFT)
        self.url_var = tb.StringVar(value="http://")
        self.url_entry = tb.Entry(url_frame, textvariable=self.url_var, width=50)
        self.url_entry.pack(side=LEFT, padx=5, fill=X, expand=True)
        
        # Wordlist selection
        wordlist_frame = tb.Frame(config_frame)
        wordlist_frame.pack(fill=X, pady=2)
        
        tb.Label(wordlist_frame, text="Wordlist:", width=15).pack(side=LEFT)
        self.wordlist_var = tb.StringVar(value="Default (Built-in)")
        self.wordlist_combo = tb.Combobox(
            wordlist_frame, 
            textvariable=self.wordlist_var,
            values=["Default (Built-in)", "Small (Quick)", "Custom File"],
            state="readonly",
            width=20
        )
        self.wordlist_combo.pack(side=LEFT, padx=5)
        
        self.browse_button = tb.Button(
            wordlist_frame,
            text="Browse",
            bootstyle="secondary-outline",
            command=self.browse_wordlist,
            state=DISABLED
        )
        self.browse_button.pack(side=LEFT, padx=5)
        
        self.wordlist_combo.bind('<<ComboboxSelected>>', self.on_wordlist_change)
        
        # Settings frame
        settings_frame = tb.Frame(config_frame)
        settings_frame.pack(fill=X, pady=2)
        
        # Threads
        tb.Label(settings_frame, text="Threads:", width=10).pack(side=LEFT)
        self.threads_var = tb.IntVar(value=10)
        threads_spin = tb.Spinbox(settings_frame, from_=1, to=50, width=10, textvariable=self.threads_var)
        threads_spin.pack(side=LEFT, padx=5)
        
        # Timeout
        tb.Label(settings_frame, text="Timeout:", width=10).pack(side=LEFT, padx=(20, 0))
        self.timeout_var = tb.IntVar(value=5)
        timeout_spin = tb.Spinbox(settings_frame, from_=1, to=30, width=10, textvariable=self.timeout_var)
        timeout_spin.pack(side=LEFT, padx=5)
        tb.Label(settings_frame, text="seconds").pack(side=LEFT)
        
        # Control buttons
        control_frame = tb.Frame(config_frame)
        control_frame.pack(fill=X, pady=10)
        
        self.start_button = tb.Button(
            control_frame,
            text="🚀 Start Fuzzing",
            bootstyle="success",
            command=self.start_fuzzing,
            width=15
        )
        self.start_button.pack(side=LEFT, padx=5)
        
        self.stop_button = tb.Button(
            control_frame,
            text="⏹ Stop",
            bootstyle="danger",
            command=self.stop_fuzzing,
            state=DISABLED,
            width=15
        )
        self.stop_button.pack(side=LEFT, padx=5)
        
        self.export_button = tb.Button(
            control_frame,
            text="💾 Export Results",
            bootstyle="info-outline",
            command=self.export_results,
            state=DISABLED,
            width=15
        )
        self.export_button.pack(side=LEFT, padx=5)
        
        # Progress frame
        progress_frame = tb.LabelFrame(self.window, text="Progress", padding=10)
        progress_frame.pack(fill=X, padx=10, pady=5)
        
        self.progress_var = tb.DoubleVar()
        self.progress_bar = tb.Progressbar(
            progress_frame,
            variable=self.progress_var,
            bootstyle="success-striped"
        )
        self.progress_bar.pack(fill=X, pady=2)
        
        self.status_label = tb.Label(progress_frame, text="Ready to start fuzzing...")
        self.status_label.pack(fill=X)
        
        # Results frame
        results_frame = tb.LabelFrame(self.window, text="Results", padding=10)
        results_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # Results notebook for tabs
        self.notebook = tb.Notebook(results_frame)
        self.notebook.pack(fill=BOTH, expand=True)
        
        # Directories tab
        self.dir_frame = tb.Frame(self.notebook)
        self.notebook.add(self.dir_frame, text="📁 Directories (0)")
        
        # Create treeview for directories
        dir_columns = ("Status", "Path", "Size", "URL")
        self.dir_tree = tb.Treeview(self.dir_frame, columns=dir_columns, show="tree headings", height=8)
        
        # Configure columns
        self.dir_tree.heading("#0", text="", anchor=W)
        self.dir_tree.column("#0", width=0, stretch=False)
        for col in dir_columns:
            self.dir_tree.heading(col, text=col)
            if col == "URL":
                self.dir_tree.column(col, width=300)
            else:
                self.dir_tree.column(col, width=80)
        
        dir_scrollbar = tb.Scrollbar(self.dir_frame, orient=VERTICAL, command=self.dir_tree.yview)
        self.dir_tree.configure(yscrollcommand=dir_scrollbar.set)
        
        self.dir_tree.pack(side=LEFT, fill=BOTH, expand=True)
        dir_scrollbar.pack(side=RIGHT, fill=Y)
        
        # Files tab
        self.file_frame = tb.Frame(self.notebook)
        self.notebook.add(self.file_frame, text="📄 Files (0)")
        
        # Create treeview for files
        file_columns = ("Status", "Filename", "Size", "URL")
        self.file_tree = tb.Treeview(self.file_frame, columns=file_columns, show="tree headings", height=8)
        
        # Configure columns
        self.file_tree.heading("#0", text="", anchor=W)
        self.file_tree.column("#0", width=0, stretch=False)
        for col in file_columns:
            self.file_tree.heading(col, text=col)
            if col == "URL":
                self.file_tree.column(col, width=300)
            else:
                self.file_tree.column(col, width=80)
        
        file_scrollbar = tb.Scrollbar(self.file_frame, orient=VERTICAL, command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=file_scrollbar.set)
        
        self.file_tree.pack(side=LEFT, fill=BOTH, expand=True)
        file_scrollbar.pack(side=RIGHT, fill=Y)
        
        # Bind double-click to open URL
        self.dir_tree.bind("<Double-1>", self.open_url)
        self.file_tree.bind("<Double-1>", self.open_url)
        
        # Statistics frame
        stats_frame = tb.Frame(results_frame)
        stats_frame.pack(fill=X, pady=5)
        
        self.stats_label = tb.Label(
            stats_frame,
            text="📊 Statistics: 0 directories, 0 files found",
            font=("Arial", 10)
        )
        self.stats_label.pack(side=LEFT)

    def on_wordlist_change(self, event=None):
        """Handle wordlist selection change"""
        if self.wordlist_var.get() == "Custom File":
            self.browse_button.config(state=NORMAL)
        else:
            self.browse_button.config(state=DISABLED)

    def browse_wordlist(self):
        """Browse for custom wordlist file"""
        filename = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.custom_wordlist_path = filename
            self.wordlist_var.set(f"Custom: {os.path.basename(filename)}")

    def start_fuzzing(self):
        """Start the directory fuzzing process"""
        url = self.url_var.get().strip()
        
        if not url or not url.startswith(('http://', 'https://')):
            messagebox.showerror("Error", "Please enter a valid URL starting with http:// or https://")
            return
        
        # Clear previous results
        self.clear_results()
        
        # Get wordlist
        wordlist_type = self.wordlist_var.get()
        if wordlist_type == "Small (Quick)":
            wordlist = get_wordlist('small')
        elif wordlist_type.startswith("Custom:"):
            wordlist = None  # Will be loaded from file
        else:
            wordlist = get_wordlist('medium')  # Default
        
        # Create fuzzer instance
        try:
            self.fuzzer = DirectoryFuzzerEngine(
                base_url=url,
                wordlist=wordlist,
                threads=self.threads_var.get(),
                timeout=self.timeout_var.get()
            )
            
            # Load custom wordlist if specified
            if wordlist_type.startswith("Custom:") and hasattr(self, 'custom_wordlist_path'):
                if not self.fuzzer.load_wordlist_from_file(self.custom_wordlist_path):
                    messagebox.showerror("Error", "Failed to load custom wordlist file")
                    return
            
            # Set callbacks
            self.fuzzer.set_progress_callback(self.update_progress)
            self.fuzzer.set_result_callback(self.add_result)
            
            # Start fuzzing in background thread
            self.fuzzing_thread = threading.Thread(target=self._run_fuzzing)
            self.fuzzing_thread.daemon = True
            self.fuzzing_thread.start()
            
            # Update UI state
            self.is_fuzzing = True
            self.start_button.config(state=DISABLED)
            self.stop_button.config(state=NORMAL)
            self.export_button.config(state=DISABLED)
            self.status_label.config(text="Fuzzing started...")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start fuzzing: {str(e)}")

    def _run_fuzzing(self):
        """Run fuzzing in background thread"""
        try:
            self.fuzzer.start_fuzzing()
            
            # Wait for completion
            while self.fuzzer.is_fuzzing_active():
                threading.Event().wait(0.1)
            
            # Update UI when done
            self.window.after(0, self._fuzzing_completed)
            
        except Exception as e:
            self.window.after(0, lambda: messagebox.showerror("Error", f"Fuzzing error: {str(e)}"))

    def _fuzzing_completed(self):
        """Handle fuzzing completion"""
        self.is_fuzzing = False
        self.start_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)
        self.export_button.config(state=NORMAL)
        self.status_label.config(text="Fuzzing completed!")

    def stop_fuzzing(self):
        """Stop the fuzzing process"""
        if self.fuzzer:
            self.fuzzer.stop_fuzzing()
        self.is_fuzzing = False
        self.start_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)
        self.export_button.config(state=NORMAL)
        self.status_label.config(text="Fuzzing stopped.")

    def update_progress(self, progress, processed, total):
        """Update progress bar and status"""
        self.window.after(0, lambda: self._update_progress_ui(progress, processed, total))

    def _update_progress_ui(self, progress, processed, total):
        """Update progress UI elements"""
        self.progress_var.set(progress)
        self.status_label.config(text=f"Progress: {processed}/{total} ({progress:.1f}%)")

    def add_result(self, result):
        """Add a new result to the appropriate tree"""
        self.window.after(0, lambda: self._add_result_ui(result))

    def _add_result_ui(self, result):
        """Add result to UI"""
        status_color = self._get_status_color(result['status_code'])
        
        # Format size
        size_str = f"{result['content_length']} B"
        if result['content_length'] > 1024:
            size_str = f"{result['content_length'] / 1024:.1f} KB"
        
        values = (result['status_code'], result['path'], size_str, result['url'])
        
        if '.' in result['path']:  # File
            item = self.file_tree.insert("", "end", values=values, tags=(status_color,))
            # Update tab text
            file_count = len(self.file_tree.get_children())
            self.notebook.tab(1, text=f"📄 Files ({file_count})")
        else:  # Directory
            item = self.dir_tree.insert("", "end", values=values, tags=(status_color,))
            # Update tab text
            dir_count = len(self.dir_tree.get_children())
            self.notebook.tab(0, text=f"📁 Directories ({dir_count})")
        
        # Configure colors
        for tree in [self.dir_tree, self.file_tree]:
            tree.tag_configure("success", foreground="green")
            tree.tag_configure("redirect", foreground="orange")
            tree.tag_configure("client_error", foreground="red")
            tree.tag_configure("forbidden", foreground="purple")
        
        # Update statistics
        dir_count = len(self.dir_tree.get_children())
        file_count = len(self.file_tree.get_children())
        self.stats_label.config(text=f"📊 Statistics: {dir_count} directories, {file_count} files found")

    def _get_status_color(self, status_code):
        """Get color tag for status code"""
        if status_code == 200:
            return "success"
        elif status_code in [301, 302, 307, 308]:
            return "redirect"
        elif status_code in [401, 403]:
            return "forbidden"
        elif status_code >= 400:
            return "client_error"
        else:
            return "success"

    def clear_results(self):
        """Clear all results"""
        for item in self.dir_tree.get_children():
            self.dir_tree.delete(item)
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        self.notebook.tab(0, text="📁 Directories (0)")
        self.notebook.tab(1, text="📄 Files (0)")
        self.stats_label.config(text="📊 Statistics: 0 directories, 0 files found")
        self.progress_var.set(0)

    def open_url(self, event):
        """Open URL in browser when double-clicked"""
        tree = event.widget
        selection = tree.selection()
        if selection:
            item = selection[0]
            url = tree.item(item)['values'][3]  # URL is the 4th column
            webbrowser.open(url)

    def export_results(self):
        """Export results to file"""
        if not self.fuzzer:
            return
        
        # Create default reports directory
        reports_dir = "/home/amine/Documents/GitHub/Python-ADV-Prog-Project/app/data/reports"
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate default filename with timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = self.url_var.get().replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
        default_filename = f"directory_fuzzing_{target_name}_{timestamp}.txt"
        default_path = os.path.join(reports_dir, default_filename)
        
        filename = filedialog.asksaveasfilename(
            title="Export Results",
            initialdir=reports_dir,
            initialfile=default_filename,
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")]
        )
        
        if filename:
            format_type = "json" if filename.lower().endswith('.json') else "txt"
            if self.fuzzer.export_results(filename, format_type):
                messagebox.showinfo("Success", f"Results exported to {filename}")
            else:
                messagebox.showerror("Error", "Failed to export results")