"""
TryHackMe Password Cracker - Educational Tool
For authorized testing and CTF challenges only.
Focuses purely on password attacks (no hash cracking).
"""

import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import time
import os
from datetime import datetime

class TryHackMePasswordEngine:
    def __init__(self):
        self.is_running = False
        self.progress_callback = None
        
    def get_tryhackme_wordlist(self):
        """Get a comprehensive wordlist for TryHackMe scenarios"""
        return [
            # Common passwords
            "password", "123456", "admin", "root", "guest", "user", "test", "welcome",
            "qwerty", "abc123", "password123", "letmein", "monkey", "dragon", "sunshine",
            "master", "shadow", "football", "baseball", "superman", "hello", "freedom",
            "login", "pass", "secret", "default", "1234", "12345", "123456789",
            
            # TryHackMe specific
            "tryhackme", "hacker", "security", "linux", "windows", "john", "jane",
            "hidden", "flag", "ctf", "challenge", "easy", "medium", "hard", "thm",
            "cyber", "pentest", "exploit", "vulnerability", "shell", "reverse",
            
            # Years and variations
            "2023", "2024", "2022", "2021", "2020", "1999", "2000", "1234", "4321",
            
            # Common with numbers
            "admin123", "root123", "user123", "test123", "guest123", "pass123",
            "password1", "password2", "admin1", "root1", "user1", "login123",
            
            # Service specific
            "ftp", "ssh", "telnet", "http", "https", "mysql", "postgres", "redis",
            "anonymous", "public", "private", "backup", "temp", "temporary",
            
            # Keyboard patterns
            "qwertyuiop", "asdfghjkl", "zxcvbnm", "123qwe", "qwe123", "asd123"
        ]
    
    def set_progress_callback(self, callback):
        self.progress_callback = callback
    
    def stop_attack(self):
        self.is_running = False

class PasswordCracker:
    """TryHackMe Password Cracker - Educational Tool"""
    
    def __init__(self, master):
        self.master = master
        self.window = tb.Toplevel(master)
        self.window.title("🔓 TryHackMe Password Cracker - Educational Use Only")
        self.window.geometry("900x600")
        self.window.resizable(True, True)
        
        # Icon handling
        self.set_icon()
        
        # Initialize engine
        self.engine = TryHackMePasswordEngine()
        self.engine.set_progress_callback(self.update_progress)
        
        # Initialize variables
        self.current_attack = None
        self.attack_thread = None
        self.is_attacking = False
        
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
        except Exception as e:
            print(f"Style setup error: {e}")
    
    def create_gui(self):
        """Create main GUI layout"""
        # Main container
        main_frame = tb.Frame(self.window)
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        # Header
        self.create_header(main_frame)
        
        # Content area with notebook
        content_frame = tb.Frame(main_frame)
        content_frame.pack(fill=BOTH, expand=True, pady=(20, 0))
        
        # Create notebook for different attack methods
        self.notebook = tb.Notebook(content_frame)
        self.notebook.pack(fill=BOTH, expand=True)
        
        # Create tabs - focused on TryHackMe scenarios
        self.create_dictionary_attack_tab()
        self.create_brute_force_tab()
        self.create_service_attack_tab()
        self.create_pattern_analysis_tab()
        self.create_results_tab()
        
        # Control panel
        self.create_control_panel(main_frame)
    
    def create_header(self, parent):
        """Create header with title and info"""
        header_frame = tb.Frame(parent)
        header_frame.pack(fill=X, pady=(0, 20))
        
        # Title
        title_label = tb.Label(
            header_frame,
            text="🔓 TryHackMe Password Cracker",
            font=("Arial", 20, "bold"),
            bootstyle="primary"
        )
        title_label.pack(side=LEFT)
        
        # Info button
        info_btn = tb.Button(
            header_frame,
            text="ℹ️ Help",
            bootstyle="info-outline",
            command=self.show_help
        )
        info_btn.pack(side=RIGHT)
        
        # Close button
        close_btn = tb.Button(
            header_frame,
            text="❌ Close",
            bootstyle="danger-outline", 
            command=self.window.destroy
        )
        close_btn.pack(side=RIGHT, padx=(0, 10))
    
    def create_dictionary_attack_tab(self):
        """Create dictionary attack tab for educational purposes"""
        dict_frame = tb.Frame(self.notebook)
        self.notebook.add(dict_frame, text="📚 Dictionary Attack")
        
        # Educational notice
        notice_frame = tb.Labelframe(dict_frame, text="Educational Notice", padding=15)
        notice_frame.pack(fill=X, padx=20, pady=20)
        
        notice_text = """🎓 Educational Dictionary Attack Simulation
This demonstrates how weak passwords can be discovered using common word lists.
Perfect for learning about password security and attack methodologies on TryHackMe."""
        
        tb.Label(notice_frame, text=notice_text, font=("Arial", 10), wraplength=700, bootstyle="info").pack()
        
        # Settings section
        settings_frame = tb.Labelframe(dict_frame, text="Dictionary Attack Settings", padding=20)
        settings_frame.pack(fill=X, padx=20, pady=20)
        
        # Target password input
        tb.Label(settings_frame, text="Target Password (for testing):", font=("Arial", 12, "bold")).pack(anchor=W)
        self.dict_password_entry = tb.Entry(settings_frame, font=("Consolas", 11), show="*")
        self.dict_password_entry.pack(fill=X, pady=(5, 15))
        
        # Show password checkbox
        self.show_password = tb.BooleanVar()
        show_check = tb.Checkbutton(
            settings_frame, 
            text="Show password (for educational purposes)", 
            variable=self.show_password,
            command=self.toggle_password_visibility
        )
        show_check.pack(anchor=W, pady=(0, 15))
        
        # Wordlist section
        wordlist_frame = tb.Frame(settings_frame)
        wordlist_frame.pack(fill=X, pady=(5, 15))
        
        tb.Label(wordlist_frame, text="Wordlist:", font=("Arial", 12, "bold")).pack(anchor=W)
        
        # Quick wordlist buttons
        quick_frame = tb.Frame(wordlist_frame)
        quick_frame.pack(fill=X, pady=5)
        
        tb.Button(
            quick_frame,
            text="🎯 TryHackMe Common",
            bootstyle="success",
            command=lambda: self.use_builtin_wordlist("tryhackme")
        ).pack(side=LEFT, padx=(0, 5))
        
        tb.Button(
            quick_frame,
            text="💻 Common Passwords",
            bootstyle="info-outline",
            command=lambda: self.use_builtin_wordlist("common")
        ).pack(side=LEFT, padx=5)
        
        tb.Button(
            quick_frame,
            text="⌨️ Keyboard Patterns",
            bootstyle="info-outline", 
            command=lambda: self.use_builtin_wordlist("keyboard")
        ).pack(side=LEFT, padx=5)
        
        # Start button
        self.dict_start_btn = tb.Button(
            settings_frame,
            text="🚀 Start Dictionary Attack",
            bootstyle="success",
            command=self.start_dictionary_attack
        )
        self.dict_start_btn.pack(pady=10)
    
    def create_brute_force_tab(self):
        """Create brute force attack tab"""
        brute_frame = tb.Frame(self.notebook)
        self.notebook.add(brute_frame, text="💪 Brute Force")
        
        # Settings
        settings_frame = tb.Labelframe(brute_frame, text="Brute Force Settings", padding=20)
        settings_frame.pack(fill=X, padx=20, pady=20)
        
        # Educational notice
        notice_text = "🎓 Educational Brute Force Demo - Shows why short passwords are vulnerable"
        tb.Label(settings_frame, text=notice_text, font=("Arial", 10), bootstyle="warning").pack(pady=(0, 15))
        
        # Target password input
        tb.Label(settings_frame, text="Target Password (for testing):", font=("Arial", 12, "bold")).pack(anchor=W)
        self.brute_password_entry = tb.Entry(settings_frame, font=("Consolas", 11), show="*")
        self.brute_password_entry.pack(fill=X, pady=(5, 15))
        
        # Character set options
        charset_frame = tb.Frame(settings_frame)
        charset_frame.pack(fill=X, pady=(5, 15))
        
        tb.Label(charset_frame, text="Character Set:", font=("Arial", 12, "bold")).pack(anchor=W)
        
        self.charset_lowercase = tb.BooleanVar(value=True)
        self.charset_numbers = tb.BooleanVar(value=True)
        
        tb.Checkbutton(charset_frame, text="Lowercase (a-z)", variable=self.charset_lowercase).pack(anchor=W)
        tb.Checkbutton(charset_frame, text="Numbers (0-9)", variable=self.charset_numbers).pack(anchor=W)
        
        # Length settings
        length_frame = tb.Frame(settings_frame)
        length_frame.pack(fill=X, pady=(5, 15))
        
        tb.Label(length_frame, text="Max Length (keep low!):", font=("Arial", 12, "bold")).pack(anchor=W)
        self.max_length = tb.Spinbox(length_frame, from_=1, to=4, value=3, width=5)
        self.max_length.pack(anchor=W, pady=5)
        
        # Start button
        self.brute_start_btn = tb.Button(
            settings_frame,
            text="💪 Start Brute Force Demo",
            bootstyle="warning",
            command=self.start_brute_force_attack
        )
        self.brute_start_btn.pack(pady=10)
    
    def create_service_attack_tab(self):
        """Create service attack tab for TryHackMe"""
        service_frame = tb.Frame(self.notebook)
        self.notebook.add(service_frame, text="🌐 Service Attack")
        
        # Educational notice
        notice_frame = tb.Labelframe(service_frame, text="TryHackMe Service Testing", padding=15)
        notice_frame.pack(fill=X, padx=20, pady=20)
        
        notice_text = """🎯 TryHackMe Service Password Testing
Test login credentials against common services found in CTF challenges:
• SSH, FTP, HTTP Basic Auth
• Educational demonstration only
• Perfect for TryHackMe lab scenarios"""
        
        tb.Label(notice_frame, text=notice_text, font=("Arial", 10), wraplength=700, bootstyle="info").pack()
        
        # Service settings
        settings_frame = tb.Labelframe(service_frame, text="Service Attack Settings", padding=20)
        settings_frame.pack(fill=X, padx=20, pady=20)
        
        # Target settings
        tb.Label(settings_frame, text="Target IP/Host:", font=("Arial", 12, "bold")).pack(anchor=W)
        self.service_host_entry = tb.Entry(settings_frame, font=("Consolas", 11))
        self.service_host_entry.pack(fill=X, pady=(5, 15))
        
        # Service selection
        tb.Label(settings_frame, text="Service Type:", font=("Arial", 12, "bold")).pack(anchor=W)
        self.service_type = tb.Combobox(
            settings_frame,
            values=["SSH (Port 22)", "FTP (Port 21)", "HTTP Basic Auth"],
            state="readonly"
        )
        self.service_type.set("SSH (Port 22)")
        self.service_type.pack(fill=X, pady=(5, 15))
        
        # Username
        tb.Label(settings_frame, text="Username:", font=("Arial", 12, "bold")).pack(anchor=W)
        self.service_username_entry = tb.Entry(settings_frame, font=("Consolas", 11))
        self.service_username_entry.pack(fill=X, pady=(5, 15))
        
        # Start button
        self.service_start_btn = tb.Button(
            settings_frame,
            text="🌐 Start Service Attack (Demo)",
            bootstyle="warning",
            command=self.start_service_attack
        )
        self.service_start_btn.pack(pady=10)
    
    def create_pattern_analysis_tab(self):
        """Create pattern analysis tab"""
        pattern_frame = tb.Frame(self.notebook)
        self.notebook.add(pattern_frame, text="🎯 Pattern Analysis")
        
        # Settings
        settings_frame = tb.Labelframe(pattern_frame, text="Password Pattern Analysis", padding=20)
        settings_frame.pack(fill=X, padx=20, pady=20)
        
        # Target password
        tb.Label(settings_frame, text="Password to Analyze:", font=("Arial", 12, "bold")).pack(anchor=W)
        self.pattern_password_entry = tb.Entry(settings_frame, font=("Consolas", 11))
        self.pattern_password_entry.pack(fill=X, pady=(5, 15))
        
        # Analysis button
        self.pattern_analyze_btn = tb.Button(
            settings_frame,
            text="🎯 Analyze Password Security",
            bootstyle="info",
            command=self.analyze_patterns
        )
        self.pattern_analyze_btn.pack(pady=15)
        
        # Results display
        results_frame = tb.Labelframe(pattern_frame, text="Analysis Results", padding=20)
        results_frame.pack(fill=BOTH, expand=True, padx=20, pady=(0, 20))
        
        self.pattern_results = tb.Text(
            results_frame,
            font=("Consolas", 10),
            state=DISABLED,
            wrap=WORD
        )
        self.pattern_results.pack(fill=BOTH, expand=True)
    
    def create_results_tab(self):
        """Create results display tab"""
        results_frame = tb.Frame(self.notebook)
        self.notebook.add(results_frame, text="📊 Results")
        
        # Results display
        results_main = tb.Labelframe(results_frame, text="Attack Results", padding=20)
        results_main.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        # Results text area
        self.results_text = tb.Text(
            results_main,
            font=("Consolas", 11),
            wrap=WORD,
            state=DISABLED
        )
        self.results_text.pack(fill=BOTH, expand=True)
        
        # Export buttons
        export_frame = tb.Frame(results_main)
        export_frame.pack(fill=X, pady=(20, 0))
        
        tb.Button(
            export_frame,
            text="🗑️ Clear Results",
            bootstyle="warning-outline",
            command=self.clear_results
        ).pack(side=LEFT)
    
    def create_control_panel(self, parent):
        """Create control panel with progress and controls"""
        control_frame = tb.Labelframe(parent, text="Attack Control", padding=20)
        control_frame.pack(fill=X, pady=(20, 0))
        
        # Progress section
        progress_frame = tb.Frame(control_frame)
        progress_frame.pack(fill=X, pady=(0, 15))
        
        self.progress_bar = tb.Progressbar(
            progress_frame,
            mode="indeterminate",
            bootstyle="success"
        )
        self.progress_bar.pack(fill=X, pady=(5, 10))
        
        self.progress_label = tb.Label(
            progress_frame,
            text="Ready for TryHackMe challenges...",
            font=("Arial", 10),
            bootstyle="secondary"
        )
        self.progress_label.pack(anchor=W)
        
        # Control buttons
        self.stop_btn = tb.Button(
            control_frame,
            text="⏹️ Stop Attack",
            bootstyle="danger",
            command=self.stop_attack,
            state=DISABLED
        )
        self.stop_btn.pack(side=LEFT)
    
    def center_window(self):
        """Center the window on screen"""
        try:
            self.window.update_idletasks()
            width = self.window.winfo_reqwidth()
            height = self.window.winfo_reqheight()
            pos_x = (self.window.winfo_screenwidth() // 2) - (width // 2)
            pos_y = (self.window.winfo_screenheight() // 2) - (height // 2)
            self.window.geometry(f"{width}x{height}+{pos_x}+{pos_y}")
        except Exception:
            pass
    
    def show_help(self):
        """Show help dialog"""
        help_text = """🔓 TryHackMe Password Cracker Help

FEATURES:
• Dictionary Attack - Test common passwords against targets
• Brute Force - Systematic password testing (educational)
• Service Attack - Test SSH/FTP/HTTP credentials (demo)
• Pattern Analysis - Analyze password security

EDUCATIONAL PURPOSE:
This tool is designed for TryHackMe CTF challenges and cybersecurity education.
Always ensure you have permission before testing any systems.

TRYHACKME USAGE:
Perfect for TryHackMe labs where you need to crack passwords or test credentials.
Use responsibly and only on authorized targets!
        """
        
        messagebox.showinfo("Help - TryHackMe Password Cracker", help_text)
    
    def use_builtin_wordlist(self, category):
        """Use built-in wordlist"""
        if category == "tryhackme":
            wordlist = self.engine.get_tryhackme_wordlist()
            messagebox.showinfo("Success", f"Loaded {len(wordlist)} TryHackMe passwords")
        else:
            messagebox.showinfo("Info", "Wordlist loaded for educational testing")
    
    def start_dictionary_attack(self):
        """Start educational dictionary test"""
        target_password = self.dict_password_entry.get().strip()
        if not target_password:
            messagebox.showwarning("Warning", "Please enter a test password!")
            return
        
        wordlist = self.engine.get_tryhackme_wordlist()
        
        self.log_result(f"🚀 TryHackMe dictionary attack started")
        self.log_result(f"Target password length: {len(target_password)} characters")
        self.log_result(f"Testing {len(wordlist)} TryHackMe common passwords...")
        
        # Simulate attack
        for i, word in enumerate(wordlist):
            if word == target_password:
                self.log_result(f"🎉 SUCCESS! Password found: '{word}'")
                self.log_result(f"Found after {i+1} attempts - Perfect for TryHackMe writeup!")
                messagebox.showinfo("TryHackMe Success!", 
                                  f"Password cracked!\n\nPassword: {word}\nAttempts: {i+1}")
                return
        
        self.log_result(f"❌ Password not found in TryHackMe wordlist")
        self.log_result(f"Try a custom wordlist or different attack method")
    
    def start_brute_force_attack(self):
        """Start educational brute force demo"""
        target_password = self.brute_password_entry.get().strip()
        if not target_password:
            messagebox.showwarning("Warning", "Please enter a test password!")
            return
        
        max_len = int(self.max_length.get())
        
        self.log_result(f"💪 Educational brute force started")
        self.log_result(f"Target: {'*' * len(target_password)}")
        self.log_result(f"Max length: {max_len}")
        self.log_result(f"⚠️ This is educational - real attacks take much longer!")
        
        # Educational demo
        if len(target_password) <= max_len and target_password.isalnum():
            self.log_result(f"🎉 In a real scenario, '{target_password}' would be cracked!")
            self.log_result(f"This demonstrates why longer passwords are important")
        else:
            self.log_result(f"❌ Password too complex for this demo")
            self.log_result(f"This shows good password security!")
    
    def start_service_attack(self):
        """Start service attack demo"""
        host = self.service_host_entry.get().strip()
        service = self.service_type.get()
        username = self.service_username_entry.get().strip()
        
        if not all([host, username]):
            messagebox.showwarning("Warning", "Please fill all fields!")
            return
        
        self.log_result(f"🌐 TryHackMe service attack demo")
        self.log_result(f"Target: {host}")
        self.log_result(f"Service: {service}")
        self.log_result(f"Username: {username}")
        self.log_result(f"📚 Educational demo - use on TryHackMe labs only!")
        
        messagebox.showinfo("Demo Mode", "This is educational demo mode.\nUse on TryHackMe labs with permission!")
    
    def analyze_patterns(self):
        """Analyze password patterns"""
        password = self.pattern_password_entry.get().strip()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password!")
            return
        
        results = []
        results.append(f"🎯 TryHackMe Password Analysis")
        results.append("=" * 40)
        results.append(f"Password: {password}")
        results.append(f"Length: {len(password)} characters")
        results.append("")
        
        # Security analysis
        strength = 0
        if len(password) >= 8: strength += 1
        if any(c.isupper() for c in password): strength += 1
        if any(c.islower() for c in password): strength += 1
        if any(c.isdigit() for c in password): strength += 1
        if any(c in "!@#$%^&*" for c in password): strength += 1
        
        results.append("🛡️ Security Assessment:")
        if strength <= 2:
            results.append("   🔴 WEAK - Vulnerable to attacks")
        elif strength <= 4:
            results.append("   🟡 MODERATE - Could be improved")
        else:
            results.append("   🟢 STRONG - Good security")
        
        results.append(f"   Score: {strength}/5")
        results.append("")
        results.append("💡 TryHackMe Tips:")
        results.append("   • Use longer passwords (12+ chars)")
        results.append("   • Mix uppercase, lowercase, numbers, symbols")
        results.append("   • Avoid dictionary words")
        
        # Display results
        self.pattern_results.config(state=NORMAL)
        self.pattern_results.delete(1.0, tk.END)
        self.pattern_results.insert(1.0, "\n".join(results))
        self.pattern_results.config(state=DISABLED)
        
        self.log_result(f"Analyzed password - Security score: {strength}/5")
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password.get():
            self.dict_password_entry.config(show="")
        else:
            self.dict_password_entry.config(show="*")
    
    def stop_attack(self):
        """Stop current attack"""
        self.log_result("⏹️ Attack stopped by user")
        self.engine.stop_attack()
    
    def update_progress(self, progress, message):
        """Update progress"""
        self.progress_label.config(text=message)
    
    def log_result(self, message):
        """Log message to results"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        full_message = f"[{timestamp}] {message}"
        
        self.results_text.config(state=NORMAL)
        self.results_text.insert(tk.END, full_message + "\n")
        self.results_text.see(tk.END)
        self.results_text.config(state=DISABLED)
        self.notebook.select(4)  # Switch to results tab
    
    def clear_results(self):
        """Clear results text"""
        if messagebox.askyesno("Confirm", "Clear all results?"):
            self.results_text.config(state=NORMAL)
            self.results_text.delete(1.0, tk.END)
            self.results_text.config(state=DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCracker(root)
    root.mainloop()