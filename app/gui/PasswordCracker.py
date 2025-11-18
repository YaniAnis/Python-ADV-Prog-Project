"""
Advanced Password Cracker GUI
Educational cybersecurity tool for authorized testing only.

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

import sys
from datetime import datetime

# Add parent directory to path for imports
current_dir = os.path.dirname(__file__)
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

try:
    from utils.password_cracker import PasswordCrackerEngine, HashAnalyzer, PasswordGenerator
    print("✅ Successfully imported password cracking engines")
except ImportError as e:
    print(f"❌ Import error: {e}")
    print(f"Current dir: {current_dir}")
    print(f"Parent dir: {parent_dir}")
    print(f"Python path: {sys.path}")
    
    # Try alternative import methods
    try:
        sys.path.append(os.path.join(parent_dir, 'utils'))
        import password_cracker
        PasswordCrackerEngine = password_cracker.PasswordCrackerEngine
        HashAnalyzer = password_cracker.HashAnalyzer
        PasswordGenerator = password_cracker.PasswordGenerator
        print("✅ Successfully imported using alternative method")
    except ImportError as e2:
        print(f"❌ Alternative import failed: {e2}")
        # Create mock classes for demonstration
        class MockEngine:
            def __init__(self):
                self.is_running = False
                self.progress_callback = None
            
            def detect_hash_type(self, hash_str):
                length = len(hash_str.strip())
                if length == 32:
                    return "md5"
                elif length == 40:
                    return "sha1"
                elif length == 64:
                    return "sha256"
                else:
                    return "unknown"
            
            def get_common_passwords(self):
                return ["password", "123456", "admin", "test", "guest", "root", "login", "welcome"]
            
            def set_progress_callback(self, callback):
                self.progress_callback = callback
            
            def stop_attack(self):
                self.is_running = False
        
        PasswordCrackerEngine = MockEngine
        HashAnalyzer = MockEngine
        PasswordGenerator = None

class PasswordCracker:
   """Advanced Password Cracker with comprehensive GUI"""
   
   def __init__(self, master):
       self.master = master
       self.window = tb.Toplevel(master)
       self.window.title("🔓 TryHackMe Password Cracker")
       self.window.geometry("1200x800")
       self.window.resizable(True, True)
       
       # Icon handling
       self.set_icon()
       
       # Initialize engine
       if PasswordCrackerEngine:
           self.engine = PasswordCrackerEngine()
           self.engine.set_progress_callback(self.update_progress)
       else:
           self.engine = None
           messagebox.showerror("Error", "Password cracking engine not available!")
           self.window.destroy()
           return
       
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
           
           # Card style
           self.style.configure(
               "Card.TFrame",
               relief="flat",
               borderwidth=1,
               background="#ffffff"
           )
           
           # Results style
           self.style.configure(
               "Results.TText",
               font=("Consolas", 11),
               background="#f8f9fa"
           )
           
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
       
       # Create tabs - focused on TryHackMe CTF scenarios
       self.create_hash_cracking_tab()
       self.create_dictionary_attack_tab()
       self.create_brute_force_tab()
       self.create_wordlist_generator_tab()
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
           font=("Arial", 24, "bold"),
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
   
   def create_hash_cracking_tab(self):
       """Create hash cracking tab for TryHackMe CTF challenges"""
       hash_frame = tb.Frame(self.notebook)
       self.notebook.add(hash_frame, text="🔍 Hash Cracking")
       
       # TryHackMe Description  
       desc_frame = tb.Labelframe(hash_frame, text="TryHackMe Hash Cracking", padding=20)
       desc_frame.pack(fill=X, padx=20, pady=20)
       
       desc_text = """🚀 TryHackMe CTF Hash Cracking Tool
Perfect for TryHackMe labs and CTF challenges:
• Crack MD5, SHA1, SHA256 hashes from challenges
• Support for multiple hash formats
• Built-in common wordlists for CTF scenarios
• Quick hash identification and analysis
• Export results for writeups

⚠️ For authorized TryHackMe labs and educational CTF challenges only!"""
       
       tb.Label(desc_frame, text=desc_text, font=("Arial", 10), wraplength=800, bootstyle="info").pack(anchor=W)
       
       # Hash Input Section
       input_frame = tb.Labelframe(hash_frame, text="Hash Input & Analysis", padding=20)
       input_frame.pack(fill=X, padx=20, pady=(0, 20))
       
       # Hash input
       tb.Label(input_frame, text="Target Hash (from TryHackMe):", font=("Arial", 12, "bold")).pack(anchor=W)
       self.hash_input = tb.Text(input_frame, height=3, font=("Consolas", 11))
       self.hash_input.pack(fill=X, pady=(5, 15))
       
       # Hash type detection
       detection_frame = tb.Frame(input_frame)
       detection_frame.pack(fill=X, pady=(0, 15))
       
       tb.Button(
           detection_frame,
           text="🔍 Auto-Detect Hash Type",
           bootstyle="info",
           command=self.detect_hash_type
       ).pack(side=LEFT)
       
       self.hash_type_result = tb.Label(
           detection_frame,
           text="Hash type: Unknown",
           font=("Arial", 11),
           bootstyle="secondary"
       )
       self.hash_type_result.pack(side=LEFT, padx=(20, 0))
       
       # Manual hash type selection
       tb.Label(input_frame, text="Or select hash type manually:", font=("Arial", 11)).pack(anchor=W)
       self.manual_hash_type = tb.Combobox(
           input_frame,
           values=["MD5", "SHA1", "SHA256", "SHA512", "NTLM", "SHA224", "SHA384"],
           state="readonly",
           width=20
       )
       self.manual_hash_type.pack(anchor=W, pady=(5, 15))
       
       # Quick crack section
       quick_frame = tb.Frame(input_frame)
       quick_frame.pack(fill=X, pady=10)
       
       tb.Button(
           quick_frame,
           text="⚡ Quick Crack (Common Passwords)",
           bootstyle="warning",
           command=self.quick_crack_hash
       ).pack(side=LEFT)
       
       tb.Button(
           quick_frame,
           text="📚 Dictionary Crack",
           bootstyle="primary",
           command=self.start_hash_dictionary_attack
       ).pack(side=LEFT, padx=(10, 0))
       
       # Results display
       results_frame = tb.Labelframe(hash_frame, text="Cracking Results", padding=20)
       results_frame.pack(fill=BOTH, expand=True, padx=20, pady=(0, 20))
       
       self.hash_results = tb.Text(
           results_frame,
           font=("Consolas", 11),
           state=DISABLED,
           wrap=WORD
       )
       
       # Scrollbar
       hash_scroll = tb.Scrollbar(results_frame, orient=VERTICAL, command=self.hash_results.yview)
       self.hash_results.configure(yscrollcommand=hash_scroll.set)
       
       self.hash_results.pack(side=LEFT, fill=BOTH, expand=True)
       hash_scroll.pack(side=RIGHT, fill=Y)
   
   def create_dictionary_attack_tab(self):
       """Create dictionary attack tab for educational purposes"""
       dict_frame = tb.Frame(self.notebook)
       self.notebook.add(dict_frame, text="📚 Dictionary Attack")
       
       # Educational notice
       notice_frame = tb.Labelframe(dict_frame, text="Educational Notice", padding=15)
       notice_frame.pack(fill=X, padx=20, pady=20)
       
       notice_text = """🎓 Educational Dictionary Attack Simulation
This demonstrates how weak passwords can be discovered using common word lists.
Perfect for learning about password security and attack methodologies."""
       
       tb.Label(notice_frame, text=notice_text, font=("Arial", 10), wraplength=700, bootstyle="info").pack()
       
       # Settings section
       settings_frame = tb.Labelframe(dict_frame, text="Educational Password Testing", padding=20)
       settings_frame.pack(fill=X, padx=20, pady=20)
       
       # Target password input (for educational testing)
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
       
       wordlist_input_frame = tb.Frame(wordlist_frame)
       wordlist_input_frame.pack(fill=X, pady=5)
       
       self.dict_wordlist_entry = tb.Entry(wordlist_input_frame, font=("Consolas", 10))
       self.dict_wordlist_entry.pack(side=LEFT, fill=X, expand=True)
       
       browse_btn = tb.Button(
           wordlist_input_frame,
           text="📁 Browse",
           command=self.browse_wordlist
       )
       browse_btn.pack(side=RIGHT, padx=(10, 0))
       
       # Quick wordlist buttons
       quick_frame = tb.Frame(wordlist_frame)
       quick_frame.pack(fill=X, pady=5)
       
       tb.Button(
           quick_frame,
           text="Common Passwords",
           bootstyle="info-outline",
           command=lambda: self.use_builtin_wordlist("common")
       ).pack(side=LEFT, padx=(0, 5))
       
       tb.Button(
           quick_frame,
           text="Keyboard Patterns",
           bootstyle="info-outline", 
           command=lambda: self.use_builtin_wordlist("keyboard")
       ).pack(side=LEFT, padx=5)
       
       tb.Button(
           quick_frame,
           text="Numeric Patterns",
           bootstyle="info-outline",
           command=lambda: self.use_builtin_wordlist("numeric")
       ).pack(side=LEFT, padx=5)
       
       # Start button
       self.dict_start_btn = tb.Button(
           settings_frame,
           text="🚀 Start Educational Dictionary Test",
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
       
       # Show password option
       self.show_brute_password = tb.BooleanVar()
       tb.Checkbutton(
           settings_frame, 
           text="Show password (educational)", 
           variable=self.show_brute_password,
           command=self.toggle_brute_password_visibility
       ).pack(anchor=W, pady=(0, 15))
       
       # Character set
       charset_frame = tb.Frame(settings_frame)
       charset_frame.pack(fill=X, pady=(5, 15))
       
       tb.Label(charset_frame, text="Character Set:", font=("Arial", 12, "bold")).pack(anchor=W)
       
       charset_options = tb.Frame(charset_frame)
       charset_options.pack(fill=X, pady=5)
       
       self.charset_lowercase = tb.BooleanVar(value=True)
       self.charset_uppercase = tb.BooleanVar(value=False)
       self.charset_numbers = tb.BooleanVar(value=True)
       self.charset_symbols = tb.BooleanVar(value=False)
       
       tb.Checkbutton(charset_options, text="Lowercase (a-z)", variable=self.charset_lowercase).pack(side=LEFT)
       tb.Checkbutton(charset_options, text="Uppercase (A-Z)", variable=self.charset_uppercase).pack(side=LEFT, padx=10)
       tb.Checkbutton(charset_options, text="Numbers (0-9)", variable=self.charset_numbers).pack(side=LEFT, padx=10)
       tb.Checkbutton(charset_options, text="Symbols", variable=self.charset_symbols).pack(side=LEFT, padx=10)
       
       # Custom charset
       tb.Label(charset_frame, text="Custom Character Set:", font=("Arial", 10)).pack(anchor=W, pady=(10, 0))
       self.custom_charset = tb.Entry(charset_frame, font=("Consolas", 10))
       self.custom_charset.pack(fill=X, pady=5)
       
       # Length settings
       length_frame = tb.Frame(settings_frame)
       length_frame.pack(fill=X, pady=(5, 15))
       
       tb.Label(length_frame, text="Password Length:", font=("Arial", 12, "bold")).pack(anchor=W)
       
       length_controls = tb.Frame(length_frame)
       length_controls.pack(fill=X, pady=5)
       
       tb.Label(length_controls, text="Min:").pack(side=LEFT)
       self.min_length = tb.Spinbox(length_controls, from_=1, to=10, value=1, width=5)
       self.min_length.pack(side=LEFT, padx=(5, 20))
       
       tb.Label(length_controls, text="Max:").pack(side=LEFT)
       self.max_length = tb.Spinbox(length_controls, from_=1, to=10, value=4, width=5)
       self.max_length.pack(side=LEFT, padx=5)
       
       tb.Label(length_controls, text="⚠️ Keep max length low for performance!", bootstyle="warning").pack(side=LEFT, padx=20)
       
       # Start button
       self.brute_start_btn = tb.Button(
           settings_frame,
           text="💪 Start Educational Brute Force Demo",
           bootstyle="warning",
           command=self.start_brute_force_attack
       )
       self.brute_start_btn.pack(pady=10)
   
   def create_wordlist_generator_tab(self):
       """Create pattern attack tab for educational purposes"""
       pattern_frame = tb.Frame(self.notebook)
       self.notebook.add(pattern_frame, text="🎯 Pattern Attack")
       
       # Educational description
       desc_frame = tb.Labelframe(pattern_frame, text="Educational Pattern Analysis", padding=20)
       desc_frame.pack(fill=X, padx=20, pady=20)
       
       desc_text = """🎓 Pattern Attack Educational Tool
Learn how attackers identify and exploit common password patterns:
• Keyboard patterns (qwerty, 123456, asdf)
• Date patterns (1990, 2023, birth years)
• Name + number combinations (john123, admin2023)
• Common substitutions (@ for a, 3 for e)

This helps you understand why complex passwords are important!"""
       
       tb.Label(desc_frame, text=desc_text, font=("Arial", 10), wraplength=800).pack(anchor=W)
       
       # Pattern settings
       settings_frame = tb.Labelframe(pattern_frame, text="Pattern Analysis Settings", padding=20)
       settings_frame.pack(fill=X, padx=20, pady=20)
       
       # Target password
       tb.Label(settings_frame, text="Test Password:", font=("Arial", 12, "bold")).pack(anchor=W)
       self.pattern_password_entry = tb.Entry(settings_frame, font=("Consolas", 11), show="*")
       self.pattern_password_entry.pack(fill=X, pady=(5, 15))
       
       # Pattern types to test
       patterns_frame = tb.Labelframe(settings_frame, text="Patterns to Test", padding=15)
       patterns_frame.pack(fill=X, pady=(0, 15))
       
       self.test_keyboard = tb.BooleanVar(value=True)
       self.test_dates = tb.BooleanVar(value=True)
       self.test_names = tb.BooleanVar(value=True)
       self.test_substitutions = tb.BooleanVar(value=True)
       
       tb.Checkbutton(patterns_frame, text="⌨️ Keyboard patterns (qwerty, 123456)", variable=self.test_keyboard).pack(anchor=W)
       tb.Checkbutton(patterns_frame, text="📅 Date patterns (years, months)", variable=self.test_dates).pack(anchor=W)
       tb.Checkbutton(patterns_frame, text="👤 Name patterns (common names)", variable=self.test_names).pack(anchor=W)
       tb.Checkbutton(patterns_frame, text="🔤 Character substitutions (@ for a)", variable=self.test_substitutions).pack(anchor=W)
       
       # Analysis button
       self.pattern_analyze_btn = tb.Button(
           settings_frame,
           text="🎯 Analyze Password Patterns",
           bootstyle="warning",
           command=self.analyze_patterns
       )
       self.pattern_analyze_btn.pack(pady=15)
       
       # Results display
       results_frame = tb.Labelframe(pattern_frame, text="Pattern Analysis Results", padding=20)
       results_frame.pack(fill=BOTH, expand=True, padx=20, pady=(0, 20))
       
       self.pattern_results = tb.Text(
           results_frame,
           font=("Consolas", 10),
           state=DISABLED,
           wrap=WORD
       )
       
       pattern_scroll = tb.Scrollbar(results_frame, orient=VERTICAL, command=self.pattern_results.yview)
       self.pattern_results.configure(yscrollcommand=pattern_scroll.set)
       
       self.pattern_results.pack(side=LEFT, fill=BOTH, expand=True)
       pattern_scroll.pack(side=RIGHT, fill=Y)
   
   def create_results_tab(self):
       """Create results display tab"""
       results_frame = tb.Frame(self.notebook)
       self.notebook.add(results_frame, text="📊 Results")
       
       # Results display
       results_main = tb.Labelframe(results_frame, text="Attack Results", padding=20)
       results_main.pack(fill=BOTH, expand=True, padx=20, pady=20)
       
       # Results text area
       text_frame = tb.Frame(results_main)
       text_frame.pack(fill=BOTH, expand=True)
       
       self.results_text = tb.Text(
           text_frame,
           font=("Consolas", 11),
           wrap=WORD,
           state=DISABLED
       )
       
       results_scroll = tb.Scrollbar(text_frame, orient=VERTICAL, command=self.results_text.yview)
       self.results_text.configure(yscrollcommand=results_scroll.set)
       
       self.results_text.pack(side=LEFT, fill=BOTH, expand=True)
       results_scroll.pack(side=RIGHT, fill=Y)
       
       # Export buttons
       export_frame = tb.Frame(results_main)
       export_frame.pack(fill=X, pady=(20, 0))
       
       tb.Button(
           export_frame,
           text="💾 Export Results",
           bootstyle="info-outline",
           command=self.export_results
       ).pack(side=LEFT)
       
       tb.Button(
           export_frame,
           text="🗑️ Clear Results",
           bootstyle="warning-outline",
           command=self.clear_results
       ).pack(side=LEFT, padx=10)
   
   def create_control_panel(self, parent):
       """Create control panel with progress and controls"""
       control_frame = tb.Labelframe(parent, text="Attack Control", padding=20)
       control_frame.pack(fill=X, pady=(20, 0))
       
       # Progress section
       progress_frame = tb.Frame(control_frame)
       progress_frame.pack(fill=X, pady=(0, 15))
       
       tb.Label(progress_frame, text="Progress:", font=("Arial", 12, "bold")).pack(anchor=W)
       
       self.progress_bar = tb.Progressbar(
           progress_frame,
           mode="determinate",
           bootstyle="success"
       )
       self.progress_bar.pack(fill=X, pady=(5, 10))
       
       self.progress_label = tb.Label(
           progress_frame,
           text="Ready to start attack...",
           font=("Arial", 10),
           bootstyle="secondary"
       )
       self.progress_label.pack(anchor=W)
       
       # Control buttons
       buttons_frame = tb.Frame(control_frame)
       buttons_frame.pack(fill=X)
       
       self.stop_btn = tb.Button(
           buttons_frame,
           text="⏹️ Stop Attack",
           bootstyle="danger",
           command=self.stop_attack,
           state=DISABLED
       )
       self.stop_btn.pack(side=LEFT)
       
       # Status indicator
       status_frame = tb.Frame(buttons_frame)
       status_frame.pack(side=RIGHT)
       
       self.status_label = tb.Label(
           status_frame,
           text="🟢 Ready",
           font=("Arial", 12, "bold"),
           bootstyle="success"
       )
       self.status_label.pack(side=RIGHT)
   
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
   
   # Event handlers and functionality methods continue in next part...
   
   def show_help(self):
       """Show help dialog"""
       help_text = """
🔓 Advanced Password Cracker Help

FEATURES:
• Hash Analysis - Identify hash types and security levels
• Dictionary Attack - Use wordlists to crack passwords
• Brute Force - Try all combinations systematically
• Hybrid Attack - Combine words with modifications
• Smart Attack - Intelligent strategy selection

USAGE TIPS:
1. Start with Hash Analysis to identify the hash type
2. For weak hashes (MD5, SHA1), try Dictionary attacks first
3. Use Brute Force only for short passwords (max 4-6 chars)
4. Hybrid attacks are effective for common password patterns
5. Smart Attack automatically combines multiple strategies

EDUCATIONAL PURPOSE:
This tool is designed for cybersecurity education and authorized testing only.
Always ensure you have permission before testing any systems.

SUPPORTED HASH TYPES:
• MD5, SHA1, SHA224, SHA256, SHA384, SHA512
• And more with automatic detection

For TryHackMe and educational labs, this tool provides comprehensive
password analysis and cracking capabilities.
       """
       
       help_window = tb.Toplevel(self.window)
       help_window.title("Help - Password Cracker")
       help_window.geometry("600x500")
       help_window.resizable(False, False)
       
       help_window.transient(self.window)
       help_window.grab_set()
       
       # Position relative to parent
       x = self.window.winfo_x() + 100
       y = self.window.winfo_y() + 100
       help_window.geometry(f"600x500+{x}+{y}")
       
       # Help content
       content_frame = tb.Frame(help_window, padding=20)
       content_frame.pack(fill=BOTH, expand=True)
       
       help_text_widget = tb.Text(
           content_frame,
           font=("Arial", 10),
           wrap=WORD,
           state=NORMAL
       )
       help_text_widget.pack(fill=BOTH, expand=True)
       help_text_widget.insert(1.0, help_text)
       help_text_widget.config(state=DISABLED)
       
       # Close button
       tb.Button(
           content_frame,
           text="Close",
           bootstyle="primary",
           command=help_window.destroy
       ).pack(pady=(20, 0))
   
   def analyze_hash(self):
       """Analyze the entered hash"""
       hash_text = self.hash_entry.get(1.0, tk.END).strip()
       if not hash_text:
           messagebox.showwarning("Warning", "Please enter a hash to analyze!")
           return
       
       result_text = f"""🔍 HASH ANALYSIS RESULTS
{'='*50}

📋 Hash Information:
  Hash: {hash_text}
  Length: {len(hash_text)} characters
  Possible Type: {self.engine.detect_hash_type(hash_text) if self.engine else 'Unknown'}

📅 Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
🎓 Educational tool - Use responsibly!
"""
       
       self.analysis_results.config(state=NORMAL)
       self.analysis_results.delete(1.0, tk.END)
       self.analysis_results.insert(1.0, result_text)
       self.analysis_results.config(state=DISABLED)
   
   def browse_wordlist(self):
       """Browse for wordlist file"""
       filename = filedialog.askopenfilename(
           title="Select Wordlist File",
           filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
       )
       if filename:
           self.dict_wordlist_entry.delete(0, tk.END)
           self.dict_wordlist_entry.insert(0, filename)
   
   def use_builtin_wordlist(self, category):
       """Use built-in wordlist"""
       if not self.engine:
           messagebox.showerror("Error", "Engine not available!")
           return
       
       wordlist = self.engine.get_common_passwords()
       import tempfile
       temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
       temp_file.write('\n'.join(wordlist))
       temp_file.close()
       
       self.dict_wordlist_entry.delete(0, tk.END)
       self.dict_wordlist_entry.insert(0, temp_file.name)
       messagebox.showinfo("Success", f"Loaded {len(wordlist)} {category} passwords")
   
   def load_common_words(self):
       """Load common words into hybrid attack"""
       common_words = ["password", "admin", "user", "test", "guest", "root", "login", "welcome"]
       self.hybrid_words.delete(1.0, tk.END)
       self.hybrid_words.insert(1.0, '\n'.join(common_words))
   
   def start_dictionary_attack(self):
       """Start educational dictionary test"""
       target_password = self.dict_password_entry.get().strip()
       if not target_password:
           messagebox.showwarning("Warning", "Please enter a test password!")
           return
       
       # Get wordlist file
       wordlist_file = self.dict_wordlist_entry.get().strip()
       
       if not wordlist_file:
           # Use built-in wordlist
           if not self.engine:
               messagebox.showerror("Error", "Engine not available!")
               return
           wordlist = self.engine.get_common_passwords()
       else:
           # Load from file
           try:
               with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                   wordlist = [line.strip() for line in f if line.strip()]
           except Exception as e:
               messagebox.showerror("Error", f"Failed to load wordlist: {str(e)}")
               return
       
       self.log_result(f"🚀 Educational dictionary test started")
       self.log_result(f"Target password length: {len(target_password)} characters")
       self.log_result(f"Testing against {len(wordlist)} dictionary words...")
       
       # Simulate dictionary attack
       found = False
       attempts = 0
       
       for word in wordlist[:100]:  # Limit to first 100 for demo
           attempts += 1
           
           # Test word and common variations
           test_words = [
               word,
               word.upper(),
               word.capitalize(),
               word + "123",
               word + "1",
               word + "!",
               word + "2023"
           ]
           
           for test_word in test_words:
               if test_word == target_password:
                   found = True
                   self.log_result(f"🎉 SUCCESS! Password found: '{test_word}'")
                   self.log_result(f"Found after {attempts} dictionary words tested")
                   self.log_result(f"This demonstrates why '{target_password}' is weak!")
                   messagebox.showinfo("Educational Demo", 
                                     f"Password found!\n\n"
                                     f"'{test_word}' was discovered after testing {attempts} words.\n"
                                     f"This shows why simple passwords are vulnerable!")
                   return
       
       if not found:
           self.log_result(f"❌ Password not found in first {attempts} dictionary words")
           self.log_result(f"This suggests '{target_password}' is more secure against dictionary attacks")
           messagebox.showinfo("Educational Demo",
                             f"Password not found in common dictionary!\n\n"
                             f"Tested {attempts} common words and variations.\n" 
                             f"This suggests better password security.")
   
   def start_brute_force_attack(self):
       """Start educational brute force demo"""
       target_password = self.brute_password_entry.get().strip()
       if not target_password:
           messagebox.showwarning("Warning", "Please enter a test password!")
           return
       
       if len(target_password) > 4:
           result = messagebox.askyesno("Performance Warning",
                                      f"Brute forcing passwords longer than 4 characters can take very long!\n"
                                      f"Your password is {len(target_password)} characters.\n\n"
                                      f"Continue with educational demo anyway?")
           if not result:
               return
       
       # Build charset
       charset = ""
       if self.charset_lowercase.get():
           charset += "abcdefghijklmnopqrstuvwxyz"
       if self.charset_uppercase.get():
           charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
       if self.charset_numbers.get():
           charset += "0123456789"
       if self.charset_symbols.get():
           charset += "!@#$%^&*"
       
       custom = self.custom_charset.get().strip()
       if custom:
           charset = custom
       
       if not charset:
           messagebox.showwarning("Warning", "Please select character set!")
           return
       
       # Get length settings
       try:
           min_len = int(self.min_length.get())
           max_len = min(int(self.max_length.get()), 5)  # Limit for demo
       except ValueError:
           messagebox.showerror("Error", "Invalid length values!")
           return
       
       self.log_result(f"💪 Educational brute force demo started")
       self.log_result(f"Target password: {'*' * len(target_password)}")
       self.log_result(f"Character set: {charset}")
       self.log_result(f"Testing lengths {min_len}-{max_len}")
       
       # Educational brute force simulation
       import itertools
       attempts = 0
       max_attempts = 10000  # Limit for demo
       
       for length in range(min_len, max_len + 1):
           if attempts >= max_attempts:
               break
           
           self.log_result(f"Testing length {length}...")
           
           for password_tuple in itertools.product(charset, repeat=length):
               attempts += 1
               test_password = ''.join(password_tuple)
               
               if test_password == target_password:
                   self.log_result(f"🎉 SUCCESS! Password found: '{test_password}'")
                   self.log_result(f"Found after {attempts} attempts")
                   self.log_result(f"This demonstrates brute force vulnerability!")
                   messagebox.showinfo("Educational Demo",
                                     f"Password cracked!\n\n"
                                     f"'{test_password}' found after {attempts} attempts.\n"
                                     f"This shows why longer passwords are important!")
                   return
               
               if attempts >= max_attempts:
                   break
               
               # Update every 1000 attempts
               if attempts % 1000 == 0:
                   self.log_result(f"Tested {attempts} combinations...")
       
       self.log_result(f"❌ Password not found after {attempts} attempts")
       self.log_result(f"This suggests the password is more secure against brute force")
       messagebox.showinfo("Educational Demo",
                         f"Password not found!\n\n"
                         f"Tested {attempts} combinations without success.\n"
                         f"This demonstrates better password security!")
   
   def toggle_brute_password_visibility(self):
       """Toggle brute force password visibility"""
       if self.show_brute_password.get():
           self.brute_password_entry.config(show="")
       else:
           self.brute_password_entry.config(show="*")
   
   def start_hybrid_attack(self):
       """Start hybrid attack"""
       target_hash = self.hybrid_hash_entry.get().strip()
       if not target_hash:
           messagebox.showwarning("Warning", "Please enter target hash!")
           return
       self.log_result(f"🔄 Hybrid attack started for: {target_hash[:20]}...")
   
   def start_smart_attack(self):
       """Start smart attack"""
       target_hash = self.smart_hash_entry.get().strip()
       if not target_hash:
           messagebox.showwarning("Warning", "Please enter target hash!")
           return
       self.log_result(f"🧠 Smart attack started for: {target_hash[:20]}...")
   
   def stop_attack(self):
       """Stop current attack"""
       self.log_result("⏹️ Attack stopped by user")
   
   def update_progress(self, progress, message):
       """Update progress bar"""
       self.progress_bar['value'] = progress
       self.progress_label.config(text=message)
   
   def update_ui_state(self, attacking):
       """Update UI state"""
       if attacking:
           self.status_label.config(text="🔴 Attacking", bootstyle="danger")
       else:
           self.status_label.config(text="🟢 Ready", bootstyle="success")
   
   def log_result(self, message):
       """Log message to results"""
       timestamp = datetime.now().strftime('%H:%M:%S')
       full_message = f"[{timestamp}] {message}"
       
       self.results_text.config(state=NORMAL)
       self.results_text.insert(tk.END, full_message + "\n")
       self.results_text.see(tk.END)
       self.results_text.config(state=DISABLED)
       self.notebook.select(5)  # Switch to results tab
   
   def export_results(self):
       """Export results to file"""
       content = self.results_text.get(1.0, tk.END)
       if not content.strip():
           messagebox.showwarning("Warning", "No results to export!")
           return
       
       filename = filedialog.asksaveasfilename(
           title="Export Results",
           defaultextension=".txt", 
           filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
       )
       
       if filename:
           try:
               with open(filename, 'w', encoding='utf-8') as f:
                   f.write(f"Password Cracker Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                   f.write("="*60 + "\n\n")
                   f.write(content)
               messagebox.showinfo("Success", f"Results exported to:\n{filename}")
           except Exception as e:
               messagebox.showerror("Error", f"Failed to export: {str(e)}")
   
   def clear_results(self):
       """Clear results text"""
       if messagebox.askyesno("Confirm", "Clear all results?"):
           self.results_text.config(state=NORMAL)
           self.results_text.delete(1.0, tk.END)
           self.results_text.config(state=DISABLED)
   
   def generate_passwords(self):
       """Generate educational passwords for testing"""
       password_type = self.password_type.get()
       count = int(self.password_count.get())
       
       passwords = []
       
       if password_type == "weak":
           weak_patterns = [
               "password", "123456", "qwerty", "abc123", "password123",
               "admin", "guest", "user", "test", "welcome"
           ]
           import random
           for i in range(count):
               base = random.choice(weak_patterns)
               if i % 3 == 0:
                   passwords.append(base)
               elif i % 3 == 1:
                   passwords.append(base + str(random.randint(1, 99)))
               else:
                   passwords.append(base + str(random.randint(2020, 2024)))
       
       elif password_type == "medium":
           import random
           words = ["security", "network", "computer", "system", "access"]
           for i in range(count):
               word = random.choice(words)
               number = random.randint(10, 999)
               symbol = random.choice("!@#$")
               if i % 2 == 0:
                   passwords.append(f"{word.capitalize()}{number}")
               else:
                   passwords.append(f"{word}{number}{symbol}")
       
       elif password_type == "strong":
           import random
           import string
           for i in range(count):
               length = random.randint(12, 16)
               chars = string.ascii_letters + string.digits + "!@#$%^&*"
               password = ''.join(random.choice(chars) for _ in range(length))
               passwords.append(password)
       
       # Display results
       self.generated_passwords.config(state=NORMAL)
       self.generated_passwords.delete(1.0, tk.END)
       
       result_text = f"🎲 Generated {len(passwords)} {password_type} passwords:\n\n"
       for i, pwd in enumerate(passwords, 1):
           result_text += f"{i:2d}. {pwd}\n"
       
       result_text += f"\n💡 Educational Use:\n"
       if password_type == "weak":
           result_text += "• Vulnerable to dictionary attacks\n"
       elif password_type == "medium":
           result_text += "• Harder but still vulnerable to patterns\n"
       else:
           result_text += "• Much stronger passwords\n"
       
       self.generated_passwords.insert(1.0, result_text)
       self.generated_passwords.config(state=DISABLED)
       self.log_result(f"Generated {len(passwords)} {password_type} passwords")
   
   def toggle_password_visibility(self):
       """Toggle password visibility"""
       if self.show_password.get():
           self.dict_password_entry.config(show="")
       else:
           self.dict_password_entry.config(show="*")
   
   def analyze_patterns(self):
       """Analyze password patterns"""
       password = self.pattern_password_entry.get().strip()
       if not password:
           messagebox.showwarning("Warning", "Please enter a password to analyze!")
           return
       
       results = []
       results.append(f"🎯 Password Pattern Analysis")
       results.append("=" * 40)
       results.append(f"Length: {len(password)} characters")
       results.append("")
       
       # Check patterns
       if self.test_keyboard.get():
           keyboard_patterns = ["qwerty", "123456", "asdf"]
           found = [p for p in keyboard_patterns if p in password.lower()]
           results.append("⌨️ Keyboard Patterns:")
           if found:
               results.append(f"   ❌ Found: {', '.join(found)}")
           else:
               results.append("   ✅ None detected")
           results.append("")
       
       if self.test_dates.get():
           import re
           years = re.findall(r'\b(19|20)\d{2}\b', password)
           results.append("📅 Date Patterns:")
           if years:
               results.append(f"   ❌ Found years: {', '.join(years)}")
           else:
               results.append("   ✅ None detected")
           results.append("")
       
       # Calculate strength
       strength = 0
       if len(password) >= 8: strength += 1
       if any(c.isupper() for c in password): strength += 1
       if any(c.islower() for c in password): strength += 1
       if any(c.isdigit() for c in password): strength += 1
       if any(c in "!@#$%^&*" for c in password): strength += 1
       
       results.append("🛡️ Overall Strength:")
       if strength <= 2:
           results.append("   🔴 WEAK")
       elif strength <= 4:
           results.append("   🟡 MODERATE") 
       else:
           results.append("   🟢 STRONG")
       
       results.append(f"   Score: {strength}/5")
       
       # Display results
       self.pattern_results.config(state=NORMAL)
       self.pattern_results.delete(1.0, tk.END)
       self.pattern_results.insert(1.0, "\n".join(results))
       self.pattern_results.config(state=DISABLED)
       
       self.log_result(f"Analyzed password - Strength: {strength}/5")
   
   def detect_hash_type(self):
       """Detect hash type for TryHackMe challenges"""
       hash_text = self.hash_input.get(1.0, tk.END).strip()
       if not hash_text:
           messagebox.showwarning("Warning", "Please enter a hash!")
           return
       
       # Simple hash detection based on length
       hash_length = len(hash_text)
       detected_type = "Unknown"
       
       if hash_length == 32:
           detected_type = "MD5"
       elif hash_length == 40:
           detected_type = "SHA1"  
       elif hash_length == 56:
           detected_type = "SHA224"
       elif hash_length == 64:
           detected_type = "SHA256"
       elif hash_length == 96:
           detected_type = "SHA384"
       elif hash_length == 128:
           detected_type = "SHA512"
       
       self.hash_type_result.config(text=f"Hash type: {detected_type}")
       self.manual_hash_type.set(detected_type)
       
       self.log_hash_result(f"Detected hash type: {detected_type} (Length: {hash_length})")
   
   def quick_crack_hash(self):
       """Quick crack using common passwords for TryHackMe"""
       hash_text = self.hash_input.get(1.0, tk.END).strip()
       if not hash_text:
           messagebox.showwarning("Warning", "Please enter a hash!")
           return
       
       hash_type = self.manual_hash_type.get().lower() or "md5"
       
       # Common TryHackMe passwords
       common_passwords = [
           "password", "123456", "admin", "root", "guest", "user",
           "test", "welcome", "qwerty", "abc123", "password123",
           "letmein", "monkey", "dragon", "sunshine", "master",
           "shadow", "football", "baseball", "superman", "hello",
           "freedom", "whatever", "nicole", "jordan", "hunter"
       ]
       
       self.log_hash_result(f"🚀 Quick cracking hash: {hash_text[:20]}...")
       self.log_hash_result(f"Hash type: {hash_type.upper()}")
       self.log_hash_result(f"Testing {len(common_passwords)} common passwords...")
       
       import hashlib
       
       for i, password in enumerate(common_passwords):
           # Generate hash
           if hash_type == "md5":
               test_hash = hashlib.md5(password.encode()).hexdigest()
           elif hash_type == "sha1":
               test_hash = hashlib.sha1(password.encode()).hexdigest()
           elif hash_type == "sha256":
               test_hash = hashlib.sha256(password.encode()).hexdigest()
           elif hash_type == "sha512":
               test_hash = hashlib.sha512(password.encode()).hexdigest()
           else:
               continue
           
           if test_hash.lower() == hash_text.lower():
               self.log_hash_result(f"🎉 SUCCESS! Password found: '{password}'")
               self.log_hash_result(f"Hash cracked after {i+1} attempts")
               messagebox.showinfo("Success!", f"Password cracked!\n\nPassword: {password}\nHash: {hash_text}")
               return
       
       self.log_hash_result("❌ Password not found in common list")
       self.log_hash_result("Try dictionary attack with larger wordlist")
   
   def start_hash_dictionary_attack(self):
       """Start hash dictionary attack for TryHackMe"""
       hash_text = self.hash_input.get(1.0, tk.END).strip()
       if not hash_text:
           messagebox.showwarning("Warning", "Please enter a hash!")
           return
       
       hash_type = self.manual_hash_type.get().lower() or "md5"
       
       # Extended wordlist for TryHackMe scenarios
       extended_passwords = [
           # Common passwords
           "password", "123456", "admin", "root", "guest", "user", "test", "welcome",
           "qwerty", "abc123", "password123", "letmein", "monkey", "dragon", "sunshine",
           "master", "shadow", "football", "baseball", "superman", "hello", "freedom",
           
           # TryHackMe specific
           "tryhackme", "hacker", "security", "linux", "windows", "john", "jane",
           "secret", "hidden", "flag", "ctf", "challenge", "easy", "medium", "hard",
           
           # Years and variations
           "2023", "2024", "2022", "1999", "2000", "1234", "4321", "0000",
           
           # Common with numbers
           "admin123", "root123", "user123", "test123", "guest123", "pass123",
           "password1", "password2", "admin1", "root1", "user1",
           
           # Keyboard patterns
           "123456789", "987654321", "qwertyuiop", "asdfghjkl", "zxcvbnm"
       ]
       
       self.log_hash_result(f"🚀 Dictionary attack started")
       self.log_hash_result(f"Target: {hash_text[:20]}...")
       self.log_hash_result(f"Hash type: {hash_type.upper()}")
       self.log_hash_result(f"Testing {len(extended_passwords)} passwords...")
       
       import hashlib
       
       for i, password in enumerate(extended_passwords):
           # Generate hash
           try:
               if hash_type == "md5":
                   test_hash = hashlib.md5(password.encode()).hexdigest()
               elif hash_type == "sha1":
                   test_hash = hashlib.sha1(password.encode()).hexdigest()
               elif hash_type == "sha256":
                   test_hash = hashlib.sha256(password.encode()).hexdigest()
               elif hash_type == "sha512":
                   test_hash = hashlib.sha512(password.encode()).hexdigest()
               else:
                   continue
               
               if test_hash.lower() == hash_text.lower():
                   self.log_hash_result(f"🎉 SUCCESS! Password cracked: '{password}'")
                   self.log_hash_result(f"Found after {i+1} attempts")
                   self.log_hash_result(f"Perfect for TryHackMe writeup!")
                   messagebox.showinfo("TryHackMe Success!", 
                                     f"Hash cracked!\n\n"
                                     f"Password: {password}\n"
                                     f"Hash: {hash_text}\n"
                                     f"Attempts: {i+1}")
                   return
                   
               # Update progress every 10 attempts
               if (i + 1) % 10 == 0:
                   self.log_hash_result(f"Progress: {i+1}/{len(extended_passwords)} tested...")
                   
           except Exception as e:
               continue
       
       self.log_hash_result("❌ Password not found in dictionary")
       self.log_hash_result("💡 Try: 1) Different hash type 2) Custom wordlist 3) Brute force")
       messagebox.showinfo("Dictionary Complete", 
                         f"Dictionary attack completed.\n"
                         f"Password not found in {len(extended_passwords)} attempts.\n"
                         f"Try a different approach or verify the hash type.")
   
   def log_hash_result(self, message):
       """Log message to hash results"""
       timestamp = datetime.now().strftime('%H:%M:%S')
       full_message = f"[{timestamp}] {message}"
       
       self.hash_results.config(state=NORMAL)
       self.hash_results.insert(tk.END, full_message + "\n")
       self.hash_results.see(tk.END)
       self.hash_results.config(state=DISABLED)



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
