import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
from datetime import datetime
import webbrowser
import sys
import os

# Import tools with error handling
try:
    from PasswordCracker import PasswordCracker
except ImportError:
    PasswordCracker = None

try:
    from PortScanner import PortScanner
except ImportError:
    PortScanner = None

try:
    from ExploitManager import ExploitManager
except ImportError:
    ExploitManager = None

try:
    from DirectoryFuzzer import DirectoryFuzzer
except ImportError:
    DirectoryFuzzer = None

try:
    from HashCracking import HashCracking
except ImportError:
    HashCracking = None

try:
    from SubdomainFinder import SubdomainFinderGUI
except ImportError:
    SubdomainFinderGUI = None

class ModernPenTestSuite(tb.Window):
    def __init__(self):
        super().__init__(themename="cosmo")
        self.title("🔒 PenTest MultiTools - Advanced Cybersecurity Suite")
        self.geometry("1400x800")
        self.resizable(True, True)
        self.iconbitmap_err_handled()
        
        # Initialize variables
        self.current_theme = "cosmo"
        self.is_dark_mode = False
        
        # Create modern UI
        self.setup_styles()
        self.create_modern_ui()
        self.mainloop()
    
    def iconbitmap_err_handled(self):
        """Set icon with error handling"""
        try:
            self.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
        except:
            pass
    
    def setup_styles(self):
        """Setup custom styles for modern appearance"""
        style = tb.Style()
        
        # Configure custom styles for cards
        style.configure(
            "Card.TFrame",
            relief="flat",
            borderwidth=1,
            background="#ffffff"
        )
        
        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 24, "bold"),
            foreground="#2c3e50"
        )
        
        style.configure(
            "Subtitle.TLabel",
            font=("Segoe UI", 12),
            foreground="#7f8c8d"
        )
    
    def create_modern_ui(self):
        """Create modern, professional UI"""
        # Main container
        main_frame = tb.Frame(self)
        main_frame.pack(fill=BOTH, expand=True, padx=0, pady=0)
        
        # Header section
        self.create_header(main_frame)
        
        # Content area
        content_frame = tb.Frame(main_frame)
        content_frame.pack(fill=BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Left panel - Tools
        left_panel = tb.Frame(content_frame)
        left_panel.pack(side=LEFT, fill=Y, padx=(0, 20))
        
        # Right panel - Info and stats
        right_panel = tb.Frame(content_frame)
        right_panel.pack(side=RIGHT, fill=BOTH, expand=True)
        
        # Create sections
        self.create_tools_section(left_panel)
        self.create_info_section(right_panel)
        
        # Footer
        self.create_footer(main_frame)
    
    def create_header(self, parent):
        """Create modern header with branding"""
        header_frame = tb.Frame(parent, style="Card.TFrame")
        header_frame.pack(fill=X, padx=20, pady=20)
        
        # Header content
        header_content = tb.Frame(header_frame)
        header_content.pack(fill=X, padx=30, pady=20)
        
        # Left side - Title and subtitle
        title_frame = tb.Frame(header_content)
        title_frame.pack(side=LEFT, fill=X, expand=True)
        
        title_label = tb.Label(
            title_frame,
            text="🔒 PenTest MultiTools",
            font=("Segoe UI", 28, "bold"),
            bootstyle="primary"
        )
        title_label.pack(anchor=W)
        
        subtitle_label = tb.Label(
            title_frame,
            text="Advanced Cybersecurity Testing Suite | University Project 2024",
            font=("Segoe UI", 12),
            bootstyle="secondary"
        )
        subtitle_label.pack(anchor=W, pady=(5, 0))
        
        # Right side - Controls
        controls_frame = tb.Frame(header_content)
        controls_frame.pack(side=RIGHT)
        
        # Theme toggle
        self.theme_var = tb.BooleanVar()
        theme_switch = tb.Checkbutton(
            controls_frame,
            text="🌙 Dark Mode",
            variable=self.theme_var,
            bootstyle="round-toggle",
            command=self.toggle_theme
        )
        theme_switch.pack(side=RIGHT, padx=(0, 10))
        
        # About button
        about_btn = tb.Button(
            controls_frame,
            text="ℹ️ About",
            bootstyle="info-outline",
            command=self.show_about
        )
        about_btn.pack(side=RIGHT, padx=(0, 10))
        
        # Exit button
        exit_btn = tb.Button(
            controls_frame,
            text="❌ Exit",
            bootstyle="danger-outline",
            command=self.confirm_exit
        )
        exit_btn.pack(side=RIGHT)
    
    def create_tools_section(self, parent):
        """Create modern tools grid"""
        tools_frame = tb.LabelFrame(
            parent,
            text="🛠️ Cybersecurity Tools",
            padding=20,
            bootstyle="primary"
        )
        tools_frame.pack(fill=BOTH, expand=True)
        
        # Tools data with modern icons and descriptions
        tools_data = []
        
        if PasswordCracker:
            tools_data.append({
                "name": "Password Cracker", 
                "icon": "🔓", 
                "desc": "Crack various password types\nand hashing algorithms",
                "bootstyle": "info",
                "command": lambda: PasswordCracker(self)
            })
        
        if PortScanner:
            tools_data.append({
                "name": "Port Scanner", 
                "icon": "🔍", 
                "desc": "Network port enumeration\nand service detection",
                "bootstyle": "primary",
                "command": lambda: PortScanner(self)
            })
        
        if ExploitManager:
            tools_data.append({
                "name": "Exploit Manager", 
                "icon": "⚡", 
                "desc": "Vulnerability testing\nand exploit framework",
                "bootstyle": "warning",
                "command": lambda: ExploitManager(self)
            })
        
        if DirectoryFuzzer:
            tools_data.append({
                "name": "Directory Fuzzer", 
                "icon": "📁", 
                "desc": "Web directory discovery\nand enumeration",
                "bootstyle": "success",
                "command": lambda: DirectoryFuzzer(self)
            })
        
        if HashCracking:
            tools_data.append({
                "name": "Hash Cracking", 
                "icon": "🔐", 
                "desc": "Password hash analysis\nand rainbow tables",
                "bootstyle": "danger",
                "command": lambda: HashCracking(self)
            })
        
        if SubdomainFinderGUI:
            tools_data.append({
                "name": "Subdomain Finder", 
                "icon": "🌐", 
                "desc": "Comprehensive subdomain\nenumeration toolkit",
                "bootstyle": "secondary",
                "command": lambda: SubdomainFinderGUI(self)
            })
        
        # Add placeholder if no tools available
        if not tools_data:
            tools_data.append({
                "name": "No Tools Available", 
                "icon": "⚠️", 
                "desc": "Tool modules not found\nCheck installation",
                "bootstyle": "warning",
                "command": lambda: self.show_tool_error()
            })
        
        # Create tool cards in grid
        for i, tool in enumerate(tools_data):
            row = i // 2
            col = i % 2
            
            tool_card = self.create_tool_card(tools_frame, tool)
            tool_card.grid(row=row, column=col, padx=10, pady=10, sticky="ew")
        
        # Configure grid weights
        tools_frame.columnconfigure(0, weight=1)
        tools_frame.columnconfigure(1, weight=1)
    
    def create_tool_card(self, parent, tool_data):
        """Create modern tool card"""
        card_frame = tb.Frame(parent, style="Card.TFrame")
        
        # Tool button with hover effect
        tool_btn = tb.Button(
            card_frame,
            text=f"{tool_data['icon']} {tool_data['name']}",
            bootstyle=f"{tool_data['bootstyle']},outline",
            command=tool_data['command'],
            width=25
        )
        tool_btn.pack(fill=X, padx=15, pady=(15, 5))
        
        # Description
        desc_label = tb.Label(
            card_frame,
            text=tool_data['desc'],
            font=("Segoe UI", 9),
            bootstyle="secondary",
            justify=CENTER
        )
        desc_label.pack(pady=(0, 15))
        
        return card_frame
    
    def create_info_section(self, parent):
        """Create information and statistics section"""
        info_frame = tb.LabelFrame(
            parent,
            text="📊 Dashboard & Information",
            padding=20,
            bootstyle="info"
        )
        info_frame.pack(fill=BOTH, expand=True)
        
        # Welcome section
        welcome_frame = tb.Frame(info_frame)
        welcome_frame.pack(fill=X, pady=(0, 20))
        
        welcome_title = tb.Label(
            welcome_frame,
            text="🎓 Welcome to PenTest MultiTools",
            font=("Segoe UI", 16, "bold"),
            bootstyle="primary"
        )
        welcome_title.pack(anchor=W)
        
        welcome_text = tb.Label(
            welcome_frame,
            text="This comprehensive cybersecurity testing suite provides professional-grade tools for penetration testing, security research, and educational purposes.",
            font=("Segoe UI", 11),
            bootstyle="secondary",
            wraplength=400,
            justify=LEFT
        )
        welcome_text.pack(anchor=W, pady=(10, 0))
        
        # Statistics section
        stats_frame = tb.LabelFrame(info_frame, text="📈 Suite Statistics", padding=15)
        stats_frame.pack(fill=X, pady=(0, 20))
        
        # Calculate available tools
        available_tools = sum([
            1 if PasswordCracker else 0,
            1 if PortScanner else 0,
            1 if ExploitManager else 0,
            1 if DirectoryFuzzer else 0,
            1 if HashCracking else 0,
            1 if SubdomainFinderGUI else 0
        ])
        
        stats_data = [
            ("🛠️ Available Tools", f"{available_tools} Professional Tools"),
            ("🎯 Target Platforms", "Web, Network, System"),
            ("🔒 Security Focus", "Educational & Authorized Testing"),
            ("👥 Team Members", "5 Cybersecurity Students")
        ]
        
        for i, (label, value) in enumerate(stats_data):
            stat_frame = tb.Frame(stats_frame)
            stat_frame.pack(fill=X, pady=2)
            
            tb.Label(
                stat_frame,
                text=label,
                font=("Segoe UI", 10, "bold")
            ).pack(side=LEFT)
            
            tb.Label(
                stat_frame,
                text=value,
                font=("Segoe UI", 10),
                bootstyle="primary"
            ).pack(side=RIGHT)
        
        # Features section
        features_frame = tb.LabelFrame(info_frame, text="✨ Key Features", padding=15)
        features_frame.pack(fill=X, pady=(0, 20))
        
        features = [
            "🚀 Real-time vulnerability assessment",
            "📊 Professional reporting and documentation",
            "🔄 Multi-threaded scanning capabilities",
            "🎯 TryHackMe and HackTheBox compatibility",
            "🛡️ Ethical hacking and educational focus",
            "💾 Export results in multiple formats"
        ]
        
        for feature in features:
            tb.Label(
                features_frame,
                text=feature,
                font=("Segoe UI", 10),
                bootstyle="secondary"
            ).pack(anchor=W, pady=2)
        
        # Quick actions
        actions_frame = tb.LabelFrame(info_frame, text="⚡ Quick Actions", padding=15)
        actions_frame.pack(fill=X)
        
        actions_grid = tb.Frame(actions_frame)
        actions_grid.pack(fill=X)
        
        # Action buttons
        tb.Button(
            actions_grid,
            text="📚 Documentation",
            bootstyle="info-outline",
            command=self.open_docs
        ).grid(row=0, column=0, padx=(0, 10), sticky="ew")
        
        tb.Button(
            actions_grid,
            text="🐙 GitHub Repo",
            bootstyle="secondary-outline", 
            command=self.open_github
        ).grid(row=0, column=1, padx=10, sticky="ew")
        
        tb.Button(
            actions_grid,
            text="🎯 TryHackMe",
            bootstyle="success-outline",
            command=self.open_tryhackme
        ).grid(row=0, column=2, padx=(10, 0), sticky="ew")
        
        actions_grid.columnconfigure(0, weight=1)
        actions_grid.columnconfigure(1, weight=1)
        actions_grid.columnconfigure(2, weight=1)
    
    def create_footer(self, parent):
        """Create modern footer"""
        footer_frame = tb.Frame(parent)
        footer_frame.pack(fill=X, side=BOTTOM, padx=20, pady=(0, 10))
        
        # Separator line
        separator = tb.Separator(footer_frame, orient=HORIZONTAL)
        separator.pack(fill=X, pady=(0, 10))
        
        # Footer content
        footer_content = tb.Frame(footer_frame)
        footer_content.pack(fill=X)
        
        # Left side - Team info
        team_label = tb.Label(
            footer_content,
            text="👥 Team: Cherfaoui M.A., Mohammed M.A., Tifahi M., Likou Y.A., Tali M.N.",
            font=("Segoe UI", 9),
            bootstyle="secondary"
        )
        team_label.pack(side=LEFT)
        
        # Right side - Version and date
        version_label = tb.Label(
            footer_content,
            text=f"v2.0 | {datetime.now().strftime('%Y-%m-%d')} | Advanced Programming Project",
            font=("Segoe UI", 9),
            bootstyle="secondary"
        )
        version_label.pack(side=RIGHT)
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        if self.theme_var.get():
            self.style.theme_use("vapor")
            self.current_theme = "vapor"
            self.is_dark_mode = True
        else:
            self.style.theme_use("cosmo")
            self.current_theme = "cosmo"
            self.is_dark_mode = False
    
    def show_about(self):
        """Show about dialog"""
        about_window = tb.Toplevel(self)
        about_window.title("About PenTest MultiTools")
        about_window.geometry("500x400")
        about_window.resizable(False, False)
        
        # Center the window
        about_window.transient(self)
        about_window.grab_set()
        
        # About content
        content_frame = tb.Frame(about_window, padding=30)
        content_frame.pack(fill=BOTH, expand=True)
        
        # Title
        tb.Label(
            content_frame,
            text="🔒 PenTest MultiTools",
            font=("Segoe UI", 20, "bold"),
            bootstyle="primary"
        ).pack(pady=(0, 20))
        
        # Description
        about_text = """
Advanced Cybersecurity Testing Suite
Version 2.0

This comprehensive penetration testing toolkit provides professional-grade tools for cybersecurity research, vulnerability assessment, and educational purposes.

🎓 University Project
Advanced Programming Course 2024

🛠️ Tools Included:
• Password Cracker
• Port Scanner  
• Exploit Manager
• Directory Fuzzer
• Hash Cracking
• Subdomain Finder

⚠️ Legal Notice:
This tool is for educational and authorized testing only. Always ensure you have explicit permission before testing any systems.
        """
        
        tb.Label(
            content_frame,
            text=about_text,
            font=("Segoe UI", 10),
            bootstyle="secondary",
            justify=LEFT
        ).pack(pady=(0, 20))
        
        # Close button
        tb.Button(
            content_frame,
            text="Close",
            bootstyle="primary",
            command=about_window.destroy
        ).pack()
    
    def confirm_exit(self):
        """Confirm exit with dialog"""
        result = tb.dialogs.Messagebox.yesno(
            title="Exit Confirmation",
            message="Are you sure you want to exit PenTest MultiTools?",
            parent=self
        )
        if result == "Yes":
            self.destroy()
    
    def open_docs(self):
        """Open documentation (placeholder)"""
        tb.dialogs.Messagebox.showinfo(
            title="Documentation",
            message="Documentation will be available soon!\nCheck the README.md file for usage instructions.",
            parent=self
        )
    
    def open_github(self):
        """Open GitHub repository (placeholder)"""
        tb.dialogs.Messagebox.showinfo(
            title="GitHub Repository", 
            message="GitHub repository link:\nhttps://github.com/your-repo/pentest-multitools",
            parent=self
        )
    
    def open_tryhackme(self):
        """Open TryHackMe website"""
        try:
            webbrowser.open("https://tryhackme.com")
        except:
            tb.dialogs.Messagebox.showinfo(
                title="TryHackMe",
                message="Visit: https://tryhackme.com\nPerfect platform for testing these tools!",
                parent=self
            )
    
    def show_tool_error(self):
        """Show error message for unavailable tools"""
        tb.dialogs.Messagebox.showwarning(
            title="Tool Unavailable",
            message="This tool module is not available.\n\n"
                   "Please check:\n"
                   "• All tool files are present in the gui directory\n"
                   "• Required dependencies are installed\n"
                   "• File permissions are correct\n\n"
                   "Available tools will be shown in the grid.",
            parent=self
        )

if __name__ == "__main__":
    ModernPenTestSuite()