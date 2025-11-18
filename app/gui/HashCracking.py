"""Advanced Hash Cracking Tool - Enhanced GUI
Comprehensive hash analysis and cracking capabilities with clean separation from backend logic
"""

import importlib.util
import os
import sys
import threading
import time
from tkinter import filedialog, messagebox

import ttkbootstrap as tb
from ttkbootstrap.constants import *

# Add utils path for enhanced backend
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'utils'))

# Try to import enhanced backend first, fallback to basic
def _load_class_from_path(file_path: str, class_name: str):
    if not os.path.isfile(file_path):
        return None
    spec = importlib.util.spec_from_file_location(os.path.splitext(os.path.basename(file_path))[0], file_path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)  # type: ignore
        return getattr(module, class_name, None)
    except Exception:
        return None

utils_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'utils'))
enh_path = os.path.join(utils_dir, 'enhanced_hash_cracker.py')
basic_path = os.path.join(utils_dir, 'hash_cracking_utils.py')

ENHANCED_BACKEND = False
EnhancedHashCracker = None
# try enhanced first
EnhancedHashCracker = _load_class_from_path(enh_path, 'EnhancedHashCracker')
if EnhancedHashCracker:
    ENHANCED_BACKEND = True
else:
    EnhancedHashCracker = _load_class_from_path(basic_path, 'EnhancedHashCracker')
    if EnhancedHashCracker:
        ENHANCED_BACKEND = True

# Import detection modules
HashDetector = None
HashCracker = None
try:
    # Try to import from modules directory
    modules_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'modules', 'HashCracker'))
    hd_path = os.path.join(modules_dir, 'HashDetector.py')
    hc_path = os.path.join(modules_dir, 'HashCracker.py')
    HashDetector = _load_class_from_path(hd_path, 'HashDetector')
    HashCracker = _load_class_from_path(hc_path, 'HashCracker')
    
    if not HashDetector or not HashCracker:
        print("Warning: HashDetector and/or HashCracker modules not found. Using basic functionality.")
        
except Exception as e:
    print(f"Error loading HashCracker modules: {e}")
    HashDetector = None
    HashCracker = None


class HashCracking:
    """Advanced Hash Cracking Tool with Enhanced Features"""

    def __init__(self, master):
        self.master = master
        self.window = tb.Toplevel(master)
        self.window.title("Advanced Hash Cracking Tool")
        self.window.geometry("1200x900")

        try:
            self.window.iconbitmap("app/assets/logo-tete-de-mort-png.ico")
        except Exception:
            pass

        self.window.resizable(True, True)

        # Initialize backend
        if ENHANCED_BACKEND:
            self.hash_cracker = EnhancedHashCracker()
            self.hash_cracker.set_callbacks(self.update_progress, self.show_result)

        # Initialize detection components
        self.hash_detector = HashDetector() if HashDetector else None
        self.base_cracker = HashCracker() if HashCracker else None

        # Control variables
        self.is_cracking = False
        self.current_thread = None

        # Extended hash types support
        self.hash_types = ["MD5", "MD4", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
                           "NTLM", "LM", "bcrypt", "MySQL", "MySQL5", "PostgreSQL", "MSSQL", "Oracle",
                           "CRC32", "Adler32", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
                           "BLAKE2b", "BLAKE2s", "WordPress", "Joomla", "Drupal7"]

        self.setup_variables()
        self.setup_ui()

    def setup_variables(self):
        """Initialize GUI variables"""
        # Dictionary attack variables
        self.wordlist_var = tb.StringVar()
        self.hash_type_var = tb.StringVar(value="MD5")

        # Enhancement options
        self.case_variations_var = tb.BooleanVar(value=True)
        self.number_appending_var = tb.BooleanVar(value=True)
        self.symbol_appending_var = tb.BooleanVar(value=True)
        self.leet_speak_var = tb.BooleanVar(value=True)
        self.year_mutations_var = tb.BooleanVar(value=True)

        # Brute force variables
        self.charset_var = tb.StringVar(value="abcdefghijklmnopqrstuvwxyz")
        self.min_length_var = tb.StringVar(value="1")
        self.max_length_var = tb.StringVar(value="6")
        self.bf_hash_type_var = tb.StringVar(value="MD5")
        self.use_common_patterns_var = tb.BooleanVar(value=True)
        self.use_keyboard_patterns_var = tb.BooleanVar(value=True)

        # Hybrid attack variables
        self.hybrid_wordlist_var = tb.StringVar()
        self.hybrid_mask_var = tb.StringVar(value="?d?d?d")
        self.hybrid_hash_type_var = tb.StringVar(value="MD5")

        # Mask attack variables
        self.mask_pattern_var = tb.StringVar(value="?l?l?l?l?d?d?d?d")
        self.mask_hash_type_var = tb.StringVar(value="MD5")

        # Combinator variables
        self.comb_wordlist1_var = tb.StringVar()
        self.comb_wordlist2_var = tb.StringVar()
        self.comb_separator_var = tb.StringVar(value="")
        self.comb_hash_type_var = tb.StringVar(value="MD5")

        # Worker options
        self.use_workers_var = tb.BooleanVar(value=False)
        self.num_workers_var = tb.StringVar(value="4")

    def setup_ui(self):
        """Setup the user interface"""
        # Main container with padding
        main_frame = tb.Frame(self.window, padding=15)
        main_frame.pack(fill=BOTH, expand=True)

        # Title with enhanced styling
        title_label = tb.Label(
            main_frame,
            text="🔓 Advanced Hash Cracking Tool",
            font=("Helvetica", 18, "bold"),
            bootstyle=INFO
        )
        title_label.pack(pady=(0, 20))

        # Create notebook for organized tabs
        self.notebook = tb.Notebook(main_frame)
        self.notebook.pack(fill=BOTH, expand=True, pady=(0, 15))

        # Create all tabs
        self.create_hash_analysis_tab()
        self.create_dictionary_attack_tab()
        self.create_brute_force_tab()
        self.create_hybrid_attack_tab()
        self.create_combinator_attack_tab()
        self.create_advanced_tools_tab()
        self.create_results_tab()

        # Control buttons
        self.create_control_buttons(main_frame)

        # Status bar
        self.create_status_bar(main_frame)

    def create_hash_analysis_tab(self):
        """Hash analysis and detection tab"""
        analysis_frame = tb.Frame(self.notebook, padding=20)
        self.notebook.add(analysis_frame, text="🔍 Hash Analysis")

        # Hash input section
        input_frame = tb.LabelFrame(analysis_frame, text="Hash Input", padding=15)
        input_frame.pack(fill=X, pady=(0, 15))

        tb.Label(input_frame, text="Enter hash to analyze:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(0, 5))

        self.hash_entry = tb.Text(input_frame, height=4, width=80, font=("Consolas", 10))
        self.hash_entry.pack(fill=X, pady=(0, 10))

        # Analysis buttons
        btn_frame = tb.Frame(input_frame)
        btn_frame.pack(fill=X)

        tb.Button(btn_frame, text="🔍 Analyze Hash", bootstyle=PRIMARY,
                  command=self.analyze_hash).pack(side=LEFT, padx=(0, 10))
        tb.Button(btn_frame, text="📂 Load from File", bootstyle=SECONDARY,
                  command=self.load_hash_file).pack(side=LEFT, padx=(0, 10))
        tb.Button(btn_frame, text="🗑️ Clear", bootstyle=WARNING,
                  command=self.clear_hash_analysis).pack(side=LEFT)

        # Detection results
        results_frame = tb.LabelFrame(analysis_frame, text="Detection Results", padding=15)
        results_frame.pack(fill=BOTH, expand=True)

        self.detection_text = tb.Text(results_frame, height=15, state=DISABLED,
                                      bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10))
        detection_scroll = tb.Scrollbar(results_frame, orient=VERTICAL, command=self.detection_text.yview)
        self.detection_text.configure(yscrollcommand=detection_scroll.set)

        self.detection_text.pack(side=LEFT, fill=BOTH, expand=True)
        detection_scroll.pack(side=RIGHT, fill=Y)

    def create_dictionary_attack_tab(self):
        """Enhanced dictionary attack configuration"""
        dict_frame = tb.Frame(self.notebook, padding=20)
        self.notebook.add(dict_frame, text="📖 Dictionary Attack")

        # Hash input section
        hash_frame = tb.LabelFrame(dict_frame, text="Target Hash", padding=15)
        hash_frame.pack(fill=X, pady=(0, 15))

        hash_input_frame = tb.Frame(hash_frame)
        hash_input_frame.pack(fill=X, pady=(0, 10))

        tb.Label(hash_input_frame, text="Hash:", font=("Helvetica", 10, "bold")).pack(side=LEFT, padx=(0, 10))
        self.dict_hash_entry = tb.Entry(hash_input_frame, width=60, font=("Consolas", 10))
        self.dict_hash_entry.pack(side=LEFT, fill=X, expand=True, padx=(0, 10))

        tb.Label(hash_input_frame, text="Type:", font=("Helvetica", 10, "bold")).pack(side=LEFT, padx=(0, 10))
        hash_type_combo = tb.Combobox(hash_input_frame, textvariable=self.hash_type_var,
                                     values=self.hash_types, state="readonly", width=15)
        hash_type_combo.pack(side=LEFT)

        # Worker options (small)
        worker_frame = tb.Frame(dict_frame)
        worker_frame.pack(fill=X, pady=(5, 0))
        tb.Checkbutton(worker_frame, text="Use worker threads", variable=self.use_workers_var).pack(side=LEFT)
        tb.Label(worker_frame, text="Workers:").pack(side=LEFT, padx=(10, 5))
        tb.Spinbox(worker_frame, from_=1, to=64, textvariable=self.num_workers_var, width=5).pack(side=LEFT)

        # Wordlist selection
        wordlist_frame = tb.LabelFrame(dict_frame, text="Wordlist Selection", padding=15)
        wordlist_frame.pack(fill=X, pady=(0, 15))

        tb.Label(wordlist_frame, text="Wordlist Path:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(0, 5))

        path_frame = tb.Frame(wordlist_frame)
        path_frame.pack(fill=X, pady=(0, 10))

        self.wordlist_entry = tb.Entry(path_frame, textvariable=self.wordlist_var, width=60)
        self.wordlist_entry.pack(side=LEFT, fill=X, expand=True, padx=(0, 10))

        tb.Button(path_frame, text="📂 Browse", bootstyle=SECONDARY,
                  command=self.browse_wordlist).pack(side=LEFT, padx=(0, 10))
        tb.Button(path_frame, text="📋 Common Lists", bootstyle=INFO,
                  command=self.show_common_wordlists).pack(side=LEFT)

        # Enhancement options
        options_frame = tb.LabelFrame(dict_frame, text="Enhancement Options", padding=15)
        options_frame.pack(fill=X, pady=(0, 15))

        # Create a grid for better organization
        opts_grid = tb.Frame(options_frame)
        opts_grid.pack(fill=X)

        self.case_variations_var = tb.BooleanVar(value=True)
        tb.Checkbutton(opts_grid, text="Case variations (upper, lower, capitalize)",
                       variable=self.case_variations_var).grid(row=0, column=0, sticky=W, pady=2)

        self.number_appending_var = tb.BooleanVar(value=True)
        tb.Checkbutton(opts_grid, text="Number mutations (append digits, years)",
                       variable=self.number_appending_var).grid(row=1, column=0, sticky=W, pady=2)

        self.symbol_appending_var = tb.BooleanVar(value=True)
        tb.Checkbutton(opts_grid, text="Symbol mutations (append !@#$% etc.)",
                       variable=self.symbol_appending_var).grid(row=2, column=0, sticky=W, pady=2)

        self.leet_speak_var = tb.BooleanVar(value=True)
        tb.Checkbutton(opts_grid, text="Leet speak transformations (a->@, e->3, etc.)",
                       variable=self.leet_speak_var).grid(row=0, column=1, sticky=W, pady=2, padx=(20, 0))

        self.year_mutations_var = tb.BooleanVar(value=True)
        tb.Checkbutton(opts_grid, text="Year mutations (2023, 23, recent years)",
                       variable=self.year_mutations_var).grid(row=1, column=1, sticky=W, pady=2, padx=(20, 0))

        # Action buttons
        action_frame = tb.Frame(dict_frame)
        action_frame.pack(pady=20)

        self.dict_start_btn = tb.Button(
            action_frame,
            text="🚀 Enhanced Dictionary Attack",
            bootstyle=SUCCESS,
            command=self.start_enhanced_dictionary_attack
        )
        self.dict_start_btn.pack(side=LEFT, padx=(0, 10))

        self.basic_dict_btn = tb.Button(
            action_frame,
            text="📖 Basic Dictionary Attack",
            bootstyle=INFO,
            command=self.start_basic_dictionary_attack
        )
        self.basic_dict_btn.pack(side=LEFT)

    def create_brute_force_tab(self):
        """Enhanced brute force attack configuration"""
        bf_frame = tb.Frame(self.notebook, padding=20)
        self.notebook.add(bf_frame, text="💪 Brute Force")

        # Hash input
        hash_frame = tb.LabelFrame(bf_frame, text="Target Hash", padding=15)
        hash_frame.pack(fill=X, pady=(0, 15))

        hash_input_frame = tb.Frame(hash_frame)
        hash_input_frame.pack(fill=X)

        tb.Label(hash_input_frame, text="Hash:", font=("Helvetica", 10, "bold")).pack(side=LEFT, padx=(0, 10))
        self.bf_hash_entry = tb.Entry(hash_input_frame, width=60, font=("Consolas", 10))
        self.bf_hash_entry.pack(side=LEFT, fill=X, expand=True, padx=(0, 10))

        tb.Label(hash_input_frame, text="Type:", font=("Helvetica", 10, "bold")).pack(side=LEFT, padx=(0, 10))
        bf_hash_type_combo = tb.Combobox(hash_input_frame, textvariable=self.bf_hash_type_var,
                                        values=self.hash_types, state="readonly", width=15)
        bf_hash_type_combo.pack(side=LEFT)

        # Character set configuration
        charset_frame = tb.LabelFrame(bf_frame, text="Character Set Configuration", padding=15)
        charset_frame.pack(fill=X, pady=(0, 15))

        tb.Label(charset_frame, text="Character Set:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(0, 5))

        charset_entry = tb.Entry(charset_frame, textvariable=self.charset_var, width=60, font=("Consolas", 10))
        charset_entry.pack(fill=X, pady=(0, 10))

        # Preset buttons
        preset_frame = tb.Frame(charset_frame)
        preset_frame.pack(fill=X)

        presets = [
            ("a-z", "abcdefghijklmnopqrstuvwxyz"),
            ("A-Z", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            ("0-9", "0123456789"),
            ("a-z + 0-9", "abcdefghijklmnopqrstuvwxyz0123456789"),
            ("All Printable", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()")
        ]

        for name, chars in presets:
            tb.Button(preset_frame, text=name,
                      command=lambda c=chars: self.charset_var.set(c)).pack(side=LEFT, padx=(0, 5))

        # Length configuration
        length_frame = tb.LabelFrame(bf_frame, text="Password Length Range", padding=15)
        length_frame.pack(fill=X, pady=(0, 15))

        length_config = tb.Frame(length_frame)
        length_config.pack()

        tb.Label(length_config, text="Min:").pack(side=LEFT, padx=(0, 5))
        tb.Spinbox(length_config, from_=1, to=15, textvariable=self.min_length_var, width=5).pack(side=LEFT, padx=(0, 20))

        tb.Label(length_config, text="Max:").pack(side=LEFT, padx=(0, 5))
        tb.Spinbox(length_config, from_=1, to=15, textvariable=self.max_length_var, width=5).pack(side=LEFT)

        # Smart options
        smart_frame = tb.LabelFrame(bf_frame, text="Smart Attack Options", padding=15)
        smart_frame.pack(fill=X, pady=(0, 15))

        self.use_common_patterns_var = tb.BooleanVar(value=True)
        tb.Checkbutton(smart_frame, text="Try common passwords first (password, admin, 123456, etc.)",
                       variable=self.use_common_patterns_var).pack(anchor=W, pady=2)

        self.use_keyboard_patterns_var = tb.BooleanVar(value=True)
        tb.Checkbutton(smart_frame, text="Include keyboard patterns (qwerty, asdf, etc.)",
                       variable=self.use_keyboard_patterns_var).pack(anchor=W, pady=2)

        # Start buttons
        button_frame = tb.Frame(bf_frame)
        button_frame.pack(pady=20)

        self.bf_start_btn = tb.Button(
            button_frame,
            text="💪 Basic Brute Force",
            bootstyle=WARNING,
            command=self.start_brute_force_attack
        )
        self.bf_start_btn.pack(side=LEFT, padx=(0, 10))

        self.smart_bf_start_btn = tb.Button(
            button_frame,
            text="🧠 Smart Brute Force",
            bootstyle=SUCCESS,
            command=self.start_smart_brute_force_attack
        )
        self.smart_bf_start_btn.pack(side=LEFT)

    def create_hybrid_attack_tab(self):
        """Hybrid attack configuration"""
        hybrid_frame = tb.Frame(self.notebook, padding=20)
        self.notebook.add(hybrid_frame, text="🔀 Hybrid Attack")

        # Hash input
        hash_frame = tb.LabelFrame(hybrid_frame, text="Target Hash", padding=15)
        hash_frame.pack(fill=X, pady=(0, 15))

        hash_input_frame = tb.Frame(hash_frame)
        hash_input_frame.pack(fill=X)

        tb.Label(hash_input_frame, text="Hash:", font=("Helvetica", 10, "bold")).pack(side=LEFT, padx=(0, 10))
        self.hybrid_hash_entry = tb.Entry(hash_input_frame, width=50, font=("Consolas", 10))
        self.hybrid_hash_entry.pack(side=LEFT, fill=X, expand=True, padx=(0, 10))

        tb.Label(hash_input_frame, text="Type:", font=("Helvetica", 10, "bold")).pack(side=LEFT, padx=(0, 10))
        hybrid_hash_type_combo = tb.Combobox(hash_input_frame, textvariable=self.hybrid_hash_type_var,
                                            values=self.hash_types, state="readonly", width=15)
        hybrid_hash_type_combo.pack(side=LEFT)

        # Configuration
        config_frame = tb.LabelFrame(hybrid_frame, text="Hybrid Attack Configuration", padding=15)
        config_frame.pack(fill=X, pady=(0, 15))

        # Wordlist
        tb.Label(config_frame, text="Wordlist:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(0, 5))
        hybrid_wordlist_frame = tb.Frame(config_frame)
        hybrid_wordlist_frame.pack(fill=X, pady=(0, 15))

        hybrid_wordlist_entry = tb.Entry(hybrid_wordlist_frame, textvariable=self.hybrid_wordlist_var, width=50)
        hybrid_wordlist_entry.pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        tb.Button(hybrid_wordlist_frame, text="📂 Browse", bootstyle=SECONDARY,
                  command=self.browse_hybrid_wordlist).pack(side=LEFT)

        # Mask pattern
        tb.Label(config_frame, text="Mask Pattern:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(0, 5))
        tb.Entry(config_frame, textvariable=self.hybrid_mask_var, width=30).pack(anchor=W)

        # Mask help
        help_frame = tb.LabelFrame(hybrid_frame, text="Mask Pattern Help", padding=15)
        help_frame.pack(fill=X, pady=(0, 15))

        help_text = ("Mask Characters:\n"
                     "?l = lowercase letters (a-z)\n"
                     "?u = uppercase letters (A-Z)\n"
                     "?d = digits (0-9)\n"
                     "?s = symbols (!@#$...)\n"
                     "Example: ?d?d?d = three digits (000-999)")

        tb.Label(help_frame, text=help_text, justify=LEFT, font=("Consolas", 9)).pack(anchor=W)

        # Start button
        self.hybrid_start_btn = tb.Button(
            hybrid_frame,
            text="🔀 Start Hybrid Attack",
            bootstyle=PRIMARY,
            command=self.start_hybrid_attack
        )
        self.hybrid_start_btn.pack(pady=20)

    def create_combinator_attack_tab(self):
        """Combinator attack configuration"""
        comb_frame = tb.Frame(self.notebook, padding=20)
        self.notebook.add(comb_frame, text="🔗 Combinator")

        # Hash input
        hash_frame = tb.LabelFrame(comb_frame, text="Target Hash", padding=15)
        hash_frame.pack(fill=X, pady=(0, 15))

        hash_input_frame = tb.Frame(hash_frame)
        hash_input_frame.pack(fill=X)

        tb.Label(hash_input_frame, text="Hash:", font=("Helvetica", 10, "bold")).pack(side=LEFT, padx=(0, 10))
        self.comb_hash_entry = tb.Entry(hash_input_frame, width=50, font=("Consolas", 10))
        self.comb_hash_entry.pack(side=LEFT, fill=X, expand=True, padx=(0, 10))

        tb.Label(hash_input_frame, text="Type:", font=("Helvetica", 10, "bold")).pack(side=LEFT, padx=(0, 10))
        comb_hash_type_combo = tb.Combobox(hash_input_frame, textvariable=self.comb_hash_type_var,
                                          values=self.hash_types, state="readonly", width=15)
        comb_hash_type_combo.pack(side=LEFT)

        # Configuration
        config_frame = tb.LabelFrame(comb_frame, text="Combinator Configuration", padding=15)
        config_frame.pack(fill=X, pady=(0, 15))

        # Wordlist 1
        tb.Label(config_frame, text="Wordlist 1:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(0, 5))
        wl1_frame = tb.Frame(config_frame)
        wl1_frame.pack(fill=X, pady=(0, 10))

        tb.Entry(wl1_frame, textvariable=self.comb_wordlist1_var, width=50).pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        tb.Button(wl1_frame, text="📂 Browse", bootstyle=SECONDARY,
                  command=self.browse_combinator_wordlist1).pack(side=LEFT)

        # Wordlist 2
        tb.Label(config_frame, text="Wordlist 2:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(0, 5))
        wl2_frame = tb.Frame(config_frame)
        wl2_frame.pack(fill=X, pady=(0, 10))

        tb.Entry(wl2_frame, textvariable=self.comb_wordlist2_var, width=50).pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        tb.Button(wl2_frame, text="📂 Browse", bootstyle=SECONDARY,
                  command=self.browse_combinator_wordlist2).pack(side=LEFT)

        # Separator
        tb.Label(config_frame, text="Separator:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(5, 5))
        sep_frame = tb.Frame(config_frame)
        sep_frame.pack(anchor=W)

        tb.Entry(sep_frame, textvariable=self.comb_separator_var, width=10).pack(side=LEFT, padx=(0, 10))
        tb.Label(sep_frame, text="(leave empty for no separator)",
                 font=("Helvetica", 9, "italic")).pack(side=LEFT)

        # Start button
        self.comb_start_btn = tb.Button(
            comb_frame,
            text="🔗 Start Combinator Attack",
            bootstyle=INFO,
            command=self.start_combinator_attack
        )
        self.comb_start_btn.pack(pady=20)

    def create_advanced_tools_tab(self):
        """Advanced tools and integrations"""
        tools_frame = tb.Frame(self.notebook, padding=20)
        self.notebook.add(tools_frame, text="⚡ Advanced Tools")

        # Hashcat integration (simple placeholder UI)
        hc_frame = tb.LabelFrame(tools_frame, text="Hashcat Integration", padding=15)
        hc_frame.pack(fill=X, pady=(0, 15))

        tb.Label(hc_frame, text="Hashcat path (optional):").pack(side=LEFT, padx=(0, 10))
        self.hashcat_path_var = tb.StringVar()
        tb.Entry(hc_frame, textvariable=self.hashcat_path_var, width=60).pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        tb.Button(hc_frame, text="📂 Browse", bootstyle=SECONDARY, command=self.browse_hashcat).pack(side=LEFT)

        tb.Label(tools_frame, text="Note: Hashcat integration is not required. This UI provides a place to configure external tools.",
                 font=("Helvetica", 9, "italic")).pack(anchor=W, pady=(10, 0))

        # John the Ripper integration
        john_frame = tb.LabelFrame(tools_frame, text="John the Ripper Integration", padding=15)
        john_frame.pack(fill=X, pady=(0, 15))

        tb.Label(john_frame, text="John the Ripper path (optional):").pack(side=LEFT, padx=(0, 10))
        self.john_path_var = tb.StringVar()
        tb.Entry(john_frame, textvariable=self.john_path_var, width=60).pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        tb.Button(john_frame, text="📂 Browse", bootstyle=SECONDARY, command=self.browse_john).pack(side=LEFT)

        # System benchmark
        benchmark_frame = tb.LabelFrame(tools_frame, text="System Benchmark", padding=15)
        benchmark_frame.pack(fill=BOTH, expand=True)

        tb.Button(benchmark_frame, text="🏃‍♂️ Run Benchmark", bootstyle=SUCCESS,
                   command=self.run_benchmark).pack(pady=(0, 10))

        self.benchmark_text = tb.Text(benchmark_frame, height=10, state=DISABLED, font=("Consolas", 9))
        benchmark_text_scroll = tb.Scrollbar(benchmark_frame, orient=VERTICAL, command=self.benchmark_text.yview)
        self.benchmark_text.configure(yscrollcommand=benchmark_text_scroll.set)

        self.benchmark_text.pack(side=LEFT, fill=BOTH, expand=True)
        benchmark_text_scroll.pack(side=RIGHT, fill=Y)

    def create_results_tab(self):
        """Create a results tab to show progress and outputs"""
        results_frame = tb.Frame(self.notebook, padding=10)
        self.notebook.add(results_frame, text="📝 Results")

        self.results_text = tb.Text(results_frame, state=DISABLED, height=20, bg="#0b0b0b", fg="#c7f9cc", font=("Consolas", 10))
        results_scroll = tb.Scrollbar(results_frame, orient=VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=results_scroll.set)

        self.results_text.pack(side=LEFT, fill=BOTH, expand=True)
        results_scroll.pack(side=RIGHT, fill=Y)

    def create_control_buttons(self, parent):
        ctrl_frame = tb.Frame(parent)
        ctrl_frame.pack(fill=X, pady=(10, 0))

        self.stop_btn = tb.Button(ctrl_frame, text="⏹ Stop", bootstyle=DANGER, command=self.stop_current_attack)
        self.stop_btn.pack(side=RIGHT, padx=(5, 0))

        self.clear_results_btn = tb.Button(ctrl_frame, text="🧹 Clear Results", bootstyle=SECONDARY, command=self.clear_results)
        self.clear_results_btn.pack(side=RIGHT, padx=(5, 0))

    def create_status_bar(self, parent):
        status_frame = tb.Frame(parent)
        status_frame.pack(fill=X, pady=(10, 0))
        self.status_var = tb.StringVar(value="Idle")
        tb.Label(status_frame, textvariable=self.status_var, anchor=W).pack(fill=X)

    # -------------------- Browse / Helpers --------------------

    def browse_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.wordlist_var.set(path)

    def show_common_wordlists(self):
        # Try to fetch from backend helper if present
        lists = []
        try:
            if hasattr(self.hash_cracker, 'get_common_wordlists'):
                lists = self.hash_cracker.get_common_wordlists()
        except Exception:
            lists = []
        if not lists:
            messagebox.showinfo("Common Wordlists", "No local wordlists found.")
            return
        choice = lists[0]  # minimal UI: choose first for now
        self.wordlist_var.set(choice)
        messagebox.showinfo("Common Wordlists", f"Loaded: {choice}")

    def browse_hybrid_wordlist(self):
        path = filedialog.askopenfilename(title="Select hybrid wordlist", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.hybrid_wordlist_var.set(path)

    def browse_combinator_wordlist1(self):
        path = filedialog.askopenfilename(title="Select wordlist 1", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.comb_wordlist1_var.set(path)

    def browse_combinator_wordlist2(self):
        path = filedialog.askopenfilename(title="Select wordlist 2", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.comb_wordlist2_var.set(path)

    def browse_hashcat(self):
        path = filedialog.askopenfilename(title="Select hashcat executable", filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if path:
            self.hashcat_path_var.set(path)

    def browse_john(self):
        path = filedialog.askopenfilename(title="Select John the Ripper executable", filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if path:
            self.john_path_var.set(path)

    # -------------------- Attack start/stop wrappers --------------------

    def start_basic_dictionary_attack(self):
        if not ENHANCED_BACKEND:
            messagebox.showwarning("Backend missing", "No backend available to perform attacks.")
            return
        hash_val = self.dict_hash_entry.get().strip()
        hash_type = self.hash_type_var.get()
        wordlist = self.wordlist_var.get().strip()
        if not hash_val or not wordlist:
            messagebox.showwarning("Missing fields", "Provide both hash and wordlist path.")
            return
        args = (hash_val, hash_type, wordlist)
        self._start_thread(self._run_basic_dictionary_attack, args)

    def _run_basic_dictionary_attack(self, hash_val, hash_type, wordlist):
        self.status_var.set("Running basic dictionary attack...")
        self.is_cracking = True
        try:
            num_workers = int(self.num_workers_var.get()) if self.use_workers_var.get() else 1
        except Exception:
            num_workers = 1
        res = self.hash_cracker.dictionary_attack(hash_val, hash_type, wordlist, num_workers=num_workers)
        self.is_cracking = False
        self.status_var.set("Idle")
        self.show_result(res)

    def start_enhanced_dictionary_attack(self):
        if not ENHANCED_BACKEND:
            messagebox.showwarning("Backend missing", "No backend available to perform attacks.")
            return
        hash_val = self.dict_hash_entry.get().strip()
        hash_type = self.hash_type_var.get()
        wordlist = self.wordlist_var.get().strip()
        if not hash_val or not wordlist:
            messagebox.showwarning("Missing fields", "Provide both hash and wordlist path.")
            return
        kwargs = {
            'use_case_variations': self.case_variations_var.get(),
            'use_number_mutations': self.number_appending_var.get(),
            'use_symbol_mutations': self.symbol_appending_var.get(),
            'use_leet_speak': self.leet_speak_var.get(),
            'use_year_mutations': self.year_mutations_var.get(),
            'max_mutations_per_word': 100
        }
        self._start_thread(self._run_enhanced_dictionary_attack, (hash_val, hash_type, wordlist, kwargs))

    def _run_enhanced_dictionary_attack(self, hash_val, hash_type, wordlist, kwargs):
        self.status_var.set("Running enhanced dictionary attack...")
        self.is_cracking = True
        try:
            num_workers = int(self.num_workers_var.get()) if self.use_workers_var.get() else 1
        except Exception:
            num_workers = 1
        res = self.hash_cracker.enhanced_dictionary_attack(hash_val, hash_type, wordlist,
                                                           use_rules=True,
                                                           case_variations=kwargs['use_case_variations'],
                                                           number_appending=kwargs['use_number_mutations'],
                                                           symbol_appending=kwargs['use_symbol_mutations'],
                                                           num_workers=num_workers)
        self.is_cracking = False
        self.status_var.set("Idle")
        self.show_result(res)

    def start_brute_force_attack(self):
        if not ENHANCED_BACKEND:
            messagebox.showwarning("Backend missing", "No backend available to perform attacks.")
            return
        hash_val = self.bf_hash_entry.get().strip()
        hash_type = self.bf_hash_type_var.get()
        charset = self.charset_var.get()
        try:
            min_len = int(self.min_length_var.get())
            max_len = int(self.max_length_var.get())
        except ValueError:
            messagebox.showwarning("Invalid input", "Min/Max length must be integers.")
            return
        self._start_thread(self._run_brute_force, (hash_val, hash_type, charset, min_len, max_len))

    def _run_brute_force(self, hash_val, hash_type, charset, min_len, max_len):
        self.status_var.set("Running brute force attack...")
        self.is_cracking = True
        # brute force remains single-threaded for now
        res = self.hash_cracker.smart_brute_force_attack(hash_val, hash_type, charset, min_len, max_len,
                                                        self.use_common_patterns_var.get())
        self.is_cracking = False
        self.status_var.set("Idle")
        self.show_result(res)

    def start_smart_brute_force_attack(self):
        # same as brute force wrapper for now
        self.start_brute_force_attack()

    def start_hybrid_attack(self):
        if not ENHANCED_BACKEND:
            messagebox.showwarning("Backend missing", "No backend available to perform attacks.")
            return
        hash_val = self.hybrid_hash_entry.get().strip()
        hash_type = self.hybrid_hash_type_var.get()
        wordlist = self.hybrid_wordlist_var.get().strip()
        mask = self.hybrid_mask_var.get().strip()
        if not hash_val or not wordlist:
            messagebox.showwarning("Missing fields", "Provide hash and wordlist.")
            return
        self._start_thread(self._run_hybrid_attack, (hash_val, hash_type, wordlist, mask))

    def _run_hybrid_attack(self, hash_val, hash_type, wordlist, mask):
        self.status_var.set("Running hybrid attack...")
        self.is_cracking = True
        try:
            res = self.hash_cracker.hybrid_attack(hash_val, hash_type, wordlist, mask)
        except Exception as e:
            res = {'success': False, 'error': str(e)}
        self.is_cracking = False
        self.status_var.set("Idle")
        self.show_result(res)

    def start_combinator_attack(self):
        if not ENHANCED_BACKEND:
            messagebox.showwarning("Backend missing", "No backend available to perform attacks.")
            return
        hash_val = self.comb_hash_entry.get().strip()
        hash_type = self.comb_hash_type_var.get()
        w1 = self.comb_wordlist1_var.get().strip()
        w2 = self.comb_wordlist2_var.get().strip()
        sep = self.comb_separator_var.get()
        if not hash_val or not w1 or not w2:
            messagebox.showwarning("Missing fields", "Provide hash and both wordlists.")
            return
        self._start_thread(self._run_combinator_attack, (hash_val, hash_type, w1, w2, sep))

    def _run_combinator_attack(self, hash_val, hash_type, w1, w2, sep):
        self.status_var.set("Running combinator attack...")
        self.is_cracking = True
        try:
            res = self.hash_cracker.combinator_attack(hash_val, hash_type, w1, w2, sep)
        except Exception as e:
            res = {'success': False, 'error': str(e)}
        self.is_cracking = False
        self.status_var.set("Idle")
        self.show_result(res)

    # -------------------- Thread helper --------------------

    def _start_thread(self, target, args=()):
        if self.current_thread and self.current_thread.is_alive():
            messagebox.showwarning("Already running", "An attack is already running. Stop it before starting another.")
            return
        self.current_thread = threading.Thread(target=target, args=args, daemon=True)
        self.current_thread.start()

    def stop_current_attack(self):
        # Signal backend to stop if possible
        self.is_cracking = False
        if ENHANCED_BACKEND and hasattr(self.hash_cracker, 'stop'):
            try:
                self.hash_cracker.stop()
            except Exception:
                pass
        self.status_var.set("Stopping...")

    # -------------------- Progress / Results --------------------

    def update_progress(self, message):
        # append to results area
        try:
            self.results_text.configure(state='normal')
            self.results_text.insert(END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
            self.results_text.see(END)
            self.results_text.configure(state='disabled')
        except Exception:
            pass

    def show_result(self, result):
        # Show final result object in results area and also a popup if cracked
        try:
            self.results_text.configure(state='normal')
            self.results_text.insert(END, f"RESULT: {result}\n\n")
            self.results_text.see(END)
            self.results_text.configure(state='disabled')
        except Exception:
            pass
        if isinstance(result, dict) and result.get('success'):
            plaintext = result.get('plaintext', '<unknown>')
            messagebox.showinfo("Hash Cracked", f"Password found: {plaintext}")

    # -------------------- Small utilities --------------------

    def analyze_hash(self):
        txt = self.hash_entry.get("1.0", END).strip()
        if not txt:
            messagebox.showwarning("Input required", "Please enter a hash to analyze.")
            return
        # Basic detection using backend if available
        if self.hash_detector:
            primary, possible = self.hash_detector.detect_hash_type(txt), []
            out = f"Detected (detector): {primary}\n"
        else:
            # Simple heuristic
            length = len(txt)
            if length == 32:
                out = "Possible: MD5, MD4, NTLM\n"
            elif length == 40:
                out = "Possible: SHA1, MySQL\n"
            else:
                out = f"Length: {length}. Unable to precisely detect.\n"
        self.detection_text.configure(state='normal')
        self.detection_text.delete("1.0", END)
        self.detection_text.insert(END, out)
        self.detection_text.configure(state='disabled')

    def load_hash_file(self):
        path = filedialog.askopenfilename(title="Load hash file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    data = f.read()
                    self.hash_entry.delete("1.0", END)
                    self.hash_entry.insert(END, data)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")

    def clear_hash_analysis(self):
        self.hash_entry.delete("1.0", END)
        self.detection_text.configure(state='normal')
        self.detection_text.delete("1.0", END)
        self.detection_text.configure(state='disabled')

    def clear_results(self):
        self.results_text.configure(state='normal')
        self.results_text.delete("1.0", END)
        self.results_text.configure(state='disabled')
        self.status_var.set("Idle")

    def _attack_finished(self):
        """Called when attack finishes"""
        self.is_cracking = False
        if ENHANCED_BACKEND and hasattr(self, 'hash_cracker'):
            try:
                self.hash_cracker.is_running = False
            except Exception:
                pass

        # Re-enable attack buttons
        try:
            self.dict_start_btn.config(state=NORMAL)
            self.basic_dict_btn.config(state=NORMAL)
            self.bf_start_btn.config(state=NORMAL)
            if hasattr(self, 'smart_bf_start_btn'):
                self.smart_bf_start_btn.config(state=NORMAL)
            self.hybrid_start_btn.config(state=NORMAL)
            self.comb_start_btn.config(state=NORMAL)
            self.stop_btn.config(state=DISABLED)
        except Exception:
            pass

        self.update_status("Attack completed")

    def stop_attack(self):
        """Stop current attack"""
        if self.is_cracking:
            self.is_cracking = False
            if ENHANCED_BACKEND and hasattr(self, 'hash_cracker'):
                try:
                    # call backend stop if available
                    if hasattr(self.hash_cracker, 'stop'):
                        self.hash_cracker.stop()
                    elif hasattr(self.hash_cracker, 'stop_cracking'):
                        self.hash_cracker.stop_cracking()
                except Exception:
                    pass
            self.update_progress("🛑 Attack stopped by user")
            self.update_status("Attack stopped")
            self._attack_finished()

    def start_smart_brute_force_attack(self):
        """Start smart brute force attack"""
        hash_value = self.bf_hash_entry.get().strip()
        hash_type = self.bf_hash_type_var.get()
        charset = self.charset_var.get().strip()
        try:
            min_length = int(self.min_length_var.get())
            max_length = int(self.max_length_var.get())
        except ValueError:
            messagebox.showwarning("Warning", "Invalid length values")
            return

        if not hash_value:
            messagebox.showwarning("Warning", "Please enter a hash")
            return
        if not charset:
            messagebox.showwarning("Warning", "Please enter a character set")
            return
        if min_length > max_length:
            messagebox.showwarning("Warning", "Min length cannot be greater than max length")
            return
        if max_length > 10:
            response = messagebox.askyesno("Warning",
                                           "Maximum length > 10 may take a very long time.\nContinue anyway?")
            if not response:
                return

        self.is_cracking = True
        if ENHANCED_BACKEND and hasattr(self, 'hash_cracker'):
            try:
                self.hash_cracker.is_running = True
            except Exception:
                pass
        try:
            self.bf_start_btn.config(state=DISABLED)
            if hasattr(self, 'smart_bf_start_btn'):
                self.smart_bf_start_btn.config(state=DISABLED)
            self.stop_btn.config(state=NORMAL)
        except Exception:
            pass

        # Switch to results tab
        try:
            self.notebook.select(self.notebook.index("end") - 1)
        except Exception:
            pass

        # Start attack in thread
        self.current_thread = threading.Thread(
            target=self._run_smart_brute_force_attack,
            args=(hash_value, hash_type, charset, min_length, max_length, self.use_common_patterns_var.get()),
            daemon=True
        )
        self.current_thread.start()

    def _run_smart_brute_force_attack(self, hash_value, hash_type, charset, min_length, max_length, use_common_patterns):
        """Run smart brute force attack in thread"""
        try:
            result = None
            if ENHANCED_BACKEND and hasattr(self, 'hash_cracker'):
                result = self.hash_cracker.smart_brute_force_attack(
                    hash_value, hash_type, charset, min_length, max_length, use_common_patterns
                )
            else:
                self.update_progress("❌ Enhanced backend not available")
            if result is not None:
                self.show_result(result)
        except Exception as e:
            self.update_progress(f"❌ Error: {e}")
        finally:
            # Ensure UI is updated on main thread
            try:
                self.window.after(0, self._attack_finished)
            except Exception:
                pass

    def run_hashcat(self):
        """Run hashcat attack (placeholder)"""
        messagebox.showinfo("Info", "Hashcat integration coming soon")

    def run_john(self):
        """Run John the Ripper attack (placeholder)"""
        messagebox.showinfo("Info", "John the Ripper integration coming soon")

    def run_benchmark(self):
        """Run system benchmark"""
        if ENHANCED_BACKEND and hasattr(self, 'hash_cracker') and hasattr(self.hash_cracker, 'benchmark_system'):
            self.update_progress("🏃‍♂️ Starting system benchmark...")

            def run_benchmark_thread():
                try:
                    results = self.hash_cracker.benchmark_system()
                    # Update benchmark display
                    try:
                        self.benchmark_text.config(state=NORMAL)
                        self.benchmark_text.delete("1.0", "end")
                        self.benchmark_text.insert("end", "📊 BENCHMARK RESULTS:\n")
                        self.benchmark_text.insert("end", "=" * 40 + "\n")
                        for algo, data in results.items():
                            if isinstance(data, dict) and 'error' in data:
                                self.benchmark_text.insert("end", f"❌ {algo}: {data['error']}\n")
                            elif isinstance(data, dict) and 'hashes_per_second' in data:
                                self.benchmark_text.insert("end", f"✅ {algo}: {data['hashes_per_second']:,} h/s\n")
                            else:
                                self.benchmark_text.insert("end", f"ℹ️ {algo}: {data}\n")
                        self.benchmark_text.config(state=DISABLED)
                    except Exception:
                        pass
                    self.update_status("Benchmark completed")
                except Exception as e:
                    self.update_progress(f"❌ Benchmark error: {str(e)}")

            threading.Thread(target=run_benchmark_thread, daemon=True).start()
        else:
            messagebox.showinfo("Info", "Benchmark requires enhanced backend")

    def update_status(self, message: str):
        """Update status bar"""
        if hasattr(self, 'status_var'):
            self.status_var.set(message)
        else:
            # Fallback if status bar doesn't exist
            print(f"[Status] {message}")


# Entry point for standalone testing
if __name__ == "__main__":
    root = tb.Window(themename="darkly")
    app = HashCracking(root)
    root.mainloop()

