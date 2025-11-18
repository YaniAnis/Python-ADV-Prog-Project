"""
Password Cracker Engine - Core Logic
Educational cybersecurity tool for authorized testing only.
"""

import hashlib
import itertools
import string
import threading
import time
import os
import requests
from typing import List, Dict, Callable, Optional, Tuple
import concurrent.futures
import queue

class PasswordCrackerEngine:
    """Core password cracking engine with multiple attack methods"""
    
    def __init__(self):
        self.is_running = False
        self.progress_callback = None
        self.result_callback = None
        self.stop_event = threading.Event()
        
        # Supported hash types
        self.hash_types = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha224': hashlib.sha224,
            'sha384': hashlib.sha384
        }
        
        # Common passwords for dictionary attacks
        self.common_passwords = [
            "password", "123456", "password123", "admin", "qwerty", "letmein",
            "welcome", "monkey", "1234567890", "abc123", "111111", "password1",
            "login", "master", "hello", "guest", "shadow", "secret", "root",
            "test", "user", "pass", "default", "changeme", "demo", "temp"
        ]
    
    def detect_hash_type(self, hash_string: str) -> str:
        """Detect hash type based on length and format"""
        hash_string = hash_string.strip().lower()
        
        # Remove common prefixes
        if hash_string.startswith('$'):
            return "unsupported"
        
        length = len(hash_string)
        
        hash_lengths = {
            32: 'md5',
            40: 'sha1',
            56: 'sha224',
            64: 'sha256',
            96: 'sha384',
            128: 'sha512'
        }
        
        return hash_lengths.get(length, 'unknown')
    
    def hash_password(self, password: str, hash_type: str) -> str:
        """Hash a password using specified algorithm"""
        if hash_type not in self.hash_types:
            return ""
        
        return self.hash_types[hash_type](password.encode()).hexdigest()
    
    def dictionary_attack(self, target_hash: str, hash_type: str, 
                         wordlist: List[str], max_threads: int = 4) -> Optional[str]:
        """Perform dictionary attack on hash"""
        self.is_running = True
        self.stop_event.clear()
        
        target_hash = target_hash.strip().lower()
        result_queue = queue.Queue()
        
        def worker(words_chunk):
            """Worker function for threading"""
            for word in words_chunk:
                if self.stop_event.is_set():
                    return
                
                word = word.strip()
                if not word:
                    continue
                
                # Try original word
                test_hash = self.hash_password(word, hash_type)
                if test_hash == target_hash:
                    result_queue.put(word)
                    return
                
                # Try common variations
                variations = [
                    word.upper(),
                    word.capitalize(),
                    word + "123",
                    word + "1",
                    word + "!",
                    "123" + word,
                ]
                
                for variation in variations:
                    if self.stop_event.is_set():
                        return
                    
                    test_hash = self.hash_password(variation, hash_type)
                    if test_hash == target_hash:
                        result_queue.put(variation)
                        return
        
        # Split wordlist into chunks for threading
        chunk_size = max(1, len(wordlist) // max_threads)
        chunks = [wordlist[i:i + chunk_size] for i in range(0, len(wordlist), chunk_size)]
        
        # Start worker threads
        threads = []
        for chunk in chunks:
            thread = threading.Thread(target=worker, args=(chunk,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Monitor progress
        total_words = len(wordlist)
        processed = 0
        
        while any(thread.is_alive() for thread in threads):
            if self.stop_event.is_set():
                break
            
            # Check for result
            try:
                result = result_queue.get_nowait()
                self.stop_event.set()  # Signal other threads to stop
                self.is_running = False
                return result
            except queue.Empty:
                pass
            
            # Update progress
            if self.progress_callback:
                progress = min(100, (processed / total_words) * 100)
                self.progress_callback(progress, f"Testing password variations... ({processed}/{total_words})")
            
            time.sleep(0.1)
            processed += chunk_size
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=1)
        
        self.is_running = False
        return None
    
    def brute_force_attack(self, target_hash: str, hash_type: str, 
                          charset: str, max_length: int = 4, min_length: int = 1) -> Optional[str]:
        """Perform brute force attack"""
        self.is_running = True
        self.stop_event.clear()
        
        target_hash = target_hash.strip().lower()
        
        for length in range(min_length, max_length + 1):
            if self.stop_event.is_set():
                break
            
            total_combinations = len(charset) ** length
            tested = 0
            
            for password_tuple in itertools.product(charset, repeat=length):
                if self.stop_event.is_set():
                    break
                
                password = ''.join(password_tuple)
                test_hash = self.hash_password(password, hash_type)
                
                if test_hash == target_hash:
                    self.is_running = False
                    return password
                
                tested += 1
                
                # Update progress every 1000 attempts
                if tested % 1000 == 0 and self.progress_callback:
                    progress = (tested / total_combinations) * 100
                    self.progress_callback(
                        progress, 
                        f"Brute forcing length {length}: {tested}/{total_combinations}"
                    )
        
        self.is_running = False
        return None
    
    def hybrid_attack(self, target_hash: str, hash_type: str, 
                     base_words: List[str], numbers: bool = True, 
                     symbols: bool = True) -> Optional[str]:
        """Perform hybrid attack (dictionary + modifications)"""
        self.is_running = True
        self.stop_event.clear()
        
        target_hash = target_hash.strip().lower()
        
        modifications = [""]
        
        if numbers:
            modifications.extend([str(i) for i in range(100)])
            modifications.extend([f"{i:02d}" for i in range(100)])
        
        if symbols:
            modifications.extend(["!", "@", "#", "$", "123", "1", "01"])
        
        total_combinations = len(base_words) * len(modifications) * 8  # 8 for different positions
        tested = 0
        
        for word in base_words:
            if self.stop_event.is_set():
                break
            
            for mod in modifications:
                if self.stop_event.is_set():
                    break
                
                # Try different positions and cases
                test_passwords = [
                    word + mod,           # append
                    mod + word,           # prepend
                    word.upper() + mod,   # uppercase + append
                    mod + word.upper(),   # prepend + uppercase
                    word.capitalize() + mod,  # capitalize + append
                    mod + word.capitalize(),  # prepend + capitalize
                    word.lower() + mod,   # lowercase + append
                    mod + word.lower()    # prepend + lowercase
                ]
                
                for test_password in test_passwords:
                    if self.stop_event.is_set():
                        break
                    
                    test_hash = self.hash_password(test_password, hash_type)
                    if test_hash == target_hash:
                        self.is_running = False
                        return test_password
                    
                    tested += 1
                    
                    if tested % 100 == 0 and self.progress_callback:
                        progress = (tested / total_combinations) * 100
                        self.progress_callback(
                            progress,
                            f"Hybrid attack: {tested}/{total_combinations}"
                        )
        
        self.is_running = False
        return None
    
    def rainbow_table_lookup(self, target_hash: str, hash_type: str) -> Optional[str]:
        """Simulate rainbow table lookup (online hash databases)"""
        self.is_running = True
        
        # Common online hash lookup APIs (for educational purposes)
        apis = [
            f"https://md5decrypt.net/en/Api/api.php?hash={target_hash}&hash_type={hash_type}&email=test@example.com&code=test",
            f"https://hashkiller.io/listmanager",
            # Note: These are examples - actual APIs may require authentication
        ]
        
        # Simulate lookup
        if self.progress_callback:
            self.progress_callback(50, "Searching rainbow tables...")
        
        time.sleep(1)  # Simulate network delay
        
        # Check against common passwords first (simulating cached results)
        target_hash = target_hash.strip().lower()
        for password in self.common_passwords:
            test_hash = self.hash_password(password, hash_type)
            if test_hash == target_hash:
                if self.progress_callback:
                    self.progress_callback(100, "Found in rainbow table!")
                self.is_running = False
                return password
        
        if self.progress_callback:
            self.progress_callback(100, "Not found in rainbow tables")
        
        self.is_running = False
        return None
    
    def load_wordlist_from_file(self, filepath: str) -> List[str]:
        """Load wordlist from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            return []
    
    def get_common_passwords(self) -> List[str]:
        """Get list of common passwords"""
        return self.common_passwords.copy()
    
    def stop_attack(self):
        """Stop current attack"""
        self.is_running = False
        self.stop_event.set()
    
    def set_progress_callback(self, callback: Callable):
        """Set progress update callback"""
        self.progress_callback = callback
    
    def set_result_callback(self, callback: Callable):
        """Set result callback"""
        self.result_callback = callback

class HashAnalyzer:
    """Analyze and provide information about hashes"""
    
    @staticmethod
    def analyze_hash(hash_string: str) -> Dict:
        """Analyze hash and provide detailed information"""
        hash_string = hash_string.strip()
        
        analysis = {
            'original': hash_string,
            'length': len(hash_string),
            'format': 'unknown',
            'possible_types': [],
            'confidence': 'unknown',
            'is_valid_hex': HashAnalyzer._is_valid_hex(hash_string),
            'contains_salt': False,
            'algorithm_info': {}
        }
        
        # Remove common prefixes and analyze
        clean_hash = hash_string.lower()
        if clean_hash.startswith('$'):
            parts = clean_hash.split('$')
            if len(parts) >= 3:
                analysis['contains_salt'] = True
                analysis['format'] = 'unix_crypt'
                # Identify specific Unix crypt formats
                if parts[1] == '1':
                    analysis['possible_types'] = ['md5crypt']
                elif parts[1] == '2a' or parts[1] == '2b':
                    analysis['possible_types'] = ['bcrypt']
                elif parts[1] == '5':
                    analysis['possible_types'] = ['sha256crypt']
                elif parts[1] == '6':
                    analysis['possible_types'] = ['sha512crypt']
        else:
            # Analyze by length for standard hashes
            length_map = {
                32: (['md5'], 'high'),
                40: (['sha1'], 'high'),
                56: (['sha224'], 'high'),
                64: (['sha256'], 'high'),
                96: (['sha384'], 'high'),
                128: (['sha512'], 'high'),
                16: (['md5_half', 'crc16'], 'low'),
                8: (['crc32'], 'low'),
                4: (['crc16_short'], 'very_low')
            }
            
            if analysis['length'] in length_map:
                analysis['possible_types'], analysis['confidence'] = length_map[analysis['length']]
            
            # Check for common hash patterns
            if analysis['is_valid_hex']:
                analysis['format'] = 'hexadecimal'
            elif HashAnalyzer._is_base64(hash_string):
                analysis['format'] = 'base64'
                analysis['possible_types'].append('base64_encoded_hash')
        
        # Add algorithm information
        for hash_type in analysis['possible_types']:
            if hash_type in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']:
                analysis['algorithm_info'][hash_type] = {
                    'security': HashAnalyzer._get_security_level(hash_type),
                    'speed': HashAnalyzer._get_cracking_speed(hash_type),
                    'recommended': hash_type in ['sha256', 'sha512']
                }
        
        return analysis
    
    @staticmethod
    def _is_valid_hex(s: str) -> bool:
        """Check if string is valid hexadecimal"""
        try:
            int(s, 16)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def _is_base64(s: str) -> bool:
        """Check if string might be base64 encoded"""
        import re
        return bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', s)) and len(s) % 4 == 0
    
    @staticmethod
    def _get_security_level(hash_type: str) -> str:
        """Get security level of hash algorithm"""
        security_levels = {
            'md5': 'very_weak',
            'sha1': 'weak',
            'sha224': 'moderate',
            'sha256': 'strong',
            'sha384': 'strong',
            'sha512': 'very_strong'
        }
        return security_levels.get(hash_type, 'unknown')
    
    @staticmethod
    def _get_cracking_speed(hash_type: str) -> str:
        """Get relative cracking speed"""
        speed_levels = {
            'md5': 'very_fast',
            'sha1': 'fast',
            'sha224': 'moderate',
            'sha256': 'moderate',
            'sha384': 'slow',
            'sha512': 'slow'
        }
        return speed_levels.get(hash_type, 'unknown')

class PasswordGenerator:
    """Generate passwords and wordlists for testing"""
    
    @staticmethod
    def generate_common_patterns(base_words: List[str]) -> List[str]:
        """Generate common password patterns"""
        patterns = []
        
        for word in base_words:
            # Basic variations
            patterns.extend([
                word,
                word.upper(),
                word.capitalize(),
                word.lower()
            ])
            
            # Number variations
            for i in range(10):
                patterns.extend([
                    f"{word}{i}",
                    f"{word}{i:02d}",
                    f"{i}{word}",
                ])
            
            # Common year variations
            for year in [2020, 2021, 2022, 2023, 2024]:
                patterns.extend([
                    f"{word}{year}",
                    f"{year}{word}"
                ])
            
            # Symbol variations
            symbols = ["!", "@", "#", "$", "123"]
            for symbol in symbols:
                patterns.extend([
                    f"{word}{symbol}",
                    f"{symbol}{word}"
                ])
        
        return list(set(patterns))  # Remove duplicates
    
    @staticmethod
    def generate_mask_wordlist(mask: str, charset_map: Dict[str, str]) -> List[str]:
        """Generate wordlist based on mask pattern (e.g., ?u?u?u?d?d?d)"""
        # ?u = uppercase, ?l = lowercase, ?d = digit, ?s = symbol
        default_charsets = {
            'u': string.ascii_uppercase,
            'l': string.ascii_lowercase, 
            'd': string.digits,
            's': '!@#$%^&*()_+-='
        }
        
        charset_map = {**default_charsets, **charset_map}
        
        # Parse mask
        positions = []
        i = 0
        while i < len(mask):
            if mask[i] == '?' and i + 1 < len(mask):
                char_type = mask[i + 1]
                if char_type in charset_map:
                    positions.append(charset_map[char_type])
                else:
                    positions.append(char_type)
                i += 2
            else:
                positions.append(mask[i])
                i += 1
        
        # Generate combinations
        if any(isinstance(pos, str) and len(pos) > 1 for pos in positions):
            # Has variable positions
            cartesian_lists = []
            for pos in positions:
                if isinstance(pos, str) and len(pos) == 1:
                    cartesian_lists.append([pos])
                else:
                    cartesian_lists.append(list(pos))
            
            passwords = []
            for combo in itertools.product(*cartesian_lists):
                passwords.append(''.join(combo))
                if len(passwords) > 10000:  # Limit for memory
                    break
            
            return passwords
        else:
            return [''.join(positions)]