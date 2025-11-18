"""Enhanced Hash Cracking Engine - Separated Logic
Comprehensive hash cracking solution with multiple attack methods and optimization strategies.
"""

import hashlib
import subprocess
import threading
import time
import os
import itertools
import random
import string
import json
import base64
import binascii
from typing import List, Dict, Optional, Callable, Generator, Tuple
import sys
import re
from pathlib import Path
import codecs
import importlib.util
import concurrent.futures

# Add the modules directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'modules'))

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

try:
    # Try to import from modules directory
    modules_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'modules', 'HashCracker'))
    hd_path = os.path.join(modules_dir, 'HashDetector.py')
    hc_path = os.path.join(modules_dir, 'HashCracker.py')
    HashDetector = _load_class_from_path(hd_path, 'HashDetector')
    HashCracker = _load_class_from_path(hc_path, 'HashCracker')
    
    if not HashDetector or not HashCracker:
        print("Warning: HashDetector and/or HashCracker modules not found. Using basic functionality.")
        if not HashDetector:
            HashDetector = None
        if not HashCracker:
            HashCracker = None
            
except Exception as e:
    print(f"Error loading HashCracker modules: {e}")
    HashDetector = None
    HashCracker = None


class EnhancedHashCracker:
    """Enhanced Hash Cracking Engine with comprehensive attack methods"""

    def __init__(self):
        # Initialize base components if available
        self.detector = HashDetector() if HashDetector else None
        self.base_cracker = HashCracker() if HashCracker else None

        # Control variables
        self.is_running = False
        self.current_process = None
        self.progress_callback = None
        self.result_callback = None

        # Statistics tracking
        self.stats = {
            'total_attempts': 0,
            'start_time': None,
            'current_method': None,
            'passwords_per_second': 0,
            'current_candidate': '',
            'estimated_completion': None
        }

        # Enhanced hash type support with more algorithms
        self.hash_algorithms = {
            # Standard cryptographic hashes
            'MD4': self._compute_md4,
            'MD5': self._compute_md5,
            'SHA1': self._compute_sha1,
            'SHA224': self._compute_sha224,
            'SHA256': self._compute_sha256,
            'SHA384': self._compute_sha384,
            'SHA512': self._compute_sha512,
            'SHA3-224': self._compute_sha3_224,
            'SHA3-256': self._compute_sha3_256,
            'SHA3-384': self._compute_sha3_384,
            'SHA3-512': self._compute_sha3_512,
            'BLAKE2b': self._compute_blake2b,
            'BLAKE2s': self._compute_blake2s,

            # Windows hashes
            'NTLM': self._compute_ntlm,
            'LM': self._compute_lm,

            # Database hashes
            'MySQL': self._compute_mysql,
            'MySQL5': self._compute_mysql5,
            'PostgreSQL': self._compute_postgresql,
            'MSSQL': self._compute_mssql,
            'Oracle': self._compute_oracle,

            # Web application hashes
            'WordPress': self._compute_wordpress,
            'Joomla': self._compute_joomla,
            'Drupal7': self._compute_drupal7,

            # Checksums
            'CRC32': self._compute_crc32,
            'Adler32': self._compute_adler32,

            # Modern password hashes
            'bcrypt': self._compute_bcrypt,
            'scrypt': self._compute_scrypt,
            'PBKDF2': self._compute_pbkdf2,
            'Argon2': self._compute_argon2,

            # Encoding/Other
            'Base64': self._decode_base64,
            'Hex': self._decode_hex,
            'ROT13': self._decode_rot13,
        }

        # Attack methods with metadata
        self.attack_methods = {
            'dictionary': {
                'name': 'Dictionary Attack',
                'description': 'Test passwords from wordlists',
                'speed': 'Fast',
                'success_rate': 'High'
            },
            'enhanced_dictionary': {
                'name': 'Enhanced Dictionary',
                'description': 'Dictionary with mutations and rules',
                'speed': 'Medium',
                'success_rate': 'Very High'
            },
            'brute_force': {
                'name': 'Brute Force',
                'description': 'Try all possible combinations',
                'speed': 'Slow',
                'success_rate': 'Guaranteed'
            },
            'smart_brute_force': {
                'name': 'Smart Brute Force',
                'description': 'Optimized brute force with patterns',
                'speed': 'Medium',
                'success_rate': 'High'
            },
            'hybrid': {
                'name': 'Hybrid Attack',
                'description': 'Combine wordlist with patterns',
                'speed': 'Medium',
                'success_rate': 'High'
            },
            'mask': {
                'name': 'Mask Attack',
                'description': 'Use specific character patterns',
                'speed': 'Fast',
                'success_rate': 'Medium'
            },
            'combinator': {
                'name': 'Combinator',
                'description': 'Combine words from multiple lists',
                'speed': 'Medium',
                'success_rate': 'Medium'
            }
        }

    def set_callbacks(self, progress_callback: Callable = None, result_callback: Callable = None):
        """Set callbacks for progress updates and results"""
        self.progress_callback = progress_callback
        self.result_callback = result_callback
        if self.base_cracker:
            self.base_cracker.set_callbacks(progress_callback, result_callback)

    # ==================== HASH COMPUTATION METHODS ====================

    def _compute_md4(self, text: str) -> Optional[str]:
        try:
            return hashlib.new('md4', text.encode()).hexdigest().lower()
        except Exception:
            return None

    def _compute_md5(self, text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest().lower()

    def _compute_sha1(self, text: str) -> str:
        return hashlib.sha1(text.encode()).hexdigest().lower()

    def _compute_sha224(self, text: str) -> str:
        return hashlib.sha224(text.encode()).hexdigest().lower()

    def _compute_sha256(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest().lower()

    def _compute_sha384(self, text: str) -> str:
        return hashlib.sha384(text.encode()).hexdigest().lower()

    def _compute_sha512(self, text: str) -> str:
        return hashlib.sha512(text.encode()).hexdigest().lower()

    def _compute_sha3_224(self, text: str) -> Optional[str]:
        try:
            return hashlib.sha3_224(text.encode()).hexdigest().lower()
        except AttributeError:
            return None

    def _compute_sha3_256(self, text: str) -> Optional[str]:
        try:
            return hashlib.sha3_256(text.encode()).hexdigest().lower()
        except AttributeError:
            return None

    def _compute_sha3_384(self, text: str) -> Optional[str]:
        try:
            return hashlib.sha3_384(text.encode()).hexdigest().lower()
        except AttributeError:
            return None

    def _compute_sha3_512(self, text: str) -> Optional[str]:
        try:
            return hashlib.sha3_512(text.encode()).hexdigest().lower()
        except AttributeError:
            return None

    def _compute_blake2b(self, text: str) -> Optional[str]:
        try:
            return hashlib.blake2b(text.encode()).hexdigest().lower()
        except AttributeError:
            return None

    def _compute_blake2s(self, text: str) -> Optional[str]:
        try:
            return hashlib.blake2s(text.encode()).hexdigest().lower()
        except AttributeError:
            return None

    def _compute_ntlm(self, text: str) -> Optional[str]:
        try:
            return hashlib.new('md4', text.encode('utf-16le')).hexdigest().lower()
        except Exception:
            return None

    def _compute_lm(self, text: str) -> str:
        """LM Hash (simplified implementation)"""
        return hashlib.md5(text.upper().encode()).hexdigest().lower()

    def _compute_mysql(self, text: str) -> str:
        """Old MySQL PASSWORD() function (approx)"""
        return hashlib.sha1(text.encode()).hexdigest().upper()

    def _compute_mysql5(self, text: str) -> str:
        """MySQL 5.x PASSWORD() function"""
        step1 = hashlib.sha1(text.encode()).digest()
        return '*' + hashlib.sha1(step1).hexdigest().upper()

    def _compute_postgresql(self, text: str) -> str:
        """PostgreSQL MD5 hash"""
        return hashlib.md5(text.encode()).hexdigest().lower()

    def _compute_mssql(self, text: str) -> str:
        """MSSQL hash (simplified)"""
        return hashlib.sha1(text.encode('utf-16le')).hexdigest().lower()

    def _compute_oracle(self, text: str) -> str:
        """Oracle hash (simplified)"""
        return hashlib.sha1(text.upper().encode()).hexdigest().upper()

    def _compute_wordpress(self, text: str) -> str:
        """WordPress phpass hash (simplified placeholder)"""
        return hashlib.md5(text.encode()).hexdigest()

    def _compute_joomla(self, text: str) -> str:
        """Joomla hash (simplified)"""
        return hashlib.md5(text.encode()).hexdigest()

    def _compute_drupal7(self, text: str) -> str:
        """Drupal 7 hash (simplified)"""
        return hashlib.sha512(text.encode()).hexdigest()

    def _compute_crc32(self, text: str) -> str:
        """CRC32 checksum"""
        import zlib
        return format(zlib.crc32(text.encode()) & 0xffffffff, '08x')

    def _compute_adler32(self, text: str) -> str:
        """Adler32 checksum"""
        import zlib
        return format(zlib.adler32(text.encode()) & 0xffffffff, '08x')

    def _compute_bcrypt(self, text: str) -> str:
        """bcrypt hash (placeholder - requires bcrypt library)"""
        return "bcrypt_placeholder"

    def _compute_scrypt(self, text: str) -> str:
        """scrypt hash (placeholder - requires scrypt library)"""
        return "scrypt_placeholder"

    def _compute_pbkdf2(self, text: str) -> str:
        """PBKDF2 hash"""
        return hashlib.pbkdf2_hmac('sha256', text.encode(), b'salt', 100000).hex()

    def _compute_argon2(self, text: str) -> str:
        """Argon2 hash (placeholder - requires argon2 library)"""
        return "argon2_placeholder"

    def _decode_base64(self, text: str) -> Optional[str]:
        """Base64 decode"""
        try:
            return base64.b64decode(text).decode('utf-8')
        except Exception:
            return None

    def _decode_hex(self, text: str) -> Optional[str]:
        """Hex decode"""
        try:
            return bytes.fromhex(text).decode('utf-8')
        except Exception:
            return None

    def _decode_rot13(self, text: str) -> str:
        """ROT13 decode"""
        try:
            return codecs.decode(text, 'rot_13')
        except Exception:
            return text

    # ==================== UTILITY METHODS ====================

    def _log_progress(self, message: str):
        """Internal method to log progress"""
        if self.progress_callback:
            self.progress_callback(message)

    def _log_result(self, result: Dict):
        """Internal method to log results"""
        if self.result_callback:
            self.result_callback(result)

    def _update_stats(self, attempts: int, candidate: str = ""):
        """Update cracking statistics"""
        self.stats['total_attempts'] = attempts
        self.stats['current_candidate'] = candidate

        if self.stats['start_time']:
            elapsed = time.time() - self.stats['start_time']
            self.stats['passwords_per_second'] = attempts / elapsed if elapsed > 0 else 0

    def verify_hash(self, plaintext: str, hash_value: str, hash_type: str) -> bool:
        """Enhanced hash verification with support for more hash types"""
        try:
            hash_func = self.hash_algorithms.get(hash_type.upper())
            if hash_func:
                computed_hash = hash_func(plaintext)
                if computed_hash:
                    return computed_hash.lower() == hash_value.lower()

            # Fallback to base cracker if available
            if self.base_cracker:
                return self.base_cracker.verify_hash(plaintext, hash_value, hash_type)

            return False

        except Exception as e:
            self._log_progress(f"Error verifying hash: {str(e)}")
            return False

    def get_supported_algorithms(self) -> List[str]:
        """Get list of supported hash algorithms"""
        return list(self.hash_algorithms.keys())

    def get_attack_methods(self) -> Dict:
        """Get available attack methods with metadata"""
        return self.attack_methods

    def detect_hash_type(self, hash_value: str) -> Tuple[str, List[str]]:
        """Enhanced hash type detection"""
        if self.detector:
            primary = self.detector.detect_hash_type(hash_value)
            all_possible = self.detector.detect_all_possible(hash_value)
            return primary, all_possible

        # Basic detection based on length and format
        hash_value = hash_value.strip()
        length = len(hash_value)
        possible_types = []

        if length == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            possible_types.extend(['MD5', 'MD4', 'NTLM'])
        elif length == 40 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            possible_types.extend(['SHA1', 'MySQL'])
        elif length == 56 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            possible_types.append('SHA224')
        elif length == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            possible_types.extend(['SHA256', 'SHA3-256', 'BLAKE2s'])
        elif length == 96 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            possible_types.append('SHA384')
        elif length == 128 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            possible_types.extend(['SHA512', 'SHA3-512', 'BLAKE2b'])

        primary_type = possible_types[0] if possible_types else "Unknown"
        return primary_type, possible_types

    # ==================== ATTACK METHODS ====================

    def dictionary_attack(self, hash_value: str, hash_type: str, wordlist_path: str,
                          max_words: int = None, num_workers: int = 1) -> Dict:
        """Basic dictionary attack (optionally multi-threaded)"""
        result = {
            'success': False,
            'plaintext': None,
            'hash_type': hash_type,
            'method': 'dictionary',
            'time_taken': 0,
            'attempts': 0
        }

        self.is_running = True
        self.stats['start_time'] = time.time()

        if not os.path.exists(wordlist_path):
            self._log_progress(f"❌ Wordlist not found: {wordlist_path}")
            return result

        self._log_progress(f"📖 Starting dictionary attack")
        attempts = 0
        comparator = self._prepare_comparator(hash_value, hash_type)

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Use simple batching when multithreading is requested
                if num_workers and num_workers > 1:
                    batch = []
                    batch_size = 512
                    for line in f:
                        if not self.is_running:
                            break
                        if max_words and attempts >= max_words:
                            break
                        candidate = line.strip()
                        if not candidate:
                            continue
                        batch.append(candidate)
                        if len(batch) >= batch_size:
                            with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as ex:
                                for ok, cand in zip(ex.map(comparator, batch), batch):
                                    attempts += 1
                                    if attempts % 10000 == 0:
                                        self._log_progress(f"🔍 Tested {attempts:,} passwords...")
                                    if ok:
                                        result['success'] = True
                                        result['plaintext'] = cand
                                        result['attempts'] = attempts
                                        result['time_taken'] = time.time() - self.stats['start_time']
                                        self._log_progress(f"✅ HASH CRACKED! Password: {cand}")
                                        self._log_result(result)
                                        return result
                            batch = []
                    # final batch
                    if batch and self.is_running:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as ex:
                            for ok, cand in zip(ex.map(comparator, batch), batch):
                                attempts += 1
                                if ok:
                                    result['success'] = True
                                    result['plaintext'] = cand
                                    result['attempts'] = attempts
                                    result['time_taken'] = time.time() - self.stats['start_time']
                                    self._log_progress(f"✅ HASH CRACKED! Password: {cand}")
                                    self._log_result(result)
                                    return result
                else:
                    for line in f:
                        if not self.is_running:
                            break
                        if max_words and attempts >= max_words:
                            break
                        candidate = line.strip()
                        if not candidate:
                            continue
                        attempts += 1
                        if attempts % 10000 == 0:
                            self._log_progress(f"🔍 Tested {attempts:,} passwords...")
                        if comparator(candidate):
                            result['success'] = True
                            result['plaintext'] = candidate
                            result['attempts'] = attempts
                            result['time_taken'] = time.time() - self.stats['start_time']
                            self._log_progress(f"✅ HASH CRACKED! Password: {candidate}")
                            self._log_result(result)
                            return result

        except Exception as e:
            self._log_progress(f"❌ Error: {str(e)}")

        result['attempts'] = attempts
        result['time_taken'] = time.time() - self.stats['start_time']
        return result

    def enhanced_dictionary_attack(self, hash_value: str, hash_type: str, wordlist_path: str,
                                   use_rules: bool = False, case_variations: bool = False,
                                   number_appending: bool = False, symbol_appending: bool = False,
                                   num_workers: int = 1) -> Dict:
        """Enhanced dictionary attack with mutations"""
        result = {
            'success': False,
            'plaintext': None,
            'hash_type': hash_type,
            'method': 'enhanced_dictionary',
            'time_taken': 0,
            'attempts': 0
        }

        self.is_running = True
        self.stats['start_time'] = time.time()

        if not os.path.exists(wordlist_path):
            self._log_progress(f"❌ Wordlist not found: {wordlist_path}")
            return result

        self._log_progress(f"🚀 Starting enhanced dictionary attack")
        attempts = 0

        comparator = self._prepare_comparator(hash_value, hash_type)
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                if num_workers and num_workers > 1:
                    # process base words in batches, each base expands into candidates locally
                    batch = []
                    batch_size = 256
                    for line in f:
                        if not self.is_running:
                            break
                        base_word = line.strip()
                        if not base_word:
                            continue
                        batch.append(base_word)
                        if len(batch) >= batch_size:
                            expanded = []
                            for bw in batch:
                                cands = [bw]
                                if case_variations:
                                    cands.extend(self._generate_case_variations(bw))
                                if number_appending:
                                    cands.extend(self._generate_number_mutations(bw))
                                if symbol_appending:
                                    cands.extend(self._generate_symbol_mutations(bw))
                                expanded.extend(cands)
                            with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as ex:
                                for ok, cand in zip(ex.map(comparator, expanded), expanded):
                                    attempts += 1
                                    if attempts % 5000 == 0:
                                        self._log_progress(f"🔍 Tested {attempts:,} passwords...")
                                    if ok:
                                        result['success'] = True
                                        result['plaintext'] = cand
                                        result['attempts'] = attempts
                                        result['time_taken'] = time.time() - self.stats['start_time']
                                        self._log_progress(f"✅ HASH CRACKED! Password: {cand}")
                                        self._log_result(result)
                                        return result
                            batch = []
                    # final batch
                    if batch and self.is_running:
                        expanded = []
                        for bw in batch:
                            cands = [bw]
                            if case_variations:
                                cands.extend(self._generate_case_variations(bw))
                            if number_appending:
                                cands.extend(self._generate_number_mutations(bw))
                            if symbol_appending:
                                cands.extend(self._generate_symbol_mutations(bw))
                            expanded.extend(cands)
                        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as ex:
                            for ok, cand in zip(ex.map(comparator, expanded), expanded):
                                attempts += 1
                                if ok:
                                    result['success'] = True
                                    result['plaintext'] = cand
                                    result['attempts'] = attempts
                                    result['time_taken'] = time.time() - self.stats['start_time']
                                    self._log_progress(f"✅ HASH CRACKED! Password: {cand}")
                                    self._log_result(result)
                                    return result
                else:
                    for line in f:
                        if not self.is_running:
                            break
                        base_word = line.strip()
                        if not base_word:
                            continue
                        candidates = [base_word]
                        if case_variations:
                            candidates.extend(self._generate_case_variations(base_word))
                        if number_appending:
                            candidates.extend(self._generate_number_mutations(base_word))
                        if symbol_appending:
                            candidates.extend(self._generate_symbol_mutations(base_word))
                        for candidate in candidates:
                            if not self.is_running:
                                break
                            attempts += 1
                            if attempts % 5000 == 0:
                                self._log_progress(f"🔍 Tested {attempts:,} passwords...")
                            if comparator(candidate):
                                result['success'] = True
                                result['plaintext'] = candidate
                                result['attempts'] = attempts
                                result['time_taken'] = time.time() - self.stats['start_time']
                                self._log_progress(f"✅ HASH CRACKED! Password: {candidate}")
                                self._log_result(result)
                                return result

        except Exception as e:
            self._log_progress(f"❌ Error: {str(e)}")

        result['attempts'] = attempts
        result['time_taken'] = time.time() - self.stats['start_time']
        return result

    def smart_brute_force_attack(self, hash_value: str, hash_type: str,
                                 charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
                                 min_length: int = 1, max_length: int = 8,
                                 use_common_patterns: bool = True) -> Dict:
        """Smart brute force with pattern optimization"""
        result = {
            'success': False,
            'plaintext': None,
            'hash_type': hash_type,
            'method': 'smart_brute_force',
            'time_taken': 0,
            'attempts': 0
        }

        self.is_running = True
        self.stats['start_time'] = time.time()

        self._log_progress(f"🧠 Starting smart brute force attack")
        attempts = 0

        comparator = self._prepare_comparator(hash_value, hash_type)
        # Phase 1: Common patterns
        if use_common_patterns:
            self._log_progress("🎯 Testing common patterns...")
            common_patterns = ['password', 'admin', 'test', '123456', 'qwerty', 'abc123']

            for pattern in common_patterns:
                if not self.is_running:
                    break
                attempts += 1
                if comparator(pattern):
                    result['success'] = True
                    result['plaintext'] = pattern
                    result['attempts'] = attempts
                    result['time_taken'] = time.time() - self.stats['start_time']
                    self._log_progress("✅ HASH CRACKED with common pattern!")
                    self._log_result(result)
                    return result

        # Phase 2: Brute force
        self._log_progress("💪 Starting brute force...")
        for length in range(min_length, max_length + 1):
            if not self.is_running:
                break

            self._log_progress(f"🔍 Testing length {length}...")

            for candidate in itertools.product(charset, repeat=length):
                if not self.is_running:
                    break

                password = ''.join(candidate)
                attempts += 1

                if attempts % 50000 == 0:
                    self._log_progress(f"🔍 Tested {attempts:,} passwords...")

                if comparator(password):
                    result['success'] = True
                    result['plaintext'] = password
                    result['attempts'] = attempts
                    result['time_taken'] = time.time() - self.stats['start_time']
                    self._log_progress(f"✅ HASH CRACKED! Password: {password}")
                    self._log_result(result)
                    return result

        result['attempts'] = attempts
        result['time_taken'] = time.time() - self.stats['start_time']
        return result

    def hybrid_attack(self, hash_value: str, hash_type: str, wordlist_path: str, mask: str = "?d?d?d") -> Dict:
        """Hybrid attack: wordlist + mask"""
        result = {
            'success': False,
            'plaintext': None,
            'hash_type': hash_type,
            'method': 'hybrid',
            'time_taken': 0,
            'attempts': 0
        }

        self.is_running = True
        self.stats['start_time'] = time.time()

        self._log_progress(f"🔀 Starting hybrid attack")
        attempts = 0

        comparator = self._prepare_comparator(hash_value, hash_type)
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            for word in words:
                if not self.is_running:
                    break
                for suffix in self._generate_mask_combinations(mask):
                    if not self.is_running:
                        break
                    candidate = word + suffix
                    attempts += 1
                    if attempts % 5000 == 0:
                        self._log_progress(f"🔍 Tested {attempts:,} combinations...")
                    if comparator(candidate):
                        result['success'] = True
                        result['plaintext'] = candidate
                        result['attempts'] = attempts
                        result['time_taken'] = time.time() - self.stats['start_time']
                        self._log_progress(f"✅ HASH CRACKED! Password: {candidate}")
                        self._log_result(result)
                        return result

        except Exception as e:
            self._log_progress(f"❌ Error: {str(e)}")

        result['attempts'] = attempts
        result['time_taken'] = time.time() - self.stats['start_time']
        return result

    def combinator_attack(self, hash_value: str, hash_type: str, wordlist1: str, wordlist2: str, separator: str = "", num_workers: int = 1) -> Dict:
        """Combinator attack (optionally multi-threaded)"""
        result = {
            'success': False,
            'plaintext': None,
            'hash_type': hash_type,
            'method': 'combinator',
            'time_taken': 0,
            'attempts': 0
        }

        self.is_running = True
        self.stats['start_time'] = time.time()

        self._log_progress(f"🔗 Starting combinator attack")
        attempts = 0

        comparator = self._prepare_comparator(hash_value, hash_type)
        # support small thread pool for combinator
        use_threads = max(1, num_workers)
        try:
            with open(wordlist1, 'r', encoding='utf-8', errors='ignore') as f1:
                words1 = [line.strip() for line in f1 if line.strip()][:1000]
            with open(wordlist2, 'r', encoding='utf-8', errors='ignore') as f2:
                words2 = [line.strip() for line in f2 if line.strip()][:1000]
            # simple threaded approach: expand combinations in manageable chunks
            batch = []
            batch_size = 512
            for word1 in words1:
                if not self.is_running:
                    break
                for word2 in words2:
                    if not self.is_running:
                        break
                    batch.append(word1 + separator + word2)
                    if len(batch) >= batch_size:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=use_threads) as ex:
                            for ok, cand in zip(ex.map(comparator, batch), batch):
                                attempts += 1
                                if attempts % 1000 == 0:
                                    self._log_progress(f"🔍 Tested {attempts:,} combinations...")
                                if ok:
                                    result['success'] = True
                                    result['plaintext'] = cand
                                    result['attempts'] = attempts
                                    result['time_taken'] = time.time() - self.stats['start_time']
                                    self._log_progress(f"✅ HASH CRACKED! Password: {cand}")
                                    self._log_result(result)
                                    return result
                        batch = []
            if batch and self.is_running:
                with concurrent.futures.ThreadPoolExecutor(max_workers=use_threads) as ex:
                    for ok, cand in zip(ex.map(comparator, batch), batch):
                        attempts += 1
                        if ok:
                            result['success'] = True
                            result['plaintext'] = cand
                            result['attempts'] = attempts
                            result['time_taken'] = time.time() - self.stats['start_time']
                            self._log_progress(f"✅ HASH CRACKED! Password: {cand}")
                            self._log_result(result)
                            return result

        except Exception as e:
            self._log_progress(f"❌ Error: {str(e)}")

        result['attempts'] = attempts
        result['time_taken'] = time.time() - self.stats['start_time']
        return result

    # ==================== HELPER METHODS ====================

    def _generate_case_variations(self, word: str) -> List[str]:
        """Generate case variations"""
        variations = [
            word.lower(),
            word.upper(),
            word.capitalize(),
            word.swapcase()
        ]
        return list(set(variations))

    def _generate_number_mutations(self, word: str) -> List[str]:
        """Generate number mutations"""
        mutations = []
        for i in range(10):
            mutations.append(word + str(i))
        for year in range(2020, 2025):
            mutations.append(word + str(year))
        return mutations

    def _generate_symbol_mutations(self, word: str) -> List[str]:
        """Generate symbol mutations"""
        symbols = ['!', '@', '#', '$', '%', '&', '*']
        mutations = []
        for symbol in symbols:
            mutations.extend([word + symbol, symbol + word])
        return mutations

    def _generate_mask_combinations(self, mask: str) -> Generator[str, None, None]:
        """Generate combinations based on mask pattern"""
        charset_map = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }

        i = 0
        charsets = []
        while i < len(mask):
            if i < len(mask) - 1 and mask[i:i+2] in charset_map:
                charsets.append(charset_map[mask[i:i+2]])
                i += 2
            else:
                charsets.append([mask[i]])
                i += 1

        if charsets:
            for combo in itertools.product(*charsets):
                yield ''.join(combo)

    def get_common_wordlists(self) -> List[str]:
        """Get available wordlists from a local 'wordlists' directory (if present)"""
        wl_dir = Path(__file__).parent / 'wordlists'
        if not wl_dir.exists() or not wl_dir.is_dir():
            return []
        wordlists = []
        for p in sorted(wl_dir.iterdir()):
            if p.is_file():
                wordlists.append(str(p))
        return wordlists

    def stop(self):
        """Stop any running attack"""
        self.is_running = False

    def _prepare_comparator(self, hash_value: str, hash_type: str) -> Callable[[str], bool]:
        """Return a fast comparator(plaintext) -> bool bound to the selected hash function and target."""
        target = hash_value.lower().strip()
        hf = self.hash_algorithms.get(hash_type.upper())
        if hf:
            def comparator(plaintext: str) -> bool:
                try:
                    h = hf(plaintext)
                    return bool(h) and h.lower() == target
                except Exception:
                    return False
            return comparator
        # fallback to base_cracker if available
        def comparator(plaintext: str) -> bool:
            try:
                if self.base_cracker:
                    return self.base_cracker.verify_hash(plaintext, target, hash_type)
            except Exception:
                pass
            return False
        return comparator