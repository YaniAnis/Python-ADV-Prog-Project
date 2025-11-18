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
    """
    Enhanced Hash Cracking Engine with comprehensive attack methods
    """

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

            # Unix/Linux hashes
            'Unix DES': self._compute_unix_des,
            'Unix MD5': self._compute_unix_md5,
            'Unix SHA256': self._compute_unix_sha256,
            'Unix SHA512': self._compute_unix_sha512,

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

    def _compute_unix_des(self, text: str) -> str:
        """Unix DES crypt (placeholder)"""
        return hashlib.md5(text.encode()).hexdigest()[:13]

    def _compute_unix_md5(self, text: str) -> str:
        """Unix MD5 crypt (simplified)"""
        return '$1$salt$' + hashlib.md5((text + 'salt').encode()).hexdigest()

    def _compute_unix_sha256(self, text: str) -> str:
        """Unix SHA256 crypt (simplified)"""
        return '$5$salt$' + hashlib.sha256((text + 'salt').encode()).hexdigest()

    def _compute_unix_sha512(self, text: str) -> str:
        """Unix SHA512 crypt (simplified)"""
        return '$6$salt$' + hashlib.sha512((text + 'salt').encode()).hexdigest()

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
        import hashlib
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
        """
        Enhanced hash type detection
        Returns: (primary_type, all_possible_types)
        """
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
            'attempts': 0,
            'wordlist_used': wordlist_path
        }

        self.is_running = True
        self.stats['start_time'] = time.time()
        self.stats['current_method'] = 'Dictionary'

        if not os.path.exists(wordlist_path):
            self._log_progress(f"❌ Wordlist not found: {wordlist_path}")
            return result

        self._log_progress(f"📖 Starting dictionary attack on {hash_type} hash")
        self._log_progress(f"📁 Wordlist: {wordlist_path}")

        attempts = 0
        comparator = self._prepare_comparator(hash_value, hash_type)

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
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
                                        self._log_progress(f"Tested {attempts:,} passwords... ({self.stats['passwords_per_second']:.0f} p/s)")
                                    if ok:
                                        result['success'] = True
                                        result['plaintext'] = cand
                                        result['attempts'] = attempts
                                        result['time_taken'] = time.time() - self.stats['start_time']
                                        self._log_progress("✅ HASH CRACKED!")
                                        self._log_progress(f"Password: {cand}")
                                        self._log_result(result)
                                        return result
                            batch = []
                    if batch and self.is_running:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as ex:
                            for ok, cand in zip(ex.map(comparator, batch), batch):
                                attempts += 1
                                if ok:
                                    result['success'] = True
                                    result['plaintext'] = cand
                                    result['attempts'] = attempts
                                    result['time_taken'] = time.time() - self.stats['start_time']
                                    self._log_progress("✅ HASH CRACKED!")
                                    self._log_progress(f"Password: {cand}")
                                    self._log_result(result)
                                    return result
                else:
                    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if not self.is_running:
                                break

                            if max_words and attempts >= max_words:
                                break

                            candidate = line.strip()
                            if not candidate:
                                continue

                            attempts += 1
                            self._update_stats(attempts, candidate)

                            if attempts % 10000 == 0:
                                self._log_progress(f"Tested {attempts:,} passwords... ({self.stats['passwords_per_second']:.0f} p/s)")

                            if comparator(candidate):
                                result['success'] = True
                                result['plaintext'] = candidate
                                result['attempts'] = attempts
                                result['time_taken'] = time.time() - self.stats['start_time']

                                self._log_progress("✅ HASH CRACKED!")
                                self._log_progress(f"Password: {candidate}")

                                self._log_result(result)
                                return result

        except Exception as e:
            self._log_progress(f"❌ Error in dictionary attack: {str(e)}")

        result['attempts'] = attempts
        result['time_taken'] = time.time() - self.stats['start_time']

        if not result['success']:
            self._log_progress(f"❌ Hash not found after {attempts:,} attempts")

        return result

    def enhanced_dictionary_attack(self, hash_value: str, hash_type: str, wordlist_path: str,
                                   use_case_variations: bool = True, use_number_mutations: bool = True,
                                   use_symbol_mutations: bool = True, use_leet_speak: bool = True,
                                   use_year_mutations: bool = True, max_mutations_per_word: int = 50,
                                   num_workers: int = 1) -> Dict:
        """Enhanced dictionary attack with comprehensive mutations (opt. multi-threaded)"""
        result = {
            'success': False,
            'plaintext': None,
            'hash_type': hash_type,
            'method': 'enhanced_dictionary',
            'time_taken': 0,
            'attempts': 0,
            'mutations_applied': [],
            'wordlist_used': wordlist_path
        }

        self.is_running = True
        self.stats['start_time'] = time.time()
        self.stats['current_method'] = 'Enhanced Dictionary'

        if not os.path.exists(wordlist_path):
            self._log_progress(f"❌ Wordlist not found: {wordlist_path}")
            return result

        mutations = []
        if use_case_variations: mutations.append("case_variations")
        if use_number_mutations: mutations.append("number_mutations")
        if use_symbol_mutations: mutations.append("symbol_mutations")
        if use_leet_speak: mutations.append("leet_speak")
        if use_year_mutations: mutations.append("year_mutations")

        self._log_progress(f"Starting enhanced dictionary attack on {hash_type} hash")
        self._log_progress(f"Wordlist: {wordlist_path}")
        self._log_progress(f"Mutations: {', '.join(mutations)}")

        attempts = 0
        comparator = self._prepare_comparator(hash_value, hash_type)
        if num_workers and num_workers > 1:
            # use batching+threads similar to enhanced_hash_cracker implementation
            batch = []
            batch_size = 512
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if not self.is_running:
                        break

                    base_word = line.strip()
                    if not base_word:
                        continue

                    # Generate all mutations for this word
                    candidates = self._generate_word_mutations(
                        base_word, use_case_variations, use_number_mutations,
                        use_symbol_mutations, use_leet_speak, use_year_mutations,
                        max_mutations_per_word
                    )

                    for candidate in candidates:
                        if not self.is_running:
                            break

                        batch.append(candidate)
                        if len(batch) >= batch_size:
                            with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as ex:
                                for ok, cand in zip(ex.map(comparator, batch), batch):
                                    attempts += 1
                                    if ok:
                                        result['success'] = True
                                        result['plaintext'] = cand
                                        result['attempts'] = attempts
                                        result['time_taken'] = time.time() - self.stats['start_time']
                                        result['mutations_applied'] = mutations

                                        self._log_progress("✅ HASH CRACKED!")
                                        self._log_progress(f"Password: {cand}")
                                        self._log_progress(f"Base word: {base_word}")

                                        self._log_result(result)
                                        return result
                            batch = []
            if batch and self.is_running:
                with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as ex:
                    for ok, cand in zip(ex.map(comparator, batch), batch):
                        attempts += 1
                        if ok:
                            result['success'] = True
                            result['plaintext'] = cand
                            result['attempts'] = attempts
                            result['time_taken'] = time.time() - self.stats['start_time']
                            result['mutations_applied'] = mutations

                            self._log_progress("✅ HASH CRACKED!")
                            self._log_progress(f"Password: {cand}")
                            self._log_progress(f"Base word: {base_word}")

                            self._log_result(result)
                            return result
        else:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if not self.is_running:
                        break

                    base_word = line.strip()
                    if not base_word:
                        continue

                    # Generate all mutations for this word
                    candidates = self._generate_word_mutations(
                        base_word, use_case_variations, use_number_mutations,
                        use_symbol_mutations, use_leet_speak, use_year_mutations,
                        max_mutations_per_word
                    )

                    for candidate in candidates:
                        if not self.is_running:
                            break

                        attempts += 1
                        self._update_stats(attempts, candidate)

                        if attempts % 5000 == 0:
                            self._log_progress(f"🔍 Tested {attempts:,} passwords...")

                        if comparator(candidate):
                            result['success'] = True
                            result['plaintext'] = candidate
                            result['attempts'] = attempts
                            result['time_taken'] = time.time() - self.stats['start_time']
                            result['mutations_applied'] = mutations

                            self._log_progress("✅ HASH CRACKED!")
                            self._log_progress(f"Password: {candidate}")
                            self._log_progress(f"Base word: {base_word}")

                            self._log_result(result)
                            return result

        result['attempts'] = attempts
        result['time_taken'] = time.time() - self.stats['start_time']
        result['mutations_applied'] = mutations

        if not result['success']:
            self._log_progress(f"❌ Hash not found after {attempts:,} attempts")

        return result

    def smart_brute_force_attack(self, hash_value: str, hash_type: str,
                                 charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
                                 min_length: int = 1, max_length: int = 8,
                                 use_common_patterns: bool = True,
                                 use_keyboard_patterns: bool = True) -> Dict:
        """Smart brute force with pattern optimization"""
        result = {
            'success': False,
            'plaintext': None,
            'hash_type': hash_type,
            'method': 'smart_brute_force',
            'time_taken': 0,
            'attempts': 0,
            'charset_used': charset,
            'length_range': f"{min_length}-{max_length}"
        }

        self.is_running = True
        self.stats['start_time'] = time.time()
        self.stats['current_method'] = 'Smart Brute Force'

        self._log_progress(f"Starting smart brute force attack on {hash_type} hash")
        self._log_progress(f"Charset: {charset}")
        self._log_progress(f"Length range: {min_length}-{max_length}")

        attempts = 0
        comparator = self._prepare_comparator(hash_value, hash_type)

        # Phase 1: Common patterns
        if use_common_patterns:
            self._log_progress("Phase 1: Testing common patterns...")
            common_patterns = self._get_common_password_patterns(min_length, max_length)

            for pattern in common_patterns:
                if not self.is_running:
                    break

                attempts += 1
                self._update_stats(attempts, pattern)

                if comparator(pattern):
                    result['success'] = True
                    result['plaintext'] = pattern
                    result['attempts'] = attempts
                    result['time_taken'] = time.time() - self.stats['start_time']

                    self._log_progress("✅ HASH CRACKED with common pattern!")
                    self._log_progress(f"Password: {pattern}")

                    self._log_result(result)
                    return result

        # Phase 2: Optimized brute force
        self._log_progress("Phase 2: Optimized brute force...")

        for length in range(min_length, max_length + 1):
            if not self.is_running:
                break

            self._log_progress(f"Testing length {length}...")

            for candidate in itertools.product(charset, repeat=length):
                if not self.is_running:
                    break

                password = ''.join(candidate)
                attempts += 1
                self._update_stats(attempts, password)

                if attempts % 50000 == 0:
                    self._log_progress(f"Tested {attempts:,} passwords... ({self.stats['passwords_per_second']:.0f} p/s)")

                if comparator(password):
                    result['success'] = True
                    result['plaintext'] = password
                    result['attempts'] = attempts
                    result['time_taken'] = time.time() - self.stats['start_time']

                    self._log_progress("✅ HASH CRACKED!")
                    self._log_progress(f"Password: {password}")

                    self._log_result(result)
                    return result

        result['attempts'] = attempts
        result['time_taken'] = time.time() - self.stats['start_time']
        return result

    # ==================== HELPER METHODS ====================

    def _generate_word_mutations(self, word: str, use_case: bool, use_numbers: bool,
                                 use_symbols: bool, use_leet: bool, use_years: bool,
                                 max_mutations: int) -> List[str]:
        """Generate comprehensive word mutations"""
        mutations = set([word])

        if use_case:
            mutations.update(self._generate_case_variations(word))

        if use_leet:
            mutations.update(self._generate_leet_speak(word))

        if use_numbers:
            new_mutations = set()
            for m in list(mutations):
                new_mutations.update(self._generate_number_mutations(m))
            mutations.update(new_mutations)

        if use_symbols:
            new_mutations = set()
            for m in list(mutations):
                new_mutations.update(self._generate_symbol_mutations(m))
            mutations.update(new_mutations)

        if use_years:
            new_mutations = set()
            for m in list(mutations):
                new_mutations.update(self._generate_year_mutations(m))
            mutations.update(new_mutations)

        mutation_list = list(mutations)
        if max_mutations and len(mutation_list) > max_mutations:
            result = [word]
            others = [m for m in mutation_list if m != word]
            result.extend(random.sample(others, min(max_mutations - 1, len(others))))
            return result

        return mutation_list

    def _generate_case_variations(self, word: str) -> List[str]:
        """Generate case variations"""
        if not word:
            return []
        variations = {
            word.lower(),
            word.upper(),
            word.capitalize(),
            word.swapcase()
        }
        if len(word) > 1:
            variations.add(word[0].upper() + word[1:].lower())
            variations.add(word[:-1].lower() + word[-1].upper())
        return list(variations)

    def _generate_leet_speak(self, word: str) -> List[str]:
        """Generate leet speak variations"""
        leet_map = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'l': '1', 'g': '9'
        }
        variations = {word}
        # single-step substitutions
        for src, repl in leet_map.items():
            if src in word.lower():
                variations.add(word.replace(src, repl))
                variations.add(word.replace(src.upper(), repl))
        return list(variations)

    def _generate_number_mutations(self, word: str) -> List[str]:
        """Generate number mutations (digits, common sequences, years)"""
        mutations = []
        # single digits
        for i in range(10):
            mutations.append(f"{word}{i}")
            mutations.append(f"{i}{word}")
        # common sequences
        common_numbers = ['123', '1234', '007', '69', '420', '777']
        for num in common_numbers:
            mutations.append(word + num)
            mutations.append(num + word)
        # recent years and last two digits
        current_year = time.gmtime().tm_year
        for y in range(current_year - 5, current_year + 1):
            mutations.append(word + str(y))
            mutations.append(word + str(y)[-2:])
        return list(set(mutations))

    def _generate_symbol_mutations(self, word: str) -> List[str]:
        """Generate symbol mutations"""
        symbols = ['!', '@', '#', '$', '%', '&', '*', '?']
        mutations = []
        for s in symbols:
            mutations.append(word + s)
            mutations.append(s + word)
        return list(set(mutations))

    def _generate_year_mutations(self, word: str) -> List[str]:
        """Generate year/appended number mutations (common years)"""
        mutations = []
        current_year = time.gmtime().tm_year
        years = [current_year, current_year - 1, current_year - 2, 1990, 1995, 2000, 2010, 2015, 2020]
        for y in years:
            mutations.append(word + str(y))
            mutations.append(str(y) + word)
            mutations.append(word + str(y)[-2:])
        return list(set(mutations))

    def _get_common_password_patterns(self, min_len: int, max_len: int) -> List[str]:
        """Return a short list of common passwords filtered by length"""
        common = [
            'password', '123456', '12345678', 'qwerty', 'abc123', 'letmein',
            'monkey', 'dragon', 'iloveyou', 'admin', 'welcome'
        ]
        return [p for p in common if min_len <= len(p) <= max_len]

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
                charsets.append(mask[i])
                i += 1
        # normalize charsets entries to sequences
        normalized = []
        for c in charsets:
            if isinstance(c, str) and len(c) == 1:
                normalized.append([c])
            else:
                normalized.append(list(c))
        for combo in itertools.product(*normalized):
            yield ''.join(combo)

    def get_common_wordlists(self) -> List[str]:
        """Get available wordlists from common folders"""
        wl = []
        candidates = [
            os.path.join(Path(__file__).parent, 'wordlists'),
            os.path.join(os.path.dirname(__file__), '..', 'data', 'wordlists'),
            '/usr/share/wordlists',
            'C:\\wordlists'
        ]
        for path in candidates:
            try:
                if os.path.isdir(path):
                    for p in sorted(Path(path).iterdir()):
                        if p.is_file():
                            wl.append(str(p))
            except Exception:
                continue
        return wl

    def benchmark_system(self) -> Dict:
        """Benchmark hash computation (simple CPU-bound test)"""
        results = {}
        test_password = "benchmark_test"
        iterations = 20000
        for name, func in self.hash_algorithms.items():
            if not callable(func):
                continue
            if name.lower() in ('bcrypt', 'scrypt', 'argon2'):
                results[name] = {'note': 'skipped (slow/unsupported here)'
                }
                continue
            try:
                start = time.time()
                for _ in range(iterations):
                    func(test_password)
                elapsed = time.time() - start
                results[name] = {
                    'hashes_per_second': int(iterations / elapsed) if elapsed > 0 else 0,
                    'time_per_hash_ms': round((elapsed / iterations) * 1000, 4)
                }
            except Exception as e:
                results[name] = {'error': str(e)}
        return results

    def stop(self):
        """Stop any running attack"""
        self.is_running = False
        if self.current_process:
            try:
                self.current_process.terminate()
            except Exception:
                pass

    # Backwards-compatible simple wrappers for API completeness

    def brute_force_attack(self, hash_value: str, hash_type: str, charset: str, min_length: int, max_length: int) -> Dict:
        """Wrapper for brute force (uses smart brute force implementation)"""
        return self.smart_brute_force_attack(hash_value, hash_type, charset, min_length, max_length, use_common_patterns=True)

    def hashcat_attack(self, *args, **kwargs) -> Dict:
        """Placeholder for external hashcat integration"""
        self._log_progress("Hashcat integration not implemented in this lightweight backend.")
        return {'success': False, 'error': 'hashcat not integrated'}

    def john_attack(self, *args, **kwargs) -> Dict:
        """Placeholder for John the Ripper integration"""
        self._log_progress("John the Ripper integration not implemented in this lightweight backend.")
        return {'success': False, 'error': 'john not integrated'}

    def detect_hash_type_enhanced(self, hash_value: str) -> Tuple[str, List[str]]:
        """Compatibility alias"""
        return self.detect_hash_type(hash_value)

    # ==================== ADDITIONAL ATTACK METHODS ====================

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
        self._log_progress("🔀 Starting hybrid attack")
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

    def combinator_attack(self, hash_value: str, hash_type: str, wordlist1: str, wordlist2: str, separator: str = "") -> Dict:
        """Combinator attack"""
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
        self._log_progress("🔗 Starting combinator attack")
        attempts = 0
        comparator = self._prepare_comparator(hash_value, hash_type)

        try:
            with open(wordlist1, 'r', encoding='utf-8', errors='ignore') as f1:
                words1 = [line.strip() for line in f1 if line.strip()][:1000]

            with open(wordlist2, 'r', encoding='utf-8', errors='ignore') as f2:
                words2 = [line.strip() for line in f2 if line.strip()][:1000]

            for word1 in words1:
                if not self.is_running:
                    break

                for word2 in words2:
                    if not self.is_running:
                        break

                    candidate = word1 + separator + word2
                    attempts += 1

                    if attempts % 1000 == 0:
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

    def _prepare_comparator(self, hash_value: str, hash_type: str) -> Callable[[str], bool]:
        """Return a fast comparator bound to the selected hash function and target hash."""
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
        def comparator(plaintext: str) -> bool:
            try:
                if self.base_cracker:
                    return self.base_cracker.verify_hash(plaintext, target, hash_type)
            except Exception:
                pass
            return False
        return comparator

