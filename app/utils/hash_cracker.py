"""
Hash Cracker Engine - Advanced Hash Analysis and Cracking
Educational cybersecurity tool for authorized testing only.
"""

import hashlib
import hmac
import base64
import binascii
import re
import threading
import time
from typing import List, Dict, Optional, Tuple, Callable
import itertools
import string

class HashCrackerEngine:
    """Advanced hash cracking and analysis engine"""
    
    def __init__(self):
        self.is_running = False
        self.progress_callback = None
        self.result_callback = None
        self.stop_event = threading.Event()
        
        # Extended hash types support
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'sha3_224': hashlib.sha3_224,
            'sha3_256': hashlib.sha3_256,
            'sha3_384': hashlib.sha3_384,
            'sha3_512': hashlib.sha3_512,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
        }
        
        # Hash identification patterns
        self.hash_patterns = {
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$', 
            'sha224': r'^[a-f0-9]{56}$',
            'sha256': r'^[a-f0-9]{64}$',
            'sha384': r'^[a-f0-9]{96}$',
            'sha512': r'^[a-f0-9]{128}$',
            'ntlm': r'^[a-f0-9]{32}$',
            'mysql323': r'^[a-f0-9]{16}$',
            'mysql41': r'^\*[A-F0-9]{40}$',
            'postgres_md5': r'^md5[a-f0-9]{32}$',
            'django_pbkdf2': r'^pbkdf2_sha256\$\d+\$[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*$',
            'bcrypt': r'^\$2[aby]?\$\d+\$[./A-Za-z0-9]{53}$',
            'scrypt': r'^\$scrypt\$N=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$',
            'argon2': r'^\$argon2[id]?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'
        }
        
        # Common weak passwords by category
        self.password_categories = {
            'common': [
                'password', '123456', 'password123', 'admin', 'qwerty', 'letmein',
                'welcome', 'monkey', '1234567890', 'abc123', 'password1', 'login',
                'master', 'hello', 'guest', 'shadow', 'secret', 'root', 'user'
            ],
            'keyboard_patterns': [
                'qwerty', 'asdf', 'zxcv', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
                '1qaz2wsx', 'qazwsx', '123qwe', 'qwe123'
            ],
            'numeric': [
                '123456', '1234567890', '000000', '111111', '123123', '654321',
                '12345678', '87654321', '1111', '0000'
            ],
            'years': [str(year) for year in range(1980, 2025)],
            'months': [
                'january', 'february', 'march', 'april', 'may', 'june',
                'july', 'august', 'september', 'october', 'november', 'december'
            ],
            'names': [
                'john', 'jane', 'admin', 'administrator', 'user', 'test', 'demo',
                'guest', 'root', 'master', 'manager', 'service', 'system'
            ]
        }
    
    def identify_hash_type(self, hash_string: str) -> List[Dict[str, any]]:
        """Identify possible hash types based on format and length"""
        hash_string = hash_string.strip()
        results = []
        
        for hash_type, pattern in self.hash_patterns.items():
            if re.match(pattern, hash_string, re.IGNORECASE):
                confidence = self._calculate_confidence(hash_string, hash_type)
                results.append({
                    'type': hash_type,
                    'confidence': confidence,
                    'description': self._get_hash_description(hash_type),
                    'security_level': self._get_security_level(hash_type),
                    'cracking_difficulty': self._get_cracking_difficulty(hash_type)
                })
        
        # Sort by confidence
        results.sort(key=lambda x: x['confidence'], reverse=True)
        return results
    
    def _calculate_confidence(self, hash_string: str, hash_type: str) -> float:
        """Calculate confidence score for hash type identification"""
        base_confidence = 0.5
        
        # Length-based confidence
        expected_lengths = {
            'md5': 32, 'ntlm': 32, 'sha1': 40, 'sha224': 56, 'sha256': 64,
            'sha384': 96, 'sha512': 128, 'mysql323': 16
        }
        
        if hash_type in expected_lengths:
            if len(hash_string) == expected_lengths[hash_type]:
                base_confidence += 0.3
        
        # Format-specific confidence boosts
        if hash_type == 'mysql41' and hash_string.startswith('*'):
            base_confidence += 0.4
        elif hash_type == 'postgres_md5' and hash_string.startswith('md5'):
            base_confidence += 0.4
        elif hash_type in ['bcrypt', 'scrypt', 'argon2'] and '$' in hash_string:
            base_confidence += 0.3
        
        # Character set validation
        if hash_type in ['md5', 'sha1', 'sha256', 'sha512', 'ntlm']:
            if all(c in '0123456789abcdefABCDEF' for c in hash_string):
                base_confidence += 0.2
        
        return min(1.0, base_confidence)
    
    def _get_hash_description(self, hash_type: str) -> str:
        """Get description of hash algorithm"""
        descriptions = {
            'md5': 'MD5 - Message Digest Algorithm 5 (Cryptographically broken)',
            'sha1': 'SHA-1 - Secure Hash Algorithm 1 (Deprecated)',
            'sha224': 'SHA-224 - Secure Hash Algorithm 224-bit',
            'sha256': 'SHA-256 - Secure Hash Algorithm 256-bit (Recommended)',
            'sha384': 'SHA-384 - Secure Hash Algorithm 384-bit',
            'sha512': 'SHA-512 - Secure Hash Algorithm 512-bit (Recommended)',
            'ntlm': 'NTLM - Windows NT Hash',
            'mysql323': 'MySQL 3.2.3 Hash',
            'mysql41': 'MySQL 4.1+ Hash',
            'postgres_md5': 'PostgreSQL MD5 Hash',
            'bcrypt': 'bcrypt - Adaptive hash function (Recommended)',
            'scrypt': 'scrypt - Password-based key derivation function',
            'argon2': 'Argon2 - Password hashing function (Latest standard)'
        }
        return descriptions.get(hash_type, f'{hash_type.upper()} hash')
    
    def _get_security_level(self, hash_type: str) -> str:
        """Get security level assessment"""
        levels = {
            'md5': 'Very Weak',
            'sha1': 'Weak', 
            'ntlm': 'Weak',
            'mysql323': 'Very Weak',
            'mysql41': 'Weak',
            'postgres_md5': 'Weak',
            'sha224': 'Moderate',
            'sha256': 'Strong',
            'sha384': 'Strong',
            'sha512': 'Strong',
            'bcrypt': 'Very Strong',
            'scrypt': 'Very Strong',
            'argon2': 'Very Strong'
        }
        return levels.get(hash_type, 'Unknown')
    
    def _get_cracking_difficulty(self, hash_type: str) -> str:
        """Get cracking difficulty assessment"""
        difficulties = {
            'md5': 'Very Easy',
            'sha1': 'Easy',
            'ntlm': 'Easy',
            'mysql323': 'Very Easy',
            'mysql41': 'Easy',
            'postgres_md5': 'Easy',
            'sha224': 'Moderate',
            'sha256': 'Moderate',
            'sha384': 'Hard',
            'sha512': 'Hard',
            'bcrypt': 'Very Hard',
            'scrypt': 'Very Hard',
            'argon2': 'Very Hard'
        }
        return difficulties.get(hash_type, 'Unknown')
    
    def crack_hash(self, hash_string: str, hash_type: str, 
                   attack_method: str, wordlist: List[str] = None,
                   charset: str = None, max_length: int = 6) -> Optional[str]:
        """Main hash cracking function"""
        self.is_running = True
        self.stop_event.clear()
        
        hash_string = hash_string.strip().lower()
        
        if attack_method == 'dictionary':
            return self._dictionary_attack(hash_string, hash_type, wordlist or self._get_default_wordlist())
        elif attack_method == 'brute_force':
            charset = charset or string.ascii_lowercase + string.digits
            return self._brute_force_attack(hash_string, hash_type, charset, max_length)
        elif attack_method == 'hybrid':
            return self._hybrid_attack(hash_string, hash_type, wordlist or self._get_default_wordlist())
        elif attack_method == 'smart':
            return self._smart_attack(hash_string, hash_type)
        else:
            return None
    
    def _get_default_wordlist(self) -> List[str]:
        """Get default wordlist combining all categories"""
        wordlist = []
        for category in self.password_categories.values():
            wordlist.extend(category)
        return wordlist
    
    def _dictionary_attack(self, target_hash: str, hash_type: str, wordlist: List[str]) -> Optional[str]:
        """Perform dictionary attack"""
        total = len(wordlist)
        
        for i, word in enumerate(wordlist):
            if self.stop_event.is_set():
                break
            
            # Test word and common variations
            candidates = self._generate_word_variations(word)
            
            for candidate in candidates:
                if self.stop_event.is_set():
                    break
                
                test_hash = self._hash_password(candidate, hash_type)
                if test_hash and test_hash.lower() == target_hash:
                    return candidate
            
            # Update progress
            if self.progress_callback and i % 10 == 0:
                progress = (i / total) * 100
                self.progress_callback(progress, f"Testing: {word} ({i}/{total})")
        
        return None
    
    def _brute_force_attack(self, target_hash: str, hash_type: str, 
                           charset: str, max_length: int) -> Optional[str]:
        """Perform brute force attack"""
        for length in range(1, max_length + 1):
            if self.stop_event.is_set():
                break
            
            total_combinations = len(charset) ** length
            tested = 0
            
            for password_tuple in itertools.product(charset, repeat=length):
                if self.stop_event.is_set():
                    break
                
                password = ''.join(password_tuple)
                test_hash = self._hash_password(password, hash_type)
                
                if test_hash and test_hash.lower() == target_hash:
                    return password
                
                tested += 1
                
                # Update progress every 1000 attempts
                if self.progress_callback and tested % 1000 == 0:
                    progress = (tested / total_combinations) * 100
                    self.progress_callback(
                        progress,
                        f"Brute force length {length}: {tested}/{total_combinations}"
                    )
        
        return None
    
    def _hybrid_attack(self, target_hash: str, hash_type: str, base_words: List[str]) -> Optional[str]:
        """Perform hybrid attack (dictionary + modifications)"""
        total = len(base_words) * 50  # Approximate variations per word
        tested = 0
        
        for word in base_words:
            if self.stop_event.is_set():
                break
            
            # Generate extensive variations
            variations = self._generate_extensive_variations(word)
            
            for variation in variations:
                if self.stop_event.is_set():
                    break
                
                test_hash = self._hash_password(variation, hash_type)
                if test_hash and test_hash.lower() == target_hash:
                    return variation
                
                tested += 1
                
                if self.progress_callback and tested % 50 == 0:
                    progress = (tested / total) * 100
                    self.progress_callback(
                        progress,
                        f"Hybrid attack: {tested}/{total} - Testing {word}"
                    )
        
        return None
    
    def _smart_attack(self, target_hash: str, hash_type: str) -> Optional[str]:
        """Intelligent attack combining multiple strategies"""
        strategies = [
            ('Common passwords', self.password_categories['common']),
            ('Keyboard patterns', self.password_categories['keyboard_patterns']),
            ('Numeric patterns', self.password_categories['numeric']),
            ('Names + numbers', self._generate_name_number_combos()),
            ('Years', self.password_categories['years']),
        ]
        
        for strategy_name, wordlist in strategies:
            if self.stop_event.is_set():
                break
            
            if self.progress_callback:
                self.progress_callback(0, f"Trying strategy: {strategy_name}")
            
            result = self._dictionary_attack(target_hash, hash_type, wordlist)
            if result:
                return result
        
        return None
    
    def _generate_word_variations(self, word: str) -> List[str]:
        """Generate common variations of a word"""
        variations = [word]
        
        # Case variations
        variations.extend([
            word.lower(),
            word.upper(), 
            word.capitalize(),
            word.title()
        ])
        
        # Number append/prepend
        for i in range(10):
            variations.extend([
                f"{word}{i}",
                f"{i}{word}",
                f"{word}0{i}",
                f"0{i}{word}"
            ])
        
        # Year variations
        for year in ['2023', '2024', '23', '24']:
            variations.extend([f"{word}{year}", f"{year}{word}"])
        
        # Symbol variations
        symbols = ['!', '@', '#', '$', '123', '1']
        for symbol in symbols:
            variations.extend([f"{word}{symbol}", f"{symbol}{word}"])
        
        # Leet speak
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        leet_word = word.lower()
        for original, replacement in leet_map.items():
            leet_word = leet_word.replace(original, replacement)
        variations.append(leet_word)
        
        return list(set(variations))  # Remove duplicates
    
    def _generate_extensive_variations(self, word: str) -> List[str]:
        """Generate extensive variations for hybrid attack"""
        variations = self._generate_word_variations(word)
        
        # Add more complex patterns
        base_variations = [word, word.upper(), word.capitalize()]
        
        # Complex number patterns
        for base in base_variations:
            for i in range(100):
                variations.extend([
                    f"{base}{i:02d}",
                    f"{base}{i:03d}",
                    f"{i:02d}{base}",
                ])
        
        # Date patterns
        for year in range(1990, 2025):
            for base in base_variations[:2]:  # Limit to avoid explosion
                variations.extend([
                    f"{base}{year}",
                    f"{year}{base}",
                    f"{base}{str(year)[-2:]}",
                    f"{str(year)[-2:]}{base}"
                ])
        
        # Complex symbol patterns
        symbol_combinations = ['!@', '@#', '#$', '!!', '123!', '!23', '@123']
        for base in base_variations[:2]:
            for symbols in symbol_combinations:
                variations.extend([f"{base}{symbols}", f"{symbols}{base}"])
        
        return list(set(variations))
    
    def _generate_name_number_combos(self) -> List[str]:
        """Generate name + number combinations"""
        combos = []
        names = self.password_categories['names']
        
        for name in names:
            for i in range(100):
                combos.extend([
                    f"{name}{i}",
                    f"{name.capitalize()}{i}",
                    f"{name}{i:02d}",
                    f"{name.capitalize()}{i:02d}"
                ])
        
        return combos
    
    def _hash_password(self, password: str, hash_type: str) -> Optional[str]:
        """Hash password using specified algorithm"""
        try:
            if hash_type in self.hash_algorithms:
                return self.hash_algorithms[hash_type](password.encode()).hexdigest()
            elif hash_type == 'ntlm':
                return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
            elif hash_type == 'mysql323':
                # Simplified MySQL 3.2.3 hash simulation
                return hashlib.md5(password.encode()).hexdigest()[:16]
            elif hash_type == 'mysql41':
                # Simplified MySQL 4.1+ hash simulation
                hash1 = hashlib.sha1(password.encode()).digest()
                hash2 = hashlib.sha1(hash1).hexdigest()
                return f"*{hash2.upper()}"
            else:
                return None
        except Exception:
            return None
    
    def analyze_hash_security(self, hash_string: str) -> Dict[str, any]:
        """Comprehensive security analysis of hash"""
        possible_types = self.identify_hash_type(hash_string)
        
        analysis = {
            'hash': hash_string,
            'length': len(hash_string),
            'possible_types': possible_types,
            'recommendations': [],
            'vulnerabilities': [],
            'estimated_crack_time': {},
            'security_score': 0
        }
        
        if not possible_types:
            analysis['recommendations'].append("Hash format not recognized - might be custom or unknown algorithm")
            return analysis
        
        # Analyze most likely type
        primary_type = possible_types[0]
        hash_type = primary_type['type']
        
        # Security recommendations
        if hash_type in ['md5', 'sha1', 'mysql323']:
            analysis['vulnerabilities'].append("Uses cryptographically broken algorithm")
            analysis['recommendations'].append("Migrate to SHA-256 or bcrypt immediately")
            analysis['security_score'] = 1
        elif hash_type in ['ntlm', 'mysql41']:
            analysis['vulnerabilities'].append("Uses weak hashing algorithm")
            analysis['recommendations'].append("Upgrade to stronger algorithm (bcrypt, scrypt, or Argon2)")
            analysis['security_score'] = 2
        elif hash_type in ['sha256', 'sha512']:
            analysis['recommendations'].append("Consider using password-specific algorithms (bcrypt, scrypt, Argon2)")
            analysis['security_score'] = 6
        elif hash_type in ['bcrypt', 'scrypt', 'argon2']:
            analysis['recommendations'].append("Using recommended password hashing algorithm")
            analysis['security_score'] = 9
        
        # Estimate crack times (simplified)
        if hash_type in ['md5', 'sha1']:
            analysis['estimated_crack_time'] = {
                'dictionary': 'Seconds to minutes',
                'brute_force_8_char': 'Hours to days',
                'rainbow_tables': 'Instant to minutes'
            }
        elif hash_type in ['sha256', 'sha512']:
            analysis['estimated_crack_time'] = {
                'dictionary': 'Minutes to hours',
                'brute_force_8_char': 'Days to weeks',
                'rainbow_tables': 'Minutes to hours'
            }
        elif hash_type in ['bcrypt', 'scrypt', 'argon2']:
            analysis['estimated_crack_time'] = {
                'dictionary': 'Hours to days',
                'brute_force_8_char': 'Years to centuries',
                'rainbow_tables': 'Not applicable'
            }
        
        return analysis
    
    def stop_cracking(self):
        """Stop current cracking operation"""
        self.is_running = False
        self.stop_event.set()
    
    def set_progress_callback(self, callback: Callable):
        """Set progress callback function"""
        self.progress_callback = callback
    
    def export_results(self, results: Dict, filepath: str) -> bool:
        """Export cracking results to file"""
        try:
            import json
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            return True
        except Exception:
            return False