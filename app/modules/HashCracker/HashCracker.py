"""
Basic Hash Cracker Implementation
Provides fundamental hash cracking capabilities for various hash types.
"""

import hashlib
import itertools
import string
from typing import Optional, List, Generator


class HashCracker:
    """Basic hash cracking implementation with dictionary and brute force attacks"""
    
    def __init__(self):
        self.is_running = False
        self.progress_callback = None
        self.result_callback = None
        
    def set_progress_callback(self, callback):
        """Set callback function for progress updates"""
        self.progress_callback = callback
    
    def set_callbacks(self, progress_callback=None, result_callback=None):
        """Set callback functions for progress updates and results"""
        self.progress_callback = progress_callback
        self.result_callback = result_callback
        
    def _update_progress(self, current: str, total: int = None, found: bool = False):
        """Update progress via callback"""
        if self.progress_callback:
            self.progress_callback(current, total, found)
    
    def _update_result(self, password: str, hash_type: str, target_hash: str):
        """Update result via callback"""
        if self.result_callback:
            result = {
                'password': password,
                'hash_type': hash_type,
                'target_hash': target_hash,
                'success': True
            }
            self.result_callback(result)
    
    def _compute_hash(self, password: str, hash_type: str) -> str:
        """Compute hash for given password and hash type"""
        try:
            password_bytes = password.encode('utf-8')
            
            if hash_type.upper() == 'MD5':
                return hashlib.md5(password_bytes).hexdigest()
            elif hash_type.upper() == 'SHA1':
                return hashlib.sha1(password_bytes).hexdigest()
            elif hash_type.upper() == 'SHA256':
                return hashlib.sha256(password_bytes).hexdigest()
            elif hash_type.upper() == 'SHA512':
                return hashlib.sha512(password_bytes).hexdigest()
            elif hash_type.upper() == 'NTLM':
                # NTLM uses UTF-16LE encoding
                return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
            else:
                # Default to MD5 if unknown
                return hashlib.md5(password_bytes).hexdigest()
        except Exception:
            return ""
    
    def dictionary_attack(self, target_hash: str, wordlist: List[str], hash_type: str = 'MD5') -> Optional[str]:
        """
        Perform dictionary attack using provided wordlist
        
        Args:
            target_hash: The hash to crack
            wordlist: List of candidate passwords
            hash_type: Type of hash (MD5, SHA1, etc.)
            
        Returns:
            Cracked password or None if not found
        """
        self.is_running = True
        target_hash = target_hash.lower().strip()
        
        try:
            for i, password in enumerate(wordlist):
                if not self.is_running:
                    break
                    
                password = password.strip()
                if not password:
                    continue
                    
                computed_hash = self._compute_hash(password, hash_type).lower()
                
                # Update progress
                self._update_progress(password, len(wordlist))
                
                if computed_hash == target_hash:
                    self._update_progress(password, len(wordlist), found=True)
                    self._update_result(password, hash_type, target_hash)
                    return password
                    
        except Exception as e:
            print(f"Error in dictionary attack: {e}")
        finally:
            self.is_running = False
            
        return None
    
    def brute_force_attack(self, target_hash: str, charset: str = None, min_length: int = 1, 
                          max_length: int = 6, hash_type: str = 'MD5') -> Optional[str]:
        """
        Perform brute force attack
        
        Args:
            target_hash: The hash to crack
            charset: Characters to use in brute force
            min_length: Minimum password length
            max_length: Maximum password length
            hash_type: Type of hash
            
        Returns:
            Cracked password or None if not found
        """
        self.is_running = True
        target_hash = target_hash.lower().strip()
        
        if charset is None:
            charset = string.ascii_lowercase + string.digits
            
        try:
            for length in range(min_length, max_length + 1):
                if not self.is_running:
                    break
                    
                for password_tuple in itertools.product(charset, repeat=length):
                    if not self.is_running:
                        break
                        
                    password = ''.join(password_tuple)
                    computed_hash = self._compute_hash(password, hash_type).lower()
                    
                    # Update progress
                    self._update_progress(password)
                    
                    if computed_hash == target_hash:
                        self._update_progress(password, found=True)
                        self._update_result(password, hash_type, target_hash)
                        return password
                        
        except Exception as e:
            print(f"Error in brute force attack: {e}")
        finally:
            self.is_running = False
            
        return None
    
    def enhanced_dictionary_attack(self, target_hash: str, wordlist: List[str], 
                                 hash_type: str = 'MD5', use_mutations: bool = True) -> Optional[str]:
        """
        Enhanced dictionary attack with password mutations
        
        Args:
            target_hash: The hash to crack
            wordlist: Base wordlist
            hash_type: Type of hash
            use_mutations: Whether to apply common mutations
            
        Returns:
            Cracked password or None if not found
        """
        self.is_running = True
        target_hash = target_hash.lower().strip()
        
        # First try basic dictionary attack
        result = self.dictionary_attack(target_hash, wordlist, hash_type)
        if result or not self.is_running:
            return result
        
        if not use_mutations:
            return None
            
        # Try with mutations
        try:
            for base_word in wordlist:
                if not self.is_running:
                    break
                    
                base_word = base_word.strip()
                if not base_word:
                    continue
                    
                # Generate mutations
                mutations = self._generate_mutations(base_word)
                
                for password in mutations:
                    if not self.is_running:
                        break
                        
                    computed_hash = self._compute_hash(password, hash_type).lower()
                    
                    # Update progress
                    self._update_progress(password)
                    
                    if computed_hash == target_hash:
                        self._update_progress(password, found=True)
                        self._update_result(password, hash_type, target_hash)
                        return password
                        
        except Exception as e:
            print(f"Error in enhanced dictionary attack: {e}")
        finally:
            self.is_running = False
            
        return None
    
    def _generate_mutations(self, word: str) -> Generator[str, None, None]:
        """Generate common password mutations"""
        mutations = [word]
        
        # Case variations
        mutations.extend([
            word.lower(),
            word.upper(),
            word.capitalize(),
            word.swapcase()
        ])
        
        # Number appending
        for i in range(10):
            mutations.append(word + str(i))
            mutations.append(str(i) + word)
            
        # Common years
        for year in ['2020', '2021', '2022', '2023', '2024', '2025']:
            mutations.append(word + year)
            mutations.append(year + word)
            
        # Symbol appending
        for symbol in ['!', '@', '#', '$', '%', '123', '!@#']:
            mutations.append(word + symbol)
            mutations.append(symbol + word)
            
        # Leet speak replacements
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        leet_word = word
        for char, replacement in leet_map.items():
            leet_word = leet_word.replace(char, replacement)
        mutations.append(leet_word)
        
        # Remove duplicates and return unique mutations
        seen = set()
        for mutation in mutations:
            if mutation and mutation not in seen:
                seen.add(mutation)
                yield mutation
    
    def stop(self):
        """Stop the current cracking operation"""
        self.is_running = False
        
    def get_supported_hash_types(self) -> List[str]:
        """Get list of supported hash types"""
        return ['MD5', 'SHA1', 'SHA256', 'SHA512', 'NTLM']
    
    def verify_hash(self, plaintext: str, hash_value: str, hash_type: str) -> bool:
        """
        Verify if plaintext matches the given hash
        
        Args:
            plaintext: The password to verify
            hash_value: The hash to compare against
            hash_type: The type of hash
            
        Returns:
            True if hash matches, False otherwise
        """
        try:
            computed_hash = self._compute_hash(plaintext, hash_type).lower()
            return computed_hash == hash_value.lower().strip()
        except Exception:
            return False