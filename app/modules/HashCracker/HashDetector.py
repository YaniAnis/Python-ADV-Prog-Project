import re
from typing import List, Optional

class HashDetector:
    """Optimized hash type detection for password cracking tools"""
    
    HASH_MODES = {
        'MD5': '0',
        'SHA1': '100', 
        'SHA256': '1400',
        'SHA512': '1700',
        'NTLM': '1000',
        'bcrypt': '3200',
        'MySQL': '300',
        'PostgreSQL': '10',
        'Oracle': '112',
        'Cisco-PIX': '150',
        'WPA/WPA2': '2500',
        'MD5crypt': '500',
        'SHA256crypt': '7400',
        'SHA512crypt': '1800',
        'Argon2': '400',
        'scrypt': '8900',
    }
    
    PATTERNS = [

        (r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$', 'bcrypt'),
        (r'^\$1\$[^$]+\$[./0-9A-Za-z]{22}$', 'MD5crypt'),
        (r'^\$5\$[^$]*\$[./0-9A-Za-z]{43}$', 'SHA256crypt'),
        (r'^\$6\$[^$]*\$[./0-9A-Za-z]{86}$', 'SHA512crypt'),
        (r'^\$argon2[id]\$v=\d+\$', 'Argon2'),
        (r'^\$pbkdf2(-sha\d+)?\$', 'PBKDF2'),
        (r'SCRYPT:\d+:\d+:\d+:[A-Za-z0-9+/=]+', 'scrypt'),
        

        (r'^\*[0-9A-F]{40}$', 'MySQL'),  
        (r'^[0-9A-F]{16}$', 'MySQL'),     
        (r'^md5[0-9a-f]{32}$', 'PostgreSQL'),
        
        (r'^[0-9A-Fa-f]{16}$', 'Cisco-PIX'),
        

        (r'.*wpa.*', 'WPA/WPA2'),
        

        (r'^[0-9a-fA-F]{32}$', ['MD5', 'NTLM']), 
        (r'^[0-9a-fA-F]{40}$', 'SHA1'),
        (r'^[0-9a-fA-F]{64}$', 'SHA256'),
        (r'^[0-9a-fA-F]{128}$', 'SHA512'),
    ]
    
    def detect_hash_type(self, hash_value: str) -> Optional[str]:
        """
        Detect hash type based on format patterns.
        Returns the most likely hash type or None if unknown.
        """
        h = hash_value.strip()
        
        if not h:
            return None
        

        for pattern, hash_type in self.PATTERNS:
            if re.match(pattern, h, re.IGNORECASE):

                if isinstance(hash_type, list):
                    return hash_type[0]
                return hash_type
        
        return None
    
    def detect_all_possible(self, hash_value: str) -> List[str]:
        """
        Return all possible hash types that match the format.
        Useful for ambiguous hashes like 32-char hex (MD5 vs NTLM).
        """
        h = hash_value.strip()
        matches = []
        
        for pattern, hash_type in self.PATTERNS:
            if re.match(pattern, h, re.IGNORECASE):
                if isinstance(hash_type, list):
                    matches.extend(hash_type)
                else:
                    matches.append(hash_type)
        
        return matches if matches else ['UNKNOWN']
    
    def get_hashcat_mode(self, hash_type: str) -> Optional[str]:
        """Get hashcat mode code for a given hash type"""
        return self.HASH_MODES.get(hash_type)
    
    def get_john_format(self, hash_type: str) -> Optional[str]:
        """Get John the Ripper format name"""

        john_formats = {
            'MD5': 'raw-md5',
            'SHA1': 'raw-sha1',
            'SHA256': 'raw-sha256',
            'SHA512': 'raw-sha512',
            'NTLM': 'nt',
            'bcrypt': 'bcrypt',
            'MD5crypt': 'md5crypt',
            'SHA256crypt': 'sha256crypt',
            'SHA512crypt': 'sha512crypt',
        }
        return john_formats.get(hash_type)

