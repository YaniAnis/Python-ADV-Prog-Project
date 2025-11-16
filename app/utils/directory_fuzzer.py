"""
Directory Fuzzing Module
A comprehensive directory and file discovery tool for penetration testing
"""

import requests
import threading
import time
from urllib.parse import urljoin, urlparse
import queue
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os


class DirectoryFuzzerEngine:
    def __init__(self, base_url, wordlist=None, threads=10, timeout=5):
        """
        Initialize the Directory Fuzzer
        
        :param base_url: Target URL to fuzz
        :param wordlist: Path to wordlist file or list of words
        :param threads: Number of concurrent threads
        :param timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist or self._get_default_wordlist()
        self.threads = threads
        self.timeout = timeout
        self.found_directories = []
        self.found_files = []
        self.status_codes = {}
        self.is_running = False
        
        # Progress tracking
        self.total_words = 0
        self.processed_words = 0
        self.progress_callback = None
        self.result_callback = None
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Common headers to appear more legitimate
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

    def _get_default_wordlist(self):
        """Get default wordlist for directory fuzzing"""
        return [
            # Common directories
            'admin', 'administrator', 'login', 'panel', 'dashboard', 'control',
            'wp-admin', 'wp-content', 'wp-includes', 'wordpress', 'wp',
            'images', 'img', 'css', 'js', 'javascript', 'assets', 'static',
            'uploads', 'files', 'download', 'downloads', 'media', 'docs',
            'backup', 'backups', 'temp', 'tmp', 'test', 'dev', 'development',
            'staging', 'prod', 'production', 'api', 'v1', 'v2', 'rest',
            'config', 'configuration', 'settings', 'setup', 'install',
            'phpmyadmin', 'phpinfo', 'info', 'server-info', 'server-status',
            'cgi-bin', 'scripts', 'bin', 'sbin', 'usr', 'var', 'etc',
            'home', 'root', 'www', 'public', 'private', 'secure', 'protected',
            'user', 'users', 'member', 'members', 'account', 'accounts',
            'profile', 'profiles', 'data', 'database', 'db', 'mysql',
            'sql', 'logs', 'log', 'error', 'errors', 'debug', 'trace',
            'stats', 'statistics', 'metrics', 'monitoring', 'status',
            'health', 'check', 'ping', 'version', 'versions', 'update',
            'patches', 'security', 'auth', 'authentication', 'oauth',
            'token', 'tokens', 'key', 'keys', 'cert', 'certificates',
            'ssl', 'tls', 'https', 'ftp', 'sftp', 'ssh', 'telnet',
            'mail', 'email', 'smtp', 'imap', 'pop3', 'webmail',
            'forum', 'forums', 'blog', 'news', 'cms', 'content',
            'shop', 'store', 'cart', 'checkout', 'payment', 'order',
            'search', 'help', 'support', 'contact', 'about', 'policy',
            'terms', 'privacy', 'legal', 'license', 'readme', 'changelog',
            
            # Common files
            'index.html', 'index.php', 'index.asp', 'index.jsp', 'default.htm',
            'home.html', 'main.html', 'welcome.html', 'login.html', 'admin.html',
            'robots.txt', 'sitemap.xml', 'sitemap.txt', '.htaccess', 'web.config',
            'crossdomain.xml', 'clientaccesspolicy.xml', 'favicon.ico',
            'phpinfo.php', 'info.php', 'test.php', 'config.php', 'database.php',
            'connect.php', 'connection.php', 'db.php', 'mysql.php',
            'backup.sql', 'dump.sql', 'database.sql', 'db.sql',
            '.env', '.env.local', '.env.production', 'config.json', 'package.json',
            '.git', '.gitignore', '.DS_Store', 'thumbs.db', 'desktop.ini',
            'error.log', 'access.log', 'debug.log', 'app.log',
            'readme.txt', 'readme.md', 'license.txt', 'changelog.txt',
        ]

    def load_wordlist_from_file(self, filepath):
        """Load wordlist from a file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                self.wordlist = [line.strip() for line in f if line.strip()]
            return True
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            return False

    def set_progress_callback(self, callback):
        """Set callback for progress updates"""
        self.progress_callback = callback

    def set_result_callback(self, callback):
        """Set callback for new results"""
        self.result_callback = callback

    def _check_url(self, word, word_queue):
        """Check if a URL path exists"""
        while self.is_running:
            try:
                word = word_queue.get_nowait()
            except queue.Empty:
                break
                
            target_url = urljoin(self.base_url + '/', word)
            
            try:
                response = self.session.get(target_url, timeout=self.timeout, allow_redirects=False)
                status_code = response.status_code
                content_length = len(response.content)
                
                # Interesting status codes
                if status_code in [200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405]:
                    result = {
                        'url': target_url,
                        'path': word,
                        'status_code': status_code,
                        'content_length': content_length,
                        'redirect_url': response.headers.get('Location', ''),
                        'content_type': response.headers.get('Content-Type', ''),
                    }
                    
                    if '.' in word:  # Likely a file
                        self.found_files.append(result)
                    else:  # Likely a directory
                        self.found_directories.append(result)
                    
                    if self.result_callback:
                        self.result_callback(result)
                
                self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1
                
            except requests.exceptions.RequestException:
                # Silently ignore network errors
                pass
            
            self.processed_words += 1
            if self.progress_callback:
                progress = (self.processed_words / self.total_words) * 100
                self.progress_callback(progress, self.processed_words, self.total_words)
            
            word_queue.task_done()

    def start_fuzzing(self):
        """Start the directory fuzzing process"""
        if self.is_running:
            return False
            
        self.is_running = True
        self.found_directories = []
        self.found_files = []
        self.status_codes = {}
        self.processed_words = 0
        self.total_words = len(self.wordlist)
        
        # Create queue and add all words
        word_queue = queue.Queue()
        for word in self.wordlist:
            word_queue.put(word)
        
        # Start worker threads
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self._check_url, args=(None, word_queue))
            t.daemon = True
            t.start()
            threads.append(t)
        
        return True

    def stop_fuzzing(self):
        """Stop the fuzzing process"""
        self.is_running = False

    def get_results(self):
        """Get current results"""
        return {
            'directories': self.found_directories,
            'files': self.found_files,
            'status_codes': self.status_codes,
            'total_found': len(self.found_directories) + len(self.found_files)
        }

    def export_results(self, filepath, format='txt'):
        """Export results to file"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                if format.lower() == 'txt':
                    from datetime import datetime
                    
                    # Header with timestamp
                    f.write("=" * 80 + "\n")
                    f.write("🎯 DIRECTORY FUZZING REPORT - PENTEST MULTITOOLS\n")
                    f.write("=" * 80 + "\n\n")
                    
                    # Scan Information
                    f.write("📊 SCAN INFORMATION\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"Target URL: {self.base_url}\n")
                    f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Threads Used: {self.threads}\n")
                    f.write(f"Timeout: {self.timeout}s\n")
                    f.write(f"Total Words Tested: {len(self.wordlist)}\n")
                    f.write(f"Total Findings: {len(self.found_directories) + len(self.found_files)}\n\n")
                    
                    # Executive Summary
                    f.write("📋 EXECUTIVE SUMMARY\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"• Directories discovered: {len(self.found_directories)}\n")
                    f.write(f"• Files discovered: {len(self.found_files)}\n")
                    f.write(f"• Accessible resources (200): {self.status_codes.get(200, 0)}\n")
                    f.write(f"• Forbidden resources (403): {self.status_codes.get(403, 0)}\n")
                    f.write(f"• Authentication required (401): {self.status_codes.get(401, 0)}\n")
                    f.write(f"• Redirects found (301/302): {self.status_codes.get(301, 0) + self.status_codes.get(302, 0)}\n\n")
                    
                    # Critical Findings (200 status codes)
                    accessible_dirs = [item for item in self.found_directories if item['status_code'] == 200]
                    accessible_files = [item for item in self.found_files if item['status_code'] == 200]
                    
                    if accessible_dirs or accessible_files:
                        f.write("🔍 CRITICAL FINDINGS (200 OK)\n")
                        f.write("-" * 40 + "\n")
                        
                        if accessible_dirs:
                            f.write("📁 Accessible Directories:\n")
                            for item in accessible_dirs:
                                f.write(f"   • {item['url']} ({item['content_length']} bytes)\n")
                            f.write("\n")
                        
                        if accessible_files:
                            f.write("📄 Accessible Files:\n")
                            for item in accessible_files:
                                content_type = item.get('content_type', 'Unknown')
                                f.write(f"   • {item['url']} ({item['content_length']} bytes) - {content_type}\n")
                            f.write("\n")
                    
                    # Potential Security Issues
                    forbidden_items = [item for item in (self.found_directories + self.found_files) if item['status_code'] == 403]
                    auth_required = [item for item in (self.found_directories + self.found_files) if item['status_code'] == 401]
                    
                    if forbidden_items or auth_required:
                        f.write("⚠️ POTENTIAL SECURITY ISSUES\n")
                        f.write("-" * 40 + "\n")
                        
                        if forbidden_items:
                            f.write("🚫 Forbidden Resources (403) - May contain sensitive data:\n")
                            for item in forbidden_items[:10]:  # Limit to first 10
                                f.write(f"   • {item['url']}\n")
                            if len(forbidden_items) > 10:
                                f.write(f"   ... and {len(forbidden_items) - 10} more\n")
                            f.write("\n")
                        
                        if auth_required:
                            f.write("🔒 Authentication Required (401) - Login panels:\n")
                            for item in auth_required:
                                f.write(f"   • {item['url']}\n")
                            f.write("\n")
                    
                    # All Directories
                    if self.found_directories:
                        f.write("📁 ALL DIRECTORIES DISCOVERED\n")
                        f.write("-" * 40 + "\n")
                        f.write(f"{'Status':<8} | {'Size':<10} | {'URL':<50}\n")
                        f.write("-" * 70 + "\n")
                        for item in self.found_directories:
                            size_str = f"{item['content_length']}B"
                            if item['content_length'] > 1024:
                                size_str = f"{item['content_length'] / 1024:.1f}KB"
                            f.write(f"{item['status_code']:<8} | {size_str:<10} | {item['url']}\n")
                        f.write("\n")
                    
                    # All Files
                    if self.found_files:
                        f.write("📄 ALL FILES DISCOVERED\n")
                        f.write("-" * 40 + "\n")
                        f.write(f"{'Status':<8} | {'Size':<10} | {'URL':<50}\n")
                        f.write("-" * 70 + "\n")
                        for item in self.found_files:
                            size_str = f"{item['content_length']}B"
                            if item['content_length'] > 1024:
                                size_str = f"{item['content_length'] / 1024:.1f}KB"
                            f.write(f"{item['status_code']:<8} | {size_str:<10} | {item['url']}\n")
                        f.write("\n")
                    
                    # Status Code Analysis
                    f.write("📈 STATUS CODE ANALYSIS\n")
                    f.write("-" * 40 + "\n")
                    status_descriptions = {
                        200: "OK - Resource accessible",
                        301: "Moved Permanently - Redirects",
                        302: "Found - Temporary redirects", 
                        401: "Unauthorized - Authentication required",
                        403: "Forbidden - Access denied",
                        404: "Not Found - Resource doesn't exist",
                        405: "Method Not Allowed - Different HTTP method might work",
                        500: "Internal Server Error - Server issues"
                    }
                    
                    for code, count in sorted(self.status_codes.items()):
                        description = status_descriptions.get(code, "Unknown status")
                        f.write(f"{code}: {count} responses - {description}\n")
                    
                    f.write("\n" + "=" * 80 + "\n")
                    f.write("🛡️ RECOMMENDATIONS:\n")
                    f.write("• Review 200 OK responses for sensitive information\n")
                    f.write("• Investigate 403 Forbidden responses for bypass techniques\n")
                    f.write("• Test 401 responses for weak authentication\n")
                    f.write("• Check redirect locations for information disclosure\n")
                    f.write("• Perform deeper enumeration on discovered directories\n")
                    f.write("=" * 80 + "\n")
                
                elif format.lower() == 'json':
                    import json
                    from datetime import datetime
                    
                    results = self.get_results()
                    results['scan_info'] = {
                        'target_url': self.base_url,
                        'scan_date': datetime.now().isoformat(),
                        'threads': self.threads,
                        'timeout': self.timeout,
                        'total_words_tested': len(self.wordlist)
                    }
                    json.dump(results, f, indent=2)
                    
            return True
        except Exception as e:
            print(f"Error exporting results: {e}")
            return False

    def is_fuzzing_active(self):
        """Check if fuzzing is currently active"""
        return self.is_running

    def get_progress(self):
        """Get current progress"""
        if self.total_words == 0:
            return 0
        return (self.processed_words / self.total_words) * 100


# Common wordlists for TryHackMe machines
COMMON_WORDLISTS = {
    'small': [
        'admin', 'login', 'panel', 'dashboard', 'wp-admin', 'phpmyadmin',
        'images', 'css', 'js', 'uploads', 'backup', 'config', 'test',
        'robots.txt', 'sitemap.xml', 'index.html', 'index.php',
    ],
    'medium': None,  # Uses default wordlist
    'large': None,   # Would load from external file
}


def get_wordlist(size='medium'):
    """Get predefined wordlist by size"""
    if size in COMMON_WORDLISTS and COMMON_WORDLISTS[size] is not None:
        return COMMON_WORDLISTS[size]
    else:
        # Return default wordlist
        fuzzer = DirectoryFuzzerEngine('http://example.com')
        return fuzzer.wordlist