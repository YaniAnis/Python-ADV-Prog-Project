"""
Subdomain Finder Core Logic
Comprehensive subdomain enumeration using multiple techniques
"""

import socket
import threading
import time
import json
import os
from typing import List, Dict, Set, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import random

# Handle optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    dns = None


class SubdomainFinder:
    """Core subdomain enumeration engine"""
    
    def __init__(self, export_manager=None):
        self.found_subdomains: Set[str] = set()
        self.results: List[Dict] = []
        self.is_running = False
        self.wordlists_dir = "app/data/wordlists"
        self.results_dir = "app/data/results"  # Fallback for backward compatibility
        self.export_manager = export_manager  # Optional ExportManager
        self._ensure_directories()
        self._create_default_wordlists()
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        os.makedirs(self.wordlists_dir, exist_ok=True)
        os.makedirs(self.results_dir, exist_ok=True)
    
    def _create_default_wordlists(self):
        """Create default subdomain wordlists"""
        # Common subdomains wordlist
        common_wordlist = os.path.join(self.wordlists_dir, "common.txt")
        if not os.path.exists(common_wordlist):
            common_subdomains = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", 
                "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", 
                "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
                "mail2", "new", "mysql", "old", "www1", "email", "img", "www3", "help", "shop",
                "api", "secure", "support", "www4", "portal", "beta", "owa", "mailserver",
                "mobile", "mx", "static", "docs", "beta2", "www5", "cache", "origin", "web",
                "bbs", "www6", "ftp2", "mx1", "www7", "www8", "www9", "wwww", "ww1", "ww2",
                "demo", "staging", "development", "production", "testing", "backup", "cdn",
                "media", "assets", "images", "uploads", "download", "downloads", "files",
                "store", "shop2", "crm", "erp", "intranet", "extranet", "vpn2", "git",
                "svn", "jenkins", "jira", "confluence", "wiki", "redmine", "trac", "bugzilla",
                "gitlab", "bitbucket", "phpmyadmin", "mysql2", "db", "database", "sql",
                "oracle", "postgres", "mongodb", "redis", "elastic", "kibana", "grafana",
                "prometheus", "nagios", "zabbix", "cacti", "munin", "icinga", "sensu",
                "puppet", "chef", "ansible", "docker", "kubernetes", "k8s", "rancher",
                "openshift", "mesos", "marathon", "consul", "vault", "etcd", "registry",
                "hub", "repository", "repo", "packages", "npm", "maven", "artifactory"
            ]
            
            with open(common_wordlist, 'w') as f:
                for subdomain in common_subdomains:
                    f.write(f"{subdomain}\n")
        
        # Create other wordlists
        self._create_service_wordlist()
        self._create_tech_wordlist()
        self._create_security_wordlist()
    
    def _create_service_wordlist(self):
        """Create service-specific subdomain wordlist"""
        service_wordlist = os.path.join(self.wordlists_dir, "services.txt")
        if not os.path.exists(service_wordlist):
            service_subdomains = [
                # Web services
                "api", "api-v1", "api-v2", "api-v3", "apigateway", "gateway", "proxy",
                "load-balancer", "lb", "cdn", "edge", "cache", "static", "media", "assets",
                
                # Authentication & Identity
                "auth", "sso", "oauth", "openid", "saml", "ldap", "ad", "directory",
                "identity", "iam", "access", "login", "signin", "signup", "register",
                
                # Monitoring & Analytics
                "monitor", "monitoring", "metrics", "logs", "analytics", "stats", "grafana",
                "kibana", "elastic", "prometheus", "nagios", "zabbix", "splunk", "datadog",
                
                # Development & CI/CD
                "ci", "cd", "build", "jenkins", "gitlab", "github", "bitbucket", "bamboo",
                "teamcity", "travis", "circle", "drone", "concourse", "spinnaker",
                
                # Databases
                "db", "database", "mysql", "postgres", "postgresql", "oracle", "mssql",
                "mongo", "mongodb", "redis", "memcached", "elasticsearch", "cassandra",
                
                # Cloud & Infrastructure
                "cloud", "aws", "azure", "gcp", "kubernetes", "k8s", "docker", "registry",
                "harbor", "nexus", "artifactory", "vault", "consul", "nomad", "terraform",
                
                # Business Applications
                "crm", "erp", "hr", "finance", "accounting", "billing", "payment", "payroll",
                "inventory", "warehouse", "logistics", "shipping", "tracking", "orders",
                
                # Communication
                "chat", "slack", "teams", "zoom", "meet", "webex", "skype", "discord",
                "mattermost", "rocket", "telegram", "whatsapp", "messenger"
            ]
            
            with open(service_wordlist, 'w') as f:
                for subdomain in service_subdomains:
                    f.write(f"{subdomain}\n")
    
    def _create_tech_wordlist(self):
        """Create technology-specific subdomain wordlist"""
        tech_wordlist = os.path.join(self.wordlists_dir, "technology.txt")
        if not os.path.exists(tech_wordlist):
            tech_subdomains = [
                # Programming Languages & Frameworks
                "java", "python", "node", "nodejs", "php", "ruby", "go", "golang", "rust",
                "scala", "kotlin", "swift", "react", "angular", "vue", "django", "flask",
                "spring", "express", "laravel", "symfony", "rails", "asp", "dotnet",
                
                # Servers & Platforms
                "apache", "nginx", "iis", "tomcat", "jetty", "weblogic", "websphere",
                "jboss", "wildfly", "glassfish", "liberty", "undertow", "netty",
                
                # CMS & Platforms
                "wordpress", "wp", "drupal", "joomla", "magento", "shopify", "woocommerce",
                "prestashop", "opencart", "typo3", "umbraco", "sitecore", "episerver",
                
                # Security Tools
                "waf", "firewall", "proxy", "vpn", "ssl", "tls", "certificate", "ca",
                "vault", "secrets", "keys", "crypto", "encryption", "security", "pentest",
                
                # Operating Systems
                "linux", "ubuntu", "centos", "rhel", "debian", "fedora", "alpine", "windows",
                "win", "unix", "freebsd", "openbsd", "macos", "ios", "android",
                
                # Protocols & Standards
                "http", "https", "ftp", "sftp", "ssh", "telnet", "smtp", "pop3", "imap",
                "dns", "ntp", "snmp", "ldap", "radius", "kerberos", "oauth", "saml", "jwt"
            ]
            
            with open(tech_wordlist, 'w') as f:
                for subdomain in tech_subdomains:
                    f.write(f"{subdomain}\n")
    
    def _create_security_wordlist(self):
        """Create security-focused subdomain wordlist"""
        security_wordlist = os.path.join(self.wordlists_dir, "security.txt")
        if not os.path.exists(security_wordlist):
            security_subdomains = [
                # Penetration Testing
                "pentest", "test", "testing", "scan", "scanner", "vuln", "vulnerability",
                "exploit", "payload", "shell", "webshell", "backdoor", "trojan",
                
                # Security Tools
                "burp", "zap", "owasp", "nessus", "openvas", "nmap", "masscan", "nuclei",
                "sqlmap", "metasploit", "msfconsole", "armitage", "cobalt", "empire",
                
                # Bug Bounty
                "bug", "bounty", "hackerone", "bugcrowd", "intigriti", "synack",
                "responsible", "disclosure", "security", "report", "hall", "fame",
                
                # Common Hidden/Admin
                "hidden", "secret", "private", "internal", "restricted", "confidential",
                "classified", "sensitive", "protected", "secure", "encrypted", "signed",
                
                # Development Environments
                "dev", "development", "test", "testing", "staging", "qa", "uat", "preprod",
                "sandbox", "demo", "preview", "beta", "alpha", "experimental", "canary",
                
                # Backup & Archives
                "backup", "bak", "old", "archive", "dump", "export", "snapshot", "mirror",
                "copy", "temp", "tmp", "cache", "log", "logs", "trace", "debug",
                
                # Default Credentials
                "admin", "administrator", "root", "user", "guest", "demo", "test", "default",
                "password", "passwd", "pwd", "login", "auth", "access", "control"
            ]
            
            with open(security_wordlist, 'w') as f:
                for subdomain in security_subdomains:
                    f.write(f"{subdomain}\n")
    
    def get_wordlists(self) -> List[str]:
        """Get available wordlist files"""
        wordlists = []
        for filename in os.listdir(self.wordlists_dir):
            if filename.endswith('.txt'):
                wordlists.append(filename)
        return sorted(wordlists)
    
    def load_wordlist(self, filename: str) -> List[str]:
        """Load wordlist from file"""
        filepath = os.path.join(self.wordlists_dir, filename)
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"Error loading wordlist {filename}: {e}")
            return []
    
    def dns_bruteforce(self, domain: str, wordlist: List[str], threads: int = 50, 
                      progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Perform DNS bruteforce enumeration"""
        results = []
        total_words = len(wordlist)
        completed = 0
        results_lock = threading.Lock()
        
        def check_subdomain(subdomain: str):
            nonlocal completed
            if not self.is_running:
                return
                
            full_domain = f"{subdomain}.{domain}"
            
            try:
                # DNS resolution check
                ip_addresses = []
                
                if HAS_DNSPYTHON:
                    try:
                        # Set timeout for DNS queries
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 3
                        resolver.lifetime = 3
                        answers = resolver.resolve(full_domain, 'A')
                        ip_addresses = [str(rdata) for rdata in answers]
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                        pass
                    except Exception:
                        # Fallback to socket for this domain
                        try:
                            ip = socket.gethostbyname(full_domain)
                            ip_addresses = [ip]
                        except (socket.gaierror, socket.timeout):
                            pass
                else:
                    # Fallback to socket
                    try:
                        socket.setdefaulttimeout(3)
                        ip = socket.gethostbyname(full_domain)
                        ip_addresses = [ip]
                    except (socket.gaierror, socket.timeout):
                        pass
                
                if ip_addresses:
                    result = {
                        "subdomain": full_domain,
                        "ip_addresses": ip_addresses,
                        "method": "DNS Bruteforce",
                        "status": "active",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    with results_lock:
                        results.append(result)
                        self.found_subdomains.add(full_domain)
                    
            except Exception as e:
                # Log error for debugging but continue
                pass
            
            with results_lock:
                completed += 1
                if progress_callback and (completed % 10 == 0 or completed == total_words):
                    try:
                        progress_callback(completed, total_words, f"Checked: {completed}/{total_words} domains")
                    except Exception:
                        pass
        
        # Multi-threaded execution with better error handling
        try:
            with ThreadPoolExecutor(max_workers=min(threads, 100)) as executor:
                futures = []
                for word in wordlist:
                    if not self.is_running:
                        break
                    future = executor.submit(check_subdomain, word)
                    futures.append(future)
                
                # Wait for completion with timeout handling
                for future in as_completed(futures, timeout=300):
                    if not self.is_running:
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        break
        except Exception as e:
            print(f"DNS bruteforce error: {e}")
        
        return results
    
    def certificate_transparency(self, domain: str, progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Search Certificate Transparency logs for subdomains"""
        results = []
        
        if not HAS_REQUESTS:
            if progress_callback:
                progress_callback(1, 1, "Requests module not available for CT search")
            return results
        
        try:
            if progress_callback:
                progress_callback(1, 5, "Querying Certificate Transparency logs...")
            
            # crt.sh API with better headers
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, timeout=45, headers=headers, verify=False)
            
            if progress_callback:
                progress_callback(2, 5, f"CT API response: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                except ValueError:
                    # Handle non-JSON response
                    if progress_callback:
                        progress_callback(5, 5, "CT API returned non-JSON data")
                    return results
                
                if progress_callback:
                    progress_callback(3, 5, f"Processing {len(data)} CT log entries...")
                
                unique_domains = set()
                
                for cert in data:
                    if not self.is_running:
                        break
                        
                    name_value = cert.get('name_value', '')
                    for line in name_value.split('\n'):
                        subdomain = line.strip().lower()
                        # Better subdomain filtering
                        if (subdomain and 
                            subdomain.endswith(f'.{domain}') and 
                            '*' not in subdomain and 
                            len(subdomain) < 100 and  # Avoid extremely long domains
                            subdomain.count('.') <= 10):  # Reasonable subdomain depth
                            unique_domains.add(subdomain)
                
                if progress_callback:
                    progress_callback(4, 5, f"Found {len(unique_domains)} unique subdomains, verifying...")
                
                # Verify active subdomains with limited concurrency
                verified_count = 0
                max_verify = min(len(unique_domains), 100)  # Limit verification to avoid timeout
                
                for subdomain in list(unique_domains)[:max_verify]:
                    if not self.is_running:
                        break
                        
                    if subdomain not in self.found_subdomains:
                        result = {
                            "subdomain": subdomain,
                            "ip_addresses": [],
                            "method": "Certificate Transparency",
                            "status": "discovered",
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        # Try to resolve IP with timeout
                        try:
                            socket.setdefaulttimeout(2)
                            ip = socket.gethostbyname(subdomain)
                            result["ip_addresses"] = [ip]
                            result["status"] = "active"
                        except (socket.gaierror, socket.timeout):
                            pass
                        except Exception:
                            pass
                        
                        results.append(result)
                        self.found_subdomains.add(subdomain)
                        verified_count += 1
                
                if progress_callback:
                    progress_callback(5, 5, f"CT search completed: {verified_count} verified")
            
            elif response.status_code == 429:
                if progress_callback:
                    progress_callback(5, 5, "CT API rate limited")
            else:
                if progress_callback:
                    progress_callback(5, 5, f"CT API error: {response.status_code}")
                    
        except requests.exceptions.Timeout:
            if progress_callback:
                progress_callback(5, 5, "CT API request timed out")
        except requests.exceptions.ConnectionError:
            if progress_callback:
                progress_callback(5, 5, "CT API connection error")
        except Exception as e:
            if progress_callback:
                progress_callback(5, 5, f"CT error: {str(e)[:50]}")
            print(f"Certificate Transparency error: {e}")
        
        return results
    
    def search_engine_enumeration(self, domain: str, progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Search engines for subdomain enumeration (limited to avoid blocking)"""
        results = []
        
        if not HAS_REQUESTS:
            if progress_callback:
                progress_callback(1, 1, "Requests module not available for search engine enumeration")
            return results
        
        # Only use DuckDuckGo to avoid being blocked by Google/Bing
        search_engines = [
            ("DuckDuckGo", f"site:*.{domain}")
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        for i, (engine, query) in enumerate(search_engines):
            if not self.is_running:
                break
                
            try:
                if progress_callback:
                    progress_callback(i + 1, len(search_engines), f"Searching {engine}...")
                
                # Use DuckDuckGo HTML interface
                url = f"https://html.duckduckgo.com/html/?q={query}"
                
                session = requests.Session()
                session.headers.update(headers)
                
                response = session.get(url, timeout=20, allow_redirects=True)
                
                if progress_callback:
                    progress_callback(i + 1, len(search_engines), f"{engine} response: {response.status_code}")
                
                if response.status_code == 200:
                    # Extract subdomains from response with improved regex
                    import re
                    
                    # More specific pattern to avoid false positives
                    pattern = rf'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(domain)})'
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    
                    found_this_engine = 0
                    for match in set(matches):
                        if not self.is_running:
                            break
                            
                        # Clean the match
                        subdomain = match.lower().strip()
                        
                        # Skip if already found or invalid
                        if (subdomain in self.found_subdomains or 
                            len(subdomain) > 100 or 
                            subdomain.count('.') > 10 or
                            any(char in subdomain for char in ['<', '>', '"', "'", ' '])):
                            continue
                        
                        result = {
                            "subdomain": subdomain,
                            "ip_addresses": [],
                            "method": f"Search Engine ({engine})",
                            "status": "discovered",
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        # Try to resolve IP with timeout
                        try:
                            socket.setdefaulttimeout(2)
                            ip = socket.gethostbyname(subdomain)
                            result["ip_addresses"] = [ip]
                            result["status"] = "active"
                        except (socket.gaierror, socket.timeout):
                            pass
                        except Exception:
                            pass
                        
                        results.append(result)
                        self.found_subdomains.add(subdomain)
                        found_this_engine += 1
                        
                        # Limit results per engine to avoid overwhelming
                        if found_this_engine >= 20:
                            break
                    
                    if progress_callback:
                        progress_callback(i + 1, len(search_engines), f"{engine}: found {found_this_engine} subdomains")
                
                elif response.status_code == 429:
                    if progress_callback:
                        progress_callback(i + 1, len(search_engines), f"{engine}: rate limited")
                else:
                    if progress_callback:
                        progress_callback(i + 1, len(search_engines), f"{engine}: error {response.status_code}")
                
                # Respectful rate limiting
                if len(search_engines) > 1:
                    time.sleep(random.uniform(3, 8))
                
            except requests.exceptions.Timeout:
                if progress_callback:
                    progress_callback(i + 1, len(search_engines), f"{engine}: timeout")
            except requests.exceptions.ConnectionError:
                if progress_callback:
                    progress_callback(i + 1, len(search_engines), f"{engine}: connection error")
            except Exception as e:
                if progress_callback:
                    progress_callback(i + 1, len(search_engines), f"{engine}: error")
                print(f"Search engine {engine} error: {e}")
        
        return results
    
    def zone_transfer(self, domain: str, progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Attempt DNS zone transfer"""
        results = []
        
        if not HAS_DNSPYTHON:
            return results
        
        try:
            if progress_callback:
                progress_callback(1, 3, "Finding nameservers...")
            
            # Get nameservers
            nameservers = []
            try:
                ns_answers = dns.resolver.resolve(domain, 'NS')
                nameservers = [str(ns) for ns in ns_answers]
            except Exception:
                return results
            
            if progress_callback:
                progress_callback(2, 3, f"Testing zone transfer on {len(nameservers)} nameservers...")
            
            for ns in nameservers:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                    
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{domain}" if name != '@' else domain
                        
                        if subdomain not in self.found_subdomains:
                            result = {
                                "subdomain": subdomain,
                                "ip_addresses": [],
                                "method": f"Zone Transfer ({ns})",
                                "status": "active",
                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                            }
                            
                            # Get IP addresses
                            for rdataset in node.rdatasets:
                                if rdataset.rdtype == dns.rdatatype.A:
                                    result["ip_addresses"].extend([str(rdata) for rdata in rdataset])
                            
                            results.append(result)
                            self.found_subdomains.add(subdomain)
                            
                except Exception:
                    # Zone transfer not allowed (expected)
                    pass
            
            if progress_callback:
                progress_callback(3, 3, "Zone transfer attempts completed")
                
        except Exception as e:
            print(f"Zone transfer error: {e}")
        
        return results
    
    def web_crawler(self, domain: str, max_pages: int = 50, progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Crawl web pages for subdomain references"""
        results = []
        
        if not HAS_REQUESTS:
            return results
        
        try:
            visited_urls = set()
            urls_to_visit = [f"http://{domain}", f"https://{domain}"]
            found_subdomains = set()
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            pages_crawled = 0
            
            while urls_to_visit and pages_crawled < max_pages and self.is_running:
                url = urls_to_visit.pop(0)
                
                if url in visited_urls:
                    continue
                
                try:
                    if progress_callback:
                        progress_callback(pages_crawled + 1, max_pages, f"Crawling: {url}")
                    
                    response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                    visited_urls.add(url)
                    pages_crawled += 1
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        # Extract subdomains from content
                        import re
                        pattern = rf'([a-zA-Z0-9.-]+\.{re.escape(domain)})'
                        matches = re.findall(pattern, content)
                        
                        for match in matches:
                            if match not in found_subdomains and match not in self.found_subdomains:
                                found_subdomains.add(match)
                        
                        # Extract new URLs to visit
                        url_pattern = rf'https?://([a-zA-Z0-9.-]*\.{re.escape(domain)}[^\s"\'>]*)'
                        new_urls = re.findall(url_pattern, content)
                        
                        for new_url in new_urls[:5]:  # Limit new URLs per page
                            if new_url not in visited_urls and len(urls_to_visit) < max_pages:
                                urls_to_visit.append(f"https://{new_url}")
                
                except Exception:
                    pass
                
                time.sleep(0.5)  # Rate limiting
            
            # Process found subdomains
            for subdomain in found_subdomains:
                result = {
                    "subdomain": subdomain,
                    "ip_addresses": [],
                    "method": "Web Crawler",
                    "status": "discovered",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                
                # Try to resolve IP
                try:
                    ip = socket.gethostbyname(subdomain)
                    result["ip_addresses"] = [ip]
                    result["status"] = "active"
                except:
                    pass
                
                results.append(result)
                self.found_subdomains.add(subdomain)
                
        except Exception as e:
            print(f"Web crawler error: {e}")
        
        return results
    
    def comprehensive_scan(self, domain: str, wordlist_files: List[str], techniques: List[str],
                          threads: int = 50, max_pages: int = 50, 
                          progress_callback: Optional[Callable] = None) -> Dict:
        """Perform comprehensive subdomain enumeration"""
        
        self.is_running = True
        self.found_subdomains.clear()
        all_results = []
        start_time = time.time()
        
        # Validate inputs
        if not domain or not techniques:
            return {
                "domain": domain,
                "error": "Invalid domain or no techniques selected",
                "results": [],
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        
        total_techniques = len(techniques)
        current_technique = 0
        
        try:
            if progress_callback:
                progress_callback(0, total_techniques, f"Starting scan for {domain}")
            
            # DNS Bruteforce
            if "dns_bruteforce" in techniques and wordlist_files and self.is_running:
                current_technique += 1
                try:
                    if progress_callback:
                        progress_callback(current_technique, total_techniques, "Starting DNS Bruteforce...")
                    
                    # Combine and validate wordlists
                    combined_wordlist = []
                    loaded_wordlists = 0
                    
                    for wordlist_file in wordlist_files:
                        try:
                            words = self.load_wordlist(wordlist_file)
                            combined_wordlist.extend(words)
                            loaded_wordlists += 1
                        except Exception as e:
                            print(f"Error loading wordlist {wordlist_file}: {e}")
                    
                    if combined_wordlist:
                        # Remove duplicates and limit size
                        combined_wordlist = list(set(combined_wordlist))
                        if len(combined_wordlist) > 10000:  # Limit to prevent memory issues
                            combined_wordlist = combined_wordlist[:10000]
                        
                        def dns_progress(current, total, message):
                            if progress_callback and self.is_running:
                                try:
                                    progress_callback(current_technique, total_techniques, 
                                                   f"DNS ({loaded_wordlists} lists): {message}")
                                except Exception:
                                    pass
                        
                        dns_results = self.dns_bruteforce(domain, combined_wordlist, threads, dns_progress)
                        all_results.extend(dns_results)
                    
                except Exception as e:
                    print(f"DNS Bruteforce error: {e}")
            
            # Certificate Transparency
            if "certificate_transparency" in techniques and self.is_running:
                current_technique += 1
                try:
                    if progress_callback:
                        progress_callback(current_technique, total_techniques, "Certificate Transparency...")
                    
                    def ct_progress(current, total, message):
                        if progress_callback and self.is_running:
                            try:
                                progress_callback(current_technique, total_techniques, f"CT: {message}")
                            except Exception:
                                pass
                    
                    ct_results = self.certificate_transparency(domain, ct_progress)
                    all_results.extend(ct_results)
                    
                except Exception as e:
                    print(f"Certificate Transparency error: {e}")
            
            # Search Engine Enumeration
            if "search_engines" in techniques and self.is_running:
                current_technique += 1
                try:
                    if progress_callback:
                        progress_callback(current_technique, total_techniques, "Search Engine Enumeration...")
                    
                    def se_progress(current, total, message):
                        if progress_callback and self.is_running:
                            try:
                                progress_callback(current_technique, total_techniques, f"Search: {message}")
                            except Exception:
                                pass
                    
                    se_results = self.search_engine_enumeration(domain, se_progress)
                    all_results.extend(se_results)
                    
                except Exception as e:
                    print(f"Search Engine error: {e}")
            
            # Zone Transfer
            if "zone_transfer" in techniques and self.is_running:
                current_technique += 1
                try:
                    if progress_callback:
                        progress_callback(current_technique, total_techniques, "Zone Transfer...")
                    
                    def zt_progress(current, total, message):
                        if progress_callback and self.is_running:
                            try:
                                progress_callback(current_technique, total_techniques, f"Zone Transfer: {message}")
                            except Exception:
                                pass
                    
                    zt_results = self.zone_transfer(domain, zt_progress)
                    all_results.extend(zt_results)
                    
                except Exception as e:
                    print(f"Zone Transfer error: {e}")
            
            # Web Crawler
            if "web_crawler" in techniques and self.is_running:
                current_technique += 1
                try:
                    if progress_callback:
                        progress_callback(current_technique, total_techniques, "Web Crawler...")
                    
                    def wc_progress(current, total, message):
                        if progress_callback and self.is_running:
                            try:
                                progress_callback(current_technique, total_techniques, f"Crawler: {message}")
                            except Exception:
                                pass
                    
                    wc_results = self.web_crawler(domain, max_pages, wc_progress)
                    all_results.extend(wc_results)
                    
                except Exception as e:
                    print(f"Web Crawler error: {e}")
            
            # Calculate final statistics
            unique_subdomains = len(self.found_subdomains)
            active_subdomains = len([r for r in all_results if r.get("status") == "active"])
            duration = time.time() - start_time
            
            # Final progress update
            if progress_callback:
                try:
                    progress_callback(total_techniques, total_techniques, 
                                   f"Scan completed: {unique_subdomains} subdomains found")
                except Exception:
                    pass
            
            return {
                "domain": domain,
                "total_found": unique_subdomains,
                "active_subdomains": active_subdomains,
                "techniques_used": [t for t in techniques if self.is_running or t in str(all_results)],
                "results": all_results,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration": round(duration, 2),
                "scan_interrupted": not self.is_running
            }
            
        except KeyboardInterrupt:
            if progress_callback:
                try:
                    progress_callback(current_technique, total_techniques, "Scan interrupted by user")
                except Exception:
                    pass
            
            return {
                "domain": domain,
                "error": "Scan interrupted by user",
                "total_found": len(self.found_subdomains),
                "active_subdomains": len([r for r in all_results if r.get("status") == "active"]),
                "results": all_results,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration": round(time.time() - start_time, 2),
                "scan_interrupted": True
            }
            
        except Exception as e:
            if progress_callback:
                try:
                    progress_callback(current_technique, total_techniques, f"Error: {str(e)[:50]}")
                except Exception:
                    pass
            
            return {
                "domain": domain,
                "error": str(e),
                "total_found": len(self.found_subdomains),
                "active_subdomains": len([r for r in all_results if r.get("status") == "active"]),
                "results": all_results,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration": round(time.time() - start_time, 2)
            }
        
        finally:
            self.is_running = False
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_running = False
    
    def save_results(self, results: Dict, format_type: str = "json") -> str:
        """Save scan results to file"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        domain = results.get("domain", "unknown")
        base_name = f"subdomains_{domain}"
        
        # Use ExportManager if available, otherwise fallback to old method
        if self.export_manager:
            try:
                from pathlib import Path
                if format_type == "json":
                    filepath = self.export_manager.get_scan_export_path(base_name, "json")
                elif format_type == "txt":
                    filepath = self.export_manager.get_scan_export_path(base_name, "txt")
                elif format_type == "csv":
                    filepath = self.export_manager.get_scan_export_path(base_name, "csv")
                else:
                    filepath = self.export_manager.get_scan_export_path(base_name, format_type)
                
                filename = str(filepath)
            except Exception as e:
                print(f"ExportManager error, using fallback: {e}")
                # Fallback to old method
                filename = f"{self.results_dir}/{base_name}_{timestamp}.{format_type}"
        else:
            # Old method for backward compatibility
            filename = f"{self.results_dir}/{base_name}_{timestamp}.{format_type}"
        
        if format_type == "json":
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
        
        elif format_type == "txt":
            with open(filename, 'w') as f:
                f.write(f"Subdomain Enumeration Results for {domain}\n")
                f.write(f"Scan Date: {results.get('timestamp', 'Unknown')}\n")
                f.write(f"Total Found: {results.get('total_found', 0)}\n")
                f.write(f"Active: {results.get('active_subdomains', 0)}\n")
                f.write("="*60 + "\n\n")
                
                for result in results.get("results", []):
                    f.write(f"Subdomain: {result['subdomain']}\n")
                    f.write(f"Status: {result['status']}\n")
                    f.write(f"Method: {result['method']}\n")
                    if result['ip_addresses']:
                        f.write(f"IP Addresses: {', '.join(result['ip_addresses'])}\n")
                    f.write(f"Timestamp: {result['timestamp']}\n")
                    f.write("-" * 40 + "\n")
        
        elif format_type == "csv":
            with open(filename, 'w') as f:
                f.write("Subdomain,Status,Method,IP_Addresses,Timestamp\n")
                for result in results.get("results", []):
                    ip_list = ';'.join(result['ip_addresses'])
                    f.write(f"{result['subdomain']},{result['status']},{result['method']},{ip_list},{result['timestamp']}\n")
        
        return filename
    
    def get_scan_statistics(self) -> Dict:
        """Get current scan statistics"""
        return {
            "total_found": len(self.found_subdomains),
            "found_subdomains": list(self.found_subdomains),
            "is_running": self.is_running
        }