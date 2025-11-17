# 🎯 Directory Fuzzer - TryHackMe Ready

## Overview
The Directory Fuzzer is a powerful web directory and file discovery tool designed for penetration testing and cybersecurity education. It replaces the previous Web Scanner module with advanced fuzzing capabilities perfect for TryHackMe machines.

## Features

### 🚀 Core Functionality
- **Multi-threaded scanning** - Configurable thread count (1-50)
- **Customizable timeouts** - Adjustable request timeouts
- **Multiple wordlists** - Built-in, small, and custom wordlist support
- **Real-time progress tracking** - Live progress bars and statistics
- **Intelligent result categorization** - Separates directories and files
- **Status code analysis** - Color-coded results by HTTP status codes

### 📊 Advanced Features
- **Export functionality** - Save results in TXT or JSON format
- **URL opening** - Double-click results to open in browser
- **Session management** - Persistent connections with retry logic
- **Stealth headers** - Mimics legitimate browser requests

### 🎨 User Interface
- **Intuitive GUI** - Clean, modern interface using ttkbootstrap
- **Tabbed results** - Organized display of directories and files
- **Real-time updates** - Live result updates during scanning
- **Statistics panel** - Summary of findings and status codes

## Wordlists

### Built-in Wordlists
1. **Default (189 entries)** - Comprehensive list for general scanning
2. **Small (17 entries)** - Quick scan for common directories/files
3. **Custom** - Load your own wordlist from file

### Common Directories Included
- Admin panels: `admin`, `administrator`, `login`, `panel`, `dashboard`
- WordPress: `wp-admin`, `wp-content`, `wp-includes`
- Development: `dev`, `test`, `staging`, `backup`
- Common paths: `images`, `css`, `js`, `uploads`, `config`

### Common Files Included
- Index files: `index.html`, `index.php`, `default.htm`
- Config files: `robots.txt`, `sitemap.xml`, `.htaccess`, `web.config`
- Info files: `phpinfo.php`, `readme.txt`, `.env`
- Backup files: `backup.sql`, `dump.sql`, `database.sql`

## Usage for TryHackMe

### Basic Scanning
1. Enter target URL (e.g., `http://10.10.10.10`)
2. Select wordlist size based on time constraints
3. Adjust threads (10-20 for TryHackMe machines)
4. Set timeout (5-10 seconds recommended)
5. Click "Start Fuzzing"

### Advanced Configuration
- **Threads**: Higher = faster, but may overwhelm target
- **Timeout**: Lower = faster, but may miss slow responses
- **Wordlist**: Custom wordlists for specific technologies

### Result Interpretation
- **200 OK** ✅ - Accessible resource found
- **301/302** ⚠️ - Redirect (potential hidden content)
- **401** 🔒 - Authentication required
- **403** 🚫 - Forbidden but exists
- **404** ❌ - Not found (filtered out)

## File Structure

```
app/
├── gui/
│   └── DirectoryFuzzer.py    # GUI interface
├── utils/
│   └── directory_fuzzer.py   # Core fuzzing logic
```

## Technical Implementation

### Backend (`utils/directory_fuzzer.py`)
- **DirectoryFuzzerEngine class** - Main fuzzing engine
- **Multi-threading** - Concurrent request processing
- **Request session** - Connection pooling and retry logic
- **Progress callbacks** - Real-time status updates
- **Export functionality** - Results persistence

### Frontend (`gui/DirectoryFuzzer.py`)
- **ttkbootstrap GUI** - Modern, responsive interface
- **Threaded execution** - Non-blocking UI during scans
- **Real-time updates** - Live progress and result display
- **Result management** - Organized display and interaction

## Security Considerations

### Legitimate Use Only
- Educational purposes (TryHackMe, HackTheBox)
- Authorized penetration testing
- Bug bounty programs with proper scope

### Responsible Disclosure
- Report findings through proper channels
- Respect rate limits and server resources
- Follow platform-specific guidelines

## TryHackMe Integration

### Machine Compatibility
- Works with any HTTP/HTTPS target
- Handles common web server responses
- Optimized for CTF-style challenges

### Common Use Cases
1. **Web challenges** - Find hidden admin panels
2. **File discovery** - Locate configuration files
3. **Backup hunting** - Find database dumps
4. **Directory traversal** - Map application structure

### Tips for Success
1. Start with small wordlist for quick reconnaissance
2. Use default wordlist for comprehensive scanning
3. Check 403 Forbidden responses - may contain hints
4. Look for backup files (.bak, .old, .backup extensions)
5. Pay attention to redirects and different status codes

## Example Workflow

1. **Initial scan**: Quick scan with small wordlist
2. **Analysis**: Review interesting findings
3. **Deep scan**: Use default wordlist on promising paths
4. **Custom scan**: Load specific wordlist for discovered technology
5. **Export**: Save results for documentation

## Dependencies
- `requests` - HTTP client library
- `ttkbootstrap` - Modern GUI framework
- `threading` - Concurrent execution
- `urllib3` - HTTP retry mechanisms

## Error Handling
- Network timeouts handled gracefully
- Connection errors logged but don't stop scanning
- Invalid URLs validated before scanning
- File I/O errors reported to user

---

**Note**: This tool is designed for educational purposes and authorized testing only. Always ensure you have permission before scanning any target.