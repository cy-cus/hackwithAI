# 🦅 HackwithAI - LLM-Powered Security Reconnaissance

> **AI-driven reconnaissance and security analysis tool with a Matrix-inspired interface**

A cutting-edge reconnaissance platform that combines traditional security tools with Large Language Model (LLM) analysis to discover and analyze attack surfaces intelligently.

---

## 🎯 Features

### Core Capabilities
- **🔍 Subdomain Discovery** – Find hidden subdomains using subfinder
- **🌐 URL Collection** – Gather URLs from waybackurls, katana, and httpx
- **📡 Endpoint Extraction** – Extract API paths from URLs and JavaScript
- **📄 JavaScript Analysis** – Browser-based JS discovery with Playwright (captures dynamic scripts)
- **🧭 Domain-Scoped Crawling** – Strict filtering keeps Wayback results scoped to the exact domain while JSleuth explores only the target domain and its subdomains
- **🔒 Secret Detection** – Find API keys, tokens, and credentials
- **🤖 AI-Powered Analysis** – Intelligent security findings using Ollama with triple-tier refusal recovery
- **🎯 Targeted Scanning** – Deep-dive analysis on selected findings, secrets, endpoints, or JS files with 20‑minute LLM context windows
- **🗂️ Output Browser Tools** – Let the chat LLM explore scan folders (list_dir/read_file/search_content) for precise answers
- **💬 AI Chat Interface** – Ask questions about scan results; the agent automatically reinforces authorized-testing context and uses file browsing when needed

### User Experience
- **Matrix-Style UI** - Pure hacker aesthetic (neon green #00ff41 + pink #ff0080)
- **Full-Screen Scanner** - Animated progress overlay with Matrix rain effect
- **Real-Time Updates** - WebSocket-powered live scanning progress
- **Search & Filter** - Instant filtering on all results
- **Organized Output** - Clean file structure with JSON exports

---

## 🚀 Quick Start

### Prerequisites
```bash
# Python 3.11+
python3.11 --version

# Ollama (for LLM analysis)
curl https://ollama.ai/install.sh | sh
ollama pull llama3.1:8b

# Security Tools
# Install subfinder, httpx, katana, waybackurls, etc.
```

### Installation

```bash
# Clone & Navigate
cd ~/Desktop/llm

# Create Python 3.11 virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install Playwright browsers (required for JS discovery)
playwright install chromium

# Start Ollama (in separate terminal)
ollama serve

# Run HackwithAI (factory flag silences ASGI warning)
uvicorn reconai.web.app:create_app --factory --reload --host 0.0.0.0 --port 8000
```

### Access
Open **http://localhost:8000** in your browser

> **Tip:** If Playwright complains about missing browsers, re-run `playwright install chromium`. This only needs to be done once per environment.

---

## 🧭 Domain & Scope Controls

HackwithAI strictly respects user-provided scopes:

1. **Waybackurls Filtering** – Only keeps URLs where the host matches `domain` or `www.domain`. Historic data from unrelated subdomains is automatically discarded.
2. **JSleuth Allowed Domains** – The Playwright crawler receives the exact domain, plus any discovered subdomains, as its allowed set. It follows internal links but never leaves that scope.
3. **JS URL Deduping & Size Modes** – All `.js` URLs from Katana + Wayback + JSleuth are deduplicated, then clipped by `js_size` (small=100, medium=1000, large=all). Inline scripts are analyzed the same as external files.
4. **Chat Context Guardrails** – The chat endpoint automatically reinforces authorized-testing context and retries any model refusal so that domain findings can be discussed confidently.

---

## 📖 Usage

### 1. Basic Scan
```
1. Enter target domain: example.com
2. Select LLM model: Llama 3.1 8B
3. Choose JS analysis size: Medium (1000 files)
4. Click "🚀 Start Scan"
5. Watch the Matrix-style scanner overlay!
```

### 2. Scan Modes

#### **🌐 Single Domain**
Full reconnaissance on one target:
- Subdomain discovery
- URL collection from multiple sources
- JavaScript file analysis
- Secret detection
- LLM security analysis

#### **🌍 Multiple Domains**
Bulk scanning:
- Enter multiple domains (one per line)
- Runs reconnaissance on each
- Aggregated results

#### **📄 JS Only**
Direct JavaScript analysis:
- Skip subdomain discovery
- Analyze specific JS file URLs
- Extract endpoints & secrets
- Fast & focused

### 3. Targeted Scanning 🎯

**What it does:**
When you select specific findings, secrets, endpoints, or JS files and click "🤖 Scan Selected with AI", the system:

1. **Identifies Relevant Files**
   - **Findings**: Scans all JS files + injects affected endpoints/parameters/evidence
   - **Secrets**: Finds the JS file where the secret was discovered
   - **Endpoints**: Collects ALL JavaScript files (endpoints come from multiple sources)
   - **JS Files**: Uses exactly the JS files you selected

2. **Fetches Source Code**
   - Downloads complete JS file content
   - Maintains source tracking for context

3. **Prepares LLM Context**
   - Creates detailed prompt with:
     * Selected items (endpoints/secrets)
     * Complete source code from relevant JS files
     * Request for security analysis

4. **LLM Analysis**
   - Ollama processes the context (up to 20 minutes timeout)
   - Analyzes code for:
     * Security vulnerabilities
     * Authentication issues
     * Authorization flaws
     * Data exposure risks
     * Common attack vectors

5. **Displays Results**
   - Shows comprehensive AI-generated security report
   - Includes affected items, severity, and recommendations

**Example Use Cases:**
- Analyze authentication endpoints for security flaws
- Investigate suspicious API keys found in JS
- Deep-dive into payment processing endpoints
- Examine admin panel access controls

> **Inline Scripts Included:** JSleuth saves inline scripts (e.g., `inline#23`) alongside external `.js` files so that targeted scans consider DOM-embedded logic as well.

### 4. AI Chat Interface 💬

Ask questions about your scan results:
```
"Show me all authentication endpoints"
"Which secrets are critical?"
"Summarize the attack surface"
"What are the highest risk findings?"
```

The LLM has access to:
- All discovered URLs and endpoints
- Extracted secrets (with file + line references)
- JavaScript analysis results
- Security findings and evidence

If the model ever responds with a refusal, HackwithAI automatically re-prompts it (three escalating prompts) and, when needed, uses the output browser tools described below.

### 5. AI Output Browser Tools 📂

When the question requires raw evidence, the chat agent can request file data instead of dumping everything into the prompt. Available tools:

| Tool | Purpose | Example |
| --- | --- | --- |
| `LIST_DIR` | Enumerate folders/files inside the current scan output | `TOOL_REQUEST: {"tool":"list_dir","path":"output/example.com_20251118_043942/js_files"}` |
| `READ_FILE` | Read a full file or slice (JSON auto-parses) | `TOOL_REQUEST: {"tool":"read_file","path":".../secrets.json","offset":0,"limit":200}` |
| `SEARCH_CONTENT` | Find strings across files/directories | `TOOL_REQUEST: {"tool":"search_content","path":".../js_files","query":"admin"}` |
| `GET_SCAN_SUMMARY` | Summarize high-level stats for the scan | `TOOL_REQUEST: {"tool":"get_scan_summary"}` |

**Usage:** The LLM prints the tool request as JSON prefixed with `TOOL_REQUEST:`. The backend executes it, appends the result as `TOOL_RESULT`, and the LLM either asks for more data or replies with `FINAL_ANSWER:`.

---

## 🏗️ Architecture

### Project Structure
```
/home/cyky/Desktop/llm/
├── reconai/
│   ├── models.py           # Pydantic data models
│   ├── llm/
│   │   └── ollama.py       # Ollama LLM backend
│   ├── recon/
│   │   ├── subfinder.py    # Subdomain discovery
│   │   ├── waybackurls.py  # Historical URL collection
│   │   ├── katana.py       # Web crawler
│   │   ├── httpx.py        # HTTP probing
│   │   └── jsanalyzer.py   # JavaScript analysis
│   ├── utils/
│   │   ├── output_manager.py      # File organization
│   │   ├── endpoint_extractor.py  # API path extraction
│   │   └── json_encoder.py        # Datetime serialization
│   ├── analyzer.py         # LLM security analysis
│   └── web/
│       ├── app.py          # FastAPI application
│       └── templates/
│           └── index.html  # Matrix-style UI
├── output/                 # Scan results
├── requirements.txt
└── README.md              # This file
```

### Data Flow

1. **Reconnaissance Phase**
   ```
   Target → Subfinder → Subdomains
         → Waybackurls → URLs
         → Katana → URLs  
         → Httpx → URLs
         → JSLeuth/JSFetcher → JS Files
   ```

2. **Analysis Phase**
   ```
   JS Files → JSAnalyzer → Endpoints, Secrets, Links
   URLs → Endpoint Extractor → API Paths
   All Data → LLM → Security Findings
   ```

3. **Storage**
   ```
   Results → OutputManager → Organized Folders
                           → JSON Files
                           → Summary Reports
   ```

### WebSocket Real-Time Updates
```
Scan Start → WebSocket Connection → Progress Updates
                                  → Status Messages
                                  → Live Stats
                                  → Scan Complete
```

---

## 🎨 UI Theme: Hacker Matrix Style

### Color Palette
```css
Matrix Green:  #00ff41  /* Primary UI color */
Neon Pink:     #ff0080  /* CTAs & accents */
Pure Black:    #000000  /* Background */
Dark Gray:     #0a0e0f  /* Secondary bg */
```

### Key Visual Elements
- ✅ Matrix rain effect (falling Japanese/binary characters)
- ✅ Animated scan line with pink pulse
- ✅ Glowing green text with pulsing shadow
- ✅ Full-screen scanner overlay during scans
- ✅ Real-time stats counter
- ✅ Timeline with glowing step dots
- ✅ Zero blue/cyan colors anywhere

---

## 📊 Output Structure

After each scan, results are saved in organized folders:

```
output/
└── example.com_20251116_183240/
    ├── subdomains/
    │   ├── subdomains.txt
    │   └── subdomains.json
    ├── endpoints/
    │   ├── endpoints.txt
    │   └── endpoints.json
    ├── parameters/
    │   ├── parameters.json
    │   └── suspicious_parameters.txt
    ├── js_files/
    │   ├── js_urls.txt
    │   ├── js_files.json
    │   └── raw/
    │       ├── script1.js
    │       ├── script1.meta.json
    │       └── ...
    ├── secrets/
    │   ├── secrets.json
    │   └── CRITICAL_SECRETS.txt
    ├── findings/
    │   ├── findings.json
    │   └── findings_summary.txt
    ├── raw/
    │   └── attack_surface.json
    ├── reports/
    │   └── summary.txt
    └── scan_state.json
```

---

## 🔧 Configuration

### Environment Variables
Create a `.env` file:
```ini
# Ollama Configuration
OLLAMA_BASE_URL=http://localhost:11434
DEFAULT_MODEL=llama3.1:8b

# Application Settings
DEBUG=true
LOG_LEVEL=INFO
PORT=8000
```

### LLM Timeout Settings
The default timeout is now **1200 seconds (20 minutes)** to handle large targeted scans.

Edit `reconai/llm/ollama.py` to adjust:
```python
timeout: int = 1200  # seconds
```

---

## 🐛 Troubleshooting

### "Playwright executable doesn't exist"
```
Looks like Playwright was just installed or updated.
Please run: playwright install chromium
```
**Solution:** Activate your virtualenv and run `playwright install chromium` once. The JS discovery engine will then launch Chromium headlessly.

### "Ollama request timed out"
**Solution:**
- Increase timeout in `reconai/llm/ollama.py` (already set to 20 min)
- Use a smaller/faster model (e.g., `deepseek-coder:1.3b`)
- Reduce the number of selected items for targeted scanning
- Ensure Ollama is running: `ollama serve`

### "Failed to save subdomains: datetime serialization"
**Solution:**
- Already fixed! All Pydantic models now have `ConfigDict` with datetime serialization
- Models automatically convert datetime to ISO format

### Port already in use
```bash
# Find and kill process
sudo lsof -i :8000
kill -9 <PID>

# Or use a different port
uvicorn reconai.web.app:create_app --port 8080
```

### Ollama not responding
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama
ollama serve

# Verify model is downloaded
ollama list
ollama pull llama3.1:8b
```

---

## 🔍 How Targeted Scanning Works

### Backend Process (`/api/scan/targeted`)

When you click "🤖 Scan Selected with AI":

1. **Request Received**
   ```python
   {
       "scan_id": "example.com_20251116_183240",
       "target_type": "endpoint",  # or "secret"
       "target_items": ["/api/users", "/api/auth/login"],
       "focus": "security",
       "model": "llama3.1:8b"
   }
   ```

2. **Load Scan Results**
   - Retrieves stored scan data from `active_scans` or file system
   - Validates scan exists and has results

3. **Identify Source Files**
   
   **For Secrets:**
   ```python
   # Find the JS file where each secret was found
   for secret in selected_secrets:
       js_file_url = endpoint_sources.get(secret)
       js_files_to_scan.add(js_file_url)
   ```
   
   **For Endpoints:**
   ```python
   # Scan ALL JS files (endpoints come from multiple sources)
   for js_file in all_discovered_js_files:
       js_files_to_scan.add(js_file.url)
   ```

4. **Fetch JS Content**
   ```python
   async def fetch_js_content(url):
       response = await httpx.get(url, timeout=30)
       return {
           'url': url,
           'content': response.text,
           'size': len(response.text)
       }
   ```

5. **Build LLM Prompt**
   ```python
   prompt = f"""
   Analyze these {target_type}s for security issues:
   
   Selected Items:
   {json.dumps(selected_items_info, indent=2)}
   
   Source Code from {len(js_contents)} JavaScript files:
   
   File: {js_url}
   ---
   {js_content}
   ---
   
   Provide detailed security analysis...
   """
   ```

6. **LLM Analysis**
   ```python
   analysis = await llm.generate(
       prompt=prompt,
       temperature=0.3,
       max_tokens=4096,
       timeout=1200  # 20 minutes
   )
   ```

7. **Return Results**
   ```json
   {
       "analysis": "Security Analysis:\n\n1. Authentication...",
       "items_analyzed": 2,
       "js_files_scanned": 18,
       "model_used": "llama3.1:8b"
   }
   ```

### Frontend Display
- Shows loading modal while LLM analyzes
- Displays comprehensive security report
- Allows copying/exporting results

---

## 📝 Recent Fixes & Improvements

### ✅ Datetime Serialization Fixed
- Added `ConfigDict` to all Pydantic models
- All datetime fields now serialize to ISO format
- No more "Object of type datetime is not JSON serializable" errors
- Fixed `model_name` namespace warning

### ✅ Timeout Issues Resolved
- Increased default LLM timeout from 300s → 1200s (20 minutes)
- Per-call timeout parameter support
- Better error messages with actual timeout values

### ✅ Complete UI Overhaul
- Removed ALL blue/cyan colors
- Pure Matrix hacker theme (green + pink)
- Full-screen animated scanner overlay
- Matrix rain background effect
- Glowing text animations
- Real-time stats counter
- Timeline with animated steps

### ✅ Targeted Scanning Improved
- Findings, Secrets, Endpoints, and JS Files tabs all support "Scan Selected with AI"
- Endpoints now scan ALL JS files for complete context
- Secrets scan specific source files
- Findings include affected endpoints, parameters, and evidence in AI prompt
- JS tab allows direct selection of scripts to analyze
- Better error handling + longer timeout support

### ✅ AI Output Browser
- Chat agent can now browse `output/<scan_id>/...` safely
- Supports listing folders, reading files, and grepping for strings
- Enables precise answers referencing exact files/lines without bloated prompts

### ✅ Search Functionality
- Search bars on Findings, Secrets, URLs, Endpoints, and JS tabs
- Instant filtering as you type
- Case-insensitive matching

---

## 🎯 Roadmap

### Planned Features
- [ ] Export reports in PDF/HTML
- [ ] Scheduled/automated scans
- [ ] Multi-user support with authentication
- [ ] Scan history and comparison
- [ ] Custom LLM prompts
- [ ] Plugin system for additional tools
- [ ] REST API for programmatic access
- [ ] Docker containerization
- [ ] Kubernetes deployment configs

### UI Enhancements
- [ ] Sound effects (terminal beeps)
- [ ] Completion animations
- [ ] Keyboard shortcuts
- [ ] Dark/stealth mode toggle
- [ ] Customizable color themes

---

## 📚 Technical Details

### Pydantic Models
All data models use `ConfigDict` for proper serialization:
```python
class Endpoint(BaseModel):
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
    
    url: str
    method: str = "GET"
    timestamp: datetime = Field(default_factory=datetime.now)
```

### Async Scanning
Reconnaissance tools run asynchronously:
```python
async def run_scan_async(scan_id, target, request):
    # Parallel execution
    subdomains = await asyncio.to_thread(run_subfinder, domain)
    urls_wayback = await asyncio.to_thread(run_waybackurls, domain)
    # ... more tools
```

### WebSocket Protocol
```javascript
ws = new WebSocket(`ws://localhost:8000/ws/scan/${scan_id}`);

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    // { progress: 75, message: "Analyzing JS...", status: "running" }
};
```

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional reconnaissance tools integration
- New LLM prompts for specialized analysis
- UI/UX enhancements
- Performance optimizations
- Bug fixes and error handling

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Always obtain proper permission before scanning any targets. The developers are not responsible for misuse or damage caused by this tool.

---

## 📄 License

MIT License - See LICENSE file for details

---

## 🙏 Credits

**Built with:**
- FastAPI - Modern web framework
- Ollama - Local LLM inference
- Subfinder, Httpx, Katana - Reconnaissance tools
- Tailwind CSS - Utility-first styling
- Lead Author & Maintainer: **Cycus Pectus**

**Inspired by:**
- Matrix digital rain aesthetic
- Traditional security tools (nmap, metasploit)
- Modern AI-powered security platforms

---

## 📞 Support

For issues, questions, or feature requests:
- Check the output logs in the terminal
- Verify Ollama is running: `ollama serve`
- Ensure all dependencies are installed
- Review this README for troubleshooting

---

**Happy Hacking! 🦅💚**

Made with 💚 by security researchers, for security researchers.
