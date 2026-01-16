# hackwithai: The Advanced Reconnaissance & Vulnerability Engine

**hackwithai** is a comprehensive, step-by-step security scanning platform designed for offensive security engineers. It automates the entire reconnaissance lifecycle, from subdomain enumeration to AI-powered vulnerability synthesis.

---

## 🚀 Key Features

*   **7-Step Modular Workflow:** Run the full chain or execute individual steps surgically.
*   **Deep JS Analysis:** Extracts endpoints, secrets, and logical flaws from JavaScript files using headless browser instrumentation (`JSleuth`).
*   **Agentic AI Reporting:** Step 7 uses a "Kay-style" autonomous agent to analyze findings and write executive summaries using OpenAI or Gemini.
*   **Real-Time Visualization:** Watch subdomains, endpoints, and bugs appear instantly in the UI as they are found.
*   **Data Persistence:** Every finding is saved to organized JSON and text files in `output/` for zero data loss.

---

## 🛠️ The 7-Step Workflow

1.  **Subdomain Enumeration**
    *   **Tools:** Subfinder, HTTPX
    *   **Action:** Finds specific subdomains for the target and validates which are live.
    *   **Output:** `output/[scan_id]/subdomains/`

2.  **Wayback Machine Archiving**
    *   **Tools:** Waybackurls
    *   **Action:** Miners historical URL data to find old endpoints, parameters, and sensitive files.
    *   **Output:** `output/[scan_id]/endpoints/`

3.  **JavaScript Discovery (Deep)**
    *   **Tools:** JSleuth Enhanced (Playwright), Manifest Hunter
    *   **Action:** Visits live sites, triggers SPA routes, and captures every internal JS file and Build Manifest.
    *   **Output:** `output/[scan_id]/js_files/`

4.  **JavaScript Analysis**
    *   **Tools:** Regex, Entropy Analysis
    *   **Action:** Scans captured JS for API keys, hardcoded credentials, hidden API routes, and cloud buckets.
    *   **Output:** `output/[scan_id]/secrets/`

5.  **Vulnerability Scanning**
    *   **Tools:** Custom Python Scanner
    *   **Action:** Fuzzes all discovered endpoints for XSS, SQLi, LFI, SSRF, and more using a smart, configurable fuzzing engine.
    *   **Output:** `output/[scan_id]/findings/`

6.  **Targeted Wordlist Generation**
    *   **Action:** Generates a custom, project-specific wordlist by extracting unique terms from all subdomains, paths, and parameters found during the scan.
    *   **Output:** `output/[scan_id]/wordlist.txt`

7.  **AI Synthesis & Reporting**
    *   **Tools:** CloudLLM (OpenAI/Gemini)
    *   **Action:** An autonomous AI agent analyzes all findings, correlates weak points, and generating a professional Executive Summary and Attack Strategy.
    *   **Output:** `output/[scan_id]/reports/ai_executive_summary.md`

---

## 💻 Usage Guide

### Starting the Server
```bash
# Activate Virtual Environment (if applicable)
source venvhackwithai/bin/activate

# Run the backend
python3 -m uvicorn reconai.web.app:app --host 0.0.0.0 --port 1337 --reload
```
Open your browser to `http://localhost:1337`.

### Running a Scan
1.  **Select Mode:** Choose **Automatic** for a hands-off run or **Manual** for step-by-step control.
2.  **Enter Target:** Type your target domain (e.g., `example.com`).
3.  **Configure Limits:**
    *   **JS Limit:** Limit how many JS files to analyze (default: 100).
    *   **Scan Limit:** Limit how many endpoints to fuzz (default: All).
4.  **Launch:** Click **Start Scan**.

### AI Analysis (Step 7)
To use the AI reporting feature:
1.  Wait for the scan to reach Step 7.
2.  Paste your **OpenAI** (`sk-...`) or **Google Gemini** (`AIza...`) API Key into the input field.
3.  Click **Run Step 7**.

---

## 📂 Output Structure

All data is saved in `output/[scan_id]/`:

| Folder | Content |
| :--- | :--- |
| `subdomains/` | List of live subdomains (`subdomains.txt`) |
| `endpoints/` | All discovered URLs from Wayback/JS (`endpoints.txt`) |
| `js_files/` | Raw JS content and metadata |
| `secrets/` | Discovered API keys and credentials (`secrets.json`) |
| `findings/` | Vulnerability scan results (`findings.json`) |
| `reports/` | Final AI Executive Summary and stats |
| `wordlist.txt` | Custom wordlist generated from the target |

---

## ⚠️ Disclaimer
This tool is for **authorized security testing only**. The user is solely responsible for any illegal or unauthorized usage. Always obtain permission before scanning a target.
