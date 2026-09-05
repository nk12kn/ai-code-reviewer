# AI Code Reviewer & Security Auditor 🛡️

A full-stack, developer-first **AI Code Reviewer & Security Auditor** that automatically detects OWASP Top 10 vulnerabilities, leaked credentials, dangerous functions, and code smells across multiple programming languages. It computes a comprehensive Security Health Score, produces visual unified diffs, and offers 1-click automated secure code remediation.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.12-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-teal.svg)
![Security](https://img.shields.io/badge/OWASP-Top%2010-red.svg)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/nk12kn/ai-code-reviewer)

---

## 🚀 Key Features

- **OWASP Top 10 & CWE Detection**:
  - **Injection Attacks (CWE-89, CWE-78, CWE-94)**: SQL Injection via f-strings / string concatenation, OS command injection (`os.system`, `subprocess(..., shell=True)`), arbitrary code execution via `eval()`/`exec()`.
  - **Secret & Credential Leaks (CWE-798)**: Leaked AWS Access Keys (`AKIA...`), OpenAI / LLM API keys (`sk-...`), GitHub PATs (`ghp_...`), private keys, and hardcoded database passwords.
  - **Broken Cryptography (CWE-327, CWE-328)**: Insecure algorithms (MD5, SHA-1) and insecure cipher modes (ECB).
  - **Cross-Site Scripting (CWE-79)**: React `dangerouslySetInnerHTML` injections, direct `innerHTML` modifications.
  - **Insecure Deserialization (CWE-502)**: Python `pickle.loads` and unsafe `yaml.load` without SafeLoader.
  - **Code Quality & Smells (CWE-390, CWE-489)**: Silent exception swallowing (`except: pass`), active debug flags in production.
- **Multi-Language Support**: Python, JavaScript, TypeScript, Java, C/C++, HTML.
- **Automated Remediation & Unified Diff**:
  - Automatically refactors vulnerable code patterns into safe, industry-standard equivalents.
  - Renders colored unified diffs (`+` added, `-` removed) with instant 1-click application.
- **Dual-Engine Architecture (Offline + Online)**:
  - **Built-in Offline Engine**: Works 100% out of the box with zero setup, zero latency, and no API keys required.
  - **Optional LLM Integration**: Connect Google Gemini or OpenAI API keys directly from the UI for deep semantic reasoning.
- **Cybersecurity Web Dashboard**:
  - Modern dark-mode interface with Tailwind CSS and FontAwesome icons.
  - Real-time circular security score gauge (0–100) and letter grades (A+ to F).
  - One-click export to **Markdown Audit Reports** and **Structured JSON**.

---

## 📁 Project Structure

```
ai-code-reviewer/
├── app.py                     # FastAPI backend application & API routes
├── run.py                     # One-click launcher with auto-port & browser launch
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
├── core/
│   ├── __init__.py
│   ├── models.py              # Pydantic schemas (ScanRequest, Issue, FixResponse)
│   ├── security_rules.py      # Multi-language static & AST rule engine
│   ├── ai_engine.py           # Remediation engine, diff generator, scoring logic
│   └── scanner.py             # Orchestrator combining rules and remediation
├── static/
│   ├── index.html             # Dashboard single-page application
│   ├── styles.css             # Cyber-security dark theme & diff styling
│   └── app.js                 # Interactive client logic & API bindings
└── samples/
    ├── vulnerable_sql.py      # Sample Python: SQL Injection, secrets, command exec
    ├── vulnerable_node.js     # Sample Node.js: Command Injection, MD5, JWT secrets
    └── vulnerable_auth.java   # Sample Java: Hardcoded DB credentials & raw queries
```

## 🌐 Permanent Cloud Deployment (24/7 Uptime)

This repository includes turnkey configuration files (`render.yaml`, `Dockerfile`, `Procfile`) for 1-click cloud hosting that runs 24/7 without needing your local computer on:

### Option 1: Deploy on Render.com (Recommended — 100% Free)
1. Fork or push this repository to your GitHub account: `https://github.com/nk12kn/ai-code-reviewer`.
2. Visit **[Render.com](https://dashboard.render.com/)** and sign in with GitHub.
3. Click **New +** -> **Blueprint** (or **Web Service**).
4. Select `ai-code-reviewer`. Render reads `render.yaml` automatically.
5. Click **Apply**. Your app will be live at `https://ai-code-reviewer-xxxx.onrender.com` with free SSL and automatic redeployment on every commit!

### Option 2: Deploy on Railway.app
1. Go to **[Railway.app](https://railway.app/)** and click **New Project**.
2. Select **Deploy from GitHub repo** and pick `ai-code-reviewer`.
3. Railway detects the `Dockerfile` or `Procfile` and assigns a permanent public HTTPS URL.

### Option 3: Deploy on Koyeb
1. Sign up at **[Koyeb.com](https://app.koyeb.com/)**.
2. Create a new service -> select **GitHub** -> pick `ai-code-reviewer`.
3. Deploy as a Python Web Service on the free tier.

---

## ⚡ Quick Start

### 1. Requirements
- Python 3.10+ (Python 3.12 recommended)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Application
```bash
python run.py
```
This automatically launches the local server at `http://127.0.0.1:8000` and opens the web dashboard in your default browser.

---

## 📡 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the interactive cybersecurity dashboard |
| `GET` | `/api/health` | Health check & loaded security rules count |
| `POST` | `/api/scan` | Scan code snippet for vulnerabilities & compute score |
| `POST` | `/api/scan/file` | Multipart file upload for analyzing whole source files |
| `POST` | `/api/remediate` | Generate automated secure code patches and unified diff |
| `GET` | `/api/samples` | Retrieve preloaded vulnerable sample code snippets |
| `POST` | `/api/export/markdown` | Generate downloadable Markdown security audit report |

---

## 🧪 Testing the Scanner

Use the preloaded sample selector in the dashboard UI or test via cURL:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "code": "import os\nAWS_KEY = \"AKIA1111222233334444\"\nos.system(\"ping \" + host)",
    "language": "python"
  }'
```

---

## 🛡️ Security Grade Scale

| Score | Grade | Status |
| :---: | :---: | :--- |
| **95 - 100** | `A+` | Excellent security posture. No critical or high risks. |
| **85 - 94** | `A` | Good security posture. Minor low/info recommendations. |
| **70 - 84** | `B` | Fair. Some medium vulnerabilities identified. |
| **55 - 69** | `C` | Needs attention. High risk issues detected. |
| **40 - 54** | `D` | Poor. Multiple severe vulnerabilities. |
| **< 40** | `F` | Critical risk! Immediate remediation required before deployment. |
