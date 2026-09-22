# AI Code Reviewer & Security Auditor

## Project Overview
The **AI Code Reviewer & Security Auditor** is a full-stack web application designed to automatically scan source code for security vulnerabilities, calculate a security health score, and generate unified diff patches to remediate detected issues. It provides both an offline heuristic static analysis engine (AST-based) and an optional AI-powered semantic analysis mode.

## Problem Statement
Modern software development moves quickly, often leading to insecure coding practices being pushed to production. Identifying OWASP Top 10 vulnerabilities (like SQL Injection, XSS, and hardcoded secrets) manually is time-consuming and error-prone. This project aims to automate the detection and remediation of these flaws at the developer level, acting as an educational tool and an automated security guardrail.

## Features
- **Project Identity & Dashboard:** Comprehensive UI with project details, Google Sign-In authentication, and a security health gauge.
- **Static AST Analysis:** In-memory code parsing to detect flaws without executing untrusted code.
- **AI Remediation Engine:** Optional LLM integration (Google Gemini) for advanced semantic refactoring and explanation generation.
- **OWASP Top 10 Coverage:** Rules mapping directly to CWEs (SQLi, XSS, Command Injection, Secrets, etc.).
- **Educational Mode:** Built-in knowledge base explaining vulnerabilities and secure coding principles.
- **Automated Patching:** Generates Git-compatible unified diffs for instant 1-click remediation.
- **Secure File Handling:** Safe upload processing and graceful error handling.

## Architecture
The application follows a client-server model:
1. **Frontend:** Vanilla HTML/JS/TailwindCSS providing an interactive code editor, vulnerability dashboard, and tabbed inspector (Issues, Diff, Clean Code).
2. **Backend:** FastAPI (Python) exposing REST endpoints (`/api/scan`, `/api/remediate`).
3. **Engines:**
   - `core/scanner.py`: Orchestrates the analysis flow.
   - `core/security_rules.py`: Contains regex and AST-based heuristic rules.
   - `core/ai_engine.py`: Synthesizes unified diff patches using heuristics or LLM APIs.

## Technology Stack
- **Frontend:** HTML5, JavaScript (ES6+), Tailwind CSS, FontAwesome.
- **Backend:** Python 3.10+, FastAPI, Uvicorn, Pydantic.
- **Authentication:** Google Identity Services (OAuth 2.0 / OIDC).
- **AI/LLM:** Google Gemini API (via HTTP requests).

## Frontend/Backend Flow
1. User pastes code or uploads a file on the UI.
2. The frontend sends a JSON payload containing the code and language to the `/api/scan` endpoint.
3. The backend routes the code through `scanner.py`, which first runs the `security_rules.py` heuristics.
4. The backend then calculates a security score and attempts to fix issues using `ai_engine.py`.
5. The frontend receives the JSON response and updates the dashboard gauges, issues list, and diff view.

## Static Analysis vs AI Integration
- **Static Analysis (Offline):** Uses deterministic pattern matching and rule-based logic to find known bad patterns (e.g., `shell=True`, `hashlib.md5`). It is fast and requires no API keys.
- **AI Integration (Online):** If configured with an API key, the `ai_engine.py` calls the Gemini API to understand semantic context and generate complex refactoring suggestions that simple regex cannot handle. *Note: AI suggestions require human review and may occasionally hallucinate.*

## Google Authentication Setup
To enable Google Sign-In:
1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project or select an existing one.
3. Navigate to **APIs & Services > Credentials**.
4. Click **Create Credentials > OAuth client ID**.
5. Select **Web application**.
6. Set **Authorized JavaScript origins** to your local dev URL (e.g., `http://localhost:8000`) or production URL.
7. Set **Authorized redirect URIs** if applicable (not required for standard popup mode).
8. Copy the **Client ID** and paste it into the `data-client_id` attribute in `static/index.html`.

## Environment Variables
The application does not strictly require environment variables for basic static analysis, but for production deployment and AI integration, set the following:
- `GOOGLE_CLIENT_ID`: Your Google OAuth Client ID.
- `GOOGLE_CLIENT_SECRET`: Your Google OAuth Client Secret (if doing backend validation).
- `OPENAI_API_KEY` / `GEMINI_API_KEY`: Kept client-side in `localStorage` in this architecture, but can be moved to `.env` for forced backend enforcement.

## Local Setup
1. Clone the repository.
2. Ensure Python 3.10+ is installed.
3. Install dependencies:
   ```bash
   pip install fastapi uvicorn pydantic python-multipart
   ```
4. Run the server:
   ```bash
   python app.py
   ```
5. Open `http://localhost:8000` in your browser.

## Production Deployment
For production, the application should be deployed using a robust ASGI server behind a reverse proxy.
1. Use `gunicorn` with `uvicorn` workers:
   ```bash
   gunicorn app:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
   ```
2. Configure Nginx or Caddy to reverse proxy traffic to port 8000 and handle SSL/TLS.
3. Ensure CORS policies in `app.py` are restricted to your production domain.

## Limitations & Known Issues
- **AST Limitations:** The static engine uses heuristic regex and basic structural checks rather than a full compiler frontend. It may produce false positives.
- **AI Hallucinations:** LLM-generated fixes might introduce syntax errors or alter business logic. Human review is mandatory.
- **Client-Side Auth:** The current Google Sign-In is purely client-side for UI demonstration purposes. A full production app must verify the JWT on the FastAPI backend before granting access to sensitive data.

## Demonstration Instructions (Viva)
1. Start the local server (`python app.py`).
2. Open the web interface.
3. Select "Python: SQL Injection & Secrets" from the Sample dropdown.
4. Click **Audit & Review Code**.
5. Show the Security Health score dropping and the critical vulnerabilities listed.
6. Switch to the **Remediation Diff** tab to show how the SQL string concatenation was replaced with parameterized queries.
7. Click **Apply Fixes** to update the editor.
8. Re-run the scan to show the score improving to an A+.
9. Navigate to the **Learn Security** dropdown to demonstrate the educational mode.
