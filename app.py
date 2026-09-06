"""FastAPI Backend Application for AI Code Reviewer & Security Auditor."""

import os
import sys
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from core.models import ScanRequest, ScanResponse, FixRequest, FixResponse
from core.scanner import CodeScanner

app = FastAPI(
    title="AI Code Reviewer & Security Auditor",
    description="Automated static security analysis, vulnerability detection, and AI auto-remediation.",
    version="1.0.0",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = CodeScanner()

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

# Mount static directory
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>AI Code Reviewer & Security Auditor API is Running</h1>")


@app.get("/robots.txt", response_class=PlainTextResponse)
async def serve_robots():
    robots_file = os.path.join(STATIC_DIR, "robots.txt")
    if os.path.exists(robots_file):
        with open(robots_file, "r", encoding="utf-8") as f:
            return PlainTextResponse(f.read())
    return PlainTextResponse("User-agent: *\nAllow: /")


@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def serve_sitemap():
    sitemap_file = os.path.join(STATIC_DIR, "sitemap.xml")
    if os.path.exists(sitemap_file):
        with open(sitemap_file, "r", encoding="utf-8") as f:
            return PlainTextResponse(f.read(), media_type="application/xml")
    return PlainTextResponse("", media_type="application/xml")
@app.get("/ads.txt", response_class=PlainTextResponse)
async def serve_ads_txt():
    ads_file = os.path.join(STATIC_DIR, "ads.txt")
    if os.path.exists(ads_file):
        with open(ads_file, "r", encoding="utf-8") as f:
            return PlainTextResponse(f.read())
    return PlainTextResponse("google.com, pub-1754691668630560, DIRECT, f08c47fec0942fa0")


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "AI Code Reviewer & Security Auditor",
        "rules_count": len(scanner.rules_engine.rules),
        "version": "1.0.0",
    }


@app.post("/api/scan", response_model=ScanResponse)
async def scan_code(request: ScanRequest):
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Code snippet cannot be empty.")
    try:
        return scanner.scan(request)
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(err)}")


@app.post("/api/scan/file", response_model=ScanResponse)
async def scan_file(file: UploadFile = File(...)):
    try:
        content_bytes = await file.read()
        code_str = content_bytes.decode("utf-8", errors="replace")
        filename = file.filename or "uploaded_file"
        lang = scanner.detect_language(code_str, filename)

        req = ScanRequest(
            code=code_str,
            filename=filename,
            language=lang,
            use_llm=False,
        )
        return scanner.scan(req)
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"File scan error: {str(err)}")


@app.post("/api/remediate", response_model=FixResponse)
async def remediate_code(request: FixRequest):
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Code snippet cannot be empty.")
    try:
        return scanner.remediate(request)
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Remediation error: {str(err)}")


@app.get("/api/samples")
async def get_samples():
    """Return preloaded vulnerable samples for testing."""
    samples = {}
    sample_files = {
        "python_sqli": ("vulnerable_sql.py", "Python: SQL Injection & Secrets"),
        "node_cmd": ("vulnerable_node.js", "Node.js: Command Injection & MD5"),
        "java_auth": ("vulnerable_auth.java", "Java: Hardcoded DB & Unsafe Query"),
    }
    for key, (filename, label) in sample_files.items():
        filepath = os.path.join(SAMPLES_DIR, filename)
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                samples[key] = {
                    "label": label,
                    "filename": filename,
                    "code": f.read(),
                }
    return samples


@app.post("/api/export/markdown", response_class=PlainTextResponse)
async def export_markdown_report(data: ScanResponse):
    """Generate a clean Markdown security audit report."""
    md = [
        f"# Security Audit Report: `{data.filename}`",
        f"**Language:** `{data.language}` | **Score:** `{data.security_score}/100` (`{data.health_grade}`) | **Total Issues:** `{data.total_issues}`",
        "",
        "## Summary of Findings",
        f"- **CRITICAL:** {data.counts_by_severity.get('CRITICAL', 0)}",
        f"- **HIGH:** {data.counts_by_severity.get('HIGH', 0)}",
        f"- **MEDIUM:** {data.counts_by_severity.get('MEDIUM', 0)}",
        f"- **LOW:** {data.counts_by_severity.get('LOW', 0)}",
        f"- **INFO:** {data.counts_by_severity.get('INFO', 0)}",
        "",
        "---",
        "## Detailed Issues List",
        "",
    ]

    for idx, issue in enumerate(data.issues, start=1):
        md.append(f"### {idx}. [{issue.severity}] {issue.title}")
        md.append(f"- **Category:** {issue.category}")
        md.append(f"- **CWE:** `{issue.cwe}`")
        md.append(f"- **OWASP:** `{issue.owasp}`")
        md.append(f"- **Location:** Line {issue.line_number}")
        md.append(f"- **Snippet:**\n```\n{issue.snippet}\n```")
        md.append(f"- **Explanation:** {issue.description}")
        md.append(f"- **Remediation:** {issue.remediation}")
        md.append("")

    if data.diff:
        md.append("---")
        md.append("## Remediation Patch (Unified Diff)")
        md.append("```diff")
        md.append(data.diff)
        md.append("```")

    return PlainTextResponse("\n".join(md), media_type="text/markdown")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
