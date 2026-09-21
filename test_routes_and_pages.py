"""Comprehensive zero-dependency test suite for AI Code Reviewer routes, pages, AdSense compliance, and APIs."""

import asyncio
import os
import sys
import xml.etree.ElementTree as ET

# Import app and components
from app import (
    app,
    STATIC_DIR,
    serve_index,
    serve_about,
    serve_contact,
    serve_privacy,
    serve_terms,
    serve_security_disclaimer,
    serve_learn_topic,
    serve_robots,
    serve_sitemap,
    serve_ads_txt,
    health_check,
    get_samples,
    scan_code,
    handle_contact,
    export_markdown_report,
)
from core.models import ScanRequest, ContactRequest, FixRequest


async def run_all_tests():
    print("==================================================")
    print(" Running Zero-Dependency Verification Test Suite")
    print("==================================================")

    # 1. Test Static & Educational HTML Page Handlers
    print("\n[*] Testing Educational & Trust Route Handlers...")
    routes_to_test = [
        ("Homepage", serve_index(), "AI Code Reviewer"),
        ("About Page", serve_about(), "About AI Code Reviewer"),
        ("Contact Page", serve_contact(), "Contact & Responsible Disclosure"),
        ("Privacy Policy", serve_privacy(), "Privacy Policy & Data Processing Disclosure"),
        ("Terms of Service", serve_terms(), "Terms of Service"),
        ("Security Disclaimer", serve_security_disclaimer(), "Security & Analysis Scope Disclaimer"),
        ("SQL Injection Guide", serve_learn_topic("sql-injection"), "SQL Injection"),
        ("XSS Guide", serve_learn_topic("xss"), "Cross-Site Scripting (XSS)"),
        ("OWASP Top 10 Guide", serve_learn_topic("owasp-top-10"), "OWASP Top 10:2025"),
        ("Secure Coding Guide", serve_learn_topic("secure-coding"), "Secure Coding Principles"),
        ("Python Security Guide", serve_learn_topic("python-security"), "Python Security Hardening"),
        ("JavaScript Security Guide", serve_learn_topic("javascript-security"), "JavaScript & Node.js Security"),
        ("Hardcoded Secrets Guide", serve_learn_topic("hardcoded-secrets"), "Hardcoded Secrets"),
        ("Command Injection Guide", serve_learn_topic("command-injection"), "OS Command Injection"),
        ("robots.txt", serve_robots(), "User-agent: *"),
        ("sitemap.xml", serve_sitemap(), "<urlset"),
        ("ads.txt", serve_ads_txt(), "pub-1754691668630560"),
    ]

    for label, coro, expected_substr in routes_to_test:
        response = await coro
        content = response.body.decode("utf-8")
        assert response.status_code == 200, f"{label} returned status {response.status_code}"
        assert expected_substr in content, f"{label} missing expected substring '{expected_substr}'"
        print(f"    [PASS] {label} -> HTTP 200 (Verified '{expected_substr[:30]}')")

    # 2. Test Invalid Slug Handling (404)
    print("\n[*] Testing 404 handling on non-existent topic...")
    try:
        await serve_learn_topic("non-existent-topic")
        assert False, "Expected 404 HTTPException on non-existent topic"
    except Exception as e:
        assert hasattr(e, "status_code") and e.status_code == 404
        print("    [PASS] Non-existent topic correctly raised HTTP 404.")

    # 3. Test Contact API
    print("\n[*] Testing Contact API Endpoint (POST /api/contact)...")
    valid_contact = ContactRequest(
        name="Security Researcher",
        email="researcher@example.com",
        subject="Responsible Vulnerability Disclosure",
        message="Reporting test security observation."
    )
    contact_res = await handle_contact(valid_contact)
    assert contact_res.status == "success"
    assert "Security Researcher" in contact_res.message
    print("    [PASS] Valid contact submission processed successfully!")

    # 4. Test Core Health and Scanner APIs
    print("\n[*] Testing Core Scanner & Remediation APIs...")
    h = await health_check()
    assert h["status"] == "healthy"
    print("    [PASS] Health check API healthy.")

    samples = await get_samples()
    assert "python_sqli" in samples
    assert "node_cmd" in samples
    assert "java_auth" in samples
    print("    [PASS] Samples API returned vulnerable presets for Python, Node.js, and Java.")

    # Scan Python SQLi
    sqli_sample = samples["python_sqli"]["code"]
    req = ScanRequest(
        code=sqli_sample,
        filename="vulnerable_sql.py",
        language="python",
        use_llm=False
    )
    scan_res = await scan_code(req)
    assert scan_res.total_issues >= 2
    assert scan_res.security_score < 50
    assert scan_res.clean_code is not None
    assert scan_res.diff is not None
    print(f"    [PASS] /api/scan detected {scan_res.total_issues} issues (Score: {scan_res.security_score}/100, Grade: {scan_res.health_grade}).")

    # Export Markdown
    md_res = await export_markdown_report(scan_res)
    md_text = md_res.body.decode("utf-8")
    assert "# Security Audit Report:" in md_text
    assert "Remediation Patch (Unified Diff)" in md_text
    print("    [PASS] /api/export/markdown generated valid markdown audit report.")

    # 5. Test sitemap.xml
    print("\n[*] Validating sitemap.xml and robots.txt...")
    sitemap_path = os.path.join(STATIC_DIR, "sitemap.xml")
    assert os.path.exists(sitemap_path), "sitemap.xml does not exist"
    tree = ET.parse(sitemap_path)
    root = tree.getroot()
    urls = [elem.text for elem in root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]
    assert len(urls) >= 14, f"Expected at least 14 URLs, found {len(urls)}"
    print(f"    [PASS] sitemap.xml contains {len(urls)} registered URLs:")
    for u in urls:
        print(f"        - {u}")

    # 6. Test Initial Security Health UI State
    print("\n[*] Verifying Initial Security Health State in index.html & app.js...")
    with open(os.path.join(STATIC_DIR, "index.html"), "r", encoding="utf-8") as f:
        html = f.read()

    assert "Not analyzed yet" in html, "index.html must have 'Not analyzed yet' initially"
    assert "PENDING" in html, "index.html must have 'PENDING' initially"
    assert "--</span>" in html, "index.html must have '--' initially"
    assert "100 A+" not in html, "index.html must NOT falsely claim 100 A+ initially"

    with open(os.path.join(STATIC_DIR, "app.js"), "r", encoding="utf-8") as f:
        app_js = f.read()

    assert 'Not analyzed yet' in app_js, "app.js resetResults() must set 'Not analyzed yet'"
    assert '"PENDING"' in app_js, "app.js resetResults() must set grade to 'PENDING'"
    assert '"--"' in app_js, "app.js resetResults() must set score to '--'"
    print("    [PASS] Initial state strictly displays 'Not analyzed yet', score '--', and 'PENDING'.")

    # 7. Test All Internal Links across HTML files
    print("\n[*] Auditing all internal href links across all HTML files...")
    import glob
    import re
    html_files = glob.glob(os.path.join(STATIC_DIR, "**", "*.html"), recursive=True) + glob.glob(os.path.join(STATIC_DIR, "*.html"))
    internal_links = set()
    for hf in set(html_files):
        with open(hf, "r", encoding="utf-8") as f:
            content = f.read()
        for match in re.findall(r'href=["\'](/[^"\'#]*)["\']', content):
            internal_links.add(match)

    print(f"    Found {len(internal_links)} distinct internal routes linked across HTML files:")
    for link in sorted(internal_links):
        # Verify link corresponds to a valid route
        if link == "/" or link == "/#analyzer":
            continue
        elif link.startswith("/learn/"):
            topic = link[7:]
            file_check = os.path.join(STATIC_DIR, "learn", f"{topic}.html")
            assert os.path.exists(file_check), f"Broken link: {link} -> {file_check} does not exist"
        elif link.startswith("/static/"):
            static_rel = link[8:]
            file_check = os.path.join(STATIC_DIR, static_rel)
            assert os.path.exists(file_check), f"Broken static link: {link} -> {file_check} does not exist"
        else:
            page_name = link[1:]
            file_check = os.path.join(STATIC_DIR, f"{page_name}.html")
            assert os.path.exists(file_check), f"Broken link: {link} -> {file_check} does not exist"
        print(f"        [OK] {link}")

    print("\n==================================================")
    print(" ALL VERIFICATION TESTS PASSED SUCCESSFULLY! (7/7)")
    print("==================================================")


if __name__ == "__main__":
    asyncio.run(run_all_tests())

