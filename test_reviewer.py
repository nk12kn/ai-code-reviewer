"""Unit and functional test suite for AI Code Reviewer & Security Auditor."""

import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.models import ScanRequest, FixRequest
from core.scanner import CodeScanner


def test_python_vulnerabilities():
    print("[*] Testing Python Vulnerability Scanner...")
    scanner = CodeScanner()

    sample_path = os.path.join(os.path.dirname(__file__), "samples", "vulnerable_sql.py")
    with open(sample_path, "r", encoding="utf-8") as f:
        code = f.read()

    req = ScanRequest(code=code, filename="vulnerable_sql.py", language="python")
    res = scanner.scan(req)

    print(f"    - Filename: {res.filename}")
    print(f"    - Language: {res.language}")
    print(f"    - Total Issues: {res.total_issues}")
    print(f"    - Security Score: {res.security_score}/100 (Grade: {res.health_grade})")
    print(f"    - Severity Breakdown: {res.counts_by_severity}")
    print(f"    - Scan Duration: {res.scan_duration_ms} ms")

    assert res.total_issues >= 4, f"Expected at least 4 issues, got {res.total_issues}"
    assert res.security_score < 50, f"Expected low score for vulnerable code, got {res.security_score}"
    assert res.diff is not None, "Expected unified diff to be generated"
    assert res.clean_code is not None, "Expected clean code to be generated"

    # Verify that clean code has a higher score
    clean_req = ScanRequest(code=res.clean_code, filename="clean.py", language="python")
    clean_res = scanner.scan(clean_req)
    print(f"    - Remediated Code Score: {clean_res.security_score}/100 (Grade: {clean_res.health_grade})")
    assert clean_res.security_score > res.security_score, "Remediated code should score significantly higher"
    print("    [PASS] Python scanner & remediation test passed!\n")


def test_node_vulnerabilities():
    print("[*] Testing Node.js / JavaScript Scanner...")
    scanner = CodeScanner()

    sample_path = os.path.join(os.path.dirname(__file__), "samples", "vulnerable_node.js")
    with open(sample_path, "r", encoding="utf-8") as f:
        code = f.read()

    req = ScanRequest(code=code, filename="vulnerable_node.js", language="javascript")
    res = scanner.scan(req)

    print(f"    - Total Issues: {res.total_issues}")
    print(f"    - Security Score: {res.security_score}/100 (Grade: {res.health_grade})")
    print(f"    - Severity Breakdown: {res.counts_by_severity}")

    assert res.total_issues >= 2, f"Expected at least 2 issues in Node sample, got {res.total_issues}"
    print("    [PASS] Node.js scanner test passed!\n")


def test_java_vulnerabilities():
    print("[*] Testing Java Scanner...")
    scanner = CodeScanner()

    sample_path = os.path.join(os.path.dirname(__file__), "samples", "vulnerable_auth.java")
    with open(sample_path, "r", encoding="utf-8") as f:
        code = f.read()

    req = ScanRequest(code=code, filename="vulnerable_auth.java", language="java")
    res = scanner.scan(req)

    print(f"    - Total Issues: {res.total_issues}")
    print(f"    - Security Score: {res.security_score}/100 (Grade: {res.health_grade})")
    print(f"    - Severity Breakdown: {res.counts_by_severity}")

    assert res.total_issues >= 2, f"Expected at least 2 issues in Java sample, got {res.total_issues}"
    print("    [PASS] Java scanner test passed!\n")


def test_clean_code():
    print("[*] Testing Clean Code Baseline...")
    scanner = CodeScanner()

    clean_code = """
import os
import logging

def get_user_data(user_id: int):
    # Parameterized query with environment variable credentials
    db_pass = os.environ.get("DB_PASSWORD")
    if not db_pass:
        raise ValueError("Missing database password")
    return {"id": user_id, "status": "active"}
"""
    req = ScanRequest(code=clean_code, filename="safe.py", language="python")
    res = scanner.scan(req)

    print(f"    - Total Issues: {res.total_issues}")
    print(f"    - Security Score: {res.security_score}/100 (Grade: {res.health_grade})")
    assert res.total_issues == 0, f"Expected 0 issues for safe code, got {res.total_issues}"
    assert res.security_score == 100, f"Expected score 100, got {res.security_score}"
    assert res.health_grade == "A+", f"Expected grade A+, got {res.health_grade}"
    print("    [PASS] Clean code scored 100/100 (A+) successfully!\n")


if __name__ == "__main__":
    print("==================================================")
    print(" Running Security Scanner Test Suite")
    print("==================================================")
    test_python_vulnerabilities()
    test_node_vulnerabilities()
    test_java_vulnerabilities()
    test_clean_code()
    print("==================================================")
    print(" ALL TESTS PASSED SUCCESSFULLY! (4/4)")
    print("==================================================")
