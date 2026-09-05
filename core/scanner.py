"""Scanner orchestrator combining static security analysis and AI remediation."""

import time
import os
from typing import Optional, List
from core.models import ScanRequest, ScanResponse, FixRequest, FixResponse
from core.security_rules import SecurityRuleEngine
from core.ai_engine import AIRemediationEngine


class CodeScanner:
    """Orchestrates security vulnerability scanning and remediation."""

    def __init__(self):
        self.rules_engine = SecurityRuleEngine()
        self.remediation_engine = AIRemediationEngine()

    def detect_language(self, code: str, filename: Optional[str] = None) -> str:
        """Heuristic language detector based on filename extension or code syntax."""
        if filename:
            ext = os.path.splitext(filename)[1].lower()
            ext_map = {
                ".py": "python",
                ".js": "javascript",
                ".jsx": "javascript",
                ".ts": "typescript",
                ".tsx": "typescript",
                ".java": "java",
                ".cpp": "cpp",
                ".c": "c",
                ".html": "html",
                ".htm": "html",
                ".json": "json",
                ".go": "go",
                ".rs": "rust",
                ".php": "php",
                ".rb": "ruby",
                ".sql": "sql",
            }
            if ext in ext_map:
                return ext_map[ext]

        # Heuristic inspection of code
        if "def " in code or "import " in code and ":" in code:
            return "python"
        elif "function " in code or "const " in code or "let " in code or "console.log" in code:
            return "javascript"
        elif "public class " in code or "System.out.println" in code:
            return "java"
        elif "#include <" in code:
            return "cpp"
        elif "<html" in code or "<div" in code:
            return "html"

        return "python"

    def scan(self, request: ScanRequest) -> ScanResponse:
        """Perform full scan and remediation on provided code snippet."""
        start_time = time.perf_counter()

        lang = request.language
        if not lang or lang.lower() == "auto":
            lang = self.detect_language(request.code, request.filename)

        # 1. Static & AST Rule Scan
        issues = self.rules_engine.scan_code(request.code, language=lang)

        # 2. Score & Grade Calculation
        score, grade, counts = self.remediation_engine.calculate_score(issues)

        # 3. Generate Remediation & Unified Diff if issues were found
        clean_code = None
        diff = None
        if issues:
            fix_res = self.remediation_engine.auto_remediate(
                code=request.code,
                issues=issues,
                language=lang,
                use_llm=request.use_llm,
                api_key=request.api_key,
                provider=request.provider,
            )
            clean_code = fix_res.fixed_code
            diff = fix_res.unified_diff
        else:
            clean_code = request.code

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return ScanResponse(
            filename=request.filename or "snippet",
            language=lang,
            total_issues=len(issues),
            security_score=score,
            health_grade=grade,
            counts_by_severity=counts,
            issues=issues,
            clean_code=clean_code,
            diff=diff,
            scan_duration_ms=duration_ms,
        )

    def remediate(self, request: FixRequest) -> FixResponse:
        """Run dedicated remediation on code."""
        lang = request.language
        if not lang or lang.lower() == "auto":
            lang = self.detect_language(request.code)

        issues = self.rules_engine.scan_code(request.code, language=lang)
        if request.issue_ids:
            issues = [i for i in issues if i.id in request.issue_ids]

        return self.remediation_engine.auto_remediate(
            code=request.code,
            issues=issues,
            language=lang,
            use_llm=bool(request.api_key),
            api_key=request.api_key,
            provider=request.provider,
        )
