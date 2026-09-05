"""AI Remediation and Semantic Analysis Engine.

Handles security score calculations, unified diff generation, automated
heuristic remediation, and optional LLM integration (Gemini / OpenAI).
"""

import difflib
import re
from typing import List, Dict, Tuple, Optional
from core.models import Issue, Severity, FixResponse


class AIRemediationEngine:
    """Intelligent remediation and scoring engine."""

    def calculate_score(self, issues: List[Issue]) -> Tuple[int, str, Dict[str, int]]:
        """Calculate a 0-100 security score and letter grade based on findings."""
        counts = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }

        for issue in issues:
            counts[issue.severity.value] += 1

        # Calculate penalty deduction
        deduction = (
            counts[Severity.CRITICAL.value] * 25
            + counts[Severity.HIGH.value] * 15
            + counts[Severity.MEDIUM.value] * 8
            + counts[Severity.LOW.value] * 3
            + counts[Severity.INFO.value] * 1
        )

        score = max(0, 100 - deduction)

        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 55:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        return score, grade, counts

    def generate_diff(self, original_code: str, fixed_code: str, filename: str = "snippet") -> str:
        """Generate a standard unified diff between original and remediated code."""
        orig_lines = original_code.splitlines(keepends=True)
        fixed_lines = fixed_code.splitlines(keepends=True)

        diff = difflib.unified_diff(
            orig_lines,
            fixed_lines,
            fromfile=f"a/{filename} (vulnerable)",
            tofile=f"b/{filename} (remediated)",
            n=3,
        )
        return "".join(diff)

    def auto_remediate(
        self,
        code: str,
        issues: List[Issue],
        language: str = "auto",
        use_llm: bool = False,
        api_key: Optional[str] = None,
        provider: Optional[str] = "gemini",
    ) -> FixResponse:
        """Remediate identified security vulnerabilities and produce diff."""
        if use_llm and api_key:
            try:
                return self._llm_remediate(code, issues, language, api_key, provider)
            except Exception as e:
                # Fallback gracefully to offline heuristic remediation
                pass

        return self._heuristic_remediate(code, issues, language)

    def _heuristic_remediate(self, code: str, issues: List[Issue], language: str) -> FixResponse:
        """Deterministic, rule-based secure refactoring without external dependencies."""
        fixed_lines = code.splitlines()
        explanations: List[str] = []
        fixed_count = 0

        # Sort issues in reverse line order so line index replacements don't drift
        sorted_issues = sorted(issues, key=lambda x: x.line_number, reverse=True)

        needs_import_os = False
        needs_import_subprocess = False
        needs_import_hashlib = False

        for issue in sorted_issues:
            idx = issue.line_number - 1
            if idx >= len(fixed_lines):
                continue
            original_line = fixed_lines[idx]
            new_line = original_line
            explanation = None

            # 1. AWS Key
            if "SEC-001" in issue.id:
                new_line = re.sub(
                    r"""["']AKIA[0-9A-Z]{16}["']""",
                    'os.environ.get("AWS_ACCESS_KEY_ID")',
                    original_line,
                )
                needs_import_os = True
                explanation = f"Line {issue.line_number}: Replaced hardcoded AWS Access Key with `os.environ.get('AWS_ACCESS_KEY_ID')`."

            # 2. OpenAI / LLM Key
            elif "SEC-002" in issue.id:
                new_line = re.sub(
                    r"""["']sk-[a-zA-Z0-9]{20,}["']""",
                    'os.environ.get("OPENAI_API_KEY")',
                    original_line,
                )
                needs_import_os = True
                explanation = f"Line {issue.line_number}: Replaced exposed API key with `os.environ.get('OPENAI_API_KEY')`."

            # 3. Hardcoded password
            elif "SEC-004" in issue.id:
                new_line = re.sub(
                    r"""(?i)(password|secret_key|client_secret)\s*=\s*["'][^"']+["']""",
                    r'\1 = os.environ.get("\1".upper(), "")',
                    original_line,
                )
                needs_import_os = True
                explanation = f"Line {issue.line_number}: Replaced hardcoded password/secret with environment variable retrieval."

            # 4. Python SQL Injection via f-string
            elif "INJ-001" in issue.id:
                # Replace cursor.execute(f"SELECT ... {var}") with cursor.execute("SELECT ... %s", (var,))
                match = re.search(
                    r"""cursor\.execute\(\s*f["'](SELECT|UPDATE|DELETE|INSERT)(.*?)\{(.*?)\}(.*?)["']\s*\)""",
                    original_line,
                    re.IGNORECASE,
                )
                if match:
                    verb, prefix, varname, suffix = match.groups()
                    new_line = f'cursor.execute("{verb}{prefix}%s{suffix}", ({varname.strip()},))'
                    explanation = f"Line {issue.line_number}: Replaced dynamic f-string SQL query with parameterized placeholder (`%s`)."

            # 5. Dangerous os.system
            elif "CMD-001" in issue.id:
                match = re.search(r"""os\.system\((.*?)\)""", original_line)
                if match:
                    cmd_arg = match.group(1).strip()
                    new_line = f"subprocess.run({cmd_arg}, shell=False, check=True)"
                    needs_import_subprocess = True
                    explanation = f"Line {issue.line_number}: Replaced unsafe `os.system` with secure `subprocess.run(..., shell=False)`."

            # 6. eval() / exec()
            elif "CMD-003" in issue.id:
                match = re.search(r"""eval\((.*?)\)""", original_line)
                if match:
                    eval_arg = match.group(1).strip()
                    new_line = f"ast.literal_eval({eval_arg})"
                    explanation = f"Line {issue.line_number}: Replaced dangerous `eval()` with safe `ast.literal_eval()`."

            # 7. React dangerouslySetInnerHTML
            elif "XSS-001" in issue.id:
                new_line = re.sub(
                    r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*(.*?)\s*\}\s*\}""",
                    r"dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(\1) }}",
                    original_line,
                )
                explanation = f"Line {issue.line_number}: Wrapped raw HTML injection with `DOMPurify.sanitize(...)` to prevent XSS."

            # 8. Insecure MD5 / SHA1 Hash
            elif "CRY-001" in issue.id:
                if "hashlib.md5" in original_line:
                    new_line = original_line.replace("hashlib.md5", "hashlib.sha256")
                    explanation = f"Line {issue.line_number}: Upgraded weak MD5 hashing algorithm to cryptographically secure SHA-256."
                elif "hashlib.sha1" in original_line:
                    new_line = original_line.replace("hashlib.sha1", "hashlib.sha256")
                    explanation = f"Line {issue.line_number}: Upgraded weak SHA-1 hashing algorithm to secure SHA-256."

            # 9. Insecure YAML Deserialization
            elif "DES-002" in issue.id:
                new_line = re.sub(r"""yaml\.load\((.*?)\)""", r"yaml.safe_load(\1)", original_line)
                explanation = f"Line {issue.line_number}: Replaced `yaml.load()` with safe deserializer `yaml.safe_load()`."

            # 10. Exception Swallowing
            elif "QAL-001" in issue.id:
                indent = len(original_line) - len(original_line.lstrip())
                spaces = " " * indent
                new_line = f"{spaces}except Exception as err:\n{spaces}    # Security: Log error details rather than swallowing silently\n{spaces}    logging.error('Encountered unexpected error: %s', err)"
                explanation = f"Line {issue.line_number}: Replaced silent `except: pass` with explicit error logging."

            # 11. Debug Mode
            elif "QAL-002" in issue.id:
                new_line = re.sub(
                    r"""(?i)debug\s*=\s*True""",
                    'debug=os.environ.get("DEBUG", "False").lower() == "true"',
                    original_line,
                )
                needs_import_os = True
                explanation = f"Line {issue.line_number}: Configured debug mode to read from environment variable instead of hardcoded `True`."

            if new_line != original_line:
                fixed_lines[idx] = new_line
                fixed_count += 1
                if explanation:
                    explanations.append(explanation)

        # Prepend missing imports if necessary
        header_imports = []
        full_text = "\n".join(fixed_lines)
        if needs_import_os and "import os" not in full_text:
            header_imports.append("import os")
        if needs_import_subprocess and "import subprocess" not in full_text:
            header_imports.append("import subprocess")
        if "ast.literal_eval" in full_text and "import ast" not in full_text:
            header_imports.append("import ast")
        if "logging.error" in full_text and "import logging" not in full_text:
            header_imports.append("import logging")

        if header_imports:
            fixed_lines = header_imports + [""] + fixed_lines
            explanations.insert(0, f"Added missing security utility imports: {', '.join(header_imports)}")

        fixed_code = "\n".join(fixed_lines)
        unified_diff = self.generate_diff(code, fixed_code)

        return FixResponse(
            original_code=code,
            fixed_code=fixed_code,
            unified_diff=unified_diff,
            fixed_count=fixed_count,
            explanations=explanations,
        )

    def _llm_remediate(
        self,
        code: str,
        issues: List[Issue],
        language: str,
        api_key: str,
        provider: str,
    ) -> FixResponse:
        """Call LLM API for advanced semantic refactoring."""
        import urllib.request
        import json

        issues_summary = "\n".join(
            [f"- Line {i.line_number}: {i.title} ({i.cwe}). Recommendation: {i.remediation}" for i in issues]
        )

        prompt = (
            f"You are an expert Cyber Security Auditor. Fix all the following security vulnerabilities in this {language} code:\n"
            f"{issues_summary}\n\n"
            f"Original Code:\n```\n{code}\n```\n\n"
            "Respond ONLY with a JSON object with this exact format:\n"
            "{\n"
            '  "fixed_code": "<full remediated code string>",\n'
            '  "explanations": ["<explanation 1>", "<explanation 2>"]\n'
            "}"
        )

        if provider == "gemini":
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"response_mime_type": "application/json"},
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode("utf-8"))
                text_content = result["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text_content)
                fixed_code = parsed.get("fixed_code", code)
                explanations = parsed.get("explanations", ["AI refactored code to eliminate security vulnerabilities."])
                diff = self.generate_diff(code, fixed_code)
                return FixResponse(
                    original_code=code,
                    fixed_code=fixed_code,
                    unified_diff=diff,
                    fixed_count=len(issues),
                    explanations=explanations,
                )

        # Fallback if unknown provider
        return self._heuristic_remediate(code, issues, language)
