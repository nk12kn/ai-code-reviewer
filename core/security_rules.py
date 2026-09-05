"""Static Security & Vulnerability Analysis Rules.

Covers OWASP Top 10, CWE classifications, secret detection, AST analysis,
and multi-language pattern matching.
"""

import re
import ast
from typing import List, Optional, Tuple
from core.models import Issue, Severity, VulnerabilityCategory


class SecurityRuleEngine:
    """Multi-language static rule and heuristic scanner."""

    def __init__(self):
        self.rules = self._init_rules()

    def _init_rules(self) -> List[dict]:
        return [
            # -------------------------------------------------------------
            # Secrets & Credentials (CWE-798, OWASP A07:2021)
            # -------------------------------------------------------------
            {
                "id": "SEC-001",
                "title": "Hardcoded AWS Access Key Identified",
                "pattern": r"(?i)(?:aws_access_key_id|aws_key)?\b(AKIA[0-9A-Z]{16})\b",
                "severity": Severity.CRITICAL,
                "category": VulnerabilityCategory.SECRET_LEAK,
                "cwe": "CWE-798: Use of Hard-coded Credentials",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "description": "Hardcoded AWS Access Key ID detected. Leaking cloud credentials can lead to complete infrastructure compromise.",
                "remediation": "Load credentials securely from environment variables (e.g., `os.getenv('AWS_ACCESS_KEY_ID')`) or use AWS IAM Roles/Secrets Manager.",
                "languages": ["all"],
            },
            {
                "id": "SEC-002",
                "title": "Hardcoded OpenAI / AI API Key",
                "pattern": r"\bsk-[a-zA-Z0-9]{20,}\b",
                "severity": Severity.CRITICAL,
                "category": VulnerabilityCategory.SECRET_LEAK,
                "cwe": "CWE-798: Use of Hard-coded Credentials",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "description": "Exposed OpenAI / LLM API key detected. Malicious actors can drain quota or access sensitive completions.",
                "remediation": "Store the API key in environment variables (e.g. `os.environ.get('OPENAI_API_KEY')`) and load via a `.env` file excluded from version control.",
                "languages": ["all"],
            },
            {
                "id": "SEC-003",
                "title": "Hardcoded GitHub Personal Access Token",
                "pattern": r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,})\b",
                "severity": Severity.CRITICAL,
                "category": VulnerabilityCategory.SECRET_LEAK,
                "cwe": "CWE-798: Use of Hard-coded Credentials",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "description": "Exposed GitHub Personal Access Token. Attackers can clone private repos or manipulate deployments.",
                "remediation": "Revoke the token immediately and inject it at runtime using GitHub Actions secrets or environment variables.",
                "languages": ["all"],
            },
            {
                "id": "SEC-004",
                "title": "Hardcoded Password / Secret in Source Code",
                "pattern": r"""(?i)(?:password|passwd|pwd|secret_key|client_secret|jwt_secret)\s*[:=]\s*["']([^"'\s]{6,})["']""",
                "severity": Severity.HIGH,
                "category": VulnerabilityCategory.SECRET_LEAK,
                "cwe": "CWE-798: Use of Hard-coded Credentials",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "description": "Hardcoded password or private secret detected in code. Anyone with source code access can authenticate.",
                "remediation": "Store secrets in an external secrets vault (e.g., HashiCorp Vault, AWS Secrets Manager) or load via `.env` file.",
                "languages": ["all"],
            },
            {
                "id": "SEC-005",
                "title": "Private Key File or Key Material in Source",
                "pattern": r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----",
                "severity": Severity.CRITICAL,
                "category": VulnerabilityCategory.SECRET_LEAK,
                "cwe": "CWE-312: Cleartext Storage of Sensitive Information",
                "owasp": "A02:2021 - Cryptographic Failures",
                "description": "Asymmetric private key certificate material found embedded directly in source code.",
                "remediation": "Never commit private keys to source control. Mount keys as Docker secrets or secure filesystem paths.",
                "languages": ["all"],
            },

            # -------------------------------------------------------------
            # SQL Injection (CWE-89, OWASP A03:2021)
            # -------------------------------------------------------------
            {
                "id": "INJ-001",
                "title": "SQL Injection via Formatted String / Concatenation",
                "pattern": r"""(?i)(?:execute|raw_query|query)\s*\(\s*f["'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}""",
                "severity": Severity.CRITICAL,
                "category": VulnerabilityCategory.INJECTION,
                "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                "owasp": "A03:2021 - Injection",
                "description": "Dynamic SQL query formed via f-string interpolation. An attacker can manipulate user input to bypass authentication or extract entire databases.",
                "remediation": "Use parameterized queries with placeholders (e.g., `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`) or an ORM like SQLAlchemy.",
                "languages": ["python"],
            },
            {
                "id": "INJ-002",
                "title": "SQL Injection via String Concatenation / Template Literals",
                "pattern": r"""(?i)(?:db\.query|connection\.execute|client\.query)\s*\(\s*(?:`.*?(?:SELECT|INSERT|UPDATE|DELETE).*?\$\{.*?\}|["'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?["']\s*\+)""",
                "severity": Severity.CRITICAL,
                "category": VulnerabilityCategory.INJECTION,
                "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                "owasp": "A03:2021 - Injection",
                "description": "SQL query formed by concatenating variables or template literals. Allows arbitrary SQL execution.",
                "remediation": "Use parameterized queries (e.g., `db.query('SELECT * FROM users WHERE email = $1', [email])`) or Prisma/TypeORM.",
                "languages": ["javascript", "typescript", "all"],
            },
            {
                "id": "INJ-003",
                "title": "Java SQL Injection via Statement Concatenation",
                "pattern": r"""(?i)statement\.executeQuery\s*\(\s*["'].*?(?:SELECT|UPDATE|DELETE).*?["']\s*\+""",
                "severity": Severity.CRITICAL,
                "category": VulnerabilityCategory.INJECTION,
                "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                "owasp": "A03:2021 - Injection",
                "description": "Raw JDBC Statement used with concatenated strings rather than PreparedStatement.",
                "remediation": "Replace Statement with `PreparedStatement` and use `pstmt.setString(1, param)`.",
                "languages": ["java", "all"],
            },

            # -------------------------------------------------------------
            # Command Injection & Unsafe Execution (CWE-78 / CWE-94, OWASP A03:2021)
            # -------------------------------------------------------------
            {
                "id": "CMD-001",
                "title": "Dangerous Command Execution (os.system / popen)",
                "pattern": r"""\b(?:os\.system|os\.popen|posix\.system)\s*\(""",
                "severity": Severity.HIGH,
                "category": VulnerabilityCategory.INJECTION,
                "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                "owasp": "A03:2021 - Injection",
                "description": "Calling `os.system` or `os.popen` spawns a subshell susceptible to command chaining (e.g., `; rm -rf /`).",
                "remediation": "Use `subprocess.run(['command', 'arg1', 'arg2'], check=True, shell=False)` without passing raw user input to a shell.",
                "languages": ["python"],
            },
            {
                "id": "CMD-002",
                "title": "subprocess with shell=True and dynamic arguments",
                "pattern": r"""subprocess\.(?:Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True""",
                "severity": Severity.HIGH,
                "category": VulnerabilityCategory.INJECTION,
                "cwe": "CWE-78: OS Command Injection",
                "owasp": "A03:2021 - Injection",
                "description": "`subprocess` invoked with `shell=True`. Allows attackers to inject shell meta-characters (`&`, `|`, `;`).",
                "remediation": "Set `shell=False` and pass arguments as a validated list of tokens: `subprocess.run(['ping', '-c', '1', host], shell=False)`.",
                "languages": ["python"],
            },
            {
                "id": "CMD-003",
                "title": "Arbitrary Code Execution via eval() or exec()",
                "pattern": r"""\b(?:eval|exec)\s*\(""",
                "severity": Severity.CRITICAL,
                "category": VulnerabilityCategory.INJECTION,
                "cwe": "CWE-94: Improper Control of Generation of Code ('Code Injection')",
                "owasp": "A03:2021 - Injection",
                "description": "Direct execution of arbitrary code strings with `eval()` or `exec()`. If user input reaches this point, complete server control is achieved.",
                "remediation": "Refactor to use static mapping, `ast.literal_eval()` for safe data parsing, or strict JSON deserialization.",
                "languages": ["python", "javascript", "typescript", "all"],
            },
            {
                "id": "CMD-004",
                "title": "Node.js child_process Command Execution",
                "pattern": r"""(?:child_process|exec|execSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|[^\n,)]*\+)""",
                "severity": Severity.HIGH,
                "category": VulnerabilityCategory.INJECTION,
                "cwe": "CWE-78: OS Command Injection",
                "owasp": "A03:2021 - Injection",
                "description": "`child_process.exec` called with concatenated command string in Node.js.",
                "remediation": "Use `execFile` or `spawn` with an array of arguments rather than `exec` with a shell string.",
                "languages": ["javascript", "typescript"],
            },

            # -------------------------------------------------------------
            # Cross-Site Scripting (XSS) (CWE-79, OWASP A03:2021)
            # -------------------------------------------------------------
            {
                "id": "XSS-001",
                "title": "React dangerouslySetInnerHTML Detected",
                "pattern": r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*""",
                "severity": Severity.HIGH,
                "category": VulnerabilityCategory.XSS,
                "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                "owasp": "A03:2021 - Injection",
                "description": "Bypasses React's built-in XSS protection. If HTML content contains untrusted data, attacker scripts will run in user browsers.",
                "remediation": "Sanitize HTML using `DOMPurify.sanitize(content)` before injecting, or render standard JSX elements.",
                "languages": ["javascript", "typescript"],
            },
            {
                "id": "XSS-002",
                "title": "Direct innerHTML Assignment",
                "pattern": r"""\.\s*innerHTML\s*=\s*(?!['"][^'"]*['"]$)""",
                "severity": Severity.HIGH,
                "category": VulnerabilityCategory.XSS,
                "cwe": "CWE-79: Cross-site Scripting",
                "owasp": "A03:2021 - Injection",
                "description": "Assigning dynamic content directly to `innerHTML` introduces DOM-based XSS vulnerabilities.",
                "remediation": "Use `element.textContent = data` or sanitize input using DOMPurify.",
                "languages": ["javascript", "typescript", "html"],
            },

            # -------------------------------------------------------------
            # Insecure Cryptography & Hashing (CWE-327 / CWE-328, OWASP A02:2021)
            # -------------------------------------------------------------
            {
                "id": "CRY-001",
                "title": "Weak Hash Algorithm (MD5 / SHA1)",
                "pattern": r"""(?:hashlib\.(?:md5|sha1)|crypto\.createHash\(['"](?:md5|sha1)['"]\)|MessageDigest\.getInstance\(['"](?:MD5|SHA-1)['"]\))""",
                "severity": Severity.MEDIUM,
                "category": VulnerabilityCategory.INSECURE_CRYPTO,
                "cwe": "CWE-328: Use of Weak Hash",
                "owasp": "A02:2021 - Cryptographic Failures",
                "description": "MD5 and SHA-1 have known collision attacks and are cryptographically broken.",
                "remediation": "Use SHA-256 (`hashlib.sha256()`) for data integrity, or `bcrypt`/`argon2` for password hashing.",
                "languages": ["python", "javascript", "typescript", "java", "all"],
            },
            {
                "id": "CRY-002",
                "title": "Insecure Cipher Mode (ECB Mode)",
                "pattern": r"""(?:MODE_ECB|AES/ECB/)""",
                "severity": Severity.HIGH,
                "category": VulnerabilityCategory.INSECURE_CRYPTO,
                "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                "owasp": "A02:2021 - Cryptographic Failures",
                "description": "Electronic Codebook (ECB) mode does not employ an initialization vector; identical plaintext blocks yield identical ciphertexts, leaking patterns.",
                "remediation": "Use authenticated encryption such as AES-GCM (`AES.MODE_GCM`).",
                "languages": ["all"],
            },

            # -------------------------------------------------------------
            # Insecure Deserialization & File Traversal (CWE-502 / CWE-22)
            # -------------------------------------------------------------
            {
                "id": "DES-001",
                "title": "Insecure Deserialization with pickle",
                "pattern": r"""\bpickle\.(?:loads?|Unpickler)\s*\(""",
                "severity": Severity.CRITICAL,
                "category": VulnerabilityCategory.DESERIALIZATION,
                "cwe": "CWE-502: Deserialization of Untrusted Data",
                "owasp": "A08:2021 - Software and Data Integrity Failures",
                "description": "`pickle` is not secure against erroneous or maliciously constructed data. Unpickling untrusted data can execute arbitrary code.",
                "remediation": "Use safe serialization formats such as JSON, Protocol Buffers, or messagepack.",
                "languages": ["python"],
            },
            {
                "id": "DES-002",
                "title": "Unsafe YAML Deserialization (yaml.load without Loader)",
                "pattern": r"""\byaml\.load\s*\([^)]*(?:Loader\s*=\s*(?:yaml\.)?Loader|\))""",
                "severity": Severity.HIGH,
                "category": VulnerabilityCategory.DESERIALIZATION,
                "cwe": "CWE-502: Deserialization of Untrusted Data",
                "owasp": "A08:2021 - Software and Data Integrity Failures",
                "description": "`yaml.load()` without SafeLoader can instantiate arbitrary Python objects leading to remote code execution.",
                "remediation": "Use `yaml.safe_load(data)` or `yaml.load(data, Loader=yaml.SafeLoader)`.",
                "languages": ["python"],
            },
            {
                "id": "PTH-001",
                "title": "Potential Path Traversal in File Operations",
                "pattern": r"""open\s*\(\s*(?:f["'].*?\{.*?\}|os\.path\.join\(.*?request\.)""",
                "severity": Severity.HIGH,
                "category": VulnerabilityCategory.PATH_TRAVERSAL,
                "cwe": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                "owasp": "A01:2021 - Broken Access Control",
                "description": "File path constructed dynamically using variable input without path sanitization or canonicalization.",
                "remediation": "Verify that `os.path.realpath(filepath)` starts with the allowed base directory, or use `pathlib.Path().resolve()`.",
                "languages": ["python"],
            },

            # -------------------------------------------------------------
            # Code Quality & Smells
            # -------------------------------------------------------------
            {
                "id": "QAL-001",
                "title": "Silent Exception Swallowing (bare except: pass)",
                "pattern": r"""except(?:\s*Exception)?\s*:\s*(?:#.*?\n\s*)?pass""",
                "severity": Severity.LOW,
                "category": VulnerabilityCategory.CODE_QUALITY,
                "cwe": "CWE-390: Detection of Error Condition Without Action",
                "owasp": "A09:2021 - Security Logging and Monitoring Failures",
                "description": "Exceptions caught and silently suppressed with `pass`. This hides bugs, security failures, and makes auditing impossible.",
                "remediation": "Catch specific exception types and log error traces: `except SpecificError as e: logger.error('Operation failed: %s', e)`.",
                "languages": ["python"],
            },
            {
                "id": "QAL-002",
                "title": "Debug Mode Enabled in Production Code",
                "pattern": r"""(?i)\b(?:debug\s*=\s*True|DEBUG\s*=\s*True)\b""",
                "severity": Severity.MEDIUM,
                "category": VulnerabilityCategory.CODE_QUALITY,
                "cwe": "CWE-489: Active Debug Code",
                "owasp": "A05:2021 - Security Misconfiguration",
                "description": "Debug mode enabled. In web frameworks (Flask/Django), debug mode exposes interactive tracebacks and allows remote code execution.",
                "remediation": "Set debug mode from environment variable: `debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'` and keep False in production.",
                "languages": ["python"],
            },
        ]

    def scan_code(self, code: str, language: str = "auto") -> List[Issue]:
        """Scan source code lines and return detected issues."""
        issues: List[Issue] = []
        lines = code.splitlines()
        detected_issue_keys = set()

        # 1. Regex & Pattern Rule Scan
        for rule in self.rules:
            rule_langs = rule["languages"]
            if "all" not in rule_langs and language != "auto" and language.lower() not in rule_langs:
                continue

            pattern = re.compile(rule["pattern"], re.MULTILINE)
            for idx, line in enumerate(lines, start=1):
                match = pattern.search(line)
                if match:
                    issue_key = (rule["id"], idx)
                    if issue_key in detected_issue_keys:
                        continue
                    detected_issue_keys.add(issue_key)

                    snippet = line.strip()
                    issues.append(
                        Issue(
                            id=f"{rule['id']}-{idx}",
                            title=rule["title"],
                            description=rule["description"],
                            severity=rule["severity"],
                            category=rule["category"],
                            line_number=idx,
                            column_number=match.start() + 1,
                            snippet=snippet,
                            cwe=rule["cwe"],
                            owasp=rule["owasp"],
                            remediation=rule["remediation"],
                            suggested_fix=None,
                        )
                    )

        # 2. Python AST Analysis for Deeper Inspection (if Python)
        if language in ["python", "auto"]:
            try:
                tree = ast.parse(code)
                ast_issues = self._scan_python_ast(tree, lines)
                for ai in ast_issues:
                    issue_key = (ai.id.split("-")[0], ai.line_number)
                    if issue_key not in detected_issue_keys:
                        detected_issue_keys.add(issue_key)
                        issues.append(ai)
            except SyntaxError:
                # Code might be partial or another language, continue
                pass

        # Sort issues by line number
        issues.sort(key=lambda x: (x.line_number, x.severity))
        return issues

    def _scan_python_ast(self, tree: ast.AST, lines: List[str]) -> List[Issue]:
        """Deep AST analysis for Python code."""
        issues: List[Issue] = []

        class SecurityVisitor(ast.NodeVisitor):
            def visit_Call(self, node: ast.Call):
                # Check for open with mode='w' on formatted string
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    if node.args and isinstance(node.args[0], ast.JoinedStr):
                        line_num = node.lineno
                        snippet = lines[line_num - 1].strip() if line_num <= len(lines) else "open(...)"
                        issues.append(
                            Issue(
                                id=f"AST-PTH-{line_num}",
                                title="Dynamic File Path Construction in open()",
                                description="File path is assembled dynamically using an f-string inside open(), which is susceptible to path traversal.",
                                severity=Severity.HIGH,
                                category=VulnerabilityCategory.PATH_TRAVERSAL,
                                line_number=line_num,
                                snippet=snippet,
                                cwe="CWE-22: Path Traversal",
                                owasp="A01:2021 - Broken Access Control",
                                remediation="Validate user-supplied filenames with `pathlib.Path(name).name` and verify within safe directory root.",
                            )
                        )

                # Check for assert statement used for security/authorization
                self.generic_visit(node)

            def visit_Assert(self, node: ast.Assert):
                line_num = node.lineno
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else "assert ..."
                issues.append(
                    Issue(
                        id=f"AST-AST-{line_num}",
                        title="Assert Statement Used in Application Logic",
                        description="`assert` statements are stripped when Python is executed with optimizations (`-O` flag). Never rely on assert for security or validation checks.",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.CODE_QUALITY,
                        line_number=line_num,
                        snippet=snippet,
                        cwe="CWE-617: Reachable Assertion",
                        owasp="A05:2021 - Security Misconfiguration",
                        remediation="Replace assertion with explicit condition and `raise ValueError(...)` or `raise PermissionError(...)`.",
                    )
                )
                self.generic_visit(node)

        visitor = SecurityVisitor()
        visitor.visit(tree)
        return issues
