from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityCategory(str, Enum):
    INJECTION = "Injection (SQL, Command, LDAP)"
    SECRET_LEAK = "Hardcoded Secret / Credential"
    BROKEN_AUTH = "Broken Authentication / Session"
    INSECURE_CRYPTO = "Insecure Cryptography"
    XSS = "Cross-Site Scripting (XSS)"
    PATH_TRAVERSAL = "Path Traversal / LFI"
    CODE_QUALITY = "Code Quality & Smell"
    DESERIALIZATION = "Insecure Deserialization"
    DOS = "Denial of Service / Resource Exhaustion"


class Issue(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    category: VulnerabilityCategory
    line_number: int
    column_number: Optional[int] = None
    snippet: str
    cwe: str
    owasp: str
    remediation: str
    suggested_fix: Optional[str] = None


class ScanRequest(BaseModel):
    code: str
    filename: Optional[str] = "snippet"
    language: str = "auto"
    use_llm: bool = False
    api_key: Optional[str] = None
    provider: Optional[str] = "gemini"


class ScanResponse(BaseModel):
    filename: str
    language: str
    total_issues: int
    security_score: int
    health_grade: str
    counts_by_severity: Dict[str, int]
    issues: List[Issue]
    clean_code: Optional[str] = None
    diff: Optional[str] = None
    scan_duration_ms: float


class FixRequest(BaseModel):
    code: str
    language: str = "auto"
    issue_ids: Optional[List[str]] = None
    api_key: Optional[str] = None
    provider: Optional[str] = "gemini"


class FixResponse(BaseModel):
    original_code: str
    fixed_code: str
    unified_diff: str
    fixed_count: int
    explanations: List[str]
