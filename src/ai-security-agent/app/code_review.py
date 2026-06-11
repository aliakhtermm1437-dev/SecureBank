"""AI-assisted code-review (heuristic, no external API needed).

Scans a diff or file content for high-confidence insecure patterns
mapped to OWASP / CWE.  Used by the CI pipeline as an extra "linter"
that focuses on framework-specific anti-patterns SonarQube/CodeQL
don't always flag clearly.

Each finding is reported with line number, snippet, CWE, ASVS reference,
and a one-line remediation suggestion.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    cwe:  str
    asvs: str
    snippet: str
    remediation: str

    def as_dict(self) -> dict: return self.__dict__.copy()


# pattern → (rule_id, CWE, ASVS, remediation)
PATTERNS: list[tuple[re.Pattern[str], tuple[str, str, str, str]]] = [
    (re.compile(r'\beval\s*\('),
     ("py-eval", "CWE-95", "ASVS V5.5.1",
      "Avoid eval(); use ast.literal_eval or a real parser")),
    (re.compile(r'\bexec\s*\('),
     ("py-exec", "CWE-95", "ASVS V5.5.1",
      "Avoid exec(); rewrite as direct code")),
    (re.compile(r'subprocess\.(Popen|run|call|check_output)\([^)]*shell\s*=\s*True'),
     ("py-shell-true", "CWE-78", "ASVS V5.3.8",
      "Pass arguments as a list and shell=False")),
    (re.compile(r'pickle\.(load|loads)\('),
     ("py-pickle", "CWE-502", "ASVS V5.5.3",
      "Replace pickle with JSON or a typed schema")),
    (re.compile(r'yaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*yaml\.Safe)'),
     ("py-yaml-load", "CWE-502", "ASVS V5.5.3",
      "Use yaml.safe_load")),
    (re.compile(r'(?<![\w.])md5\s*\(', re.IGNORECASE),
     ("weak-md5", "CWE-327", "ASVS V6.2.2",
      "Replace MD5 with SHA-256 or BLAKE2")),
    (re.compile(r'(?<![\w.])sha1\s*\(', re.IGNORECASE),
     ("weak-sha1", "CWE-327", "ASVS V6.2.2",
      "Replace SHA-1 with SHA-256 or stronger")),
    (re.compile(r'random\.(random|randint|choice)\('),
     ("weak-random", "CWE-338", "ASVS V6.3.1",
      "For security use secrets.* instead of random.*")),
    (re.compile(r'verify\s*=\s*False'),
     ("tls-verify-off", "CWE-295", "ASVS V9.2.1",
      "Never disable TLS verification; pin or trust the CA")),
    (re.compile(r'execute\(\s*[fF]"', re.MULTILINE),
     ("sql-f-string", "CWE-89", "ASVS V5.3.4",
      "Use parameterized queries — never f-strings into execute()")),
    (re.compile(r'(?i)["\'](AKIA[0-9A-Z]{16})["\']'),
     ("secret-aws-key", "CWE-798", "ASVS V14.2.1",
      "Remove the AWS key and rotate it; load from Vault")),
    (re.compile(r'(?i)password\s*=\s*["\'][^"\']{4,}["\']'),
     ("hardcoded-password", "CWE-798", "ASVS V2.10.1",
      "Move credentials to Vault")),
    (re.compile(r'allow_origin\s*=\s*\[\s*["\']\*["\']'),
     ("cors-wildcard", "CWE-942", "ASVS V14.4.1",
      "Replace * with an explicit allow-list")),
    (re.compile(r'(?<![\w.])strcpy\s*\(', re.IGNORECASE),
     ("c-strcpy", "CWE-121", "ASVS V14.x",
      "Use snprintf/strncpy_s")),
    (re.compile(r'(?<![\w.])printf\s*\([a-zA-Z_]\w*\s*\)'),
     ("c-fmt-string", "CWE-134", "ASVS V14.x",
      'Use printf("%s", user) — never printf(user)')),
]


def scan_text(content: str, file_name: str) -> list[Finding]:
    findings: list[Finding] = []
    for idx, line in enumerate(content.splitlines(), start=1):
        # Skip obvious comment-only lines for noisy patterns
        stripped = line.lstrip()
        if stripped.startswith("#") and "noqa" in stripped:
            continue
        for pat, (rule, cwe, asvs, fix) in PATTERNS:
            if pat.search(line):
                findings.append(Finding(
                    file=file_name, line=idx, rule=rule,
                    cwe=cwe, asvs=asvs, snippet=line.strip()[:200],
                    remediation=fix,
                ))
    return findings


def scan_path(root: str) -> list[Finding]:
    p = Path(root)
    all_findings: list[Finding] = []
    targets = []
    if p.is_file():
        targets = [p]
    else:
        for ext in ("*.py", "*.js", "*.ts", "*.c", "*.cpp", "*.go", "*.rs", "*.java"):
            targets.extend(p.rglob(ext))
    for f in targets:
        try:
            all_findings.extend(scan_text(f.read_text("utf-8", errors="ignore"), str(f)))
        except Exception:
            continue
    return all_findings
