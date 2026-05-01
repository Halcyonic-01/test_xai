from __future__ import annotations

"""
Recommendation Engine — Maps vulnerabilities to actionable fix suggestions.

Provides specific, code-level fix recommendations based on CWE, rule ID,
and the code context of each finding.
"""

import logging
import re

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────
# Fix recommendation database
# ──────────────────────────────────────────

RECOMMENDATIONS = {
    # SQL Injection
    "CWE-89": {
        "title": "SQL Injection Prevention",
        "description": "User input is being concatenated directly into SQL queries.",
        "fix": (
            "Use parameterized queries (prepared statements) instead of string formatting.\n"
            "Replace: cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
            "With:    cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ],
    },
    # Command Injection
    "CWE-78": {
        "title": "OS Command Injection Prevention",
        "description": "User input is passed to shell commands without sanitization.",
        "fix": (
            "Avoid shell=True and os.system(). Use subprocess with a list of arguments.\n"
            "Replace: subprocess.run(f'ls {user_input}', shell=True)\n"
            "With:    subprocess.run(['ls', user_input], shell=False)"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
        ],
    },
    # XSS
    "CWE-79": {
        "title": "Cross-Site Scripting (XSS) Prevention",
        "description": "User input is rendered in HTML without proper escaping.",
        "fix": (
            "Always escape user input before rendering in HTML.\n"
            "Use template engine auto-escaping (Jinja2, React JSX).\n"
            "Apply Content-Security-Policy headers."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ],
    },
    # Hardcoded Credentials
    "CWE-798": {
        "title": "Remove Hardcoded Credentials",
        "description": "Secrets are hardcoded in source code.",
        "fix": (
            "Move secrets to environment variables or a secrets manager.\n"
            "Replace: password = \"my_secret_password\"\n"
            "With:    password = os.environ.get(\"DB_PASSWORD\")\n"
            "Use tools like AWS Secrets Manager, HashiCorp Vault, or .env files."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
        ],
    },
    # Insecure Deserialization
    "CWE-502": {
        "title": "Insecure Deserialization Prevention",
        "description": "Untrusted data is being deserialized using an unsafe method.",
        "fix": (
            "Avoid pickle, yaml.load(), and eval() with untrusted data.\n"
            "Replace: data = pickle.load(file)\n"
            "With:    data = json.load(file)\n"
            "If pickle is required, use hmac to verify data integrity first."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
        ],
    },
    # Weak Crypto
    "CWE-328": {
        "title": "Replace Weak Hash Functions",
        "description": "Using cryptographically weak hash functions (MD5, SHA1).",
        "fix": (
            "Use SHA-256 or stronger for integrity checks.\n"
            "For passwords, use bcrypt, scrypt, or argon2.\n"
            "Replace: hashlib.md5(data)\n"
            "With:    hashlib.sha256(data)"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
        ],
    },
    # Path Traversal
    "CWE-22": {
        "title": "Path Traversal Prevention",
        "description": "User input is used in file paths without validation.",
        "fix": (
            "Validate and sanitize file paths. Use os.path.realpath() and check\n"
            "that the resolved path is within the expected directory.\n"
            "base = os.path.realpath('/safe/directory')\n"
            "path = os.path.realpath(os.path.join(base, user_input))\n"
            "if not path.startswith(base): raise ValueError('Path traversal!')"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
        ],
    },
    # SSRF
    "CWE-918": {
        "title": "Server-Side Request Forgery (SSRF) Prevention",
        "description": "User-controlled URLs are fetched without validation.",
        "fix": (
            "Validate and whitelist allowed URLs/domains.\n"
            "Block requests to internal IPs (127.0.0.1, 10.x, 192.168.x).\n"
            "Use an allowlist of permitted external services."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
        ],
    },
}

# Rule ID patterns → CWE mapping for Semgrep rules that don't include CWE
RULE_TO_CWE = {
    r"sql.injection|sqli": "CWE-89",
    r"command.injection|os.system|subprocess": "CWE-78",
    r"xss|cross.site": "CWE-79",
    r"hardcoded.secret|hardcoded.password|credential": "CWE-798",
    r"pickle|deserialization|yaml.load": "CWE-502",
    r"md5|sha1|weak.hash|weak.crypto": "CWE-328",
    r"path.traversal|directory.traversal": "CWE-22",
    r"ssrf|server.side.request": "CWE-918",
}


def get_recommendation(
    rule_id: str,
    cwe: str | None = None,
    code_snippet: str = "",
    ai_recommendation: str | None = None,
) -> dict:
    """
    Get a fix recommendation for a finding.

    Args:
        rule_id: Semgrep rule ID.
        cwe: CWE identifier (e.g., "CWE-89").
        code_snippet: The vulnerable code.
        ai_recommendation: Optional recommendation from CodeLlama.

    Returns:
        Dict with title, description, fix, references.
    """
    # Try direct CWE lookup
    recommendation = None

    if cwe:
        # Normalize CWE format: "CWE-89: SQL Injection" → "CWE-89"
        cwe_id = cwe.split(":")[0].strip()
        recommendation = RECOMMENDATIONS.get(cwe_id)

    # Try rule ID pattern matching
    if not recommendation:
        for pattern, cwe_key in RULE_TO_CWE.items():
            if re.search(pattern, rule_id, re.IGNORECASE):
                recommendation = RECOMMENDATIONS.get(cwe_key)
                break

    # Build result
    if recommendation:
        result = {**recommendation}
        # Append AI recommendation if available
        if ai_recommendation:
            result["ai_suggestion"] = ai_recommendation
        return result

    # Fallback: generic recommendation
    result = {
        "title": "Security Issue Detected",
        "description": f"Rule '{rule_id}' flagged a potential security issue.",
        "fix": ai_recommendation or "Review the flagged code and apply appropriate security controls.",
        "references": ["https://cheatsheetseries.owasp.org/"],
    }
    return result
