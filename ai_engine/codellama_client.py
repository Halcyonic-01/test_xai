from __future__ import annotations

"""
CodeLlama Client — Interface to CodeLlama via Ollama API.

Sends code snippets + vulnerability context to CodeLlama and parses
the response for risk analysis. Includes fallback heuristic scoring
when Ollama is unavailable.
"""

import json
import logging
import re
import httpx

from config import settings

logger = logging.getLogger(__name__)


class CodeLlamaClient:
    """Client for interacting with CodeLlama through Ollama."""

    def __init__(self):
        self.base_url = settings.ollama_base_url
        self.model = settings.codellama_model
        self._available: bool | None = None

    async def is_available(self) -> bool:
        """Check if Ollama is running and the model is loaded."""
        if self._available is not None:
            return self._available

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                if resp.status_code == 200:
                    models = [m["name"] for m in resp.json().get("models", [])]
                    self._available = any(self.model in m for m in models)
                    if not self._available:
                        logger.warning(
                            f"Ollama is running but model '{self.model}' not found. "
                            f"Available: {models}. Pull it with: ollama pull {self.model}"
                        )
                    return self._available
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")

        self._available = False
        return False

    async def analyze_vulnerability(
        self,
        code_snippet: str,
        vulnerability_type: str,
        message: str,
        file_path: str,
        context: str = "",
    ) -> dict:
        """
        Send a vulnerability to CodeLlama for contextual analysis.

        Args:
            code_snippet: The vulnerable code.
            vulnerability_type: Semgrep rule ID or CWE.
            message: Semgrep's description of the issue.
            file_path: Path to the file containing the vulnerability.
            context: Surrounding code context.

        Returns:
            Dict with keys: risk_score (float), analysis (str), factors (dict)
        """
        if not await self.is_available():
            logger.info("CodeLlama unavailable — using heuristic fallback")
            return self._heuristic_analysis(code_snippet, vulnerability_type, message)

        prompt = self._build_prompt(
            code_snippet, vulnerability_type, message, file_path, context
        )

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.1,  # Low temp for consistent analysis
                            "num_predict": 1024,
                        },
                    },
                )

                if resp.status_code != 200:
                    logger.error(f"Ollama returned {resp.status_code}: {resp.text[:200]}")
                    return self._heuristic_analysis(code_snippet, vulnerability_type, message)

                response_text = resp.json().get("response", "")
                return self._parse_response(response_text, code_snippet, vulnerability_type, message)

        except Exception as e:
            logger.error(f"CodeLlama analysis failed: {e}")
            return self._heuristic_analysis(code_snippet, vulnerability_type, message)

    def _build_prompt(
        self,
        code_snippet: str,
        vulnerability_type: str,
        message: str,
        file_path: str,
        context: str,
    ) -> str:
        """Build the analysis prompt for CodeLlama."""
        return f"""You are a security expert analyzing code vulnerabilities. Analyze the following finding and provide a structured risk assessment.

## Vulnerability Details
- **Type**: {vulnerability_type}
- **File**: {file_path}
- **Scanner Message**: {message}

## Vulnerable Code
```
{code_snippet}
```

## Surrounding Context
```
{context}
```

## Your Task
Provide a JSON response with EXACTLY this structure:
{{
    "risk_score": <float 0.0 to 10.0>,
    "severity_weight": <float 0.0 to 1.0>,
    "exploitability": <float 0.0 to 1.0>,
    "data_sensitivity": <float 0.0 to 1.0>,
    "exposure": <float 0.0 to 1.0>,
    "fix_complexity": <float 0.0 to 1.0>,
    "analysis": "<brief explanation of the risk>",
    "recommendation": "<specific fix suggestion>"
}}

Scoring guidelines:
- severity_weight: How severe is this vulnerability class? (e.g., RCE=1.0, info leak=0.3)
- exploitability: How easy is it to exploit this specific instance?
- data_sensitivity: Does this code handle sensitive data (passwords, PII, tokens)?
- exposure: Is this in a public-facing endpoint, API handler, or internal utility?
- fix_complexity: How hard is it to fix? (simple param query=0.2, architectural=0.9)

Respond ONLY with the JSON object, no additional text."""

    def _parse_response(
        self,
        response_text: str,
        code_snippet: str,
        vulnerability_type: str,
        message: str,
    ) -> dict:
        """Parse CodeLlama's response into a structured dict."""
        try:
            # Try to extract JSON from the response
            json_match = re.search(r"\{[^{}]*\}", response_text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())

                # Validate and clamp values
                return {
                    "risk_score": max(0.0, min(10.0, float(data.get("risk_score", 5.0)))),
                    "factors": {
                        "severity_weight": max(0.0, min(1.0, float(data.get("severity_weight", 0.5)))),
                        "exploitability": max(0.0, min(1.0, float(data.get("exploitability", 0.5)))),
                        "data_sensitivity": max(0.0, min(1.0, float(data.get("data_sensitivity", 0.5)))),
                        "exposure": max(0.0, min(1.0, float(data.get("exposure", 0.5)))),
                        "fix_complexity": max(0.0, min(1.0, float(data.get("fix_complexity", 0.5)))),
                    },
                    "analysis": data.get("analysis", ""),
                    "recommendation": data.get("recommendation", ""),
                }
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse CodeLlama response: {e}")

        # Fall back to heuristic if parsing fails
        return self._heuristic_analysis(code_snippet, vulnerability_type, message)

    @staticmethod
    def _heuristic_analysis(code_snippet: str, vulnerability_type: str, message: str) -> dict:
        """
        Heuristic-based fallback when CodeLlama is unavailable.
        Uses rule-based scoring based on vulnerability type and code patterns.
        """
        code_lower = code_snippet.lower()
        vuln_lower = vulnerability_type.lower()

        # ── Base severity by vulnerability type ──
        severity_map = {
            "sql": 0.9, "injection": 0.9, "rce": 1.0, "command": 0.85,
            "xss": 0.7, "cross-site": 0.7, "deserialization": 0.8,
            "pickle": 0.8, "hardcoded": 0.7, "secret": 0.75, "credential": 0.8,
            "crypto": 0.5, "hash": 0.45, "md5": 0.5, "sha1": 0.45,
            "path-traversal": 0.7, "ssrf": 0.8, "xxe": 0.75,
        }
        severity_weight = 0.5
        for keyword, score in severity_map.items():
            if keyword in vuln_lower or keyword in message.lower():
                severity_weight = max(severity_weight, score)

        # ── Exploitability: check for user input indicators ──
        input_indicators = ["request", "input", "param", "argv", "stdin", "form", "query", "body"]
        exploitability = 0.3
        for indicator in input_indicators:
            if indicator in code_lower:
                exploitability = 0.8
                break

        # ── Data sensitivity: check for sensitive data keywords ──
        sensitive_keywords = ["password", "secret", "token", "key", "credit", "ssn", "email", "auth"]
        data_sensitivity = 0.3
        for keyword in sensitive_keywords:
            if keyword in code_lower:
                data_sensitivity = 0.8
                break

        # ── Exposure: check if it's in a route handler ──
        exposure_indicators = ["@app.", "@router.", "def get", "def post", "def put", "def delete",
                               "func handler", "http.Handle", "express.", "app.get", "app.post"]
        exposure = 0.4
        for indicator in exposure_indicators:
            if indicator in code_snippet:
                exposure = 0.85
                break

        # ── Fix complexity ──
        fix_complexity = 0.3  # Most fixes are straightforward

        # ── Compute weighted risk score ──
        weights = {
            "severity_weight": 0.30,
            "exploitability": 0.25,
            "data_sensitivity": 0.20,
            "exposure": 0.15,
            "fix_complexity": 0.10,
        }
        factors = {
            "severity_weight": round(severity_weight, 2),
            "exploitability": round(exploitability, 2),
            "data_sensitivity": round(data_sensitivity, 2),
            "exposure": round(exposure, 2),
            "fix_complexity": round(fix_complexity, 2),
        }

        weighted_sum = sum(factors[k] * weights[k] for k in weights)
        risk_score = round(weighted_sum * 10, 1)  # Scale to 0-10

        return {
            "risk_score": risk_score,
            "factors": factors,
            "analysis": f"Heuristic analysis: {vulnerability_type} detected. "
                        f"Severity={severity_weight:.1f}, Exploitability={exploitability:.1f}.",
            "recommendation": "Review the flagged code and apply the scanner's suggested fix.",
        }
