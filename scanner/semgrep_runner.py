from __future__ import annotations

"""
Semgrep Runner — Invokes Semgrep CLI and parses results.

Supports:
  - Scanning local directories
  - Using auto config or custom rules
  - Parsing JSON output into structured findings
"""

import json
import subprocess
import logging
from pathlib import Path
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class SemgrepFinding:
    """A single finding from Semgrep scan."""

    rule_id: str
    severity: str  # ERROR, WARNING, INFO
    file: str
    line_start: int
    line_end: int
    code_snippet: str
    message: str
    cwe: str | None = None
    owasp: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class SemgrepRunner:
    """Wrapper around Semgrep CLI for running security scans."""

    def __init__(self, custom_rules_path: str | None = None):
        """
        Args:
            custom_rules_path: Path to custom Semgrep rules directory/file.
                             If None, uses Semgrep's auto config.
        """
        self.custom_rules_path = custom_rules_path

    def scan(self, target_path: str, config: str = "auto") -> list[SemgrepFinding]:
        """
        Run Semgrep scan on the target path.

        Args:
            target_path: Path to the directory or file to scan.
            config: Semgrep config — "auto" for default rules, or path to custom rules.

        Returns:
            List of SemgrepFinding objects.
        """
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        # Build the command
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--no-git-ignore",
            "--config", config,
        ]

        # Add custom rules if specified
        if self.custom_rules_path:
            cmd.extend(["--config", self.custom_rules_path])

        cmd.append(str(target))

        logger.info(f"Running Semgrep: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            # Semgrep returns exit code 1 when findings exist, which is expected
            if result.returncode not in (0, 1):
                logger.error(f"Semgrep error (exit {result.returncode}): {result.stderr}")
                raise RuntimeError(f"Semgrep failed: {result.stderr[:500]}")

            return self._parse_output(result.stdout)

        except subprocess.TimeoutExpired:
            raise RuntimeError("Semgrep scan timed out after 5 minutes")
        except FileNotFoundError:
            raise RuntimeError(
                "Semgrep CLI not found. Install it with: pip install semgrep"
            )

    def _parse_output(self, raw_json: str) -> list[SemgrepFinding]:
        """Parse Semgrep JSON output into structured findings."""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
            return []

        findings = []
        results = data.get("results", [])

        for result in results:
            # Extract CWE and OWASP from metadata
            metadata = result.get("extra", {}).get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            owasp_list = metadata.get("owasp", [])

            finding = SemgrepFinding(
                rule_id=result.get("check_id", "unknown"),
                severity=result.get("extra", {}).get("severity", "INFO"),
                file=result.get("path", "unknown"),
                line_start=result.get("start", {}).get("line", 0),
                line_end=result.get("end", {}).get("line", 0),
                code_snippet=result.get("extra", {}).get("lines", ""),
                message=result.get("extra", {}).get("message", ""),
                cwe=cwe_list[0] if cwe_list else None,
                owasp=owasp_list[0] if owasp_list else None,
                metadata=metadata,
            )
            findings.append(finding)

        logger.info(f"Semgrep found {len(findings)} issues")
        return findings

    @staticmethod
    def get_file_context(file_path: str, line: int, context_lines: int = 5) -> str:
        """
        Extract code context around a specific line in a file.
        Used to provide CodeLlama with surrounding context.

        Args:
            file_path: Path to the source file.
            line: The line number of interest (1-indexed).
            context_lines: Number of lines before and after to include.

        Returns:
            String containing the code context with line numbers.
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return ""

            lines = path.read_text().splitlines()
            start = max(0, line - context_lines - 1)
            end = min(len(lines), line + context_lines)

            context_parts = []
            for i in range(start, end):
                marker = " >>> " if i == line - 1 else "     "
                context_parts.append(f"{marker}{i + 1:4d} | {lines[i]}")

            return "\n".join(context_parts)

        except Exception as e:
            logger.warning(f"Could not read file context: {e}")
            return ""
