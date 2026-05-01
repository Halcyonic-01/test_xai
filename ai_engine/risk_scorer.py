from __future__ import annotations

"""
Risk Scorer — Orchestrates the full analysis pipeline.

Flow: Semgrep Finding → Code Context → CodeLlama → Risk Score + Factors
"""

import logging
from scanner.semgrep_runner import SemgrepFinding, SemgrepRunner
from ai_engine.codellama_client import CodeLlamaClient

logger = logging.getLogger(__name__)


class RiskScorer:
    """Orchestrates vulnerability analysis: Semgrep → CodeLlama → risk score."""

    def __init__(self):
        self.codellama = CodeLlamaClient()

    async def score_finding(self, finding: SemgrepFinding) -> dict:
        """
        Analyze a single Semgrep finding and produce a risk score with factors.

        Args:
            finding: A SemgrepFinding from the scanner.

        Returns:
            Dict with risk_score, risk_factors, analysis, recommendation.
        """
        # Get surrounding code context for better AI analysis
        context = SemgrepRunner.get_file_context(
            finding.file, finding.line_start, context_lines=10
        )

        # Determine vulnerability type string
        vuln_type = finding.cwe or finding.rule_id

        # Send to CodeLlama (or fallback to heuristic)
        result = await self.codellama.analyze_vulnerability(
            code_snippet=finding.code_snippet,
            vulnerability_type=vuln_type,
            message=finding.message,
            file_path=finding.file,
            context=context,
        )

        return {
            "risk_score": result["risk_score"],
            "risk_factors": result["factors"],
            "ai_analysis": result["analysis"],
            "recommendation": result["recommendation"],
        }

    async def score_findings(self, findings: list[SemgrepFinding]) -> list[dict]:
        """
        Score multiple findings. Returns list of enriched finding dicts.

        Each result merges the original finding data with AI analysis.
        """
        scored = []

        for finding in findings:
            try:
                score_result = await self.score_finding(finding)

                enriched = {
                    **finding.to_dict(),
                    **score_result,
                }
                scored.append(enriched)

            except Exception as e:
                logger.error(f"Failed to score finding {finding.rule_id}: {e}")
                # Include the finding with a default score on error
                enriched = {
                    **finding.to_dict(),
                    "risk_score": 5.0,
                    "risk_factors": {
                        "severity_weight": 0.5,
                        "exploitability": 0.5,
                        "data_sensitivity": 0.5,
                        "exposure": 0.5,
                        "fix_complexity": 0.5,
                    },
                    "ai_analysis": f"Analysis error: {str(e)}",
                    "recommendation": "Manual review recommended.",
                }
                scored.append(enriched)

        # Sort by risk score descending
        scored.sort(key=lambda x: x["risk_score"], reverse=True)

        return scored
