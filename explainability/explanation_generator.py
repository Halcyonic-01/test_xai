from __future__ import annotations

"""
Explanation Generator — Produces human-readable explanations for findings.

Turns raw risk factor scores into natural language that developers can understand,
explaining *why* a finding is dangerous and *what* makes it high-risk.
"""

import logging
from explainability.risk_factors import (
    compute_risk_breakdown,
    get_risk_level,
    FactorContribution,
)

logger = logging.getLogger(__name__)


def generate_explanation(
    rule_id: str,
    message: str,
    risk_score: float,
    risk_factors: dict,
    ai_analysis: str | None = None,
) -> str:
    """
    Generate a full human-readable explanation for a security finding.

    Args:
        rule_id: Semgrep rule ID.
        message: Semgrep's finding message.
        risk_score: Computed risk score (0–10).
        risk_factors: Dict of factor name → value.
        ai_analysis: Optional CodeLlama analysis text.

    Returns:
        Multi-line explanation string.
    """
    risk_level = get_risk_level(risk_score)
    contributions = compute_risk_breakdown(risk_factors)

    lines = []

    # ── Header ──
    lines.append(f"🔒 Security Finding: {rule_id}")
    lines.append(f"   Risk Level: {risk_level} ({risk_score}/10)")
    lines.append("")

    # ── What was found ──
    lines.append(f"📋 What: {message}")
    lines.append("")

    # ── Why it's risky (factor breakdown) ──
    lines.append("📊 Why this risk score?")
    for contrib in contributions:
        bar = _score_bar(contrib.value)
        lines.append(
            f"   {contrib.label:.<30s} {bar} {contrib.value:.1f} ({contrib.level})"
        )
        lines.append(f"      ↳ {contrib.description}")
    lines.append("")

    # ── Top risk drivers ──
    top_factors = [c for c in contributions if c.level == "high"]
    if top_factors:
        lines.append("⚠️  Key Risk Drivers:")
        for factor in top_factors:
            lines.append(f"   • {factor.label}: {factor.description}")
        lines.append("")

    # ── AI Analysis (if available) ──
    if ai_analysis and "Heuristic" not in ai_analysis:
        lines.append(f"🤖 AI Analysis: {ai_analysis}")
        lines.append("")

    return "\n".join(lines)


def generate_summary(findings_count: int, risk_scores: list[float]) -> str:
    """
    Generate a scan summary.

    Args:
        findings_count: Total number of findings.
        risk_scores: List of risk scores from all findings.

    Returns:
        Summary string.
    """
    if not risk_scores:
        return "✅ No security issues found!"

    avg_score = sum(risk_scores) / len(risk_scores)
    max_score = max(risk_scores)
    critical = sum(1 for s in risk_scores if s >= 8.0)
    high = sum(1 for s in risk_scores if 6.0 <= s < 8.0)
    medium = sum(1 for s in risk_scores if 4.0 <= s < 6.0)
    low = sum(1 for s in risk_scores if s < 4.0)

    return (
        f"📊 Scan Summary\n"
        f"   Total findings: {findings_count}\n"
        f"   Average risk score: {avg_score:.1f}/10\n"
        f"   Highest risk score: {max_score:.1f}/10\n"
        f"   ├─ 🔴 Critical: {critical}\n"
        f"   ├─ 🟠 High: {high}\n"
        f"   ├─ 🟡 Medium: {medium}\n"
        f"   └─ 🟢 Low: {low}"
    )


def _score_bar(value: float, width: int = 10) -> str:
    """Create a visual bar for a 0–1 score."""
    filled = int(value * width)
    empty = width - filled
    return f"[{'█' * filled}{'░' * empty}]"
