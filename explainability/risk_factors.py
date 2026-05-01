"""
Risk Factors — SHAP-like explainability for security risk scores.

Computes individual factor contributions and generates
a human-readable breakdown of *why* a finding is risky.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# Factor definitions with weights and descriptions
FACTOR_DEFINITIONS = {
    "severity_weight": {
        "label": "Vulnerability Severity",
        "weight": 0.30,
        "description": "How severe is this class of vulnerability (e.g., RCE vs info leak)?",
        "low": "Low-severity issue with minimal impact",
        "medium": "Moderate severity — could lead to data exposure",
        "high": "Critical severity — could lead to system compromise",
    },
    "exploitability": {
        "label": "Exploitability",
        "weight": 0.25,
        "description": "How easy is it for an attacker to exploit this specific instance?",
        "low": "Requires complex preconditions to exploit",
        "medium": "Exploitable with moderate effort",
        "high": "Easily exploitable — user input flows directly to vulnerable sink",
    },
    "data_sensitivity": {
        "label": "Data Sensitivity",
        "weight": 0.20,
        "description": "Does this code handle sensitive data (credentials, PII, tokens)?",
        "low": "Handles non-sensitive data only",
        "medium": "May process semi-sensitive information",
        "high": "Directly handles passwords, tokens, PII, or financial data",
    },
    "exposure": {
        "label": "Attack Surface Exposure",
        "weight": 0.15,
        "description": "Is this code reachable from external inputs (API endpoints, public routes)?",
        "low": "Internal utility, not directly reachable",
        "medium": "Indirectly reachable via internal services",
        "high": "Directly exposed in a public API endpoint or route handler",
    },
    "fix_complexity": {
        "label": "Fix Complexity",
        "weight": 0.10,
        "description": "How difficult is it to remediate this vulnerability?",
        "low": "Simple fix — parameter substitution or config change",
        "medium": "Moderate — requires refactoring a function or adding validation",
        "high": "Complex — requires architectural changes",
    },
}


@dataclass
class FactorContribution:
    """A single factor's contribution to the overall risk score."""

    name: str
    label: str
    value: float          # Raw factor value (0.0 – 1.0)
    weight: float         # Factor weight in the model
    contribution: float   # value × weight (actual contribution to score)
    level: str            # "low", "medium", "high"
    description: str      # Human-readable reason for this level

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "label": self.label,
            "value": round(self.value, 2),
            "weight": round(self.weight, 2),
            "contribution": round(self.contribution, 3),
            "level": self.level,
            "description": self.description,
        }


def compute_risk_breakdown(risk_factors: dict) -> list[FactorContribution]:
    """
    Compute SHAP-like factor contributions from raw risk factor scores.

    Args:
        risk_factors: Dict with keys matching FACTOR_DEFINITIONS
                     (severity_weight, exploitability, etc.) and float values 0–1.

    Returns:
        List of FactorContribution objects, sorted by contribution descending.
    """
    contributions = []

    for factor_name, definition in FACTOR_DEFINITIONS.items():
        value = risk_factors.get(factor_name, 0.5)
        weight = definition["weight"]
        contribution = value * weight

        # Determine level
        if value < 0.4:
            level = "low"
        elif value < 0.7:
            level = "medium"
        else:
            level = "high"

        contributions.append(
            FactorContribution(
                name=factor_name,
                label=definition["label"],
                value=value,
                weight=weight,
                contribution=contribution,
                level=level,
                description=definition[level],
            )
        )

    # Sort by contribution (highest impact first)
    contributions.sort(key=lambda c: c.contribution, reverse=True)

    return contributions


def compute_risk_score(risk_factors: dict) -> float:
    """
    Compute the final risk score (0–10) from factor values.

    This is the weighted sum of all factors, scaled to 0–10.
    """
    weighted_sum = 0.0
    for factor_name, definition in FACTOR_DEFINITIONS.items():
        value = risk_factors.get(factor_name, 0.5)
        weighted_sum += value * definition["weight"]

    return round(weighted_sum * 10, 1)


def get_risk_level(score: float) -> str:
    """Convert a 0–10 risk score to a human-readable level."""
    if score >= 8.0:
        return "CRITICAL"
    elif score >= 6.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score >= 2.0:
        return "LOW"
    else:
        return "INFO"
