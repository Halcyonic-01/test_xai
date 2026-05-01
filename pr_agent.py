"""
XAI-SecOps PR Agent — Atlantis-style GitHub PR Security Scanner.

When a Pull Request is opened, this script:
  1. Runs Semgrep on the codebase
  2. Scores every finding with CodeLlama (or heuristic fallback)
  3. Generates full XAI explanations & recommendations
  4. Saves results to MongoDB (if configured)
  5. Posts a rich, dashboard-quality comment on the PR
"""

import os
import sys
import json
import asyncio
import httpx
from scanner.semgrep_runner import SemgrepRunner
from ai_engine.risk_scorer import RiskScorer
from explainability.explanation_generator import generate_explanation, generate_summary
from explainability.risk_factors import compute_risk_breakdown, get_risk_level
from explainability.recommendation_engine import get_recommendation


# ── Helpers ────────────────────────────────────────────

def _risk_emoji(score: float) -> str:
    if score >= 8.0:
        return "🔴"
    if score >= 6.0:
        return "🟠"
    if score >= 4.0:
        return "🟡"
    return "🟢"


def _severity_from_score(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _format_finding_comment(finding: dict, index: int) -> str:
    """Format a single finding into a rich Markdown block like the dashboard."""
    score = finding["risk_score"]
    emoji = _risk_emoji(score)
    level = get_risk_level(score)
    rule = finding["rule_id"]
    file_path = finding["file"]
    line = finding.get("line_start", "?")
    snippet = finding.get("code_snippet", "")
    message = finding.get("message", "")

    # Build risk-factor bar chart (text version of dashboard chart)
    factors = finding.get("risk_factors", {})
    contributions = compute_risk_breakdown(factors)
    factor_lines = []
    for c in contributions:
        bar_filled = int(c.value * 10)
        bar_empty = 10 - bar_filled
        bar = "█" * bar_filled + "░" * bar_empty
        factor_lines.append(f"  {c.label:<28s} [{bar}] {c.value:.1f} ({c.level})")

    # Get recommendation
    rec = get_recommendation(rule, finding.get("cwe"), snippet, finding.get("recommendation"))
    rec_title = rec.get("title", "Security Issue")
    rec_fix = rec.get("fix", "Review the code.")
    rec_refs = rec.get("references", [])

    # Build the block
    lines = [
        f"<details>",
        f"<summary>{emoji} <b>#{index} — {rule}</b> &nbsp;|&nbsp; <code>{file_path}:{line}</code> &nbsp;|&nbsp; Score: <b>{score}/10</b> ({level})</summary>",
        f"",
        f"**What was found:** {message}",
        f"",
        f"```python",
        f"{snippet}",
        f"```",
        f"",
        f"**📊 Risk Factor Breakdown:**",
        f"```",
    ]
    lines.extend(factor_lines)
    lines.append("```")
    lines.append("")

    # AI analysis
    ai = finding.get("ai_analysis")
    if ai and "Heuristic" not in ai:
        lines.append(f"**🤖 AI Analysis:** {ai}")
        lines.append("")

    # Full Explanation
    explanation = finding.get("explanation")
    if explanation:
        lines.append("**🧠 Explainability Report:**")
        lines.append("```")
        lines.append(explanation)
        lines.append("```")
        lines.append("")

    # Recommendation
    lines.append(f"**🔧 Recommendation — {rec_title}**")
    for fix_line in rec_fix.split("\n"):
        if fix_line.strip():
            lines.append(f"> {fix_line}")
    lines.append("")

    if rec_refs:
        lines.append("**📚 References:**")
        for ref in rec_refs[:2]:
            lines.append(f"- {ref}")
        lines.append("")

    lines.append("</details>")
    lines.append("")
    return "\n".join(lines)


def _format_full_comment(scored_findings: list[dict]) -> str:
    """Build the complete PR comment body."""
    total = len(scored_findings)
    scores = [f["risk_score"] for f in scored_findings]
    avg = sum(scores) / len(scores) if scores else 0
    max_score = max(scores) if scores else 0
    critical = sum(1 for s in scores if s >= 8.0)
    high = sum(1 for s in scores if 6.0 <= s < 8.0)
    medium = sum(1 for s in scores if 4.0 <= s < 6.0)
    low = sum(1 for s in scores if s < 4.0)

    # Header
    lines = [
        "## 🛡️ XAI-SecOps Security Scan Report",
        "",
    ]

    # Summary table
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| **Total Findings** | {total} |")
    lines.append(f"| **Average Risk Score** | {avg:.1f} / 10 |")
    lines.append(f"| **Highest Risk Score** | {max_score:.1f} / 10 |")
    lines.append(f"| 🔴 Critical | {critical} |")
    lines.append(f"| 🟠 High | {high} |")
    lines.append(f"| 🟡 Medium | {medium} |")
    lines.append(f"| 🟢 Low | {low} |")
    lines.append("")

    # Visual risk bar
    if total > 0:
        parts = []
        if critical:
            parts.append(f"🔴 ×{critical}")
        if high:
            parts.append(f"🟠 ×{high}")
        if medium:
            parts.append(f"🟡 ×{medium}")
        if low:
            parts.append(f"🟢 ×{low}")
        lines.append(f"**Risk Distribution:** {' &nbsp;|&nbsp; '.join(parts)}")
        lines.append("")

    # Individual findings (show ALL, not just top 5)
    lines.append("---")
    lines.append("")
    lines.append("### 📋 Detailed Findings")
    lines.append("")

    for i, finding in enumerate(scored_findings, 1):
        lines.append(_format_finding_comment(finding, i))

    # Footer
    lines.append("---")
    lines.append("*Powered by **XAI-SecOps** — Explainable AI Security Operations*")

    return "\n".join(lines)


# ── Main Agent ─────────────────────────────────────────

async def run_pr_agent():
    import uuid
    from datetime import datetime, timezone
    MongoDB = None  # optional dependency; set if available

    # 1. Read GitHub Actions environment
    github_event_path = os.environ.get("GITHUB_EVENT_PATH")
    github_token = os.environ.get("GITHUB_TOKEN")
    github_repository = os.environ.get("GITHUB_REPOSITORY")
    mongodb_uri = os.environ.get("MONGODB_URI")

    if not github_event_path or not github_token or not github_repository:
        print("Not running in a GitHub PR environment. Skipping PR comment.")
        return

    with open(github_event_path, "r") as f:
        event_data = json.load(f)

    if "pull_request" not in event_data:
        print("Event is not a pull request. Skipping.")
        return

    pr_number = event_data["pull_request"]["number"]
    scan_target = f"{github_repository}/pull/{pr_number}"
    scan_id = str(uuid.uuid4())

    # 2. Connect to MongoDB (optional)
    db = None
    if mongodb_uri:
        try:
            from database import MongoDB as _MongoDB  # local import to keep optional
            MongoDB = _MongoDB
        except ModuleNotFoundError:
            print("MONGODB_URI set but 'database' module not found; skipping MongoDB persistence.")
            MongoDB = None

    if mongodb_uri and MongoDB is not None:
        print("Connecting to MongoDB...")
        await MongoDB.connect()
        db = MongoDB.get_db()

        await db.scans.insert_one({
            "scan_id": scan_id,
            "target": scan_target,
            "status": "running",
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "avg_risk_score": 0.0,
            "created_at": datetime.now(timezone.utc),
            "completed_at": None,
            "error": None,
        })

    # 3. Run Semgrep
    print("Running Semgrep scan...")
    scanner = SemgrepRunner()
    findings = scanner.scan(".", config="auto")

    if not findings:
        print("No findings — posting clean report.")
        if db is not None:
            await db.scans.update_one(
                {"scan_id": scan_id},
                {"$set": {"status": "completed", "completed_at": datetime.now(timezone.utc)}},
            )
            await MongoDB.close()

        await post_comment(
            github_token,
            github_repository,
            pr_number,
            "## 🛡️ XAI-SecOps Security Scan Report\n\n✅ **No security vulnerabilities found!** This PR is safe to merge.\n\n---\n*Powered by **XAI-SecOps** — Explainable AI Security Operations*",
        )
        return

    # 4. Score with CodeLlama (or heuristic fallback)
    print(f"Scoring {len(findings)} findings with AI engine...")
    scorer = RiskScorer()
    scored_findings = await scorer.score_findings(findings)

    # 5. Generate explanations for every finding
    for sf in scored_findings:
        sf["explanation"] = generate_explanation(
            sf["rule_id"], sf["message"], sf["risk_score"], sf["risk_factors"],
            ai_analysis=sf.get("ai_analysis"),
        )

    # 6. Save to MongoDB
    if db is not None:
        print("Saving results to MongoDB...")
        finding_docs = []
        for sf in scored_findings:
            risk_score = sf.get("risk_score", 0)
            severity = sf.get("severity") or _severity_from_score(risk_score)
            line_start = sf.get("line_start", 1)
            line_end = sf.get("line_end", line_start)
            rec = get_recommendation(sf["rule_id"], sf.get("cwe"), sf["code_snippet"], sf.get("recommendation"))
            finding_docs.append({
                "scan_id": scan_id,
                "rule_id": sf["rule_id"],
                "severity": severity,
                "file": sf["file"],
                "line_start": line_start,
                "line_end": line_end,
                "code_snippet": sf["code_snippet"],
                "message": sf["message"],
                "risk_score": risk_score,
                "risk_level": get_risk_level(risk_score),
                "risk_factors": sf.get("risk_factors", {}),
                "explanation": sf["explanation"],
                "recommendation": rec,
                "cwe": sf.get("cwe"),
                "owasp": sf.get("owasp"),
                "ai_analysis": sf.get("ai_analysis"),
                "created_at": datetime.now(timezone.utc),
            })


        if finding_docs:
            await db.findings.insert_many(finding_docs)

        risk_scores = [f["risk_score"] for f in scored_findings]
        avg_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

        await db.scans.update_one({"scan_id": scan_id}, {"$set": {
            "status": "completed",
            "total_findings": len(finding_docs),
            "critical_count": sum(1 for s in risk_scores if s >= 8.0),
            "high_count": sum(1 for s in risk_scores if 6.0 <= s < 8.0),
            "medium_count": sum(1 for s in risk_scores if 4.0 <= s < 6.0),
            "low_count": sum(1 for s in risk_scores if s < 4.0),
            "avg_risk_score": round(avg_score, 1),
            "completed_at": datetime.now(timezone.utc),
        }})
        await MongoDB.close()

    # 6.5 Run Auto-Remediation to create fix PRs
    from auto_remediate import apply_auto_remediation
    if db is not None and finding_docs:
        print("Triggering experimental Auto-Remediation...")
        try:
            apply_auto_remediation(finding_docs)
        except Exception as e:
            print(f"Auto-remediation failed: {e}")

    # 7. Build & post the rich comment
    comment_body = _format_full_comment(scored_findings)
    print("Posting comment to GitHub PR...")
    await post_comment(github_token, github_repository, pr_number, comment_body)

    # 8. Fail CI if critical findings exist
    has_critical = any(f["risk_score"] >= 8.0 for f in scored_findings)
    if has_critical:
        print("❌ Critical findings detected — failing CI.")
        sys.exit(1)
    else:
        print("✅ No critical findings — CI passes.")


async def post_comment(token: str, repo: str, pr_number: int, body: str):
    """Post a comment to a GitHub Pull Request."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, json={"body": body})
        if response.status_code != 201:
            print(f"Failed to post comment: {response.status_code} {response.text}")
        else:
            print("Successfully posted PR comment.")


if __name__ == "__main__":
    asyncio.run(run_pr_agent())
