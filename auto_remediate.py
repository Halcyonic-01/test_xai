import os
import subprocess
import logging
from datetime import datetime
import json
import urllib.request
import urllib.error
import re

logger = logging.getLogger(__name__)


def _comment_prefix_for_file(file_path: str) -> str:
    """Return a safe single-line comment prefix based on file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in {".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".c", ".cpp", ".cs", ".rs"}:
        return "//"
    return "#"


def _build_fix_comment_block(
    comment_prefix: str, rule_id: str, fix_text: str, vulnerable_line: str
) -> str:
    """Build a remediation block containing only code-like comment lines."""
    lines = []
    extracted_code_lines = []
    for text_line in fix_text.split("\n"):
        cleaned = text_line.strip()
        if not cleaned:
            continue

        lowered = cleaned.lower()
        if lowered.startswith(("use ", "replace:", "with:", "fix:", "avoid ", "ensure ", "should ")):
            # Skip English guidance labels/sentences.
            continue

        # Keep lines that look like actual code.
        if re.search(r"[=;{}]|->|=>", cleaned) or re.search(r"\w+\(.*\)", cleaned):
            if "cursor.execute" in lowered:
                continue
            extracted_code_lines.append(cleaned)

    if not extracted_code_lines:
        extracted_code_lines.append(vulnerable_line.strip())

    for code_line in extracted_code_lines:
        lines.append(f"{comment_prefix} {code_line}")
    return "".join(f"    {line}\n" for line in lines)


def _line_from_file(file_path: str, line_num: int) -> str:
    """Best-effort lookup of vulnerable source line for PR preview."""
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
        if 0 < line_num <= len(lines):
            return lines[line_num - 1].rstrip("\n")
    except Exception:
        pass
    return "<unable to locate vulnerable line>"


def _create_pr_via_api(branch_name: str, title: str, body: str) -> str:
    """Create PR via GitHub REST API (fallback when gh CLI is unavailable)."""
    token = os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repository:
        raise RuntimeError("Missing GITHUB_TOKEN or GITHUB_REPOSITORY for API PR creation.")

    owner, repo = repository.split("/", 1)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
    payload = json.dumps({
        "title": title,
        "body": body,
        "head": branch_name,
        "base": "main",
    }).encode("utf-8")

    req = urllib.request.Request(
        api_url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as response:
            if response.status not in (200, 201):
                raise RuntimeError(f"PR API call failed with status {response.status}")
            response_data = json.loads(response.read().decode("utf-8"))
            return response_data.get("html_url", "")
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        # Treat "already exists" as successful from an idempotency perspective.
        if exc.code == 422 and "A pull request already exists" in body_text:
            return "already_exists"
        raise RuntimeError(f"PR API call failed: HTTP {exc.code} - {body_text}") from exc


def apply_auto_remediation(findings: list[dict]):
    """
    Experimental Auto-Remediation:
    Reads the high/critical findings, attempts to apply basic fixes to the files,
    creates a new branch, commits the fixes, and raises a PR using the GitHub CLI.
    """
    if not os.getenv("GITHUB_ACTIONS"):
        msg = "Not running in GitHub Actions. Skipping auto-remediation PR creation."
        logger.info(msg)
        return {"status": "skipped", "reason": msg}

    # Filter for critical/high findings
    actionable_findings = [f for f in findings if f.get("risk_score", 0) >= 6.0]
    if not actionable_findings:
        msg = "No actionable high/critical findings for auto-remediation."
        logger.info(msg)
        return {"status": "skipped", "reason": msg}

    if not os.getenv("GITHUB_TOKEN"):
        msg = "GITHUB_TOKEN missing; cannot push branch or create remediation PR."
        logger.error(msg)
        return {"status": "failed", "reason": msg}

    branch_name = f"xaisec-auto-fix-{int(datetime.now().timestamp())}"
    
    try:
        # 1. Create a new branch
        subprocess.run(["git", "checkout", "-b", branch_name], check=True)
        
        # 2. Apply fixes (Prototype: appending fix comments above the vulnerable line)
        # In a full implementation, this would use AST or LLM to precisely replace the vulnerable code.
        files_modified = set()
        for finding in actionable_findings:
            file_path = finding["file"]
            line_num = finding["line_start"]
            rule_id = finding["rule_id"]
            rec = finding.get("recommendation", {})
            fix_text = rec.get("fix", "Review this line for vulnerabilities.")
            
            if not os.path.exists(file_path):
                continue
                
            with open(file_path, "r") as f:
                lines = f.readlines()
                
            # Insert the fix comment right above the vulnerable line
            # Format it nicely as a multi-line comment
            comment_prefix = _comment_prefix_for_file(file_path)
            vulnerable_line = ""
            if 0 < line_num <= len(lines):
                vulnerable_line = lines[line_num - 1].rstrip("\n")
            fix_comment = _build_fix_comment_block(
                comment_prefix=comment_prefix,
                rule_id=rule_id,
                fix_text=fix_text,
                vulnerable_line=vulnerable_line or "<unable to locate vulnerable line>",
            )
                
            # 0-indexed line_num
            insert_idx = max(0, line_num - 1)
            lines.insert(insert_idx, fix_comment)
            
            with open(file_path, "w") as f:
                f.writelines(lines)
            files_modified.add(file_path)

        if not files_modified:
            msg = "No files were successfully modified."
            logger.info(msg)
            return {"status": "skipped", "reason": msg}

        # 3. Commit the changes
        subprocess.run(["git", "add", "."], check=True)
        subprocess.run([
            "git",
            "-c", "user.name=github-actions[bot]",
            "-c", "user.email=github-actions[bot]@users.noreply.github.com",
            "commit",
            "-m",
            "🔒 Auto-Remediation: Apply XAI-SecOps security fixes",
        ], check=True)
        
        # 4. Push the branch
        subprocess.run(["git", "push", "origin", branch_name], check=True)
        
        # 5. Create the PR using GitHub CLI (gh)
        pr_title = "🔒 Auto-Remediation: Security Fixes from XAI-SecOps"
        pr_body = (
            "## 🛡️ XAI-SecOps Auto-Remediation\n\n"
            "This PR was automatically generated by the XAI-SecOps bot to fix critical vulnerabilities "
            "detected in the latest scan.\n\n"
            "**Please review the changes carefully before merging. These fixes were generated by an AI agent and require human verification.**\n\n"
            "### Vulnerabilities Addressed:\n"
        )
        for finding in actionable_findings:
            pr_body += f"- **{finding['rule_id']}** in `{finding['file']}:{finding['line_start']}`\n"
        pr_body += "\n### Inline Fix Comments Added\n\n"
        for finding in actionable_findings[:5]:
            file_path = finding["file"]
            line_num = finding["line_start"]
            rule_id = finding["rule_id"]
            rec = finding.get("recommendation", {})
            fix_text = rec.get("fix", "Review this line for vulnerabilities.")
            comment_prefix = _comment_prefix_for_file(file_path)
            vulnerable_line = _line_from_file(file_path, line_num)
            preview_block = _build_fix_comment_block(
                comment_prefix=comment_prefix,
                rule_id=rule_id,
                fix_text=fix_text,
                vulnerable_line=vulnerable_line,
            )
            pr_body += (
                f"#### `{rule_id}` at `{file_path}:{line_num}`\n"
                "```text\n"
                f"{preview_block}"
                "```\n\n"
            )
            
        # Prefer gh CLI when available; fall back to GitHub REST API.
        gh_available = subprocess.run(
            ["gh", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0
        if gh_available:
            subprocess.run([
                "gh", "pr", "create",
                "--title", pr_title,
                "--body", pr_body,
                "--head", branch_name,
                "--base", "main"
            ], check=True, env={**os.environ, "GH_TOKEN": os.environ.get("GITHUB_TOKEN")})
            pr_url = "(created via gh)"
        else:
            pr_url = _create_pr_via_api(branch_name, pr_title, pr_body)
        
        logger.info(f"Successfully created Auto-Remediation PR from branch {branch_name}")
        return {"status": "created", "branch": branch_name, "pr_url": pr_url}

    except subprocess.CalledProcessError as e:
        logger.error(f"Auto-Remediation failed during git/gh operations: {e}")
        return {"status": "failed", "reason": str(e)}
    except Exception as e:
        logger.error(f"Auto-Remediation failed: {e}")
        return {"status": "failed", "reason": str(e)}
