#!/usr/bin/env python3
"""
parse_results.py
Aggregates security scan results from multiple scanners into a unified report.
"""

import json
import argparse
import os
from datetime import datetime, timezone
from pathlib import Path


def parse_semgrep(path: Path) -> dict:
    """Parse Semgrep JSON output."""
    try:
        with open(path) as f:
            data = json.load(f)
        findings = data.get("results", [])
        return {
            "total": len(findings),
            "findings": [
                {
                    "rule": f.get("check_id", "unknown"),
                    "severity": f.get("extra", {}).get("severity", "unknown"),
                    "file": f.get("path", "unknown"),
                    "line": f.get("start", {}).get("line", 0),
                    "message": f.get("extra", {}).get("message", ""),
                }
                for f in findings
            ],
        }
    except (FileNotFoundError, json.JSONDecodeError):
        return {"total": 0, "findings": [], "error": "Results not found or malformed"}


def parse_bandit(path: Path) -> dict:
    """Parse Bandit JSON output."""
    try:
        with open(path) as f:
            data = json.load(f)
        findings = data.get("results", [])
        return {
            "total": len(findings),
            "high": sum(1 for f in findings if f.get("issue_severity") == "HIGH"),
            "medium": sum(1 for f in findings if f.get("issue_severity") == "MEDIUM"),
            "low": sum(1 for f in findings if f.get("issue_severity") == "LOW"),
            "findings": [
                {
                    "test_id": f.get("test_id"),
                    "test_name": f.get("test_name"),
                    "severity": f.get("issue_severity"),
                    "confidence": f.get("issue_confidence"),
                    "file": f.get("filename"),
                    "line": f.get("line_number"),
                    "message": f.get("issue_text"),
                }
                for f in findings
            ],
        }
    except (FileNotFoundError, json.JSONDecodeError):
        return {"total": 0, "findings": [], "error": "Results not found or malformed"}


def parse_betterleaks(path: Path) -> dict:
    """Parse Betterleaks JSON output."""
    try:
        with open(path) as f:
            data = json.load(f)
        findings = data if isinstance(data, list) else data.get("findings", [])
        return {
            "total": len(findings),
            "findings": [
                {
                    "type": f.get("type", "secret"),
                    "file": f.get("file", "unknown"),
                    "line": f.get("line", 0),
                    "description": f.get("description", ""),
                }
                for f in findings
            ],
        }
    except (FileNotFoundError, json.JSONDecodeError):
        return {"total": 0, "findings": [], "error": "Results not found or malformed"}


def parse_pip_audit(path: Path) -> dict:
    """Parse pip-audit JSON output."""
    try:
        with open(path) as f:
            data = json.load(f)
        vulns = data.get("dependencies", [])
        vulnerable = [d for d in vulns if d.get("vulns")]
        total_vulns = sum(len(d.get("vulns", [])) for d in vulnerable)
        return {
            "total": total_vulns,
            "affected_packages": len(vulnerable),
            "findings": [
                {
                    "package": d.get("name"),
                    "version": d.get("version"),
                    "vulns": [
                        {
                            "id": v.get("id"),
                            "description": v.get("description", "")[:200],
                            "fix_versions": v.get("fix_versions", []),
                        }
                        for v in d.get("vulns", [])
                    ],
                }
                for d in vulnerable
            ],
        }
    except (FileNotFoundError, json.JSONDecodeError):
        return {"total": 0, "findings": [], "error": "Results not found or malformed"}


def parse_checkov(path: Path) -> dict:
    """Parse Checkov JSON output."""
    try:
        with open(path) as f:
            data = json.load(f)
        # Checkov can return a list or dict depending on frameworks scanned
        if isinstance(data, list):
            failed = sum(len(d.get("results", {}).get("failed_checks", [])) for d in data)
            passed = sum(len(d.get("results", {}).get("passed_checks", [])) for d in data)
        else:
            failed = len(data.get("results", {}).get("failed_checks", []))
            passed = len(data.get("results", {}).get("passed_checks", []))
        return {
            "total": failed,
            "passed": passed,
            "failed": failed,
        }
    except (FileNotFoundError, json.JSONDecodeError):
        return {"total": 0, "findings": [], "error": "Results not found or malformed"}


def main():
    parser = argparse.ArgumentParser(description="Aggregate security scan results")
    parser.add_argument("--results-dir", required=True, help="Directory containing scan result artifacts")
    parser.add_argument("--repo", required=True, help="Repository name (owner/repo)")
    parser.add_argument("--run-id", required=True, help="GitHub Actions run ID")
    parser.add_argument("--branch", required=True, help="Branch name")
    parser.add_argument("--output", required=True, help="Output file path")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)

    # Locate result files — artifacts are downloaded into subdirectories
    def find_result(name):
        for p in results_dir.rglob(name):
            return p
        return results_dir / name  # fallback

    report = {
        "metadata": {
            "repo": args.repo,
            "run_id": args.run_id,
            "branch": args.branch,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "summary": {},
        "semgrep": parse_semgrep(find_result("semgrep.json")),
        "bandit": parse_bandit(find_result("bandit.json")),
        "betterleaks": parse_betterleaks(find_result("betterleaks.json")),
        "pip_audit": parse_pip_audit(find_result("pip-audit.json")),
        "checkov": parse_checkov(find_result("checkov.json")),
    }

    # Build summary
    report["summary"] = {
        "total_findings": sum(
            report[tool].get("total", 0)
            for tool in ["semgrep", "bandit", "betterleaks", "pip_audit", "checkov"]
        ),
        "secrets_detected": report["betterleaks"].get("total", 0) > 0,
        "vulnerable_dependencies": report["pip_audit"].get("affected_packages", 0),
        "iac_failures": report["checkov"].get("failed", 0),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Aggregated results written to {args.output}")
    print(f"Total findings: {report['summary']['total_findings']}")
    if report["summary"]["secrets_detected"]:
        print("WARNING: Secrets detected — review Betterleaks results immediately")


if __name__ == "__main__":
    main()
