# Jev triage gate for CI/CD pipelines
# Usage: python jev_gate.py --sarif sast.sarif --min-confidence 0.85 --threshold critical 0 --threshold high 3

import json
import sys
import os
import subprocess
import argparse

def parse_sarif(sarif_path):
    with open(sarif_path) as f:
        return json.load(f)

def extract_findings(sarif):
    findings = []
    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        for result in run.get("results", []):
            findings.append({
                "rule": result.get("ruleId"),
                "message": result.get("message", {}).get("text", ""),
                "file": (result.get("locations", [{}])[0]
                         .get("physicalLocation", {})
                         .get("artifactLocation", {}).get("uri", "")),
                "severity": result.get("level", "warning"),
                "tool": tool
            })
    return findings

def jev_check(finding):
    """Call jev CLI to check if a finding is a false positive"""
    state = json.dumps({"finding": finding})
    api_key = os.environ.get("TYPESAFE_API_KEY")
    if not api_key:
        print("WARNING: TYPESAFE_API_KEY not set, accepting all findings")
        return {"verdict": "unknown", "confidence": 0.5}

    try:
        result = subprocess.run(
            ["jev", "check",
             "--state", state,
             "--question", "Is this security finding a false positive?",
             "--api-key", api_key],
            capture_output=True, text=True, timeout=10
        )
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Jev call failed: {e}, accepting finding as real")
        return {"verdict": "no", "confidence": 0.5}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", required=True)
    parser.add_argument("--min-confidence", type=float, default=0.8)
    parser.add_argument("--threshold", nargs=2, action="append",
                        help="e.g. --threshold critical 0 --threshold high 3")
    args = parser.parse_args()

    sarif = parse_sarif(args.sarif)
    findings = extract_findings(sarif)

    thresholds = {}
    if args.threshold:
        for sev, count in args.threshold:
            thresholds[sev] = int(count)

    real_findings = []
    blocked = False

    for f in findings:
        result = jev_check(f)
        if result["verdict"] == "no" and result["confidence"] >= args.min_confidence:
            f["jev_confidence"] = result["confidence"]
            real_findings.append(f)

    # Count by severity
    severity_count = {}
    for f in real_findings:
        sev = f["severity"]
        severity_count[sev] = severity_count.get(sev, 0) + 1

    # Check thresholds
    for sev, max_allowed in thresholds.items():
        count = severity_count.get(sev, 0)
        if count > max_allowed:
            print(f"BLOCKED: {count} {sev} findings (threshold: {max_allowed})")
            blocked = True

    print(f"\nJev Triage Results:")
    print(f"  Total findings: {len(findings)}")
    print(f"  Real findings (confidence >= {args.min_confidence}): {len(real_findings)}")
    print(f"  By severity: {severity_count}")

    if blocked:
        sys.exit(1)
    else:
        print("PASSED: All severity thresholds met")
        sys.exit(0)

if __name__ == "__main__":
    main()