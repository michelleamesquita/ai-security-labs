# Batch triage script using Jev
# Usage: python batch_triage.py findings.json --min-confidence 0.8

import json
import subprocess
import sys
import os
import argparse
from pathlib import Path

def triage_finding(finding, api_key, min_confidence=0.8):
    state = json.dumps({"finding": finding})

    try:
        result = subprocess.run(
            ["jev", "check",
             "--state", state,
             "--question", "Is this security finding a false positive?",
             "--min-confidence", str(min_confidence),
             "--api-key", api_key],
            capture_output=True, text=True, timeout=10
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"verdict": "unknown", "confidence": 0.0, "error": str(e)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", help="JSON file with findings array")
    parser.add_argument("--min-confidence", type=float, default=0.8)
    parser.add_argument("--output", default="triaged.json")
    args = parser.parse_args()

    api_key = os.environ.get("TYPESAFE_API_KEY")
    if not api_key:
        print("ERROR: TYPESAFE_API_KEY not set")
        sys.exit(1)

    findings = json.loads(Path(args.input_file).read_text())

    print(f"Triaging {len(findings)} findings...")

    for i, f in enumerate(findings):
        result = triage_finding(f, api_key, args.min_confidence)
        f["jev_verdict"] = result.get("verdict", "unknown")
        f["jev_confidence"] = result.get("confidence", 0.0)
        if i % 10 == 0:
            print(f"  Progress: {i}/{len(findings)}")

    # Separate
    real = [f for f in findings
            if f["jev_verdict"] == "no" and f["jev_confidence"] >= args.min_confidence]
    fp = [f for f in findings
          if f["jev_verdict"] == "yes" and f["jev_confidence"] >= args.min_confidence]
    review = [f for f in findings
              if f["jev_confidence"] < args.min_confidence or f["jev_verdict"] == "unknown"]

    output = {
        "total": len(findings),
        "real": real,
        "false_positive": fp,
        "needs_review": review,
        "summary": {
            "total": len(findings),
            "real_count": len(real),
            "fp_count": len(fp),
            "review_count": len(review)
        }
    }

    Path(args.output).write_text(json.dumps(output, indent=2))
    print(f"\nResults saved to {args.output}")
    print(f"  Real: {len(real)} | False Positive: {len(fp)} | Needs Review: {len(review)}")

if __name__ == "__main__":
    main()