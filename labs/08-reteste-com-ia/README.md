# Lab 06 — Reteste com IA

**Objetivo:** Usar IA para planejar, executar e documentar reteste de vulnerabilidades corrigidas.

**Ferramentas:** Claude (ou qualquer LLM), scripts Python, curl/httpie.

**Fluxo:**
1. Do ticket original + diff da correção → IA gera roteiro de reteste
2. Execução automatizada dos payloads
3. IA analisa resultados e classifica correção como eficaz/parcial/inválida
4. Relatório de encerramento com evidência e cadeia de custódia

---

## Setup

```bash
cd labs/06-reteste-com-ia
pip install requests pyyaml
```

---

## 1. Geração do Plano de Reteste

### Prompt template (`toolkit/prompts/retest-plan.md`)

```markdown
You are a security engineer generating a retest plan from a fixed vulnerability ticket.

INPUT:
- Ticket JSON: {ticket}
- Fix diff: {diff}
- Original finding: {finding}

OUTPUT (JSON):
{
  "ticket_id": "...",
  "tests": [
    {
      "id": "RT-001",
      "type": "original_payload",
      "description": "...",
      "payload": "...",
      "endpoint": "...",
      "expected_result": "vulnerability_no_longer_exploitable",
      "bypass_attempts": ["variation_1", "variation_2"]
    }
  ],
  "edge_cases": ["endpoints não citados no ticket que usam o mesmo pattern"],
  "risk_areas": ["trechos do diff que podem não fechar todas as variantes"]
}
```

### Script (`scripts/generate_plan.py`)

```python
import json, subprocess, sys

ticket = json.loads(sys.argv[1])
diff = sys.argv[2]
finding = json.loads(sys.argv[3])

prompt = f"""You are a security engineer generating a retest plan.
Ticket: {json.dumps(ticket, indent=2)}
Fix Diff: {diff}
Original Finding: {json.dumps(finding, indent=2)}

Return JSON with: tests (original_payload + bypass_variations), edge_cases, risk_areas.
Tests must cover: the exact original payload, URL-encoded variant, case variation,
double-encoding, alternative HTTP methods, and correlated endpoints.

Output ONLY valid JSON.
"""

# Chamar Claude/OpenAI
result = subprocess.run(
    ["python", "-c", f"""
import anthropic
client = anthropic.Anthropic()
msg = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=2000,
    messages=[{{"role": "user", "content": {json.dumps(prompt)}}}]
)
print(msg.content[0].text)
"""],
    capture_output=True, text=True
)

plan = json.loads(result.stdout)
print(json.dumps(plan, indent=2))
```

---

## 2. Execução dos Testes

```python
# scripts/execute_retest.py
import requests, json, time
from urllib.parse import quote, urlencode

def run_test(test, base_url, headers):
    """Executa um teste de reteste e coleta evidência"""
    evidence = {
        "test_id": test["id"],
        "timestamp": time.time(),
        "payload": test["payload"],
        "variations": []
    }

    # Payload original
    for method in ["GET", "POST"]:
        if method == "GET":
            url = f"{base_url}{test['endpoint']}?{urlencode({'q': test['payload']})}"
            r = requests.get(url, headers=headers, timeout=10)
        else:
            r = requests.post(
                f"{base_url}{test['endpoint']}",
                json={"input": test["payload"]},
                headers=headers, timeout=10
            )

        evidence["variations"].append({
            "method": method,
            "status": r.status_code,
            "response_snippet": r.text[:500],
            "headers": dict(r.headers)
        })

    # Bypass variations
    for bypass in test.get("bypass_attempts", []):
        r = requests.post(
            f"{base_url}{test['endpoint']}",
            json={"input": bypass},
            headers=headers, timeout=10
        )
        evidence["variations"].append({
            "method": "POST",
            "payload_variant": bypass,
            "status": r.status_code,
            "response_snippet": r.text[:500]
        })

    return evidence
```

---

## 3. Análise do Resultado (IA)

```python
# scripts/analyze_results.py

prompt = f"""Analyze retest results against fix diff.

Fix Diff: {diff}
Retest Evidence: {evidence}

Classify the fix as one of:
- "eficaz": vulnerability fully mitigated, no bypass worked
- "parcial": some bypass variations still work
- "invalida": fix does not address the root cause

Return JSON:
{{
  "verdict": "eficaz|parcial|invalida",
  "confidence": 0.0-1.0,
  "reasoning": "cite specific code lines from diff",
  "residual_risk": "what attack surface remains",
  "recommendation": "close|reopen|partial_close"
}}
"""
```

---

## 4. Relatório de Encerramento

```markdown
# Retest Report — Ticket {ticket_id}

## Original Finding
- **Vulnerability:** SQL Injection in /api/users
- **Severity:** Critical
- **CWE:** CWE-89

## Fix Applied
- **Commit:** abc1234
- **Diff Summary:** Added parameterized queries to User.query.filter()

## Retest Results

| Test ID | Payload | Expected | Result | Status |
|---------|---------|----------|--------|--------|
| RT-001 | `' OR '1'='1` | Blocked | 400 Bad Request | ✅ |
| RT-002 | `' OR '1'='1` (URL encoded) | Blocked | 400 Bad Request | ✅ |
| RT-003 | `' UNION SELECT NULL--` | Blocked | 400 Bad Request | ✅ |
| RT-004 | `/api/admin/users?id=' OR 1=1--` (endpoint correlato) | Blocked | 400 Bad Request | ✅ |

## AI Analysis
- **Verdict:** Eficaz
- **Confidence:** 0.92
- **Reasoning:** The parameterized query at app/routes/users.py:42 prevents all tested injection vectors.
- **Residual Risk:** None — all endpoints in the user module use the same parameterized pattern.

## Decision
✅ **CLOSE** — Fix is effective. Evidence attached.

## Chain of Custody
- Retest executed by: AI-assisted pipeline, run #2841
- Date: 2026-11-23T14:30:00Z
- Evidence hash (SHA-256): e3b0c44...
```

---

## Pipeline de Reteste Automatizado

```yaml
# .github/workflows/retest.yml
name: Automated Retest
on:
  issues:
    types: [closed]

jobs:
  retest:
    if: contains(github.event.issue.labels.*.name, 'fix-applied')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate Retest Plan
        run: python scripts/generate_plan.py "$ISSUE_BODY" "$FIX_DIFF" "$FINDING"
      - name: Execute Retest
        run: python scripts/execute_retest.py --plan retest-plan.json
      - name: Analyze Results
        run: python scripts/analyze_results.py --evidence evidence.json
      - name: Post Retest Report
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('retest-report.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: report
            });
```

---

## Referências

- Slides Módulo 6 — GoHacking IA para AppSec
- [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final)