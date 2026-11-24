# Lab 05 — SAST + AI Triage Pipeline

**Objetivo:** Pipeline DevSecOps que usa IA para classificar, deduplicar e priorizar findings de SAST, SCA e IaC automaticamente.

**Ferramentas:** Semgrep, Trivy, Checkov, DefectDojo, LLM (via OpenRouter/OpenAI)

---

## Arquitetura do Pipeline

```
PLAN → CODE → BUILD → TEST → RELEASE → OPERATE
                          ↑
                    SAST · SCA · IaC
                          ↓
                    SARIF unificado
                          ↓
                 ╔═══ AI TRIAGE ═══╗
                 ║  1. Dedup       ║
                 ║  2. Classify    ║
                 ║  3. Prioritize  ║
                 ║  4. Filter FP   ║
                 ╚═════════════════╝
                          ↓
                 DefectDojo / Dashboard
```

---

## Setup

```bash
cd labs/05-sast-ai-triage

# Instalar scanners
pip install semgrep
brew install trivy checkov  # macOS

# Python deps
pip install pyyaml requests sarif-tools
```

---

## Pipeline script

```python
# scripts/triage_pipeline.py
"""
Pipeline:
1. Roda SAST (Semgrep), SCA (Trivy), IaC (Checkov)
2. Converte outputs para SARIF unificado
3. Chama LLM para triagem contextual
4. Publica métricas
"""
import subprocess, json, os
from pathlib import Path

REPO = os.getenv("REPO_PATH", ".")
OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY")

def run_semgrep():
    """SAST — análise estática de código"""
    subprocess.run([
        "semgrep", "--config", "p/security-audit",
        "--config", "./policies/semgrep/",
        "--sarif", "-o", "sast.sarif",
        REPO
    ])

def run_trivy():
    """SCA — vulnerabilidades em dependências"""
    subprocess.run([
        "trivy", "fs", "--format", "sarif",
        "-o", "sca.sarif", "."
    ])

def run_checkov():
    """IaC — misconfigurations em infra"""
    subprocess.run([
        "checkov", "-d", "./infra",
        "-o", "sarif", "--output-file-path", "iac.sarif"
    ])

def merge_sarif(files, output="merged.sarif"):
    """Une múltiplos SARIF em um único"""
    # sarif-tools merge
    subprocess.run(["sarif", "merge"] + files + ["--output", output])

def llm_triage(sarif_path):
    """Camada de decisão: LLM avalia cada finding"""
    with open(sarif_path) as f:
        sarif = json.load(f)

    findings = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            finding = {
                "rule": result.get("ruleId"),
                "message": result.get("message", {}).get("text"),
                "file": result.get("locations", [{}])[0]
                    .get("physicalLocation", {})
                    .get("artifactLocation", {}).get("uri"),
                "severity": result.get("level")
            }
            findings.append(finding)

    # Batch: envia para LLM classificar
    prompt = f"""Analyze these security findings and for each one return:
- is_false_positive: true/false
- severity: critical/high/medium/low/info
- cwe: CWE ID if applicable
- reasoning: one sentence

Findings:
{json.dumps(findings[:50], indent=2)}  # batch de 50
"""
    # ... chamada OpenRouter/OpenAI
    return findings

if __name__ == "__main__":
    run_semgrep()
    run_trivy()
    run_checkov()
    merge_sarif(["sast.sarif", "sca.sarif", "iac.sarif"])
    triaged = llm_triage("merged.sarif")
    # Publica métricas
    print(json.dumps({"total": len(triaged), "triaged": True}))
```

---

## GitHub Actions Workflow

```yaml
# .github/workflows/security-triage.yml
name: Security Scan + AI Triage
on: [pull_request]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: SAST + SCA + IaC
        run: |
          pip install semgrep sarif-tools
          python scripts/triage_pipeline.py
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}

      - name: Upload to DefectDojo
        run: |
          curl -X POST "$DOJO_URL/api/v2/import-scan/" \
            -H "Authorization: Token $DOJO_TOKEN" \
            -F "file=@merged.sarif" \
            -F "scan_type=SARIF" \
            -F "engagement=$DOJO_ENGAGEMENT" \
            -F "verified=false" \
            -F "active=true"

      - name: Gate — bloqueia se critical > N
        run: |
          critical_count=$(python -c "
          import json
          with open('merged.sarif') as f:
              d = json.load(f)
          count = sum(1 for r in d['runs'][0]['results']
                      if r.get('level') == 'error')
          print(count)
          ")
          if [ "$critical_count" -gt 0 ]; then
            echo "BLOCKED: $critical_count critical findings"
            exit 1
          fi
```

---

## Modelo de Maturidade (N0-N4)

| Nível | O que acontece | IA agrega? |
|-------|---------------|------------|
| **N0 — Ad-hoc** | Sem inventário, scan esporádico | ❌ |
| **N1 — Reativo** | Scanner no CI, resultado ignorado | ❌ |
| **N2 — Consistente** | Processo igual entre squads, SARIF padronizado | ✅ Começa aqui |
| **N3 — Medido** | MTTR, cobertura, recorrência guiam priorização | ✅✅ |
| **N4 — Otimizado** | Triagem, política e reteste assistidos, com auditoria | ✅✅✅ |

---

## Métricas-chave

```python
# metrics/publish.py
metrics = {
    "findings_total": 234,
    "findings_deduped": 189,
    "false_positive_rate": 0.12,
    "mttr_hours": 48,
    "coverage_pct": 94,
    "critical_blocked": 3,
    "high_accepted_as_risk": 12
}
```

## Score de Risco Contextual (3 eixos)

O slide pede: exploitabilidade + exposição + criticidade do ativo. O LLM avalia cada eixo e o score final é o produto:

```python
# scripts/risk_score.py
def contextual_risk_score(finding, app_context):
    """
    Score = Exploitabilidade × Exposição × Criticidade
    Cada eixo: 0.0-1.0. Score final: 0.0-1.0
    """
    prompt = f"""Score this finding on 3 axes (0.0-1.0):

Finding: {json.dumps(finding, indent=2)}
Context: {app_context}

Return JSON:
{{
  "exploitability": 0.0-1.0,  // TEMP CHECK: quão fácil é explorar? precisa de auth? WAF? sanitization?
  "exposure": 0.0-1.0,        // SPACE CHECK: endpoint público? internet-facing?攻撃 surface ampla?
  "asset_criticality": 0.0-1.0, // ASSET CHECK: lida com PII? pagamentos? admin? dados sensíveis?
  "composite_score": 0.0-1.0,   // exploitability × exposure × asset_criticality
  "reasoning": "why these scores"
}}
"""
    # ... chamada LLM
    scores = json.loads(llm_response)
    return scores
```

| Eixo | Pergunta-chave |
|------|---------------|
| **Exploitabilidade** | Precisa de auth? Tem WAF? Input é sanitizado? |
| **Exposição** | Endpoint público? Internet-facing? Quantos usuários alcança? |
| **Criticidade do ativo** | Lida com PII? Pagamentos? Dados admin? |

---

## Amostragem Manual (30 itens)

O slide pede taxa de falso positivo em amostra manual de 30 itens:

```python
# scripts/sample_audit.py
def sample_and_audit(findings, n=30):
    """
    Pega amostra aleatória estratificada por severidade,
    envia pra revisão humana, calcula taxa de FP.
    """
    import random

    # Estratificada: proporcional à severidade
    by_severity = {}
    for f in findings:
        by_severity.setdefault(f["severity"], []).append(f)

    sample = []
    for sev, items in by_severity.items():
        k = max(1, int(n * len(items) / len(findings)))
        sample.extend(random.sample(items, min(k, len(items))))

    # Auditoria: cada item precisa de voto humano
    print(f"Amostra de {len(sample)} itens para revisão manual:")
    for f in sample:
        # Aqui um humano classificaria como real/fp
        # Registramos a decisão
        pass

    # Cálculo da taxa
    fp_count = sum(1 for f in sample if f.get("human_verdict") == "false_positive")
    fp_rate = fp_count / len(sample)

    print(f"Taxa de falso positivo (amostra): {fp_rate:.1%}")
    print(f"Intervalo de confiança (95%): {fp_rate - 1.96*sqrt(...)} - {fp_rate + 1.96*sqrt(...)}")
    return fp_rate
```

---

## Documento de Decisão de Triagem

Para cada finding, decisão explícita e rastreável:

```python
# scripts/triage_decision.py
def decide(finding):
    """
    Portão 1: Bloquear (critical + score > 0.8 + confidence > 0.9)
    Portão 2: Abrir ticket automático (high + score > 0.6)
    Portão 3: Backlog (medium)
    Portão 4: Registrar apenas (low/info)
    Portão 5: Descartar (confidence < 0.5)
    """
    score = finding["risk_score"]["composite_score"]
    sev = finding["severity"]
    conf = finding.get("ai_confidence", 0.5)

    if sev == "critical" and score > 0.8 and conf > 0.9:
        return {"action": "BLOCK_MERGE", "reason": "Critical + high confidence + high exposure"}
    elif sev in ("critical", "high") and score > 0.6:
        return {"action": "AUTO_TICKET", "reason": f"High severity with risk score {score:.2f}"}
    elif sev == "medium":
        return {"action": "BACKLOG", "reason": "Medium severity — backlog for triage"}
    elif conf < 0.5:
        return {"action": "DISCARD", "reason": f"Low confidence ({conf:.2f}) — likely noise"}
    else:
        return {"action": "LOG_ONLY", "reason": "Low severity — for metrics only"}
```

**Justificativa dos thresholds:**
- **0.9 confidence** para bloquear: falso bloqueio custa velocidade do time; só bloqueamos quando IA + score concordam fortemente
- **0.6 score** para ticket: abaixo disso, exposição ou criticidade não justificam ação imediata
- **0.5 confidence** para descartar: abaixo disso, IA está essencialmente chutando

---

## Triagem com Jev (alternativa ao LLM tradicional)

Troque o LLM genérico pelo Jev — mais rápido, mais barato, decisão tipada:

```python
# scripts/jev_sast_triage.py
import subprocess, json, os

API_KEY = os.environ["TYPESAFE_API_KEY"]

def jev_triage_finding(finding):
    """Jev decide: false positive? qual severidade? qual CWE?"""

    state = json.dumps({
        "rule": finding["rule"],
        "message": finding["message"],
        "code": finding.get("code_snippet", ""),
        "file": finding["file"],
        "line": finding["line"]
    })

    # 1. É falso positivo?
    fp = subprocess.run([
        "jev", "check",
        "--state", state,
        "--question", "Is this security finding a false positive? "
                       "Consider: is user input reachable? Is there sanitization?",
        "--api-key", API_KEY
    ], capture_output=True, text=True)
    fp_result = json.loads(fp.stdout)

    if fp_result["verdict"] == "yes" and fp_result["confidence"] > 0.8:
        return {"action": "DISCARD", "reason": f"Jev FP confidence {fp_result['confidence']:.2f}"}

    # 2. Qual severidade? (usa jev_score)
    sev = subprocess.run([
        "jev", "score",
        "--state", state,
        "--scale", "1:Informational, 2:Low, 3:Medium, 4:High, 5:Critical",
        "--api-key", API_KEY
    ], capture_output=True, text=True)
    sev_result = json.loads(sev.stdout)

    severity_map = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
    severity = severity_map.get(sev_result["score"], "medium")

    # 3. Classificar tipo (usa jev_classify)
    cls = subprocess.run([
        "jev", "classify",
        "--state", state,
        "--classes", "SQL Injection, XSS, SSRF, Path Traversal, "
                      "Authentication Bypass, Misconfiguration, "
                      "Exposed Secret, Vulnerable Dependency, False Positive",
        "--api-key", API_KEY
    ], capture_output=True, text=True)
    cls_result = json.loads(cls.stdout)

    return {
        "action": "AUTO_TICKET" if severity in ("critical", "high") else "BACKLOG",
        "severity": severity,
        "severity_confidence": sev_result["confidence"],
        "classification": cls_result["label"],
        "classification_confidence": cls_result["confidence"],
        "fp_confidence": fp_result["confidence"]
    }

# Batch: 500 findings em ~1.6 min (Jev) vs ~25 min (LLM tradicional)
def batch_triage_jev(findings):
    results = []
    for i, f in enumerate(findings):
        result = jev_triage_finding(f)
        f.update(result)
        results.append(f)
        if i % 50 == 0:
            print(f"Jev triage: {i}/{len(findings)} ({i*200}ms)")
    return results
```

**Comparação de custo × velocidade (500 findings):**

| Métrica | LLM tradicional (GPT-4o-mini) | Jev (System One) |
|---------|------------------------------|-------------------|
| Tempo total | ~25 min | ~1.6 min |
| Custo estimado | ~$0.50 | ~$0.05 |
| Formato da resposta | Texto livre (precisa parse) | JSON tipado (yes/no, score, label) |
| Confiança | "Alta confiança" (qualitativo) | 0.94 (quantitativo, threshold programável) |

---

## Referências

- [OWASP DSOMM](https://dsomm.owasp.org/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [DefectDojo](https://www.defectdojo.org)
- [Semgrep Registry](https://semgrep.dev/r)
- [Jev CLI](https://github.com/dipendra-sharma/jev-cli)
- [Jev Security Benchmarks](https://github.com/Gaurav-Gosain/jev-sec-bench)