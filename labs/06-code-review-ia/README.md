# Lab 06 — Code Review com IA

**Objetivo:** Revisar PRs e diffs de segurança usando IA, com schema obrigatório, validação por ferramenta determinística e decisão documentada.

**Base:** Módulo 4 dos slides — "Revisão de Código com IA"

---

## Fluxo

```
PR / Diff
  → [1] LLM analisa com schema obrigatório (CWE, evidência, impacto, confiança, correção)
  → [2] Semgrep/CodeQL validam achados deterministicamente
  → [3] IA gera sugestão de correção + teste de regressão
  → [4] Decisão documentada: entra na fila ou é descartado + motivo
  → [5] Comunicação adaptada: dev / liderança / auditoria
```

---

## Setup

```bash
cd labs/06-code-review-ia
pip install anthropic requests pyyaml
```

---

## 1. Executar Code Review

```bash
# Pega diff de um PR
gh pr diff $PR_NUMBER > pr.diff

# Roda análise com schema obrigatório
python scripts/code_review.py pr.diff \
  --context "API de e-commerce Flask + SQLAlchemy. Rotas críticas: /auth, /checkout, /admin" \
  --output review-result.json
```

### Script (`scripts/code_review.py`)

```python
import json, subprocess, sys, os
from pathlib import Path

DIFF = sys.argv[1]
CONTEXT = os.environ.get("REVIEW_CONTEXT", "")
OUTPUT = sys.argv[2] if len(sys.argv) > 2 else "review-result.json"

prompt = f"""You are a senior AppSec engineer reviewing a pull request diff.

CONTEXT: {CONTEXT}

DIFF:
{Path(DIFF).read_text()}

Return JSON array of findings. Each finding MUST have ALL fields:
{{
  "cwe": "CWE-XXX",
  "title": "vulnerability type + component",
  "severity": "critical|high|medium|low",
  "file": "path:line",
  "evidence": "exact code snippet from diff",
  "impact": "what attacker can do with this",
  "confidence": 0.0-1.0,
  "fix_suggestion": "specific code change",
  "regression_test": "how to verify the fix works"
}}

RULES:
- Only report security issues (not style/formatting)
- Every finding MUST cite exact lines from the diff
- Confidence < 0.7: mark severity one level down
- If no security issues found, return empty array []
"""
# ... chamada LLM
```

---

## 2. Validar com Semgrep

```bash
# Validação determinística
semgrep --config p/security-audit \
        --config p/owasp-top-ten \
        --config ../toolkit/policies/semgrep-ai-agent.yml \
        --sarif -o semgrep-validation.sarif .

# Cruza achados da IA com Semgrep
python scripts/cross_validate.py review-result.json semgrep-validation.sarif
```

```python
# scripts/cross_validate.py
"""Cruza findings da IA com resultados do Semgrep.
   IA + Semgrep concordam → alta confiança
   IA diz que existe, Semgrep não pegou → possível falso positivo ou blind spot da ferramenta
   Semgrep pegou, IA não → blind spot do modelo"""

def cross_validate(ai_findings, semgrep_sarif):
    semgrep_rules = {r["ruleId"] for run in semgrep_sarif["runs"]
                     for r in run["results"]}

    for f in ai_findings:
        f["semgrep_match"] = any(
            rule in str(f.get("evidence", ""))
            for rule in semgrep_rules
        )
        if f["semgrep_match"]:
            f["confidence"] = min(1.0, f["confidence"] + 0.15)
        else:
            f["confidence"] = max(0.3, f["confidence"] - 0.1)
    return ai_findings
```

---

## 3. Documento de Decisão

Para cada finding, a IA decide e documenta:

```json
{
  "finding_id": "CR-001",
  "decision": "queue|discard|needs_human",
  "reason": "Por que entrou na fila ou foi descartado",
  "queue_priority": 1,
  "human_review_required": false
}
```

Critérios:
- **Queue**: severity ≥ high E confidence ≥ 0.8 E semgrep_match = true
- **Needs human**: severity ≥ high MAS (confidence < 0.8 OU semgrep_match = false)
- **Discard**: severity ≤ low OU confidence < 0.6

---

## 4. Comunicação em 3 Níveis

O mesmo finding, 3 públicos diferentes:

### Para Dev (técnico, acionável)

```markdown
## SQL Injection em /api/users?id= — CWE-89

**Arquivo:** `app/routes/users.py:42`
**Severidade:** Critical (CVSS 9.8)

**Problema:**
```python
# ❌ Linha 42 — input do usuário interpolado direto na query
User.query.filter(f'id={request.args.get("id")}')
```

**Correção:**
```python
# ✅ Query parametrizada
User.query.filter(User.id == request.args.get("id"))
```

**Como testar:**
```bash
curl "http://localhost:8080/api/users?id=1%20OR%201=1--"
# Antes: retornava todos os usuários
# Depois: deve retornar 400 Bad Request
```
```

### Para Liderança (risco, impacto no negócio)

```markdown
## Risco Crítico — Exposição de Dados via SQL Injection

**Impacto no negócio:** Atacante pode extrair toda a base de usuários
(incluindo emails, hashes de senha, dados de pagamento).

**Tempo estimado de correção:** 2h (trocar f-string por query parametrizada)

**Risco de não corrigir:** Vazamento de dados = multa LGPD + perda de reputação

**SLA:** 24h para critical
```

### Para Auditoria (conformidade, rastreabilidade)

```markdown
## Registro de Conformidade — SEC-2026-042

**CWE-89:** Improper Neutralization of Special Elements used in SQL Command
**OWASP:** A03:2021 Injection | LLM01:2025 Prompt Injection (se aplicável)
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Evidência:** Commit abc1234, arquivo app/routes/users.py:42
**Correção aplicada:** Commit def5678 — query parametrizada
**Validação:** Semgrep rule python.sqlalchemy.security — 0 findings pós-fix
**Reteste:** RT-001 a RT-004 — todos passaram (relatório em anexo)

**Cadeia de custódia:**
- Detectado por: IA code review (modelo Claude Sonnet 4) + Semgrep
- Revisado por: [nome], [data]
- Corrigido por: [nome], commit def5678
- Retestado por: pipeline automatizado, run #2841
```

---

## 5. Métricas de Code Review

| Métrica | Como medir | Meta |
|---------|-----------|------|
| Precisão dos achados | Achados confirmados ÷ total | ≥ 80% |
| Cobertura de PRs críticos | PRs sensíveis revisados ÷ total | 100% |
| Tempo até primeiro sinal | Mediana entre abertura do PR e comentário | ≤ 10 min |
| Taxa de falso positivo | Comentários descartados ÷ emitidos | Tendência de queda |
| Correção com teste | Sugestões aceitas com teste ÷ aceitas | ≥ 90% |

---

## GitHub Actions Bot de Review

```yaml
name: AI Code Review
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: AI Security Review
        run: |
          python scripts/code_review.py \
            <(git diff origin/${{ github.base_ref }}...HEAD) \
            --output review.json

      - name: Post Findings as PR Comments
        run: python scripts/post_review.py review.json ${{ github.event.pull_request.number }}

      - name: Gate — block if critical
        run: |
          critical=$(python -c "import json; d=json.load(open('review.json')); print(sum(1 for f in d if f['severity']=='critical'))")
          if [ "$critical" -gt 0 ]; then
            echo "BLOCKED: $critical critical findings"
            exit 1
          fi
```

---

## O que usar em cada ponto (slide 125)

| Componente | Função |
|-----------|--------|
| **GitHub/GitLab** | Entrada natural: PR, diff, comentários, status checks |
| **Semgrep / CodeQL** | Regras determinísticas — reduzem achados sem evidência |
| **LLM com RAG** | Recupera padrões internos, guidelines, decisões anteriores |
| **SARIF** | Formato comum para normalizar e integrar |
| **Score por risco** | Combina severidade, alcance, ativo, exposição, confiança |
| **Human-in-the-loop** | Aprovação final humana em crítico e alto |