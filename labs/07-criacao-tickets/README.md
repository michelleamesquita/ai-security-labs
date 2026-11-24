# Lab 07 — Criação de Tickets com IA

**Objetivo:** Transformar findings de SAST/DAST em tickets prontos para engenharia, com schema obrigatório, enriquecimento automático e checklist de qualidade.

**Base:** Módulo 5 dos slides — "Criação e Gestão de Tickets de Segurança"

---

## Fluxo

```
Findings (SARIF/JSON)
  → [1] Normalizar + deduplicar
  → [2] Enriquecer (CWE, OWASP, CVSS, owner automático)
  → [3] Gerar ticket com schema obrigatório
  → [4] Checklist de qualidade (score ≥ 70)
  → [5] Comunicação em 3 níveis
  → [6] Criar no Jira/Azure DevOps com evidências
```

---

## Setup

```bash
cd labs/07-criacao-tickets
pip install requests pyyaml jira
```

---

## 1. Normalização e Dedup

```python
# scripts/normalize.py
import json, hashlib
from pathlib import Path

def normalize_finding(raw, tool):
    """Normaliza finding de qualquer ferramenta para schema padrão"""
    return {
        "id": generate_id(raw),
        "title": f"{raw.get('ruleId', 'Unknown')} in {raw.get('file', 'unknown')}",
        "severity": map_severity(raw.get("level", "warning")),
        "cwe": raw.get("cwe", "CWE-000"),
        "component": raw.get("file", ""),
        "line": raw.get("line", 0),
        "tool": tool,
        "fingerprint": hashlib.sha256(
            f"{raw.get('ruleId')}:{raw.get('file')}:{raw.get('line')}".encode()
        ).hexdigest()[:16]
    }

def deduplicate(findings):
    """Remove duplicados por fingerprint"""
    seen = set()
    unique = []
    for f in findings:
        fp = f["fingerprint"]
        if fp not in seen:
            seen.add(fp)
            unique.append(f)
    return unique

def map_severity(level):
    mapping = {"error": "critical", "warning": "high",
               "note": "medium", "none": "low"}
    return mapping.get(level, "medium")
```

---

## 2. Enriquecimento

```python
# scripts/enrich.py
def enrich(finding):
    """Adiciona CWE, OWASP, impacto e recomendação via IA"""

    prompt = f"""Enrich this security finding:

{json.dumps(finding, indent=2)}

Return JSON with:
- cwe: most specific CWE (e.g. CWE-89, not CWE-000)
- owasp_category: from OWASP Top 10 2021
- owasp_llm_category: from OWASP LLM Top 10 if applicable, else null
- cvss_score: 0.0-10.0
- cvss_vector: "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X"
- impact_business: 1-2 sentences on business impact
- recommendation: specific fix approach
"""
    # ... chamada LLM
    return finding

def assign_owner(finding, inventory):
    """Owner automático vindo do inventário, não da memória"""
    component = finding["component"]
    # Busca no inventário de código → time
    for pattern, team in inventory.items():
        if component.startswith(pattern):
            return team
    return "security-team"  # fallback
```

---

## 3. Geração de Ticket

```python
# scripts/generate_ticket.py
"""
Assert obrigatório antes de criar ticket:
  assert validate_schema(ticket)
  assert has_evidence(ticket)
  assert has_owner(ticket.asset)
"""

def validate_schema(ticket):
    """Valida contra ticket.schema.json"""
    import jsonschema
    schema = json.loads(Path("../../toolkit/schemas/ticket.schema.json").read_text())
    jsonschema.validate(ticket, schema)
    return True

def has_evidence(ticket):
    """Evidência obrigatória: código + payload OU request/response"""
    evidence = ticket.get("evidence", {})
    return bool(evidence.get("code") or evidence.get("request"))

def has_owner(asset):
    """Owner deve vir do inventário"""
    return bool(asset and asset.get("team"))

def create_ticket(finding, inventory):
    enriched = enrich(finding)
    owner = assign_owner(enriched, inventory)

    ticket = {
        "id": enriched["id"],
        "title": enriched["title"],
        "type": map_type(enriched),
        "severity": enriched["severity"],
        "cvss_score": enriched.get("cvss_score"),
        "cvss_vector": enriched.get("cvss_vector"),
        "cwe": enriched["cwe"],
        "owasp": enriched.get("owasp_category"),
        "owasp_llm": enriched.get("owasp_llm_category"),
        "component": enriched["component"],
        "description": enriched.get("description"),
        "reproduction_steps": enriched.get("reproduction_steps", []),
        "evidence": enriched.get("evidence", {}),
        "impact_business": enriched.get("impact_business"),
        "fix_suggestion": {
            "approach": enriched.get("recommendation"),
            "code_example": enriched.get("fix_code")
        },
        "acceptance_criteria": generate_acceptance(enriched),
        "assignee": owner,
        "sla_hours": sla_by_severity(enriched["severity"]),
        "status": "backlog"
    }

    # Asserts obrigatórios (slide 142)
    assert validate_schema(ticket), "Schema validation failed"
    assert has_evidence(ticket), "Missing evidence"
    assert has_owner({"team": owner}), "Missing owner"

    return ticket
```

---

## 4. Checklist de Qualidade

```python
# scripts/check_quality.py
def quality_check(ticket):
    """Score 0-100. < 70 = volta pro analista."""
    score = 0

    # Título: vuln + componente + CWE? (20 pts)
    if ticket["cwe"] and ticket["cwe"] != "CWE-000":
        score += 10
    if ticket["component"]:
        score += 10

    # Descrição: o que, onde, como explorar? (15 pts)
    if len(ticket.get("description", "")) >= 30:
        score += 15

    # Severidade: CVSS com vetor? (15 pts)
    if ticket.get("cvss_vector", "").startswith("CVSS:3"):
        score += 15

    # Evidência: código ou payload? (15 pts)
    if has_evidence(ticket):
        score += 15

    # Reprodução: passo a passo? (15 pts, obrigatório high+)
    if ticket.get("reproduction_steps"):
        score += 15
    elif ticket["severity"] in ("critical", "high"):
        score -= 20  # penalidade forte — high+ SEM repro steps

    # Critérios de aceite? (10 pts)
    if ticket.get("acceptance_criteria"):
        score += 10

    # Recomendação: approach, não só "arrumar"? (10 pts)
    if ticket.get("fix_suggestion", {}).get("approach"):
        score += 10

    return min(100, max(0, score))

def sla_by_severity(severity):
    return {"critical": 4, "high": 24, "medium": 72, "low": 168}.get(severity, 72)
```

---

## 5. Comunicação em 3 Níveis

### Dev (ticket do Jira)

```markdown
## SEC-2026-042 — SQL Injection em /api/users?id=

**Severidade:** Critical | **CWE-89** | **CVSS 9.8**
**Componente:** app/routes/users.py:42
**SLA:** 4h

### O que está errado
```python
User.query.filter(f'id={request.args.get("id")}')  # ← input do usuário na query
```

### Como corrigir
```python
User.query.filter(User.id == request.args.get("id"))
```

### Critérios de aceite
- [ ] Semgrep rule `sqlalchemy-sqli`: 0 findings
- [ ] Reteste: payload `1 OR 1=1--` retorna 400
- [ ] Endpoints correlatos (/api/admin/users) também parametrizados

### Evidências
- Payload: `curl "http://localhost:8080/api/users?id=1 OR 1=1--"`
- Screenshot: [anexo]
```

### Liderança (resumo semanal)

```markdown
## Status AppSec — Semana 47

### Críticos
- **SEC-042**: SQL Injection em API de usuários — expõe base inteira.
  Em fila para correção. SLA: 4h.

### Abertos esta semana: 12
- 2 críticos, 4 altos, 5 médios, 1 baixo

### Fechados: 8
- MTTR médio: 6h (críticos), 18h (altos)

### Tendência: ↓ 15% em relação à semana anterior
```

### Auditoria (relatório de conformidade)

```markdown
## Registro de Conformidade — Trimestre Q4

### SEC-2026-042
- **CWE-89:** Improper Neutralization of SQL Commands
- **OWASP:** A03:2021
- **CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Detectado:** 2026-11-20, SAST pipeline (Semgrep)
- **Corrigido:** 2026-11-20, commit def5678
- **Retestado:** 2026-11-20, pipeline automatizado run #2841
- **Fechado:** 2026-11-20
- **Tempo total:** 3.5h (dentro do SLA de 4h)
- **Revisor:** [nome]
- **Evidência:** relatório de reteste em anexo
```

---

## 6. Integração com Jira

```python
# scripts/create_in_jira.py
from jira import Jira

def create_in_jira(ticket):
    jira = Jira(url=os.environ["JIRA_URL"], token=os.environ["JIRA_TOKEN"])

    issue = jira.create_issue(
        project="APPSEC",
        summary=ticket["title"],
        description=format_for_jira(ticket),
        issuetype={"name": "Bug" if ticket["severity"] != "info" else "Task"},
        priority=map_jira_priority(ticket["severity"]),
        labels=["appsec", ticket["cwe"], f"severity:{ticket['severity']}"],
        attachments=collect_evidence(ticket)
    )

    # Registra quem gerou, revisou e aprovou
    issue.add_comment(f"Ticket gerado por IA. Schema validado. Score de qualidade: {ticket['_quality_score']}")
    return issue.key
```

---

## Pipeline Completo

```yaml
name: SAST → Tickets
on:
  schedule:
    - cron: '0 6 * * 1'  # toda segunda 6am
  workflow_dispatch:

jobs:
  findings-to-tickets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run SAST + DAST
        run: |
          semgrep --config p/security-audit --sarif -o sast.sarif .
          zap-baseline.py -t https://staging.example.com -J dast.json

      - name: Normalize + Dedup
        run: python scripts/normalize.py sast.sarif dast.json > normalized.json

      - name: Enrich + Generate Tickets
        run: python scripts/generate_tickets.py normalized.json > tickets.json

      - name: Quality Check
        run: python scripts/check_quality.py tickets.json

      - name: Create in Jira
        run: python scripts/create_in_jira.py tickets.json
        env:
          JIRA_URL: ${{ secrets.JIRA_URL }}
          JIRA_TOKEN: ${{ secrets.JIRA_TOKEN }}
```