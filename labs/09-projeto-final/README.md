# Lab 07 — Projeto Final Integrado

**Objetivo:** Exercício end-to-end: threat model → code review → tickets → correção simulada → reteste → métricas → governança.

**Entrada:** Aplicação vulnerável, documentação mínima, repositório, findings.

**Saída:** Relatório final com riscos, evidências, decisões, métricas e próximos passos.

---

## Estrutura de Entregáveis

```
/appsec-ai-toolkit
  prompts/
    threat-model.md
    code-review.md
    ticket-quality.md
    retest-plan.md
  schemas/
    finding.schema.json
    ticket.schema.json
  reports/
    threat-model.md
    vulnerability-tickets.csv
    retest-report.md
    final-report.md
  metrics/
    dashboard.json
  governance/
    adoption-plan.md
```

---

## Fluxo End-to-End

```
APLICAÇÃO VULNERÁVEL
        ↓
[1] THREAT MODELING (STRIDE / STRIDE-GPT)
        ↓
[2] CODE REVIEW (PR/Diff com foco em segurança)
        ↓
[3] TICKETS (Findings → tickets completos e priorizados)
        ↓
[4] CORREÇÃO SIMULADA (Sugestão de fix via IA)
        ↓
[5] RETESTE (Plano, execução, validação)
        ↓
[6] MÉTRICAS (MTTR, cobertura, qualidade)
        ↓
[7] GOVERNANÇA (Plano de adoção, ROI, riscos)
        ↓
RELATÓRIO FINAL
```

---

## 1. Threat Modeling

Usar STRIDE-GPT ou Claude:

```bash
# Prompt em toolkit/prompts/threat-model.md
cat > threat-model-input.json << 'EOF'
{
  "app_name": "Vulnerable E-Commerce API",
  "description": "REST API for e-commerce with user auth, product catalog, cart, and payments. Flask + SQLAlchemy + JWT.",
  "components": [
    "POST /auth/login",
    "GET /api/products",
    "POST /api/cart",
    "POST /api/checkout",
    "GET /api/users/{id}",
    "GET /api/admin/orders"
  ],
  "data_flows": [
    "User → Login → JWT Token",
    "User → Cart → Checkout → Payment Gateway",
    "Admin → Admin API → Database"
  ],
  "trust_boundaries": [
    "Internet ↔ API Gateway",
    "API ↔ Database",
    "API ↔ Payment Gateway (external)"
  ]
}
EOF

# Gerar threat model com Claude
python scripts/threat_model.py threat-model-input.json > reports/threat-model.md
```

---

## 2. Code Review

```bash
# Prompt em toolkit/prompts/code-review.md
gh pr diff $PR_NUMBER > pr.diff

python scripts/code_review.py pr.diff \
  --context "E-commerce API, critical paths: auth, checkout, admin" \
  --output reports/code-review.md
```

Critérios de qualidade do ticket:
- Título: vulnerabilidade + componente + CWE
- Descrição: o que, onde, como explorar
- Severidade: CVSS justificado
- Evidência: trecho de código + payload
- Recomendação: o que mudar, com exemplo

---

## 3. Geração de Tickets

```python
# scripts/generate_tickets.py
ticket = {
    "id": "SEC-2026-042",
    "title": "SQL Injection in /api/users?id= — CWE-89",
    "severity": "critical",
    "cvss": 9.8,
    "component": "app/routes/users.py:42",
    "description": "User ID parameter is directly interpolated into SQL query without parameterization",
    "evidence": {
        "code": 'User.query.filter(f\'id={request.args.get("id")}\')',
        "payload": "1 OR 1=1--",
        "impact": "Full database exposure, authentication bypass"
    },
    "fix_suggestion": {
        "approach": "parameterized_query",
        "code": 'User.query.filter(User.id == request.args.get("id"))',
        "diff": "- User.query.filter(f'id={request.args.get(\"id\")}')\n+ User.query.filter(User.id == request.args.get(\"id\"))"
    },
    "acceptance_criteria": [
        "All user-facing queries use parameterized SQLAlchemy methods",
        "Semgrep rule sqlalchemy-sqli returns zero findings",
        "Manual retest confirms original payload returns 400"
    ]
}
```

---

## 4. Simulação de Correção

```python
# scripts/simulate_fix.py
# Aplica sugestão de fix, gera novo commit, cria PR
subprocess.run(["git", "checkout", "-b", f"fix/{ticket['id']}"])
# Aplica diff
Path(ticket["component"]).write_text(fixed_code)
subprocess.run(["git", "commit", "-am", f"fix: {ticket['title']}"])
subprocess.run(["gh", "pr", "create",
    "--title", f"Fix: {ticket['title']}",
    "--body", f"Closes #{ticket['id']}\n\n{ticket['fix_suggestion']['approach']}",
    "--base", "main"])
```

---

## 5. Reteste (reusa Lab 06)

```bash
python ../06-reteste-com-ia/scripts/generate_plan.py \
  "$(cat ticket-SEC-2026-042.json)" \
  "$(git diff main...fix/SEC-2026-042)" \
  "$(cat finding.json)" \
  > retest-plan.json

python ../06-reteste-com-ia/scripts/execute_retest.py \
  --plan retest-plan.json \
  --base-url https://staging-api.example.com

python ../06-reteste-com-ia/scripts/analyze_results.py \
  --evidence evidence.json \
  --diff "$(git diff main...fix/SEC-2026-042)" \
  > retest-report.md
```

---

## 6. Métricas

```json
{
  "program_metrics": {
    "total_findings": 12,
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 1,
    "fixed": 8,
    "accepted_risk": 2,
    "false_positive": 2,
    "mttr_hours": {
      "critical": 4,
      "high": 24,
      "medium": 72
    },
    "coverage_pct": 94,
    "retest_sla_pct": 100,
    "ai_triage_accuracy": 0.88
  },
  "ai_governance": {
    "prompts_versioned": true,
    "human_review_critical": true,
    "data_policy_compliant": true,
    "audit_trail_complete": true
  }
}
```

---

## 7. Governança e Plano de Adoção

### Como vender adoção sem vender mágica

| Sem governança | Com governança |
|---------------|----------------|
| Cada time usa IA de um jeito | Casos de uso aprovados, dados permitidos, modelos autorizados |
| Sem métrica de qualidade | Métricas comparando antes/depois |
| Dados sensíveis em prompts | Logs, revisão humana, trilha de auditoria |
| Automação sem owner | Owner definido para prompt, integração e decisão |

### Indicadores de sucesso

| Métrica | Como medir | Meta |
|---------|-----------|------|
| Tempo de triagem | Mediana antes/depois da IA | -30% a -50% |
| Qualidade do ticket | Tickets aceitos sem devolução / total | ≥ 90% |
| Cobertura de revisão | PRs críticos com revisão IA + humana | 100% crítico |
| Reteste em dia | Tickets dentro do SLA | ≥ 95% |
| Uso seguro de IA | Execuções em conformidade | 100% |

---

## Avaliação do Projeto

| Critério | Peso |
|----------|------|
| Qualidade técnica do threat model | 20% |
| Precisão dos tickets (severidade, CWE, evidência) | 25% |
| Cobertura do reteste (original + bypass + edge cases) | 20% |
| Rastreabilidade (cadeia de custódia) | 15% |
| Métricas e governança | 10% |
| Clareza da comunicação (relatório executivo) | 10% |

---

## Referências

- Slides Módulo 7 — GoHacking IA para AppSec
- [OWASP SAMM v2](https://owaspsamm.org)
- [NIST SSDF (SP 800-218)](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [SLSA Framework](https://slsa.dev)