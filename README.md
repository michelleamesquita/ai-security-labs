# AI Security Labs 🔐🤖

**Laboratórios práticos de AI Security & AppSec com IA — do prompt injection ao pipeline DevSecOps autônomo.**

Este repositório é o complemento hands-on do treinamento **IA para AppSec (GoHacking)**, criado por [Michelle Mesquita](https://michelleamesquita.medium.com) e Magno Logan. Cada lab cobre um cenário real de ataque ou defesa em sistemas com IA, com ferramentas open source que você roda na sua máquina.

---

## Estrutura

```
ai-security-labs/
├── labs/
│   ├── 01-prompt-injection/        # Promptfoo: red team contra LLMs
│   ├── 02-agent-red-teaming/       # ARTEX + PentAGI: pentest autônomo
│   ├── 03-jev-appsec/              # Jev (TypeSafe): triagem e scanner de vulns
│   ├── 04-claude-code-security/    # Skills scanner + MCP scanner + JAM (rules)
│   │   └── jam/                    # Joint Analysis Module: pipeline 4 estágios
│   ├── 05-sast-ai-triage/          # Pipeline SAST/DAST/SCA + triagem com IA/Jev
│   ├── 06-code-review-ia/          # Revisão de PR/diff com schema + 3 níveis de comunicação
│   ├── 07-criacao-tickets/         # Findings → tickets com schema, checklist e Jira
│   ├── 08-reteste-com-ia/          # Reteste automatizado: plano, bypass, validação
│   ├── 09-projeto-final/           # Projeto end-to-end: threat model → reteste → governança
│   └── 10-hermes-security/         # Harness Hermes: superfície de ataque + hardening
├── toolkit/
│   ├── prompts/                    # 8 prompts versionados (inclui comunicação 3 níveis)
│   ├── schemas/                    # Schemas JSON para findings e tickets
│   ├── scripts/                    # Scripts de integração (Jev gate, batch triage)
│   └── policies/                   # Policy-as-Code (Semgrep rules para agentes)
└── docs/                           # Referências, OWASP mapping, glossário
```

---

## Labs × Módulos do Treinamento

| Lab | Módulo | Atividade "Mão na Massa" |
|-----|--------|--------------------------|
| 01 — Prompt Injection | Mód. 2 (Vulnerabilidades) | Red team contra LLM com promptfoo |
| 02 — Agent Red Teaming | Mód. 2 (Vulnerabilidades) | ARTEX + PentAGI — ataque e detecção blue team |
| 03 — Jev AppSec | Extra | Modelo de decisão para triagem — não está nos slides |
| 04 — Claude Code Security | Mód. 4 (Skills & MCP) | Scan de Skills + MCP servers — 6 padrões de ataque + **JAM (4 estágios)** |
| 05 — SAST + AI Triage | **Mód. 3 — Mão na Massa** | Pipeline com Semgrep+Trivy, score 3 eixos, amostra de 30, decisão documentada + **triagem com Jev** |
| 06 — Code Review com IA | **Mód. 4 — Mão na Massa** | Revisão de PR com schema, Semgrep cross-validation, comunicação 3 níveis |
| 07 — Criação de Tickets | **Mód. 5 — Mão na Massa** | Normalizar, enriquecer, gerar ticket, checklist qualidade, Jira |
| 08 — Reteste com IA | **Mód. 6 — Mão na Massa** | Plano de reteste, payloads bypass, análise de diff, relatório |
| 09 — Projeto Final | **Mód. 7 — Mão na Massa** | Threat model → code review → tickets → reteste → métricas → governança |
| 10 — Hermes Security | Slide 242 (Harness) | Superfície de ataque do harness + 7 mitigações com comandos reais |

---

## Quick Start

```bash
git clone https://github.com/michelleamesquita/ai-security-labs.git
cd ai-security-labs

# Lab 01 — Prompt Injection (5 min)
cd labs/01-prompt-injection/promptfoo
npm install
npx promptfoo redteam setup
npx promptfoo redteam run

# Lab 03 — Jev AppSec (2 min)
export TYPESAFE_API_KEY=your_key
cd labs/03-jev-appsec/jev-triage
go run main.go

# Lab 05 — SAST Pipeline (5 min)
cd labs/05-sast-ai-triage
pip install semgrep sarif-tools
python scripts/triage_pipeline.py

# Lab 06 — Code Review (3 min)
cd labs/06-code-review-ia
gh pr diff 42 > pr.diff
python scripts/code_review.py pr.diff
```

---

## Por que Jev para AppSec?

[Jev](https://typesafe.ai) é um **modelo de decisão**, não de geração de texto. Isso resolve o maior problema de usar LLMs em pipelines de segurança:

| LLM tradicional | Jev (System One) |
|----------------|------------------|
| Gera texto livre → precisa de parser | Retorna tipos nativos: yes/no, score, choice |
| Alucina justificativas | Retorna probabilidade calibrada por classe |
| Lento (segundos) | Rápido (centenas de ms) |
| Custo alto por chamada | Custo baixo, escala para milhares de findings |

**Casos de uso em AppSec:**
- **Triagem**: `jev_check` → "Esse finding é falso positivo?" com threshold de confiança
- **Priorização**: `jev_score` → severidade 1-5 com probabilidade
- **Classificação**: `jev_classify` → "Injection / Misconfiguration / Secret / False"
- **Decisão de bloqueio**: `jev_check` → "Esse PR deve ser bloqueado?" → exit code no CI

---

## Conceitos-chave do treinamento

### Módulo 1 — Agentes
- LLM = predição estatística de próximo token — sem fronteira nativa instrução/dado
- Agente = LLM + Memória + Ferramentas + Planejamento
- Arquitetura: Percepção → Orquestrador → Ferramentas → Loop

### Módulo 2 — Vulnerabilidades em Agentes
- **Prompt Injection** (OWASP LLM01): direta e indireta — sem solução 100%
- **Plan-Then-Execute Pattern**: plano travado antes de dados externos
- **Action-Selector Pattern**: LLM só escolhe ações pré-aprovadas
- **Excessive Agency** (OWASP LLM06): funcionalidade, permissão e autonomia
- **Token Vault**: token opaco por escopo — resolve IDOR entre agentes

### Módulo 3 — DevSecOps com IA
- IA como camada de decisão (não substitui scanner nem engenheiro)
- Modelo de maturidade: N0-N4, IA agrega valor a partir de N2
- **Score de risco contextual**: exploitabilidade × exposição × criticidade do ativo
- **5 portões de decisão**: bloquear merge, abrir ticket, backlog, registrar, descartar
- Amostra manual de 30 itens para taxa de falso positivo

### Módulo 4 — Revisão de Código com IA
- Schema obrigatório: CWE, evidência, impacto, confiança, correção
- Cross-validation: IA + Semgrep/CodeQL → achados com alta confiança
- **Comunicação em 3 níveis**: dev (técnico), liderança (risco/negócio), auditoria (conformidade)
- Métricas: precisão ≥ 80%, cobertura PRs críticos 100%, tempo até sinal ≤ 10min

### Módulo 5 — Criação de Tickets
- Pipeline: findings → normalizar → dedup → enriquecer → ticket → checklist → Jira
- 3 asserts obrigatórios: `validate_schema`, `has_evidence`, `has_owner`
- Score de qualidade ≥ 70 para ir pra engenharia
- Owner automático vindo do inventário, não da memória do analista

### Módulo 6 — Reteste
- Plano: payload original + variações de bypass + endpoints correlatos
- 3 execuções para consistência (Nuclei)
- IA classifica: eficaz / parcial / inválida
- Relatório com cadeia de custódia e evidência

### Módulo 7 — Projeto Final
- Fluxo end-to-end: threat model → code review → tickets → correção → reteste → métricas
- Toolkit pessoal: prompts versionados, schemas, scripts, políticas
- Governança: adoção com/sem governança, métricas de sucesso

---

## Ferramentas cobertas

| Ferramenta | Categoria | Lab |
|-----------|-----------|-----|
| [Promptfoo](https://promptfoo.dev) | LLM Red Teaming | 01 |
| [ARTEX](https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/) | Pentest Autônomo | 02 |
| [PentAGI](https://pentagi.com) | Pentest Multi-Agente | 02 |
| [Jev](https://typesafe.ai) | Modelo de Decisão | 03 |
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | Coding Agent | 04, 06, 08 |
| [MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | MCP Security | 04 |
| [Skill Scanner](https://github.com/cisco-ai-defense) | Skill Security | 04 |
| [Semgrep](https://semgrep.dev) | SAST | 05, 06, 07 |
| [Trivy](https://trivy.dev) | SCA + Container | 05 |
| [Checkov](https://www.checkov.io) | IaC Security | 05 |
| [Nuclei](https://nuclei.projectdiscovery.io) | DAST / Reteste | 08 |
| [DefectDojo](https://www.defectdojo.org) | ASPM | 05 |
| [Jira](https://www.atlassian.com/software/jira) | Issue Tracker | 07 |

---

## Referências

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP DSOMM](https://dsomm.owasp.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [CERT-EU: Beware of ARTEX](https://cert.europa.eu/blog/from-penetration-testing-to-cyber-threat-beware-of-artex)
- [Google Cloud: ARTEX and Friends](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks)
- [CSA Research Note: ARTEX](https://labs.cloudsecurityalliance.org/research/csa-research-note-artex-agentic-pentest-frameworks-in-the-wi/)
- [Jev Security Benchmarks](https://github.com/Gaurav-Gosain/jev-sec-bench)
- [Cisco AI Defense: MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner)

---

## Licença

MIT — Use apenas contra sistemas que você possui ou está explicitamente autorizado a testar.

---

_Criado por [Michelle Mesquita](https://michelleamesquita.medium.com) — AI Security & DevSecOps & AppSec Engineer 👩‍💻_