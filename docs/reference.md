# IA para AppSec — Documentação Complementar

## Arquiteturas de Referência

### Agente LLM (Módulo 1)

```
┌─────────────────────────────────────────┐
│                 AGENTE                   │
│  ┌─────────┐  ┌──────────────────────┐  │
│  │Percepção│  │    Orquestrador      │  │
│  │ (input) │──▶      (LLM core)     │──▶│ Ação
│  └─────────┘  └──────────────────────┘  │
│                      │                   │
│          ┌───────────┼───────────┐       │
│          ▼           ▼           ▼       │
│     ┌────────┐ ┌─────────┐ ┌────────┐   │
│     │Memória │ │Ferramenta│ │ Dados  │   │
│     │(estado)│ │ (APIs)  │ │ (RAG)  │   │
│     └────────┘ └─────────┘ └────────┘   │
└─────────────────────────────────────────┘
```

### Arquitetura de Defesa (Módulo 2)

```
User → WAF/TLS/Rate Limit → Guard Model → Agente
                                  ↓
                          Bloqueia jailbreak,
                          injeção, código
                          inseguro
```

### MCP Architecture (Módulo 4)

```
User → MCP Host → MCP Client → MCP Server → Tool/Resource
                        ↓
              JSON-RPC (stdio/SSE/HTTP+SSE)
```

## OWASP Top 10 for LLM Applications (2025)

| # | Vulnerabilidade | Lab |
|---|----------------|-----|
| LLM01 | Prompt Injection | 01, 04 |
| LLM02 | Insecure Output Handling | 01, 05 |
| LLM03 | Training Data Poisoning | 01 |
| LLM04 | Model Denial of Service | 01 |
| LLM05 | Supply Chain Vulnerabilities | 04 |
| LLM06 | Excessive Agency | 02, 04 |
| LLM07 | System Prompt Leakage | 01, 04 |
| LLM08 | Vector/Embedding Weaknesses | — |
| LLM09 | Misinformation/Overreliance | 01, 05 |
| LLM10 | Unbounded Consumption | 02 |

## Padrões de Design Seguro para Agentes

### 1. Plan-Then-Execute
O agente monta TODO o plano ANTES de acessar dados externos. O plano é travado.
Injeção pode poluir conteúdo de um passo, mas não adiciona passos.

### 2. Action-Selector
O LLM só escolhe dentro de ações pré-aprovadas. Output das ferramentas NÃO volta
para o LLM — sem loop adversarial possível. Máxima segurança, menor flexibilidade.

### 3. Token Vault
Tokens opacos por escopo, curta duração. Resolve IDOR entre agentes.
Cada agente recebe token válido apenas para seu escopo específico.

### 4. AI Gateway
Rate limit + autenticação + logging centralizados. Corta abuso automatizado
(fuzzing de payloads) e centraliza chaves, custos e políticas.

## Glossário

| Termo | Definição |
|-------|-----------|
| **Agente** | LLM + Memória + Ferramentas + Planejamento — executa ações autônomas |
| **Harness** | Camada de software que envolve o modelo (runtime, tools, memória, gateway) |
| **MCP** | Model Context Protocol — padroniza tools de servidores externos |
| **Tool Poisoning** | Instruções maliciosas na descrição de uma tool |
| **Rug Pull** | Server se comporta bem na instalação e vira malicioso após update |
| **Blast Radius** | Cadeia: Browser MCP → Agent → GitHub/Slack/AWS MCP |
| **SARIF** | Static Analysis Results Interchange Format — padrão de output |
| **ASPM** | Application Security Posture Management |
| **SLSA** | Supply-chain Levels for Software Artifacts |
| **SSDF** | Secure Software Development Framework (NIST SP 800-218) |

## Referências Acadêmicas

- Beurer-Kellner et al., 2025 — "Prompt Injection is Probably Undecidable" (arXiv 2506.08837)
- Gödel Proof — aplicado à indistinguibilidade instrução/dado em linguagem natural
- CSA Research Note — NIST Continuous AI Monitoring

## Links Úteis

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [Agent Skills Spec](https://agentskills.io)
- [SLSA Framework](https://slsa.dev)
- [DefectDojo](https://www.defectdojo.org)