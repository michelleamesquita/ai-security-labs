# Lab 10 — Hermes Agent Security

**Objetivo:** Mapear a superfície de ataque do harness Hermes Agent e aplicar as mitigações concretas — conectando com o slide 242 ("Harness, Hermes e OpenClaw — o novo perímetro").

**Ferramenta:** [Hermes Agent (Nous Research)](https://github.com/NousResearch/hermes-agent)

---

## Por que o harness é o novo perímetro

O slide 242 define harness como a camada que envolve o modelo:

```
HARNESS
  Modelo (LLM)
  Runtime (loop de execução)
  Ferramentas (tools)
  Memória (contexto persistente)
  Gateway / canais
```

Hermes é centrado em memória: **80+ skills, terminal/arquivo/código, contexto entre sessões**. Isso significa que a superfície de ataque não é o modelo — é o que o envolve. Um prompt injection que atravessa o modelo só faz dano se o harness der as ferramentas para isso.

---

## Superfície de Ataque do Hermes

| # | Vetor | Como o atacante entra | O dano |
|---|-------|----------------------|--------|
| 1 | **Skills (SKILL.md)** | Skill maliciosa instalada — instruções + scripts | Exfiltração, sigilo, execução oculta |
| 2 | **MCP servers** | Server de terceiro com tool poisoning | Tool poisoning, rug pull, credential theft |
| 3 | **Memória persistente** | Memória envenenada persiste entre sessões | Instruções falsas re-injetadas a cada sessão |
| 4 | **Project context files** | `AGENTS.md` / `.hermes.md` de repo clonado | Prompt injection indireta (injeção via repo) |
| 5 | **Ferramentas** | Terminal, arquivo, browser, código | Excessive agency — comandos destrutivos |
| 6 | **Gateway multi-plataforma** | Telegram, Discord, Slack, WhatsApp | Blast radius ampliado: um agente em N canais |
| 7 | **Secrets** | `~/.hermes/.env` | System prompt leakage → chaves vazam |
| 8 | **Shell hooks / plugins** | PostToolUse executa em background | Execução invisível ao usuário |

---

## Mitigações com Comandos Reais

### 1. Secret Redaction (on por padrão)

Hermes escaneia tool output por strings de API keys/tokens ANTES de entrar no contexto:

```bash
# Verificar
hermes config get security.redact_secrets

# Garantir que está ligado
hermes config set security.redact_secrets true
```

⚠️ **Restart required.** O toggle é snapshotado no import — um LLM não consegue virar sozinho no meio da tarefa (proteção deliberada).

### 2. PII Redaction no Gateway

```bash
hermes config set privacy.redact_pii true
```

Hasha user IDs e remove telefones do contexto antes de chegar ao modelo.

### 3. Command Approval (não usar YOLO)

```bash
# Recomendado: middle ground
hermes config set approvals.mode smart

# NUNCA em produção:
# hermes config set approvals.mode off   # = --yolo
```

| Mode | Comportamento |
|------|--------------|
| `smart` | Auto-aprova comandos de baixo risco, nega destrutivos, pergunta quando incerto |
| `manual` | Sempre pergunta |
| `off` | Bypass total (equivalente a `--yolo`) |

### 4. Reset de Permissões (quando suspeitar de acúmulo)

```bash
# Limpa o allowlist de comandos "sempre permitir"
hermes config set command_allowlist '[]'

# Remove consent de shell hooks
rm -f ~/.hermes/shell-hooks-allowlist.json

# Sanity check
hermes config get approvals.mode   # deve ser != off
```

### 5. Segredos no Lugar Certo

```bash
# Segredos SEMPRE em .env, NUNCA em config.yaml
~/.hermes/.env          # API keys e secrets
~/.hermes/config.yaml   # configurações (nunca secrets)
```

Regra do harness: **settings em config.yaml, secrets em .env**. Um system prompt que vaza não deve conter credencial nenhuma.

### 6. Isolamento por Profile

```bash
# Profiles isolam configs, sessions, skills e memória
# Resolve o caminho real via $HERMES_HOME, nunca hardcode ~/.hermes
echo $HERMES_HOME
```

Use profiles separados para tarefas de risco (ex: um profile "sandbox" sem gateway, sem MCP crítico).

### 7. Desabilitar Tools de Rede/Mídia

```bash
hermes tools   # abre o seletor; desabilita browser/image-gen/web por plataforma
```

Mantenha o modelo longe de ferramentas de rede se a tarefa não exige.

---

## Exercício Prático — Auditoria de um Harness

### Passo 1 — Inventário da superfície

```bash
# Que skills estão instaladas?
ls -la "$HERMES_HOME/skills/" 2>/dev/null || ls -la ~/.hermes/skills/

# Que MCP servers estão configurados?
hermes mcp list 2>/dev/null || cat ~/.hermes/mcp_servers.yaml 2>/dev/null

# Que profiles existem?
ls ~/.hermes/profiles/ 2>/dev/null

# Approval mode atual?
hermes config get approvals.mode
```

### Passo 2 — Aplicar o JAM nas Skills

Reuse o pipeline do Lab 04 para escanear cada SKILL.md:

```bash
cd ../04-claude-code-security/jam
python run_jam.py skill ~/.hermes/skills/alguma-skill/SKILL.md
```

Procure os 6 sinais: callback externo, instrução de sigilo, execução ofuscada, dep sem pin, tag oculta, hook com comando.

### Passo 3 — Aplicar o JAM nos MCP servers

```bash
cd ../04-claude-code-security/jam
python run_jam.py mcp path/to/mcp_server.py
# ou remoto
python run_jam.py mcp remote http://localhost:8001/sse
```

### Passo 4 — Verificar o blast radius

```bash
# Quais canais de gateway estão ativos?
hermes dashboard   # painel mostra messaging channels

# Regra: um agente comprometido alcança TODOS os canais conectados
# Mitigação: profile por canal, ou desabilitar canais não essenciais
```

---

## Padrões de Defesa do Módulo 2 aplicados ao Hermes

| Padrão | Como aplicar no Hermes |
|--------|----------------------|
| **Plan-Then-Execute** | Skills que travam o plano antes de tocar dados externos (não ler web antes de decidir as tools) |
| **Action-Selector** | `hermes tools` para restringir o conjunto de tools a um fixo pré-aprovado |
| **Token Vault** | Credenciais por escopo via MCP — nunca um token amplo no .env do harness |
| **AI Gateway** | Rate limit + autenticação + logging no gateway multi-plataforma |
| **Least privilege** | Profile sandbox sem gateway, sem terminal, sem MCP crítico |

---

## Checklist de Hardening (uma linha por item)

```yaml
hermes_hardening:
  - security.redact_secrets: true          # nunca desligar
  - privacy.redact_pii: true               # se lida com dados de usuário
  - approvals.mode: smart                  # nunca off em produção
  - command_allowlist: "[]"                # auditar periodicamente
  - secrets_in: .env                       # nunca em config.yaml
  - skills_scanned: true                   # JAM antes de instalar
  - mcp_scanned: true                      # JAM antes de conectar
  - profiles_isolated: true                # sandbox separado para risco
  - gateway_channels: minimal              # só os canais necessários
  - network_tools: disabled_unless_needed  # browser/image-gen off por padrão
```

---

## O que isso conecta

- **Slide 242** — Hermes como harness centrado em memória (o "novo perímetro")
- **Módulo 2** — Prompt injection, excessive agency, token vault, padrões de defesa
- **Lab 04** — JAM: o scanner de skills/MCP reutilizado aqui
- **Lab 03** — Jev: usar `jev_check` para decidir "essa skill é maliciosa?" com threshold

---

## Referências

- [Hermes Agent (Nous Research)](https://github.com/NousResearch/hermes-agent)
- [Hermes Docs](https://hermes-agent.nousresearch.com/docs/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Model Context Protocol](https://modelcontextprotocol.io)
