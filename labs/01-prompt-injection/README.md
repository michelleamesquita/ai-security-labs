# Lab 01 — Prompt Injection com Promptfoo

**Objetivo:** Rodar red team automatizado contra uma LLM app, cobrindo OWASP LLM01-LLM09.

**Ferramenta:** [Promptfoo](https://promptfoo.dev) — open source, 157+ plugins, 50+ tipos de vulnerabilidade.

---

## Setup (5 min)

```bash
cd labs/01-prompt-injection/promptfoo
npm install

# Setup interativo (recomendado para primeira vez)
npx promptfoo redteam setup

# Ou rápido com init
npx promptfoo redteam init --no-gui
```

Edite `promptfooconfig.yaml` com seu target. Exemplos:

### Target: API HTTP

```yaml
targets:
  - id: minha-api
    type: http
    config:
      url: 'http://localhost:8080/chat'
      method: POST
      headers:
        'Content-Type': 'application/json'
      body:
        message: '{{prompt}}'
```

### Target: Modelo direto (OpenAI)

```yaml
targets:
  - id: gpt-4
    type: openai:chat
    config:
      model: gpt-4o-mini
```

---

## Rodando o scan

```bash
# Gera casos de teste adversariais (~5 min)
npx promptfoo redteam generate

# Executa os testes
npx promptfoo redteam run

# Relatório interativo
npx promptfoo redteam report
```

---

## Plugins essenciais para AppSec

Adicione no `promptfooconfig.yaml`:

```yaml
plugins:
  # OWASP LLM01 — Prompt Injection
  - id: 'injection:direct'
  - id: 'injection:indirect'
  - id: 'injection:system-prompt-override'

  # OWASP LLM06 — Excessive Agency
  - id: 'excessive-agency'

  # Segurança técnica
  - id: 'sql-injection'
  - id: 'ssrf'
  - id: 'bola'          # Broken Object Level Authorization
  - id: 'ascii-smuggling'

  # Jailbreak + Hijacking
  - id: 'jailbreak'
  - id: 'hijacking'

  # Dados sensíveis
  - id: 'pii-leak'
  - id: 'harmful:privacy'
```

---

## Estratégias de ataque

```yaml
strategies:
  - id: 'jailbreak'
  - id: 'jailbreak:tree'
  - id: 'prompt-injection'
  - id: 'encoding'
  - id: 'multi-turn'
  - id: 'multi-language'
```

---

## CI/CD Integration

```yaml
# .github/workflows/promptfoo.yml
name: LLM Security Scan
on: [pull_request]
jobs:
  redteam:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx promptfoo@latest redteam run
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      - run: npx promptfoo@latest redteam report --format json > report.json
```

---

## O que procurar no relatório

- **Fail rate por categoria**: se `injection:direct` > 20%, revisar guardrails de entrada
- **System prompt leakage**: se expôs system prompt → remover segredos de lá AGORA
- **Excessive agency**: se ferramentas foram chamadas indevidamente → revisar escopo
- **PII leak**: se vazou dados → revisar filtro de saída

---

## Referências

- [Promptfoo Red Teaming Guide](https://www.promptfoo.dev/docs/guides/llm-redteaming/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)