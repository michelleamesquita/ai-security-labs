# Lab 03 — Jev para AppSec

**Objetivo:** Usar o modelo de decisão Jev (TypeSafe) para triagem de findings de segurança e detecção de código vulnerável.

**O que é Jev:** Um "System One" model — não gera texto. Você manda estado + pergunta tipada, ele devolve resposta tipada + probabilidade calibrada.

---

## Por que Jev resolve problemas reais de AppSec

Em um pipeline de segurança, você precisa de **decisões**, não de parágrafos:

| Tarefa | LLM tradicional | Jev |
|--------|----------------|-----|
| "Esse finding é falso positivo?" | "Após análise do contexto, considerando o fluxo de dados..." → precisa de regex | `{verdict: "no", confidence: 0.94}` |
| "Qual severidade?" | "Considero este finding de severidade ALTA porque..." → precisa de parser | `{score: 4, nearest_level: "HIGH", confidence: 0.89}` |
| Triar 500 findings | 500 × 3s = 25min, $0.50+ | 500 × 200ms = 1.6min, $0.05 |
| Threshold no CI | Precisa de script de parsing | `jev check --min-confidence 0.9 && exit 0 || exit 1` |

---

## Setup

### Instalar Jev CLI

```bash
# Go
go install github.com/dipendra-sharma/jev-cli@latest

# Ou direto
git clone https://github.com/dipendra-sharma/jev-cli.git
cd jev-cli
go build -o jev .
```

### API Key

```bash
export TYPESAFE_API_KEY=ts_...
# Ou via OpenRouter:
export OPENROUTER_API_KEY=sk-or-...
```

---

## Lab A — Triagem de Findings

### 1. Classificação: injection vs misconfiguration vs secret vs false

```bash
cat > finding.json << 'EOF'
{
  "finding": {
    "title": "SQL Injection in /api/users?id=",
    "tool": "semgrep",
    "rule": "python.sqlalchemy.security.sqlalchemy-sqli",
    "file": "app/routes/users.py",
    "line": 42,
    "code": "User.query.filter(f'id={request.args.get(\"id\")}')",
    "reachability": "direct_user_input_to_sink",
    "exploitability": "no_waf_or_sanitization"
  }
}
EOF

# jev_check: é falso positivo?
jev check \
  --state finding.json \
  --question "Is this security finding a false positive? The code directly interpolates user input into a SQL query without parameterization." \
  --api-key "$TYPESAFE_API_KEY"

# jev_classify: que tipo de vulnerabilidade?
jev classify \
  --state finding.json \
  --classes "SQL Injection, XSS, SSRF, Misconfiguration, Exposed Secret, False Positive" \
  --api-key "$TYPESAFE_API_KEY"

# jev_score: qual severidade (1-5)?
jev score \
  --state finding.json \
  --scale "1:Informational, 2:Low, 3:Medium, 4:High, 5:Critical" \
  --api-key "$TYPESAFE_API_KEY"
```

### 2. Script de triagem em lote

```python
# jev-triage/batch_triage.py
import subprocess, json, sys
from pathlib import Path

findings = json.loads(Path(sys.argv[1]).read_text())

for f in findings:
    state = json.dumps({"finding": f})
    result = subprocess.run(
        ["jev", "check",
         "--state", state,
         "--question", "Is this security finding a false positive?",
         "--min-confidence", "0.8",
         "--api-key", "$TYPESAFE_API_KEY"],
        capture_output=True, text=True
    )
    verdict = json.loads(result.stdout)
    f["jev_verdict"] = verdict["verdict"]
    f["jev_confidence"] = verdict["confidence"]

# Pipeline: só passa findings com confidence > 0.8 de serem reais
real_findings = [f for f in findings if f["jev_verdict"] == "no" and f["jev_confidence"] > 0.8]
print(json.dumps(real_findings, indent=2))
```

---

## Lab B — Scanner de Código Vulnerável

Baseado no [jev-sec-bench](https://github.com/Gaurav-Gosain/jev-sec-bench):

```bash
git clone https://github.com/Gaurav-Gosain/jev-sec-bench.git
cd jev-sec-bench
export TYPESAFE_API_KEY=ts_...

# Rodar benchmarks
go run ./cmd/jev-sec-bench -bench all

# Dashboard interativo
go run ./cmd/jev-tui
```

### O que o benchmark testa

| Benchmark | Dataset | Métrica |
|-----------|---------|---------|
| **Prompt injection** | 662 mensagens (`deepset/prompt-injections`) | Precision/Recall |
| **Vulnerable code** | 200 pares (`CyberNative/Code_Vulnerability_Security_DPO`) | Accuracy |

---

## Lab C — Gate de CI/CD com Jev

```yaml
# .github/workflows/jev-gate.yml
name: Jev Security Gate
on: [pull_request]
jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # SAST scan
      - name: Run Semgrep
        run: semgrep --config p/security-audit --sarif -o sast.sarif

      # Jev triage — decide se bloqueia
      - name: Jev Triage Gate
        env:
          TYPESAFE_API_KEY: ${{ secrets.TYPESAFE_API_KEY }}
        run: |
          python scripts/jev_gate.py \
            --sarif sast.sarif \
            --min-confidence 0.85 \
            --threshold critical 0 \
            --threshold high 3
```

---

## Limitações do Jev (importante!)

Do [jaggedness report](https://docs.typesafe.ai) oficial:

| Limitação | Impacto em AppSec |
|-----------|-------------------|
| **Não é calculator** | Não use para contagem de findings, datas ou comparações numéricas |
| **Leitura literal** | Negativas e condições implícitas podem confundir — escreva perguntas diretas |
| **Estado grande irrelevante** | Mande SÓ o que o finding precisa — accuracy cai com ruído |
| **Input adversário** | Não trata estado como hostil por padrão — NÃO use sozinho como guardrail |
| **Calibração é agregada** | Confiança de uma chamada individual pode estar errada; use threshold + amostragem |

---

## Referências

- [Jev CLI](https://github.com/dipendra-sharma/jev-cli)
- [Jev Security Benchmarks](https://github.com/Gaurav-Gosain/jev-sec-bench)
- [Jev + Claude Code](https://github.com/FrancoisChastel/jev-code)
- [CVE Triage Agent (You.com + Jev)](https://github.com/youdotcom-oss/cve-triage-agent)
- [Building a Faster, Cheaper Vulnerability Scanner With Jev](https://depthfirst.com/research/building-a-faster-cheaper-vulnerability-scanner-with-jev)
- [TypeSafe Jev Docs](https://docs.typesafe.ai)