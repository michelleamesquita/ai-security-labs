# Lab 02 — Agent Red Teaming com ARTEX + PentAGI

**Objetivo:** Entender, deployar e detectar agentes de pentest autônomos. Simular ataque e defesa.

**Ferramentas:**
- [ARTEX](https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/) — Go, multi-agente, PostgreSQL, Next.js console
- [PentAGI](https://pentagi.com) — Docker, multi-agente, 20+ ferramentas profissionais

---

## Parte A — ARTEX Attack Simulation

> ⚠️ Use APENAS contra sistemas que você possui ou está autorizado a testar.

```bash
cd labs/02-agent-red-teaming/artex

# Requisitos
# - Go ≥ 1.21
# - PostgreSQL 15+
# - Node.js 18+ (para console web)
# - API key de LLM (OpenRouter recomendado)

# Clone (fork público)
git clone https://github.com/<fork>/artex.git
cd artex

# Configurar .env
cp .env.example .env
# Editar: LLM_API_KEY, DB_URL, ADMIN_PASSWORD

# Subir banco
docker run -d --name artex-pg \
  -e POSTGRES_PASSWORD=artex \
  -e POSTGRES_DB=artex \
  -p 5432:5432 postgres:15

# Build e run
go build -o artex ./cmd/artex
./artex serve

# Console em https://localhost:8443
```

### Cenário: Teste contra API REST

```bash
# Via CLI
./artex run \
  --target "https://juice-shop.herokuapp.com" \
  --goal "Find and exploit authentication bypass and injection vulnerabilities" \
  --scope "*.herokuapp.com" \
  --model "deepseek/deepseek-chat"
```

---

## Parte B — PentAGI Setup

```bash
cd labs/02-agent-red-teaming/pentagi

# Docker Compose (30K+ stars no GitHub)
curl -O https://raw.githubusercontent.com/vxcontrol/pentagi/main/docker-compose.yml

# Configurar .env com API keys
cat > .env << 'EOF'
OPEN_AI_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
# Pelo menos um provider
EOF

docker compose up -d

# Console em https://localhost:8443
# Login: admin@pentagi.com / admin
```

### Cenário: Web App Security Assessment

No console web do PentAGI, crie um Flow com:

```
Assess https://target.example for common web application vulnerabilities.
Focus on authentication, file handling, and injection issues.
Stay within the provided target only and summarize confirmed findings
with reproduction steps.
```

---

## Parte C — Detecção de ARTEX (Blue Team)

### Assinaturas comportamentais (Unit 42 / CERT-EU / Google)

| Hallmark | O que observar |
|----------|---------------|
| **Think-then-act cadence** | Rajadas de 1-14 requests em ~1s, pausa de 25-31s |
| **Machine speed** | 200+ client secrets validados em ~3 min |
| **Spec-driven targeting** | Rotas de OpenAPI atacadas quase imediatamente |
| **Self-correction** | HTTP 422 → ajustado e retry em segundos |
| **Check-own-work** | GET após quase todo write bem-sucedido |
| **Canary inputs** | `evil.com`, `test@example.com`, `deadbeef...` antes de payloads reais |
| **Recheck loops** | Polling a cada 48s por 3 dias |

### Fingerprints frágeis (não confiáveis sozinhas)

```
User-Agent: scopeweaver
User-Agent: artex-enrich/1.0
Page title: ARTEX
Next.js _next/static/chunks
Keep-alive messages a cada ~5s (workers)
```

### Sinais volumétricos (mais duráveis)

```
- Burst de activity em control-plane
- Novas origens de autenticação
- Bulk data access patterns
- Conexões com webhook.site, OAST, serviços de túnel
- Múltiplos user-agents genéricos (curl, python-requests, Boto3) em sequência
```

### Regra Suricata de exemplo

```rules
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Possible ARTEX — webhook.site callback";
    flow:established,to_server;
    http.host; pcre:"/[a-z0-9]{8,12}\.webhook\.site/";
    threshold:type both,track by_src,count 5,seconds 60;
    classtype:trojan-activity;
    sid:1000001;
)
```

---

## O que acontece depois do deploy

Monitore com:

```bash
# Logs dos agentes
docker logs -f pentagi-agent-1

# Tráfego de rede (sandbox)
tcpdump -i docker0 -w artex-traffic.pcap

# Syscalls (sandbox)
strace -f -p $(pgrep -f "artex") -e trace=network,execve
```

---

## Referências

- [Unit 42: ARTEX and AI-Powered Red Teaming Tools](https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/)
- [CERT-EU: Beware of ARTEX](https://cert.europa.eu/blog/from-penetration-testing-to-cyber-threat-beware-of-artex)
- [CSA Research Note: ARTEX](https://labs.cloudsecurityalliance.org/research/csa-research-note-artex-agentic-pentest-frameworks-in-the-wi/)
- [Google Cloud: ARTEX and Friends](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks)
- [PentAGI Documentation](https://pentagi.com/docs/)