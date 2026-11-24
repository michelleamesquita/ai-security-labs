# MCP & Skills JAM — Joint Analysis Module

Pipeline unificado de análise de segurança para **MCP servers** e **Skills**, cobrindo
os 6 padrões de ataque MCP dos slides + os 4 riscos de Skills maliciosas.

---

## Arquitetura do Pipeline

```
SKILL.md / mcp_server.py / tools.json
              │
              ▼
    ┌─────────────────────┐
    │  [1] ANÁLISE        │  Pattern matching + scan de dependências
    │      ESTÁTICA       │  Rápido, barato, primeira triagem
    └─────────┬───────────┘
              ▼
    ┌─────────────────────┐
    │  [2] ANÁLISE        │  LLM/Jev avalia intenção real vs propósito
    │      SEMÂNTICA      │  declarado. Detecta descompasso.
    └─────────┬───────────┘
              ▼
    ┌─────────────────────┐
    │  [3] CUSTOM RULES   │  Regras da organização (política, compliance)
    │      ORG            │  Cobertura de dados, escopo, compliance
    └─────────┬───────────┘
              ▼
    ┌─────────────────────┐
    │  [4] ANÁLISE        │  Compara contra catálogo aprovado.
    │      COMPOSICIONAL  │  Detecta risco de combinação entre Skills.
    └─────────┬───────────┘
              ▼
    VEREDITO: APPROVE / REVIEW / BLOCK
```

---

## Estágio 1 — Análise Estática (determinística)

### 1.1 Skills — Sinais de texto

```yaml
# rules/skill-static.yaml
rules:
  - id: SKILL-EXFIL-CALLBACK
    pattern: 'https?://[^\s"''`]+'
    context: 'URL fora do domínio esperado, presente no corpo do SKILL.md'
    severity: HIGH
    cwe: CWE-200
    owasp: LLM01 (Prompt Injection)

  - id: SKILL-SECRECY-INSTRUCTION
    pattern: '(não mencion|do not mention|não conte|do not tell|não revele|do not reveal)'
    severity: CRITICAL
    reason: "Instrução de sigilo remove supervisão humana"
    owasp: LLM01

  - id: SKILL-OBFUSCATED-EXEC
    pattern: '(base64|eval|exec\(|__import__|subprocess|curl \||wget )'
    context: 'Execução ofuscada dentro de instruções do SKILL.md'
    severity: CRITICAL
    cwe: CWE-94

  - id: SKILL-UNPINNED-DEP
    pattern: '(pip install|npm install|go get) [a-z0-9_-]+$'
    context: 'Instalação de dependência sem pin de versão'
    severity: MEDIUM
    cwe: CWE-1104

  - id: SKILL-HIDDEN-TAG
    pattern: '(<HIDDEN>|<secret>|<system>|</?hidden)'
    severity: CRITICAL
    reason: "Tag oculta para esconder instruções do usuário"
    owasp: LLM01
```

### 1.2 MCP — Sinais de código

```yaml
# rules/mcp-static.yaml
rules:
  - id: MCP-CORS-ANY
    pattern: 'allow_origins=\["\*"\]'
    severity: HIGH
    cwe: CWE-942
    reason: "CORS aberto permite ataque via browser"

  - id: MCP-DNS-REBINDING-DISABLED
    pattern: 'enable_dns_rebinding_protection\s*=\s*False'
    severity: CRITICAL
    cwe: CWE-350
    reason: "Sem proteção DNS rebinding, server é atacável via browser"

  - id: MCP-TOOL-IMPERATIVE-DOCSTRING
    pattern: 'YOU MUST|YOU MUST READ|<HIDDEN>|do not mention'
    context: 'Docstring da tool com instrução imperativa dirigida ao LLM'
    severity: CRITICAL
    owasp: LLM01
    reason: "Tool poisoning — instrução escondida na descrição"

  - id: MCP-SECRET-RESOURCE
    pattern: '(system://secrets|@mcp.resource\("(system|confidential|admin))'
    severity: CRITICAL
    cwe: CWE-200
    reason: "Resource exposto além do escopo declarado"

  - id: MCP-WIDE-PERMISSION
    pattern: '(scope|permissions)\s*=\s*\[?.{0,3}(read|write|admin)'
    severity: HIGH
    cwe: CWE-862
    reason: "Permissões mais amplas que o necessário"
```

---

## Estágio 2 — Análise Semântica (LLM/Jev)

### 2.1 Jev — decisão tipada

```python
# jam/semantic_jev.py
import subprocess, json, os

API_KEY = os.environ["TYPESAFE_API_KEY"]

def analyze_skill(skill_content):
    """Jev avalia: intenção real vs propósito declarado"""
    state = json.dumps({
        "skill_content": skill_content[:8000],  # Jev: 32k context, mande só o necessário
        "declared_purpose": extract_declared_purpose(skill_content)
    })

    # 1. Intenção maliciosa?
    r1 = subprocess.run([
        "jev", "check",
        "--state", state,
        "--question", "Does this skill contain instructions that go beyond "
                       "its declared purpose and could harm the user?",
        "--api-key", API_KEY
    ], capture_output=True, text=True)
    malicious = json.loads(r1.stdout)

    # 2. Exfiltração?
    r2 = subprocess.run([
        "jev", "check",
        "--state", state,
        "--question", "Does this skill attempt to exfiltrate user data to "
                       "external services without clear consent?",
        "--api-key", API_KEY
    ], capture_output=True, text=True)
    exfil = json.loads(r2.stdout)

    # 3. Classificar tipo de risco
    r3 = subprocess.run([
        "jev", "classify",
        "--state", state,
        "--classes", "Benign, Data Exfiltration, Prompt Injection, "
                      "Credential Theft, Supply Chain Risk, Excessive Scope",
        "--api-key", API_KEY
    ], capture_output=True, text=True)
    category = json.loads(r3.stdout)

    return {
        "malicious_verdict": malicious["verdict"],
        "malicious_confidence": malicious["confidence"],
        "exfiltration_verdict": exfil["verdict"],
        "exfiltration_confidence": exfil["confidence"],
        "category": category["label"],
        "category_confidence": category["confidence"]
    }

def extract_declared_purpose(content):
    """Extrai o propósito declarado do SKILL.md (frontmatter description)"""
    for line in content.split("\n"):
        if line.startswith("description:"):
            return line.split(":", 1)[1].strip()
    return "unknown"
```

### 2.2 Regra de decisão

```python
# jam/decision.py
def decide(skill_analysis, static_findings):
    """
    Combina estática + semântica → veredito
    """
    # Bloqueio imediato: qualquer sinal crítico determinístico
    if any(f["severity"] == "CRITICAL" for f in static_findings):
        return {"verdict": "BLOCK", "reason": "Critical static signature"}

    # Jev: intenção maliciosa com alta confiança
    if (skill_analysis["malicious_verdict"] == "yes"
            and skill_analysis["malicious_confidence"] > 0.8):
        return {"verdict": "BLOCK", "reason": f"Jev: malicious intent {skill_analysis['malicious_confidence']:.2f}"}

    # Exfiltração com alta confiança
    if (skill_analysis["exfiltration_verdict"] == "yes"
            and skill_analysis["exfiltration_confidence"] > 0.8):
        return {"verdict": "BLOCK", "reason": f"Jev: exfiltration {skill_analysis['exfiltration_confidence']:.2f}"}

    # Categoria de risco + confiança média → revisão humana
    if skill_analysis["category"] != "Benign" and skill_analysis["category_confidence"] > 0.5:
        return {"verdict": "REVIEW", "reason": f"Jev: {skill_analysis['category']} needs human review"}

    return {"verdict": "APPROVE", "reason": "No critical signals"}
```

---

## Estágio 3 — Custom Rules (organização)

```yaml
# rules/org-policies.yaml
org_rules:
  # O que SUA organização bloqueia
  - id: ORG-NO-EXTERNAL-CALLBACK
    description: "Nenhum callback para domínios fora da allowlist"
    allowed_domains: ["internal.company.com", "api.company.com"]
    severity: BLOCK

  - id: ORG-NO-BROAD-SCOPE
    description: "Skill não pode pedir acesso a mais de 3 ferramentas"
    max_tools: 3
    severity: BLOCK

  - id: ORG-DATA-CLASSIFICATION
    description: "Skill não pode tocar dados classificados como PII/PCI"
    protected_data: ["PII", "PCI", "PHI"]
    severity: BLOCK

  - id: ORG-MANDATORY-PINNING
    description: "Toda dependência deve ter versão pinada + hash"
    require: ["version_pin", "checksum"]
    severity: REVIEW
```

---

## Estágio 4 — Análise Composicional

```python
# jam/compositional.py
def analyze_combination(new_skill, approved_catalog):
    """
    Detecta risco de combinação entre Skills:
    Skill A (benigna) + Skill B (benigna) = Skill A+B (perigosa)
    """
    risks = []

    # 1. Tool overlap — duas skills que juntas cobrem um fluxo sensível
    new_tools = set(new_skill.get("tools", []))
    for existing in approved_catalog:
        overlap = new_tools & set(existing.get("tools", []))
        if overlap and both_touch_sensitive(overlap):
            risks.append({
                "type": "tool_overlap",
                "with": existing["name"],
                "overlap": list(overlap)
            })

    # 2. Privilege escalation — nova skill pede mais que similar aprovada
    for existing in approved_catalog:
        if similar_purpose(new_skill, existing):
            if len(new_skill["tools"]) > len(existing["tools"]) * 1.5:
                risks.append({
                    "type": "privilege_escalation",
                    "with": existing["name"],
                    "detail": f"{len(new_skill['tools'])} vs {len(existing['tools'])} tools"
                })

    # 3. Chain risk — skill A escreve, skill B exfiltra
    if new_skill.get("can_write") and any(s.get("can_exfiltrate") for s in approved_catalog):
        risks.append({
            "type": "chain_risk",
            "detail": "write-capable skill combined with exfil-capable skill"
        })

    return risks
```

---

## MCP JAM — 6 Padrões de Ataque (slides)

| # | Padrão | Detecção estática | Detecção semântica | Severidade |
|---|--------|-------------------|-------------------|------------|
| 01 | **Tool Poisoning** | `YOU MUST`, `<HIDDEN>` na docstring | Jev: "a descrição instrui além de documentar?" | CRITICAL |
| 02 | **Rug Pull** | Diff de update sem changelog | Jev: "mudança de comportamento vs versão anterior?" | HIGH |
| 03 | **Prompt Injection via Resource** | Texto de comando dentro de campo de dados | Jev: "resource contém instrução embutida?" | CRITICAL |
| 04 | **Credential Theft** | Server pede mais permissões que usa | Jev: "permissões excedem o fluxo OAuth padrão?" | CRITICAL |
| 05 | **Cross-Server Escalation** | Tool response instrui chamar outro server | Jev: "resposta sugere pivot para outro server?" | HIGH |
| 06 | **Supply Chain Compromise** | Typosquatting, 1 contribuidor, popularidade súbita | Jev: "pacote parece legítimo mas é suspeito?" | CRITICAL |

---

## Skills — 4 Riscos Principais

| Risco | Prevalência | Detecção |
|-------|-------------|----------|
| **Prompt Injection** | instruções escondidas no SKILL.md | SKILL-HIDDEN-TAG + Jev |
| **Exfiltração de dados** | callbacks disfarçados | SKILL-EXFIL-CALLBACK + Jev |
| **Escalação de privilégio** | pede mais escopo que precisa | ORG-NO-BROAD-SCOPE + composicional |
| **Supply chain** | dependências sem pin | SKILL-UNPINNED-DEP |

---

## CLI de Orquestração

```python
# jam/run_jam.py
"""
Pipeline completo: Skills ou MCP → 4 estágios → veredito

Uso:
  python run_jam.py skill path/to/SKILL.md
  python run_jam.py mcp path/to/mcp_server.py
  python run_jam.py mcp remote http://localhost:8001/sse
"""
import sys, json

def run_jam(target_type, target_path):
    # [1] Estático
    if target_type == "skill":
        static_findings = run_static_rules(target_path, "rules/skill-static.yaml")
    else:
        static_findings = run_static_rules(target_path, "rules/mcp-static.yaml")

    print(f"[1] Estática: {len(static_findings)} achados")
    for f in static_findings:
        print(f"    {f['severity']}: {f['id']} — {f.get('reason', '')}")

    # [2] Semântico (Jev)
    content = open(target_path).read()
    semantic = analyze_skill(content)
    print(f"[2] Semântica: {semantic['category']} (conf {semantic['category_confidence']:.2f})")

    # [3] Custom rules
    org_findings = run_org_rules(target_path)
    print(f"[3] Org: {len(org_findings)} violações")

    # [4] Composicional
    compositional = analyze_combination(
        {"tools": extract_tools(target_path)},
        load_approved_catalog()
    )
    print(f"[4] Composicional: {len(compositional)} riscos de combinação")

    # Veredito
    verdict = decide(semantic, static_findings + org_findings)
    print(f"\nVEREDITO: {verdict['verdict']} — {verdict['reason']}")
    return verdict

if __name__ == "__main__":
    run_jam(sys.argv[1], sys.argv[2])
```

---

## Referências

- [MCP Scanner (Cisco AI Defense)](https://github.com/cisco-ai-defense/mcp-scanner)
- [Skill Scanner (Cisco AI Defense)](https://github.com/cisco-ai-defense)
- [Jev CLI](https://github.com/dipendra-sharma/jev-cli)
- [MCP Specification](https://modelcontextprotocol.io)
