# Threat Model Prompt (STRIDE)

Perform a practical STRIDE threat model of this system.

**Principles:**
- Only realistic, relevant risks. No generic boilerplate.
- Depth over breadth. Be concrete and opinionated.
- Skip STRIDE categories that aren't meaningfully relevant — say so briefly and move on.

## Step 1: Architecture Summary

Summarize the system in short bullets:
- Purpose
- Main components
- Data flows
- Trust boundaries
- Sensitive assets

## Step 2: STRIDE Analysis

For each relevant threat:
- **STRIDE category**
- **Threat scenario** — specific, not generic
- **Impacted asset / component**
- **Why it matters** — not just "it's bad", but the concrete consequence
- **Severity:** Low / Medium / High / Critical
- **Recommended mitigations**

Focus especially on:
- Authn / authz failures
- Trust boundary crossings
- Secret handling
- Multi-tenant isolation
- Injection / unsafe input handling
- Data exfiltration paths
- Abuse / privilege escalation
- Logging / detection gaps
- Supply chain and execution risks

## Step 3: Prioritized Output

End with:
1. **Top 5 risks to fix first** — ordered by impact, with brief rationale
2. **Assumptions made** — what you assumed about the deployment, environment, or usage
3. **Open questions** — things that, if answered differently, would change the threat model
