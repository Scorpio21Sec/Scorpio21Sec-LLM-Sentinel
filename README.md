# LLM-Sentinel
LLM-Sentinel — LLM Security Detection Platform: Built a Python/FastAPI security gateway detecting prompt injection, jailbreaks, data leakage and RAG attacks, with automated risk scoring and OWASP LLM Top 10/MITRE ATLAS mapping.

# LLM-Sentinel

LLM-Sentinel focuses on **security telemetry, detection, and evaluation** for LLM applications.

## Detection coverage

The project tracks detections for:

- Prompt injection
- Jailbreak attempts
- System-prompt extraction
- Sensitive-data leakage
- Malicious URLs
- Excessive agency
- Tool abuse
- RAG poisoning
- Indirect prompt injection
- Insecure output handling

## Findings taxonomy (no arbitrary AI risk scores)

Findings are mapped to:

1. **OWASP LLM Top 10** categories
2. **MITRE ATLAS** adversary techniques

and are intentionally **not** represented as arbitrary "AI risk scores."

| Detection | OWASP LLM Top 10 mapping | MITRE ATLAS mapping |
| --- | --- | --- |
| Prompt injection | LLM01: Prompt Injection | Prompt Injection |
| Jailbreak attempts | LLM01: Prompt Injection | Prompt Injection, LLM Jailbreak |
| System-prompt extraction | LLM01: Prompt Injection | Prompt Extraction / Prompt Injection |
| Sensitive-data leakage | LLM06: Sensitive Information Disclosure | Exfiltration / Disclosure techniques |
| Malicious URLs | LLM02: Insecure Output Handling | Phishing / Payload Delivery via generated content |
| Excessive agency | LLM08: Excessive Agency | Unauthorized Action via Agent/Tool Misuse |
| Tool abuse | LLM07: Insecure Plugin Design, LLM08: Excessive Agency | Tool Abuse / Capability Misuse |
| RAG poisoning | LLM03: Training Data Poisoning | Data Poisoning |
| Indirect prompt injection | LLM01: Prompt Injection, LLM02: Insecure Output Handling | Indirect Prompt Injection |
| Insecure output handling | LLM02: Insecure Output Handling | Unsafe Output / Downstream Exploitation |

