# LLM Sentinel Threat Model

## Objective

LLM Sentinel is designed to identify common security indicators
in LLM application inputs, retrieved content, and model-associated
text.

The project focuses on defensive security testing.

---

## Assets

The system may interact with:

- System prompts
- Developer instructions
- User data
- Retrieved documents
- API credentials
- Tool/API permissions
- Model outputs
- Application logs

---

## Threat Actors

Potential threat actors include:

- Malicious users
- Compromised document sources
- Malicious RAG content
- Attackers attempting prompt injection
- Attackers attempting credential extraction
- Attackers attempting unauthorized tool use

---

## Threat Categories

### Prompt Injection

An attacker attempts to influence model behavior by inserting
instructions into user-controlled input.

Rule:

`PI001`

---

### Prompt Extraction

An attacker attempts to retrieve hidden system or developer
instructions.

Rule:

`PI002`

---

### Guardrail Bypass

An attacker attempts to circumvent application safety controls.

Rule:

`PI003`

---

### Secret Exposure

Credentials or sensitive authentication material may accidentally
appear in LLM-associated content.

Rule:

`SECRET001`

---

### RAG Poisoning

Untrusted retrieved documents may contain instructions designed
to manipulate downstream model behavior.

Rule:

`RAG001`

---

### Tool Abuse

An attacker may attempt to cause an AI agent to perform an
unauthorized external action.

Rule:

`TOOL001`

---

## Security Controls

Recommended controls include:

1. Input validation
2. Instruction hierarchy enforcement
3. Retrieval provenance validation
4. RAG document sanitization
5. Output validation
6. Tool authorization
7. Least-privilege permissions
8. Human approval for high-impact actions
9. Secret management
10. Security logging and monitoring

---

## Trust Boundaries

The primary trust boundaries are:

User
  |
  v
LLM Application
  |
  +--> System Instructions
  |
  +--> User Input
  |
  +--> RAG Documents
  |
  +--> Tools / APIs
  |
  v
LLM
  |
  v
Application Output

User-controlled input and retrieved documents should be treated
as untrusted.

---

## Security Principle

LLM Sentinel follows a core principle:

> Treat model instructions and retrieved content according to
> their trust level rather than assuming all text is trustworthy.