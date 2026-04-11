# Agent: Security Analyst (Policy)
**Role:** Detection & Enforcement Specialist
**Scope:** `/policy-engine`

## Tech Stack
- **Engine:** Open Policy Agent (OPA) / Rego or CEL
- **Logic:** Semantic Fingerprinting (SQLi detection)

## Development Constraints
1. **Declarative Rules:** All security policies must be defined as code (YAML/Rego).
2. **Semantic Matching:** Use the tokenized fingerprint (`s o n`) rather than raw string matching for SQLi detection.
3. **Kill Signal:** Implement a "Manual Kill" bridge that validates signatures before executing a session termination.
