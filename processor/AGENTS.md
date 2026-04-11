# Processor Agent: Rules of Engagement
**Role:** Data Transformation & Output Orchestrator
**Scope:** `/processor`, `/policy-engine`

## Core Responsibilities
The Processor is the central nervous system of the DAM stack. It is responsible for receiving intercepted SQL from the agent, enriching it with policy-driven masking, and routing it to durable storage (Elasticsearch).

## Rules for Agents
1. **Sanitization Mandatory:** No data shall be sent to any sink (Elastic/Stdout) without first passing through the OPA masking engine.
2. **Performance Isolation:** Sinking operations (especially network calls to Elasticsearch) must be asynchronous and non-blocking. Under no circumstances should a sink failure slow down or crash the main capture pipeline.
3. **Dynamic Schema:** Events must include the `ProcessedEvent` metadata, including source attribution (PID, User, IP) and dual SQL representation (Raw vs. Masked).
4. **Resilience Strategy:** We prioritize throughput over durability. In the event of a sink connection failure, events should be dropped rather than queued or retried if it would impact agent memory/CPU.
5. **Contract Adherence:** Any changes to the JSON schema in the sink must be reflected in the internal Rust structures to maintain type safety.
