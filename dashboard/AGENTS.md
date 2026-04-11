# Agent: Frontend Lead
**Role:** Observability & UI Specialist
**Scope:** `/dashboard`

## Tech Stack
- **Framework:** Next.js / Tailwind CSS
- **Visualization:** Real-time stream (WebSockets/gRPC-web)
- **Data Source:** ClickHouse / OTel Collector

## Development Constraints
1. **Real-time First:** The dashboard must display SQL streams with <2s latency from capture to screen.
2. **The "Big Red Button":** Implement a secure, multi-factor confirmation for the Manual Session Kill trigger.
3. **Visual Context:** Always show the K8s Pod metadata alongside the raw SQL for incident context.
