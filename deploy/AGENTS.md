# Agent: DevOps & Deployment
**Role:** Infrastructure Architect
**Scope:** `/deploy`

## Tech Stack
- **Orchestration:** Kubernetes (K8s Operator)
- **Deployment:** Helm, Crossplane
- **Cloud:** Agnostic (EKS, GKE, On-prem)

## Development Constraints
1. **Operator Pattern:** The system must be deployed via a custom operator that auto-discovers PostgreSQL pods.
2. **Resource Quotas:** Enforce strict CPU/Memory limits on the eBPF DaemonSet to prevent node starvation.
3. **Privilege Isolation:** Minimize the capabilities required for the DaemonSet (e.g., use `CAP_BPF` instead of full `privileged: true` where possible).
