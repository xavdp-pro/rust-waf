# Contracts

JSON profiles are design examples, not executable configuration. Step 01 must formalize and validate their schema and composition.

Composition follows core → WordPress → externally maintained site profile. Site exceptions are explicit and must not silently weaken shared invariants. Effective profile versions must accompany decisions and evidence.

The event and measurement requirements are described in observability/README.md. A read-only metric endpoint is never a WAF command interface.
