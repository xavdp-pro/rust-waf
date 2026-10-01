# Actual status — 2026-10-01

## Present

Architecture, roadmap, agent instructions, illustrative profile contracts, and reusable origin/scoring tools are included. The scorer has a synthetic self-test. The public repository contains no deployment or customer evidence.

## Not implemented or proven

The Rust engine and HTTP proxy do not exist yet. Profile composition is not executed. Generic rules, WordPress specialization, automatic local bans, full visitor qualification, and end-to-end forwarding protection remain to be implemented and tested. Detection, false positives, and Rust overhead are not measured.

The profile JSON files explicitly say design-only. Crate directories contain design notes, not placeholder code pretending to implement protection. Origin metrics default to the truthful pre-engine state and require a real decision source before integration changes that state.

Update this file only with actual completed behavior, a commit reference, reproducible commands, results, and limitations. Configuration, service health, HTTP errors, and synthetic fixtures are not proof that an attack did not reach the backend.
