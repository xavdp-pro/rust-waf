# Contributing

README.md is the shared entry point for humans and agents. Read the actual status, architecture, roadmap, and AGENTS.md before work.

1. Choose a bounded roadmap step.
2. Branch from main using a short-lived name such as `step-01/profile-contracts` or `fix/scoring`.
3. Keep a coherent change to code, generic profile, and contract together.
4. Verify the intended behavior and limitations; update status and reproducible evidence.
5. Open a reviewable PR explaining the problem, result, checks, and limitations.

No permanent engine/WordPress/site branches. Site-specific work belongs in a separately maintained private repository, with an explicit shared-version reference. GitHub access and agent access must be configured separately; publishing code does not grant private access.

Run `python3 tools/check_repository.py` and `python3 observability/evaluate_waf.py --self-test`. The latter checks a synthetic fixture, not WAF protection. No hosted CI is enabled in this foundation; add useful bounded CI when implementation starts.

Use English throughout the repository. No private deployment material or raw production evidence may be attached to a public PR.
