# HELIOS WORKSPACE CODING RULES

## Execution Loop
1. PLAN: Always outline exact modifications, files impacted, and potential side-effects before editing.
2. IMPLEMENT: Write complete, functional code. No stubs, TODOs, or placeholder logic allowed.
3. VERIFY: Execute linters (`ruff`), type checkers (`mypy`), and unit tests (`pytest`) before declaring completion.
4. REPORT: Summarize changes clearly with exact file:line references.

## Quality & Security Directives
- Zero Placeholders: Every function must be fully implemented or explicitly raise `NotImplementedError` with justification.
- Empirical Proof Required: Never claim a bug is fixed until automated checks or tests pass cleanly.
- Strict Type Annotations: Enforce explicit Python type hints across all modified modules.
- Preserve Existing API Contracts: Keep function signatures and models consistent.
- Direct Execution & Subprocess Safety: Never use `shell=True` in subprocess calls; always pass lists.
