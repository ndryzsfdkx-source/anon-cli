# Contributing (pilot)

- Keep GLITCH code in `packages/glitch_core/` **unchanged** except for minimal build glue.
- All cross-module data must go through `packages/schema/`.
- Add tests for any new rule mapping or threshold logic.
- Run `pytest` + ensure the e2e SARIF golden doesn’t regress unless intended (update with rationale).