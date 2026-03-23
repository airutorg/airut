# Code Review Workflow

Review code changes before creating a PR. This workflow is executed by a
subagent launched after implementation is complete and tests pass.

## Instructions

Read `CLAUDE.md` first to understand project standards. Then review the diff
between the working branch and `origin/main`:

```bash
git diff origin/main...HEAD
```

Read every changed file in full (not just the diff) to understand the context.

Apply your standard code review judgment, and additionally verify each item in
the project-specific checklist below.

## Project-Specific Checklist

### 1. Documentation and specs

- [ ] If behavior changed, are the relevant `spec/*.md` files updated?
- [ ] Specs describe goals, architecture, and contracts — not implementation
  details. Flag any spec text that duplicates what the code already says.
- [ ] No documentation drift: do `doc/*.md` files still match reality?

### 2. Type safety

- [ ] No use of `Any` (or `object` as a substitute) where a concrete or generic
  type can be defined. Every `Any` must be justified.
- [ ] No `# type: ignore` without a specific error code and justification.

### 3. File and function size

- [ ] New or modified files should not exceed ~400 lines. Flag files that have
  grown too large and suggest how to split them.
- [ ] Functions and methods should do one thing. Flag any over ~50 lines.
- [ ] Classes that accumulate unrelated responsibilities should be split.

### 4. Code duplication

- [ ] Look for duplicated logic across the changed files and the rest of the
  codebase. Flag candidates for extraction into shared utilities.

### 5. Interface cleanliness — no legacy wrappers

- [ ] No backwards-compatibility shims: type aliases to renamed types,
  re-exports, wrapper functions that just forward to the new function, unused
  parameters kept "for compatibility."
- [ ] Callers are updated throughout — not just the declaration. Grep for all
  references.
- [ ] Interfaces and APIs are clean after the change. Watch for signs of lazy
  updates designed to avoid breaking callers (e.g., optional parameters that
  should be required, union types that paper over a migration, **kwargs
  pass-through to avoid signature changes).
- [ ] If a refactor made an interface awkward, clean it up in the same PR.

### 6. Test quality

- [ ] Tests validate externally visible behavior, not implementation details.
- [ ] Assertions verify correct behavior — not just "no exception was raised."
- [ ] Integration tests (`tests/integration/`) test end-to-end contracts.
- [ ] No `sleep()` in tests. Use polling, events, or mock time instead.
- [ ] No `pytest.skip()` — write proper mocks.

### 7. General

- [ ] No `print()` — use `logging`.
- [ ] No secrets or credentials in committed files.
- [ ] Error handling is appropriate (not excessive, not missing at boundaries).

## Output Format

Organize findings by severity:

- **Must fix** — correctness, security, spec violations, `Any` usage, missing
  tests, legacy wrappers / unclean interfaces.
- **Should fix** — duplication, overly large files/functions, unclear naming,
  missing doc updates.
- **Nit** — style, minor improvements (keep these brief).

For each finding, include the file path, line range, and a concrete suggestion.
If the review is clean, say so explicitly.
