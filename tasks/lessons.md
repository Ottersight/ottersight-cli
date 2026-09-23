# Lessons

Patterns learned from corrections. Review at session start. One entry per lesson:
what went wrong, the rule that prevents it.

## 2026-09-23 — Stacked PRs and `--delete-branch`

- **What went wrong:** PR #12 targeted the branch of PR #11. Merging #11 with `gh pr merge --delete-branch` deleted that base branch, GitHub closed #12, and it could not be reopened or retargeted (even after recreating the branch). Replaced by #13.
- **Rule:** Before merging a PR whose branch is the base of another PR, first retarget the dependent PR (`gh pr edit <n> --base main`), or merge without `--delete-branch`. Prefer rebasing the follow-up onto `main` over stacking when both will merge the same day.

