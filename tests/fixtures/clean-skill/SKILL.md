---
name: commit-message-helper
description: Writes clear commit messages following Conventional Commits from a diff or a description of changes. Use it when the user asks for a commit message or a summary of changes for a repository.
---

# Commit message helper

Generates a commit message from the changes the user describes.

## Steps

1. Read the diff or the description of changes the user provides.
2. Pick the type (`feat`, `fix`, `docs`, `refactor`, `test`, `chore`).
3. Write a summary under 72 characters, in the imperative mood.
4. Add a short body only if the change needs context.

To count the lines of a diff you can use `scripts/count_lines.py`.
