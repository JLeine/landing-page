# AGENTS.md

Personal landing page for [leine.info](https://leine.info/) — a single self-contained `index.html` (inline CSS/JS, no build step, no dependencies, no tests or linters).

## Preview

```sh
python3 -m http.server   # then open http://localhost:8000
```

There is no build, test, lint, typecheck, or codegen command. Verify changes by opening the page in a browser.

## Deploy (destructive — read before committing)

Pushing to `main` runs `.github/workflows/deploy.yml`, which mirrors the repo to Hetzner `public_html/` over FTPS with `--delete`. The repo is the source of truth: removing a file deletes it from the live site, and **any file not excluded below is published publicly**.

Excluded from upload: `.git`, `.github`, `.gitignore`, `README.md`, `LICENSE`, `_site`. `.htaccess` **is** uploaded.

Work on a feature branch and merge to `main` via PR (see git history); only the `main` push deploys. Renovate opens PRs for GitHub Actions version bumps.

## Constraints

- **No external assets.** The CSP in `.htaccess` restricts `default-src`/`style-src`/`script-src` to `'self'` plus inline (`'unsafe-inline'`). Avoid CDNs, external fonts, or third-party scripts; inline CSS/JS is expected.
- **HSTS is intentionally not set** in `.htaccess`. Do not add it unless the user explicitly asks.
- Everything is deployed as-is, so keep dotfiles/config files out of the site root unless intended.

## Commit messages

Use Conventional Commits: `<type>(<optional scope>): <imperative subject>`, e.g. `docs: add commit message guidance`, `fix: correct dark-mode button contrast`. Common types: `feat`, `fix`, `docs`, `chore`, `refactor`, `perf`. Note the existing `git log` predates this convention.

## Gotchas

- Avatar is served via responsive variants referenced in `index.html`: `avatar-160/320.{jpg,webp}` (with `<picture>`/`srcset`). `avatar.jpg` is only referenced by JSON-LD; `og-image.png` is the social card image. Replacing the photo means regenerating **all** variants, not just `avatar.jpg`.
- `www.leine.info` → `leine.info` and `/index.html` → `/` redirects live in `.htaccess`.
- Repo convention: avoid literal em dashes in content — use hyphens or HTML entities (see `git log`).
