# landing-page

Source of my personal landing page at [leine.info](https://leine.info/).

A single, self-contained `index.html` — no build step, no dependencies. It includes
dark-mode support via `prefers-color-scheme`, scroll reveal animations (a few lines of
vanilla JS via `IntersectionObserver`, degrades gracefully with JS disabled) and links
to my professional profiles. The profile picture is self-hosted as `avatar.jpg`.

## Usage

Open `index.html` directly in a browser, or serve the directory:

```sh
python3 -m http.server
```

## Deployment

Merging to `main` triggers [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml),
which mirrors the site to the `public_html` folder of the Hetzner web hosting account
over FTPS using `lftp`. The repository is the source of truth: the target is mirrored
with `--delete`, so files removed from the repo are removed from the server too.

Only website files are uploaded — `.git*`, `.github*`, `README.md` and `LICENSE` are excluded.

### Required repository secrets

Add these under *Settings → Secrets and variables → Actions*:

| Secret | Required | Description |
|--------|----------|-------------|
| `FTP_SERVER` | yes | FTP host, e.g. `www123.hosting.com` |
| `FTP_USERNAME` | yes | FTP user |
| `FTP_PASSWORD` | yes | FTP password |
| `FTP_PORT` | no | FTP port, defaults to `21` |

Notes:

- Use a dedicated FTP sub-account whose root is the website directory if your hosting
  package supports it.
- FTPS is enforced (`ftp:ssl-force`). If your server uses a self-signed or mismatched
  certificate, certificate verification can be disabled by removing
  `set ssl:verify-certificate yes` from the workflow — this weakens transport security,
  so prefer fixing the certificate.
- Passwords containing `"`, `` ` ``, `$` or `\` may break the inline `lftp` command;
  pick a password made of letters, digits and common symbols.

## License

[MIT](LICENSE)
