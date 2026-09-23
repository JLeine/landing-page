# landing-page

Source of my personal landing page at [leine.info](https://leine.info/).

A single, self-contained `index.html` — no build step, no dependencies, no JavaScript. It includes
dark-mode support via `prefers-color-scheme`, CSS scroll-driven reveal animations
(progressively enhanced, degrades gracefully) and links to my professional profiles.
The profile picture is self-hosted as `avatar.jpg`.

## Usage

Open `index.html` directly in a browser, or serve the directory:

```sh
python3 -m http.server
```

## License

[MIT](LICENSE)
