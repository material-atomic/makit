# makit.sh pages kept in the repository

The website (makit.sh) is served from a RunSnip project; most of it is static and edited there. The config
playground is versioned here because it depends on the release: its WebAssembly (`scripts/playground.sh`, makit's own
config check with the catalog) is published on the `playground` branch by `.github/workflows/playground.yml`, and the
page loads it through jsDelivr. At a release, upload these three files next to the others:

- `playground.html`
- `js/playground.js`
- `css/playground.css`

Try it locally: `scripts/playground.sh`, copy `dist/playground/` to `site/playground/` with the site's `css/style.css`
and `js/app.js`, and serve `site/` on `http://127.0.0.1` (the page then loads the WebAssembly from `playground/`).
