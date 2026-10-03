# makit.sh pages kept in the repository

The website (makit.sh) is served from a RunSnip project; most of it is static and edited there. The config
playground is versioned here because it depends on the release: its WebAssembly (`scripts/playground.sh`, makit's own
config check with the catalog) is published on the `playground` branch by `.github/workflows/playground.yml`, and the
page loads it through jsDelivr. At a release, upload these three files next to the others:

- `playground.html`
- `js/playground.js`
- `css/playground.css`

Where the browser has WebMCP (`document.modelContext`; Chrome 154 with the "WebMCP for testing" flag, or
`--enable-features=WebMCP`), the playground also offers its check to the visitor's AI agent as tools:
`makit_check_shield_config`, `makit_get_shield_config`, `makit_set_shield_config`, `makit_load_preset`, `makit_catalog`
and `makit_export_shield_config`. They run in the page like the buttons do — nothing is sent anywhere — and a note under
the title says so only when they registered. Elsewhere the page is unchanged.

Also kept here, as uploaded to makit.sh: `css/style.css` (the whole site, dark only) and `js/shots.js` (the 3D carousel
of terminal captures on the home page; the images come from `docs/img/terminal/web/` through jsDelivr).

Try it locally: `scripts/playground.sh`, copy `dist/playground/` to `site/playground/` with the site's `css/style.css`
and `js/app.js`, and serve `site/` on `http://127.0.0.1` (the page then loads the WebAssembly from `playground/`).
