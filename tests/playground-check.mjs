// The playground's WebAssembly answers like `makit shield config check`: run by tests/playground.sh after
// scripts/playground.sh, in Node (the same file the browser loads).
import fs from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
require(`${process.argv[2]}/lib/wasm/wasm_exec.js`);
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(fs.readFileSync(process.argv[3]), go.importObject);
go.run(instance);
let fail = 0;
const expect = (what, ok) => { console.log(`  ${ok ? '✓' : '✗'} ${what}`); if (!ok) fail = 1; };
const check = (y, o) => JSON.parse(globalThis.makitCheck(y, o));
expect('a valid config is valid, with [] issues', (() => { const r = check('mode: observe\n'); return r.valid && Array.isArray(r.issues) && !r.issues.length; })());
const typo = check('trusted_proxy: [vpc]\n');
expect('a misspelt key is an error with its line and the right name', !typo.valid && typo.issues[0].line === 1 && typo.issues[0].message.includes('trusted_proxies'));
const bot = check('bots:\n  policy:\n    ai-crawler: maybe\n');
expect('the embedded catalog is used: an unknown bot action is an error', !bot.valid && bot.issues.some((i) => i.message.includes('maybe')));
expect('a config for pods is valid in the playground', check('admin: 0.0.0.0:9180\ncluster: { listen: ":9181", peers: ["dns:a.b.svc:9181"] }\n', { kubernetes: true }).valid
  && !check('admin: 0.0.0.0:9180\ncluster: { listen: ":9181", peers: ["dns:a.b.svc:9181"] }\n', { kubernetes: true }).issues.length);
const cat = JSON.parse(globalThis.makitCatalog());
expect('the catalog lists bot categories, score levels and rules', Object.keys(cat.bot_categories).length > 5 && cat.score_http.levels.length >= 3 && cat.rules.length > 0);
const t0 = performance.now();
for (let i = 0; i < 50; i++) check('mode: block\ntrusted_proxies: [cloudflare]\nsites:\n  - match: [a.example]\n');
console.log(`  (${((performance.now() - t0) / 50).toFixed(1)} ms per check)`);
process.exit(fail);
