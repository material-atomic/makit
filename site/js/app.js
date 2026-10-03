// Copy buttons: <button class="copy" data-copy="text"> or next to a <code>.
function copyText(text, btn) {
  const done = () => {
    btn.classList.add('done');
    btn.textContent = 'Copied';
    setTimeout(() => { btn.classList.remove('done'); btn.textContent = 'Copy'; }, 1600);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, () => fallback(text) && done());
  } else if (fallback(text)) {
    done();
  }
}

function fallback(text) {
  const t = document.createElement('textarea');
  t.value = text;
  t.style.position = 'fixed';
  t.style.opacity = '0';
  document.body.appendChild(t);
  t.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
  t.remove();
  return ok;
}

document.addEventListener('click', (e) => {
  const btn = e.target.closest('.copy');
  if (!btn) return;
  const text = btn.dataset.copy || btn.parentElement.querySelector('code').innerText;
  copyText(text.trim(), btn);
});

// Links that leave this site open in a new tab — on every page, including content rendered later (docs).
function isExternal(a) {
  try {
    const u = new URL(a.getAttribute('href'), location.href);
    return /^https?:$/.test(u.protocol) && u.host !== location.host;
  } catch (e) {
    return false;
  }
}

function markExternal(root) {
  root.querySelectorAll('a[href]').forEach((a) => {
    if (isExternal(a)) {
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
    }
  });
}

markExternal(document);
new MutationObserver((changes) => {
  changes.forEach((c) => c.addedNodes.forEach((n) => { if (n.nodeType === 1) markExternal(n.matches('a') ? n.parentNode : n); }));
}).observe(document.body, { childList: true, subtree: true });

// The header menu on phones: the links fold behind a button (CSS shows it under 720px). Closes on a link, outside, Esc.
(() => {
  const top = document.querySelector('header.top');
  const nav = top && top.querySelector('nav');
  if (!nav) return;
  nav.id = nav.id || 'site-nav';
  const btn = document.createElement('button');
  btn.className = 'nav-toggle';
  btn.setAttribute('aria-controls', nav.id);
  const lines = (open) => `<svg viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" focusable="false"><path d="${open
    ? 'M6 6l12 12M18 6L6 18' : 'M4 7h16M4 12h16M4 17h16'}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`;
  const set = (open) => {
    top.classList.toggle('open', open);
    btn.setAttribute('aria-expanded', String(open));
    btn.setAttribute('aria-label', open ? 'Close menu' : 'Menu');
    btn.innerHTML = lines(open);
  };
  set(false);
  nav.before(btn);
  top.classList.add('menu');
  btn.addEventListener('click', () => set(!top.classList.contains('open')));
  nav.addEventListener('click', (e) => { if (e.target.closest('a')) set(false); });
  // composedPath, not contains(): the button's icon is redrawn on click, so the clicked node is no longer in the page.
  document.addEventListener('click', (e) => { if (!e.composedPath().includes(top)) set(false); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && top.classList.contains('open')) { set(false); btn.focus(); } });
})();
