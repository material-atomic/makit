// The "In your terminal" carousel: the current screen in front, its neighbours turned away in 3D. It turns by itself
// every few seconds — paused while the pointer is on it, while it is off screen, or by its pause button — and picks
// up again a few seconds after someone used the arrows, dots, keys or a swipe. With reduced motion it fades instead.
(() => {
  const root = document.getElementById('shots');
  if (!root) return;
  const EVERY = 4500;  // ms per screen
  const RESUME = 6000; // ms after a manual change before turning again
  const slides = [...root.querySelectorAll('.slide')];
  const cap = root.querySelector('.cap');
  const dots = root.querySelector('.dots');
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const n = slides.length;
  // Lighter copies for the carousel (1600 px WebP); the link keeps the full-size capture.
  slides.forEach((s) => {
    const img = s.querySelector('img');
    if (img && !/\/web\//.test(img.src)) img.src = img.src.replace('/terminal/', '/terminal/web/').replace(/\.png$/, '.webp');
    if (img && img.decode) img.decode().catch(() => {});
  });
  const pos = new Array(n).fill(null); // each slide's last offset from the front one
  let cur = 0;
  let timer = null;
  let hover = false;
  let visible = false;
  let paused = false; // by the button
  let resumeAt = 0;
  root.style.setProperty('--every', `${EVERY}ms`);

  slides.forEach((s, i) => {
    const b = document.createElement('button');
    b.setAttribute('aria-label', `Screen ${i + 1} of ${n}`);
    b.addEventListener('click', () => manual(i));
    dots.append(b);
  });
  const toggle = document.createElement('button');
  toggle.className = 'play';
  const controls = document.createElement('div'); // dots and the pause button on one centred row
  controls.className = 'controls';
  dots.before(controls);
  controls.append(dots, toggle);
  toggle.addEventListener('click', () => { paused = !paused; update(); });

  function place() {
    const narrow = root.clientWidth < 640;
    slides.forEach((s, i) => {
      let d = i - cur;
      if (d > n / 2) d -= n;
      if (d < -n / 2) d += n;
      const a = Math.abs(d);
      // A slide going round the back (from one end to the other) jumps there unseen instead of flying across.
      const jump = pos[i] !== null && Math.abs(d - pos[i]) > 1;
      pos[i] = d;
      if (jump) s.style.transition = 'none';
      s.classList.toggle('on', d === 0);
      s.setAttribute('aria-hidden', d === 0 ? 'false' : 'true');
      s.querySelectorAll('a').forEach((x) => (x.tabIndex = d === 0 ? 0 : -1));
      if (still) { // reduced motion: a soft crossfade in place, no travel and no turn
        s.style.transform = `translateX(-50%) scale(${d === 0 ? 1 : 0.97})`;
        s.style.opacity = d === 0 ? 1 : 0;
        s.style.zIndex = d === 0 ? 10 : 0;
        s.style.pointerEvents = d === 0 ? 'auto' : 'none';
        return;
      }
      const x = d * (narrow ? 34 : 44);
      s.style.transform = `translateX(calc(-50% + ${x}%)) translateZ(${-a * 220}px) rotateY(${-d * 32}deg)`;
      s.style.opacity = a > 2 ? 0 : 1;
      s.style.setProperty('--shade', Math.min(a * 0.38, 0.8)); // dimmed by an overlay: opacity only, no filter
      s.style.zIndex = 10 - a;
      s.style.pointerEvents = a > 2 ? 'none' : 'auto';
      if (jump) { void s.offsetWidth; s.style.transition = ''; }
    });
    [...dots.children].forEach((b, i) => {
      b.classList.remove('on');
      if (i === cur) { void b.offsetWidth; b.classList.add('on'); } // restart the progress bar
    });
    const fc = slides[cur].querySelector('figcaption');
    cap.innerHTML = fc ? fc.innerHTML : '';
  }

  // One timer, re-armed on every change: the dot's progress bar and the turn stay in step.
  function update() {
    clearTimeout(timer);
    const running = visible && !hover && !paused && !document.hidden;
    root.classList.toggle('running', running);
    toggle.textContent = paused ? '▶' : '⏸';
    toggle.setAttribute('aria-label', paused ? 'Play' : 'Pause');
    if (!running) return;
    const wait = Math.max(EVERY, resumeAt - Date.now());
    timer = setTimeout(() => { cur = (cur + 1) % n; place(); update(); }, wait);
  }
  function go(i) { cur = (i + n) % n; place(); update(); }
  function manual(i) { resumeAt = Date.now() + RESUME; go(i); }

  root.querySelector('.prev').addEventListener('click', () => manual(cur - 1));
  root.querySelector('.next').addEventListener('click', () => manual(cur + 1));
  slides.forEach((s, i) => s.addEventListener('click', (e) => {
    if (i !== cur) { e.preventDefault(); manual(i); } // a neighbour comes to the front; the front one opens
  }));
  root.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowLeft') manual(cur - 1);
    if (e.key === 'ArrowRight') manual(cur + 1);
  });
  let x0 = null;
  root.addEventListener('touchstart', (e) => { x0 = e.touches[0].clientX; }, { passive: true });
  root.addEventListener('touchend', (e) => {
    if (x0 === null) return;
    const dx = e.changedTouches[0].clientX - x0;
    if (Math.abs(dx) > 40) manual(cur + (dx < 0 ? 1 : -1));
    x0 = null;
  });
  // Pause only while the pointer is on the screens themselves (not on the arrows or dots).
  const stage = root.querySelector('.stage');
  stage.addEventListener('mouseenter', () => { hover = true; update(); });
  stage.addEventListener('mouseleave', () => { hover = false; update(); });
  document.addEventListener('visibilitychange', update);
  addEventListener('resize', place);
  new IntersectionObserver((es) => es.forEach((e) => { visible = e.isIntersecting; update(); }), { threshold: 0.25 }).observe(root);
  place();
  update();
})();
