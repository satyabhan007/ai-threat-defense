/**
 * ============================================================
 * app.js — AI Threat Defense Interactive Course Engine
 * ============================================================
 *
 * ARCHITECTURE (for agents reading this file):
 * ─────────────────────────────────────────────
 * This is a Single-Page Application (SPA) with two views:
 *
 *   1. HOME VIEW  (#view-home)
 *      - Chapter cards grid (from COURSE_DATA in course-data.js)
 *      - Overall progress bar
 *      - Jev Analysis section (pre-computed, no API key needed)
 *
 *   2. CHAPTER VIEW  (#view-chapter)
 *      - 5 level tabs (Analyst → Expert), unlocked progressively
 *      - Level content: analogy callout, body text, code block, link
 *      - Checkpoint quiz at Expert level (3 questions)
 *      - Prev/Next level navigation
 *
 * PROGRESS MODEL:
 *   localStorage key: "atd_progress"
 *   Value: JSON object { [chapterId]: levelReached }
 *     levelReached: 0 = not started, 1-4 = levels unlocked, 5 = quiz passed
 *
 * DATA DEPENDENCIES:
 *   window.COURSE_DATA — loaded by course-data.js (must be before app.js)
 *   window.PRECOMPUTED_JEV — Jev scores defined in this file below
 *
 * VIEW SWITCHING:
 *   showHome()   — shows #view-home, hides #view-chapter
 *   showChapter(chapterIndex) — reverse; renders the selected chapter
 *
 * ============================================================
 * FILE STRUCTURE:
 *   1. Constants & state
 *   2. ComfyUI canvas animation
 *   3. Progress persistence (localStorage)
 *   4. Home view render
 *   5. Chapter view render
 *   6. Level tab logic
 *   7. Quiz logic
 *   8. Jev analysis render (no API key, pre-computed)
 *   9. Boot (DOMContentLoaded)
 * ============================================================
 */

/* ══════════════════════════════════════════════════════════════════════
   1. CONSTANTS & STATE
   ══════════════════════════════════════════════════════════════════════ */

/** Pre-computed Jev results (jev-latest · 2026-09-21 · topic: ML Security).
 *  These are real scores from the API — no key needed to view them.
 *  Structure matches /tmp/jev_results.json */
const PRECOMPUTED_JEV = {
  topic: 'ML Security & Threat Detection — Senior ML Engineer',
  composite_avg: 80,
  industry_fit_chapters: 8,
  chapters: [
    { id:'ch01', composite:86, relevance_score:2.94, relevance_confidence:0.94,
      relevance_probabilities:{'0':0.00,'1':0.00,'2':0.06,'3':0.94},
      readiness_score:2.01, readiness_confidence:0.52, industry_fit_probability:0.50 },
    { id:'ch02', composite:83, relevance_score:2.61, relevance_confidence:0.61,
      relevance_probabilities:{'0':0.00,'1':0.00,'2':0.39,'3':0.61},
      readiness_score:2.32, readiness_confidence:0.32, industry_fit_probability:0.50 },
    { id:'ch03', composite:76, relevance_score:2.40, relevance_confidence:0.58,
      relevance_probabilities:{'0':0.00,'1':0.01,'2':0.58,'3':0.41},
      readiness_score:2.08, readiness_confidence:0.90, industry_fit_probability:0.50 },
    { id:'ch04', composite:76, relevance_score:2.25, relevance_confidence:0.73,
      relevance_probabilities:{'0':0.00,'1':0.01,'2':0.73,'3':0.26},
      readiness_score:2.30, readiness_confidence:0.30, industry_fit_probability:0.50 },
    { id:'ch05', composite:82, relevance_score:2.24, relevance_confidence:0.61,
      relevance_probabilities:{'0':0.00,'1':0.08,'2':0.60,'3':0.32},
      readiness_score:2.78, readiness_confidence:0.78, industry_fit_probability:0.50 },
    { id:'ch06', composite:82, relevance_score:2.83, relevance_confidence:0.83,
      relevance_probabilities:{'0':0.00,'1':0.00,'2':0.17,'3':0.83},
      readiness_score:1.90, readiness_confidence:0.00, industry_fit_probability:0.50 },
    { id:'ch07', composite:71, relevance_score:2.15, relevance_confidence:0.72,
      relevance_probabilities:{'0':0.00,'1':0.06,'2':0.72,'3':0.22},
      readiness_score:2.13, readiness_confidence:0.70, industry_fit_probability:0.50 },
    { id:'ch08', composite:83, relevance_score:2.68, relevance_confidence:0.68,
      relevance_probabilities:{'0':0.00,'1':0.01,'2':0.29,'3':0.70},
      readiness_score:2.22, readiness_confidence:0.22, industry_fit_probability:0.50 },
  ],
};

/** Level names and icons — index 0..4 maps to Analyst→Expert */
const LEVELS = [
  { name: 'Analyst',      icon: '🔍' },
  { name: 'Practitioner', icon: '⚙️' },
  { name: 'Builder',      icon: '🔧' },
  { name: 'Advanced',     icon: '🚀' },
  { name: 'Expert',       icon: '🏆' },
];

// Mutable state
let currentChapterIndex = -1;  // which chapter is open (-1 = home)
let currentLevelIndex   = 0;   // which level tab is active (0-4)
let quizAnswers         = {};   // { questionIndex: selectedOption }
let quizSubmitted       = false;

/* ══════════════════════════════════════════════════════════════════════
   2. AURORA PULSE BACKGROUND
   ══════════════════════════════════════════════════════════════════════
   Simple, ecstatic "focus mode" background:
   - Fine 30px dot-matrix blueprint grid
   - 6 large slow-drifting aurora orbs with gaussian aura
   - 4 flowing sine-curve data streams with traveling comet particles
   - Soft cursor radial glow
   - Focus mode: CSS body.in-chapter → #nodeCanvas { opacity: 0.08 }
   No heavy node cards — visual complexity is ZERO in chapter view.
   ══════════════════════════════════════════════════════════════════════ */
class NodeGraph {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx    = canvas.getContext('2d');
    this.mouse  = { x: -9999, y: -9999, active: false };
    this.W = this.H = 0;
    this.orbs    = [];
    this.streams = [];
    this.raf     = null;

    this._resize();
    this._init();

    window.addEventListener('resize', () => { this._resize(); this._init(); });
    window.addEventListener('pointermove', e => { this.mouse.x = e.clientX; this.mouse.y = e.clientY; this.mouse.active = true; });
    window.addEventListener('pointerleave', () => { this.mouse.active = false; });
  }

  _resize() {
    this.W = this.canvas.width  = window.innerWidth;
    this.H = this.canvas.height = window.innerHeight;
  }

  _init() {
    const W = this.W, H = this.H;

    // 6 aurora orbs — slow, large, deeply blurred
    this.orbs = [
      { cx: W * 0.15, cy: H * 0.25, r: W * 0.22, hue: 186, alpha: 0.06, speed: 0.00018, px: 0.0, py: 2.1 },
      { cx: W * 0.75, cy: H * 0.20, r: W * 0.19, hue: 262, alpha: 0.05, speed: 0.00022, px: 1.1, py: 0.4 },
      { cx: W * 0.50, cy: H * 0.70, r: W * 0.25, hue: 142, alpha: 0.05, speed: 0.00015, px: 3.3, py: 1.0 },
      { cx: W * 0.88, cy: H * 0.75, r: W * 0.18, hue: 310, alpha: 0.04, speed: 0.00020, px: 0.7, py: 3.2 },
      { cx: W * 0.30, cy: H * 0.80, r: W * 0.16, hue:  28, alpha: 0.04, speed: 0.00017, px: 2.0, py: 0.9 },
      { cx: W * 0.65, cy: H * 0.45, r: W * 0.20, hue: 186, alpha: 0.03, speed: 0.00013, px: 1.8, py: 2.7 },
    ];

    // 4 sine-wave data streams
    const hues = [186, 262, 142, 310];
    this.streams = hues.map((hue, i) => ({
      hue,
      yBase:    H * (0.18 + i * 0.20),
      amp:      18 + i * 8,
      freq:     0.008 - i * 0.001,
      speed:    0.00022 + i * 0.00006,
      particles: [0, 0.33, 0.67],
    }));
  }

  /* Fine 30-px dot grid */
  _drawGrid(ctx) {
    const step = 30;
    ctx.fillStyle = 'rgba(255,255,255,0.025)';
    for (let x = 0; x < this.W; x += step)
      for (let y = 0; y < this.H; y += step)
        ctx.fillRect(x, y, 1, 1);
  }

  /* Aurora orb — radial gradient with enormous radius, very low alpha */
  _drawOrb(ctx, orb, t) {
    const drift = 38;
    const x = orb.cx + Math.sin(t * orb.speed + orb.px) * drift;
    const y = orb.cy + Math.cos(t * orb.speed + orb.py) * drift;
    const pulse = orb.alpha + 0.012 * Math.sin(t * 0.0009 + orb.px);

    const g = ctx.createRadialGradient(x, y, 0, x, y, orb.r);
    g.addColorStop(0,   `hsla(${orb.hue},100%,60%,${pulse})`);
    g.addColorStop(0.4, `hsla(${orb.hue},90%,50%,${pulse * 0.45})`);
    g.addColorStop(1,   `hsla(${orb.hue},80%,40%,0)`);
    ctx.fillStyle = g;
    ctx.beginPath();
    ctx.arc(x, y, orb.r, 0, Math.PI * 2);
    ctx.fill();
  }

  /* Sine-wave stream with comet particles */
  _drawStream(ctx, s, t) {
    const W = this.W;
    // Draw the sine path
    ctx.beginPath();
    for (let x = 0; x <= W; x += 3) {
      const y = s.yBase + Math.sin(x * s.freq + t * 0.0008) * s.amp;
      x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.strokeStyle = `hsla(${s.hue},100%,65%,0.10)`;
    ctx.lineWidth   = 1;
    ctx.stroke();

    // Comet particles along the sine curve
    for (const offset of s.particles) {
      const prog = ((t * s.speed + offset) % 1);
      const px   = prog * W;
      const py   = s.yBase + Math.sin(px * s.freq + t * 0.0008) * s.amp;

      // Tail
      for (let tail = 4; tail >= 0; tail--) {
        const tp   = Math.max(0, prog - tail * 0.018);
        const tx   = tp * W;
        const ty   = s.yBase + Math.sin(tx * s.freq + t * 0.0008) * s.amp;
        const tr   = tail === 0 ? 2.5 : (1.8 - tail * 0.3);
        const ta   = tail === 0 ? 0.90 : (0.45 - tail * 0.09);
        ctx.beginPath();
        ctx.arc(tx, ty, Math.max(0.5, tr), 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${s.hue},100%,${tail===0?90:70}%,${ta})`;
        if (tail === 0) { ctx.shadowColor = `hsla(${s.hue},100%,80%,0.8)`; ctx.shadowBlur = 7; }
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }
  }

  _draw(t) {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.W, this.H);

    // 1. Dot grid
    this._drawGrid(ctx);

    // 2. Aurora orbs (order: back to front)
    for (const orb of this.orbs) this._drawOrb(ctx, orb, t);

    // 3. Sine data streams
    for (const s of this.streams) this._drawStream(ctx, s, t);

    // 4. Cursor soft glow (very subtle)
    if (this.mouse.active) {
      const g = ctx.createRadialGradient(this.mouse.x, this.mouse.y, 0, this.mouse.x, this.mouse.y, 180);
      g.addColorStop(0,   'rgba(121,40,202,0.07)');
      g.addColorStop(0.6, 'rgba(0,242,254,0.03)');
      g.addColorStop(1,   'rgba(0,0,0,0)');
      ctx.fillStyle = g;
      ctx.fillRect(this.mouse.x - 180, this.mouse.y - 180, 360, 360);
    }
  }

  start() {
    const loop = (t) => { this._draw(t); this.raf = requestAnimationFrame(loop); };
    this.raf = requestAnimationFrame(loop);
  }
}

/* ══════════════════════════════════════════════════════════════════════
   3. PROGRESS PERSISTENCE
   ══════════════════════════════════════════════════════════════════════
   Progress is stored as { [chapterId]: levelReached } where:
     0 = not started (no levels completed)
     1 = Analyst completed
     2 = Practitioner completed
     3 = Builder completed
     4 = Advanced completed
     5 = Expert + quiz passed (chapter complete)
   ══════════════════════════════════════════════════════════════════════ */

const STORAGE_KEY = 'atd_progress';

/** Load progress from localStorage. Returns {} if none saved. */
function loadProgress() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
  } catch {
    return {};
  }
}

/** Save progress to localStorage. */
function saveProgress(progress) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(progress));
}

/** Get the number of levels reached for a chapter (0-5). */
function getChapterProgress(chId) {
  const p = loadProgress();
  return p[chId] || 0;
}

/** Advance a chapter's progress by one level (up to 5). */
function advanceLevelProgress(chId, toLevel) {
  const p = loadProgress();
  p[chId] = Math.max(p[chId] || 0, toLevel);
  saveProgress(p);
  updateOverallProgress();
}

/** Compute total completed chapters (progress === 5) and update UI. */
function updateOverallProgress() {
  const p = loadProgress();
  const total     = window.COURSE_DATA.length;
  const completed = Object.values(p).filter(v => v >= 5).length;
  const pct       = Math.round((completed / total) * 100);

  // Navbar mini bar
  const fill  = document.getElementById('overall-progress-fill');
  const label = document.getElementById('overall-progress-label');
  if (fill)  fill.style.width = pct + '%';
  if (label) label.textContent = `${completed}/${total} chapters`;

  // Home hero bar
  const homeFill  = document.getElementById('home-prog-fill');
  const homeLabel = document.getElementById('home-prog-text');
  if (homeFill)  homeFill.style.width = pct + '%';
  if (homeLabel) homeLabel.textContent = `Overall progress: ${pct}% · ${completed}/${total} chapters completed — pick any chapter below`;
}

/* ══════════════════════════════════════════════════════════════════════
   4. VIEW SWITCHING
   ══════════════════════════════════════════════════════════════════════ */

/** Show the home view (chapter grid + Jev analysis). */
function showHome() {
  document.body.classList.remove('in-chapter');
  document.getElementById('view-home').classList.remove('hidden');
  document.getElementById('view-chapter').classList.add('hidden');
  document.getElementById('breadcrumb').classList.add('hidden');
  document.getElementById('overall-progress-wrap').classList.remove('hidden');
  currentChapterIndex = -1;
  updateOverallProgress();
  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/** Show the chapter view for chapterIndex (0-7). */
function showChapter(chIndex) {
  document.body.classList.add('in-chapter');
  currentChapterIndex = chIndex;
  currentLevelIndex   = 0;
  quizAnswers         = {};
  quizSubmitted       = false;

  document.getElementById('view-home').classList.add('hidden');
  document.getElementById('view-chapter').classList.remove('hidden');
  document.getElementById('breadcrumb').classList.remove('hidden');
  document.getElementById('overall-progress-wrap').classList.add('hidden');

  const ch = window.COURSE_DATA[chIndex];
  document.getElementById('breadcrumb-chapter').textContent = `${ch.icon} ${ch.title}`;

  // Render the chapter header and first level
  renderChapterHeader(ch);
  renderLevelTabs(ch, chIndex);
  renderLevel(ch, chIndex, 0);
  updateLevelNavButtons(chIndex, 0);

  window.scrollTo({ top: 0, behavior: 'instant' });
}

/* ══════════════════════════════════════════════════════════════════════
   5. HOME VIEW RENDER
   ══════════════════════════════════════════════════════════════════════ */

/** Build the chapter cards grid on the home page. */
function renderChapterCards() {
  const grid = document.getElementById('chapters-grid');
  if (!grid) return;

  grid.innerHTML = window.COURSE_DATA.map((ch, idx) => {
    const prog     = getChapterProgress(ch.id);  // 0-5
    const pct      = Math.round((prog / 5) * 100);
    const done     = prog >= 5;
    const started  = prog > 0;
    const jevData  = PRECOMPUTED_JEV.chapters.find(c => c.id === ch.id);
    const jevScore = jevData ? jevData.composite : '--';

    // Badge: "Complete ✓" | "In Progress" | level number
    let badge = '';
    if (done)         badge = `<span class="ch-badge done">✓ Complete</span>`;
    else if (started) badge = `<span class="ch-badge inprog">L${prog} reached</span>`;

    // Progress dots (5 dots, filled up to prog)
    const dots = Array.from({ length: 5 }, (_, i) =>
      `<span class="prog-dot ${i < prog ? 'filled' : ''}"></span>`
    ).join('');

    return `
      <button class="chapter-card ${done ? 'done' : ''}" data-ch="${idx}" id="card-${ch.id}">
        <div class="card-top">
          <div class="card-icon">${ch.icon}</div>
          <div class="card-meta">
            <span class="card-tag">${ch.tag}</span>
            ${badge}
          </div>
          <div class="card-jev-score" title="Jev ML Security score">
            <span class="jev-mini-score">${jevScore}</span>
            <span class="jev-mini-label">/100</span>
          </div>
        </div>
        <h3 class="card-num-title"><span class="card-num">${ch.num}.</span> ${ch.title}</h3>
        <p class="card-subtitle">${ch.subtitle}</p>
        <div class="card-use-cases">
          ${ch.useCases.map(u => `<span class="use-case-tag">${u}</span>`).join('')}
        </div>
        <div class="card-progress-dots">${dots}</div>
        <div class="card-progress-bar-wrap">
          <div class="card-progress-bar" style="width:${pct}%"></div>
        </div>
      </button>
    `;
  }).join('');

  // Attach click handlers
  grid.querySelectorAll('[data-ch]').forEach(btn => {
    btn.addEventListener('click', () => showChapter(parseInt(btn.dataset.ch, 10)));
  });
}

/* ══════════════════════════════════════════════════════════════════════
   6. CHAPTER VIEW RENDER
   ══════════════════════════════════════════════════════════════════════ */

/** Render the chapter header (icon, tag, title, subtitle, use cases). */
function renderChapterHeader(ch) {
  document.getElementById('ch-eyebrow').innerHTML = `
    <span class="ch-icon">${ch.icon}</span>
    <span class="ch-tag-badge">${ch.tag}</span>
  `;
  document.getElementById('ch-title').textContent    = `${ch.num}. ${ch.title}`;
  document.getElementById('ch-subtitle').textContent = ch.subtitle;
  document.getElementById('ch-use-cases').innerHTML  = ch.useCases
    .map(u => `<span class="use-case-tag">${u}</span>`).join('');
}

/**
 * Render the 5 level tabs, respecting the user's current progress.
 * Levels are "locked" if the previous level hasn't been completed.
 * The first level (Analyst) is always unlocked.
 */
function renderLevelTabs(ch, chIndex) {
  const prog    = getChapterProgress(ch.id);  // levels completed so far
  const tabsEl  = document.getElementById('level-tabs');

  tabsEl.innerHTML = LEVELS.map((lv, i) => {
    const unlocked = i <= prog;               // prog=0 → only tab 0 unlocked
    const active   = i === currentLevelIndex;
    const done     = i < prog || (prog >= 5 && i === 4);
    const lockIcon = done ? '✓' : (unlocked ? '' : '🔒');

    return `
      <button
        class="level-tab ${active ? 'active' : ''} ${done ? 'done' : ''} ${!unlocked ? 'locked' : ''}"
        data-level="${i}"
        ${!unlocked ? 'disabled' : ''}
        id="tab-level-${i}"
      >
        ${lv.icon} ${lv.name} ${lockIcon ? `<span class="tab-lock">${lockIcon}</span>` : ''}
      </button>
    `;
  }).join('');

  // Attach click handlers for unlocked tabs
  tabsEl.querySelectorAll('[data-level]:not([disabled])').forEach(btn => {
    btn.addEventListener('click', () => {
      const lvIdx = parseInt(btn.dataset.level, 10);
      switchLevel(chIndex, lvIdx);
    });
  });
}

/** Switch to a specific level tab within the current chapter. */
function switchLevel(chIndex, lvIdx) {
  currentLevelIndex = lvIdx;
  quizAnswers   = {};
  quizSubmitted = false;
  const ch = window.COURSE_DATA[chIndex];
  renderLevelTabs(ch, chIndex);
  renderLevel(ch, chIndex, lvIdx);
  updateLevelNavButtons(chIndex, lvIdx);
  // Smooth scroll to content
  document.getElementById('level-content').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Render the content for one level.
 * Level 4 (Expert) also shows the chapter quiz after the level content.
 */
function renderLevel(ch, chIndex, lvIdx) {
  const lv      = ch.levels[lvIdx];
  const content = document.getElementById('level-content');

  // Code block (optional)
  const codeBlock = lv.code ? `
    <div class="code-block">
      <div class="code-header">
        <span class="code-lang">${lv.codeLang || 'code'}</span>
        <button class="copy-btn" data-code="${encodeURIComponent(lv.code)}" title="Copy code">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
          Copy
        </button>
      </div>
      <pre><code>${escapeHtml(lv.code)}</code></pre>
    </div>
  ` : '';

  // External link (optional)
  const linkEl = lv.link ? `
    <a href="${lv.link.href}" target="_blank" class="level-code-link">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
        <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
      </svg>
      ${lv.link.label}
    </a>
  ` : '';

  // Callout box (optional — "In your daily life" style)
  const calloutEl = lv.callout ? `
    <div class="level-callout">
      <div class="callout-label">${lv.callout.label}</div>
      <div class="callout-body">${lv.callout.text}</div>
    </div>
  ` : '';

  content.innerHTML = `
    <div class="level-pane" id="level-pane-${lvIdx}">
      <h2 class="level-heading">${LEVELS[lvIdx].icon} ${LEVELS[lvIdx].name}</h2>

      <!-- Analogy callout (orange) — always present -->
      <div class="analogy-box">
        <div class="analogy-label">🔴 ANALOGY</div>
        <p>${lv.analogy}</p>
      </div>

      <!-- Main body text -->
      <div class="level-body">${lv.body}</div>

      ${calloutEl}
      ${codeBlock}
      ${linkEl}
    </div>

    <!-- Quiz rendered at Expert level (index 4) -->
    ${lvIdx === 4 ? renderQuizHTML(ch, chIndex) : ''}
  `;

  // Wire up copy buttons
  content.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const code = decodeURIComponent(btn.dataset.code);
      navigator.clipboard.writeText(code).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy`; }, 2000);
      });
    });
  });

  // Wire up quiz at Expert level
  if (lvIdx === 4) wireQuiz(ch, chIndex);
}

/* ══════════════════════════════════════════════════════════════════════
   7. LEVEL NAVIGATION
   ══════════════════════════════════════════════════════════════════════ */

/** Update Prev / Next level button states. */
function updateLevelNavButtons(chIndex, lvIdx) {
  const prog    = getChapterProgress(window.COURSE_DATA[chIndex].id);
  const prevBtn = document.getElementById('btn-prev-level');
  const nextBtn = document.getElementById('btn-next-level');

  if (!prevBtn || !nextBtn) return;

  // Prev button
  if (lvIdx === 0) {
    prevBtn.textContent = '← All chapters';
    prevBtn.onclick = () => {
      transitionOut(() => showHome());
    };
  } else {
    prevBtn.textContent = '← Previous';
    prevBtn.onclick = () => switchLevel(chIndex, lvIdx - 1);
  }

  // Next button
  if (lvIdx < 4) {
    nextBtn.textContent = 'Next level →';
    nextBtn.style.display = '';
    // Only show if this level has been "unlocked" (user can advance)
    nextBtn.onclick = () => {
      // Mark current level as completed, unlock next
      advanceLevelProgress(window.COURSE_DATA[chIndex].id, lvIdx + 1);
      switchLevel(chIndex, lvIdx + 1);
    };
  } else {
    // Expert level: hide next (quiz completion drives progress)
    nextBtn.style.display = 'none';
  }
}

/* ══════════════════════════════════════════════════════════════════════
   8. QUIZ LOGIC
   ══════════════════════════════════════════════════════════════════════
   The quiz has 3 questions per chapter.
   Each question has 4 options; one correct answer.
   Submitting shows: correct/wrong highlight + explanation for each question.
   Passing (all correct) marks the chapter as fully completed (progress = 5).
   ══════════════════════════════════════════════════════════════════════ */

/** Build the quiz HTML string (inserted at Expert level). */
function renderQuizHTML(ch, chIndex) {
  const prog = getChapterProgress(ch.id);
  const alreadyPassed = prog >= 5;

  const questionsHTML = ch.quiz.map((q, qi) => `
    <div class="quiz-question" id="quiz-q-${qi}">
      <p class="quiz-q-text">${qi + 1}. ${q.q}</p>
      <div class="quiz-options" id="quiz-opts-${qi}">
        ${q.options.map((opt, oi) => `
          <label class="quiz-option" id="quiz-opt-${qi}-${oi}">
            <input type="radio" name="quiz-q-${qi}" value="${oi}" ${alreadyPassed ? 'disabled' : ''}/>
            <span>${opt}</span>
          </label>
        `).join('')}
      </div>
      <div class="quiz-explanation hidden" id="quiz-exp-${qi}">
        <strong>💡 ${q.explain}</strong>
      </div>
    </div>
  `).join('');

  return `
    <div class="quiz-block" id="chapter-quiz">
      <div class="quiz-header">
        <span class="quiz-star">⭐</span>
        <div>
          <h3>Checkpoint — ${ch.title}</h3>
          <p>Answer all 3 correctly to complete this chapter. Explanations appear for every answer.</p>
        </div>
      </div>
      ${alreadyPassed ? '<div class="quiz-passed-banner">✅ You\'ve passed this chapter\'s checkpoint!</div>' : ''}
      <div class="quiz-questions">${questionsHTML}</div>
      ${alreadyPassed ? '' : `
        <button class="quiz-submit-btn" id="quiz-submit">Check my answers</button>
        <div id="quiz-result" class="quiz-result hidden"></div>
      `}
    </div>
  `;
}

/** Wire up quiz interactivity after it's rendered in the DOM. */
function wireQuiz(ch, chIndex) {
  const submitBtn = document.getElementById('quiz-submit');
  if (!submitBtn) return;  // already passed — no submit button

  submitBtn.addEventListener('click', () => {
    if (quizSubmitted) return;

    // Collect selected answers
    const answers = {};
    ch.quiz.forEach((_, qi) => {
      const sel = document.querySelector(`input[name="quiz-q-${qi}"]:checked`);
      if (sel) answers[qi] = parseInt(sel.value, 10);
    });

    // Require all answered
    if (Object.keys(answers).length < ch.quiz.length) {
      const result = document.getElementById('quiz-result');
      result.className = 'quiz-result error';
      result.textContent = 'Please answer all questions before submitting.';
      return;
    }

    quizSubmitted = true;
    let correctCount = 0;

    ch.quiz.forEach((q, qi) => {
      const selected = answers[qi];
      const correct  = q.answer;
      const isRight  = selected === correct;
      if (isRight) correctCount++;

      // Highlight options
      document.querySelectorAll(`#quiz-opts-${qi} .quiz-option`).forEach((label, oi) => {
        label.querySelector('input').disabled = true;
        if (oi === correct) label.classList.add('correct');
        else if (oi === selected && !isRight) label.classList.add('wrong');
      });

      // Show explanation
      const exp = document.getElementById(`quiz-exp-${qi}`);
      if (exp) exp.classList.remove('hidden');
    });

    // Show result
    const result = document.getElementById('quiz-result');
    const passed = correctCount === ch.quiz.length;

    if (passed) {
      result.className = 'quiz-result pass';
      result.innerHTML = `🎉 Perfect score! Chapter complete. <button class="quiz-next-ch-btn" id="quiz-next-ch">→ Next chapter</button>`;
      advanceLevelProgress(ch.id, 5);  // Mark as fully completed
      renderLevelTabs(ch, chIndex);    // Re-render tabs to show completion
      renderChapterCards();            // Update home grid

      // Wire next chapter button
      setTimeout(() => {
        const nextCh = document.getElementById('quiz-next-ch');
        if (nextCh) {
          nextCh.addEventListener('click', () => {
            const nextIdx = chIndex + 1;
            if (nextIdx < window.COURSE_DATA.length) {
              transitionOut(() => showChapter(nextIdx));
            } else {
              transitionOut(() => showHome());
            }
          });
        }
      }, 0);
    } else {
      result.className = 'quiz-result fail';
      result.innerHTML = `${correctCount}/${ch.quiz.length} correct — review the explanations above and try again.`;
      // Re-enable submit after 2s for retry
      setTimeout(() => {
        quizSubmitted = false;
        submitBtn.textContent = 'Try again';
        // Reset radio buttons
        ch.quiz.forEach((_, qi) => {
          document.querySelectorAll(`#quiz-opts-${qi} input`).forEach(inp => inp.disabled = false);
          const opts = document.querySelectorAll(`#quiz-opts-${qi} .quiz-option`);
          opts.forEach(l => { l.classList.remove('correct', 'wrong'); });
          const exp = document.getElementById(`quiz-exp-${qi}`);
          if (exp) exp.classList.add('hidden');
        });
      }, 2000);
    }
  });
}

/* ══════════════════════════════════════════════════════════════════════
   9. PAGE TRANSITION
   ══════════════════════════════════════════════════════════════════════ */
const overlay = document.getElementById('pageTransition');

function transitionOut(callback) {
  overlay.classList.add('active');
  setTimeout(() => {
    callback();
    setTimeout(() => overlay.classList.remove('active'), 300);
  }, 250);
}

/* ══════════════════════════════════════════════════════════════════════
   10. JEV ANALYSIS RENDER (home page, no API key)
   ══════════════════════════════════════════════════════════════════════
   Renders the 8 score cards from PRECOMPUTED_JEV.
   No API key required — scores are baked in.
   ══════════════════════════════════════════════════════════════════════ */

/** Map composite score (0-100) to an HSL colour string. */
function jevColor(score) {
  if (score >= 75) return 'hsl(142,80%,55%)';   // green
  if (score >= 55) return 'hsl(186,100%,55%)';   // cyan
  if (score >= 35) return 'hsl(28,95%,60%)';     // orange
  return 'hsl(0,80%,55%)';                        // red
}

/** Render all 8 Jev score cards into #jev-scores-grid. */
function renderJevCards() {
  const grid = document.getElementById('jev-scores-grid');
  if (!grid) return;

  grid.innerHTML = window.COURSE_DATA.map(ch => {
    const data  = PRECOMPUTED_JEV.chapters.find(c => c.id === ch.id);
    if (!data) return '';

    const color  = jevColor(data.composite);
    const circ   = 163;
    const offset = circ - (data.composite / 100) * circ;

    // Probability bars for relevance levels
    const levels = ['Unrelated', 'Adjacent', 'Direct', 'Core'];
    const probBars = Object.entries(data.relevance_probabilities)
      .sort((a, b) => +a[0] - +b[0])
      .map(([k, v]) => `
        <div class="jev-prob-row">
          <span class="jev-prob-label">${levels[+k]}</span>
          <div class="jev-prob-bar-wrap">
            <div class="jev-prob-bar-fill" style="width:${Math.round(v*100)}%;background:${color}"></div>
          </div>
          <span class="jev-prob-pct">${Math.round(v*100)}%</span>
        </div>
      `).join('');

    const avgConf = ((data.relevance_confidence + data.readiness_confidence) / 2);
    const confClass = avgConf >= 0.65 ? 'conf-high' : (avgConf >= 0.35 ? 'conf-medium' : 'conf-low');
    const noulYes = data.industry_fit_probability >= 0.5;

    return `
      <div class="jev-score-card scored" id="jev-card-${ch.id}">
        <div class="jev-card-top">
          <div class="jev-card-title">
            <span class="jev-card-icon">${ch.icon}</span>
            <div>
              <div class="jev-card-num">CH${ch.num}</div>
              <h4>${ch.title}</h4>
            </div>
          </div>
          <div class="jev-score-ring-wrap">
            <svg class="jev-score-ring" width="64" height="64" viewBox="0 0 64 64">
              <circle class="jev-ring-bg" cx="32" cy="32" r="26"/>
              <circle class="jev-ring-fill" cx="32" cy="32" r="26"
                stroke="${color}" style="stroke-dashoffset:${offset}"/>
            </svg>
            <div class="jev-ring-label">
              <span class="jev-ring-score">${data.composite}</span>
              <span class="jev-ring-max">/100</span>
            </div>
          </div>
        </div>
        <div class="jev-prob-bars">${probBars}</div>
        <div class="jev-confidence-row">
          <span class="jev-confidence-label">Confidence</span>
          <span class="jev-confidence-pill ${confClass}">${Math.round(avgConf*100)}%</span>
        </div>
        <div class="jev-noul-verdict ${noulYes ? 'yes' : 'no'}">
          <span class="noul-icon">${noulYes ? '✅' : '⚠️'}</span>
          <span>${noulYes ? 'Resume-impactful' : 'Less central'}</span>
          <span class="noul-prob">p(yes)=${Math.round(data.industry_fit_probability*100)}%</span>
        </div>
      </div>
    `;
  }).join('');
}

/* ══════════════════════════════════════════════════════════════════════
   11. UTILITIES
   ══════════════════════════════════════════════════════════════════════ */

/** Escape HTML special characters for safe insertion into <pre><code>. */
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* ══════════════════════════════════════════════════════════════════════
   12. BOOT
   ══════════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {

  // Start ComfyUI animated canvas background
  const canvas = document.getElementById('nodeCanvas');
  if (canvas) {
    const graph = new NodeGraph(canvas);
    graph.start();
  }

  // Navbar logo → home
  document.getElementById('nav-home-btn')?.addEventListener('click', () => {
    transitionOut(() => showHome());
  });

  // Breadcrumb home link
  document.getElementById('breadcrumb-home')?.addEventListener('click', () => {
    transitionOut(() => showHome());
  });

  // Render home content
  renderChapterCards();
  renderJevCards();
  updateOverallProgress();

  // Show home view on boot
  showHome();
});
