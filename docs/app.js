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
  composite_avg: 59,
  industry_fit_chapters: 8,
  chapters: [
    { id:'ch01', composite:66, relevance_score:2.50, relevance_confidence:0.50,
      relevance_probabilities:{'0':0.00,'1':0.02,'2':0.47,'3':0.51},
      readiness_score:1.19, readiness_confidence:0.65, industry_fit_probability:0.50 },
    { id:'ch02', composite:62, relevance_score:2.28, relevance_confidence:0.69,
      relevance_probabilities:{'0':0.00,'1':0.01,'2':0.70,'3':0.29},
      readiness_score:1.21, readiness_confidence:0.48, industry_fit_probability:0.50 },
    { id:'ch03', composite:47, relevance_score:1.72, relevance_confidence:0.66,
      relevance_probabilities:{'0':0.00,'1':0.31,'2':0.66,'3':0.03},
      readiness_score:0.93, readiness_confidence:0.38, industry_fit_probability:0.50 },
    { id:'ch04', composite:64, relevance_score:1.86, relevance_confidence:0.82,
      relevance_probabilities:{'0':0.00,'1':0.16,'2':0.82,'3':0.02},
      readiness_score:2.03, readiness_confidence:0.03, industry_fit_probability:0.50 },
    { id:'ch05', composite:64, relevance_score:1.54, relevance_confidence:0.53,
      relevance_probabilities:{'0':0.00,'1':0.46,'2':0.53,'3':0.01},
      readiness_score:2.52, readiness_confidence:0.52, industry_fit_probability:0.50 },
    { id:'ch06', composite:77, relevance_score:2.74, relevance_confidence:0.74,
      relevance_probabilities:{'0':0.00,'1':0.00,'2':0.25,'3':0.75},
      readiness_score:1.67, readiness_confidence:0.10, industry_fit_probability:0.50 },
    { id:'ch07', composite:58, relevance_score:1.85, relevance_confidence:0.81,
      relevance_probabilities:{'0':0.00,'1':0.17,'2':0.81,'3':0.02},
      readiness_score:1.61, readiness_confidence:0.37, industry_fit_probability:0.50 },
    { id:'ch08', composite:37, relevance_score:1.11, relevance_confidence:0.85,
      relevance_probabilities:{'0':0.02,'1':0.86,'2':0.11,'3':0.01},
      readiness_score:1.08, readiness_confidence:0.00, industry_fit_probability:0.50 },
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
   2. ComfyUI NODE-GRAPH CANVAS
   ══════════════════════════════════════════════════════════════════════
   Draws an animated background resembling ComfyUI's node editor:
   - Nodes: either "dot" (simple circle) or "box" (mini ComfyUI node card)
   - Edges: bezier curves with animated data-packet dots travelling along them
   - Palette: 5 HSL hues (cyan, violet, green, orange, magenta)
   ══════════════════════════════════════════════════════════════════════ */
class NodeGraph {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx    = canvas.getContext('2d');
    this.nodes  = [];
    this.edges  = [];
    this.raf    = null;
    this._resize();
    this._generate();
    window.addEventListener('resize', () => { this._resize(); this._generate(); });
  }

  _resize() {
    this.canvas.width  = window.innerWidth;
    this.canvas.height = window.innerHeight;
    this.W = this.canvas.width;
    this.H = this.canvas.height;
  }

  _generate() {
    // Node density: ~1 node per 28,000px² of screen area
    const N = Math.max(8, Math.floor((this.W * this.H) / 28000));
    this.nodes = Array.from({ length: N }, () => ({
      x: Math.random() * this.W,
      y: Math.random() * this.H,
      vx: (Math.random() - 0.5) * 0.2,   // slow drift
      vy: (Math.random() - 0.5) * 0.2,
      r: 3 + Math.random() * 4,
      hue: [186, 262, 142, 28, 322][Math.floor(Math.random() * 5)],
      pulse: Math.random() * Math.PI * 2,
      pulseSpeed: 0.012 + Math.random() * 0.02,
      type: Math.random() > 0.7 ? 'box' : 'dot',
      inputs:  Math.floor(Math.random() * 3),   // socket count (ComfyUI style)
      outputs: Math.floor(Math.random() * 3),
    }));

    // Edges: connect nodes within 200px (max N*2 edges to avoid O(n²) overload)
    this.edges = [];
    for (let i = 0; i < this.nodes.length; i++) {
      for (let j = i + 1; j < this.nodes.length; j++) {
        const dx   = this.nodes[i].x - this.nodes[j].x;
        const dy   = this.nodes[i].y - this.nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 200 && this.edges.length < N * 2) {
          this.edges.push({ a: i, b: j, dist });
        }
      }
    }
  }

  /** Draw a ComfyUI-style mini node card with socket dots */
  _drawBox(ctx, n, t) {
    const w = 70, h = 44;
    const x = n.x - w / 2, y = n.y - h / 2;
    const glow = 0.3 + 0.2 * Math.sin(n.pulse + t * n.pulseSpeed);

    ctx.save();
    ctx.shadowColor = `hsla(${n.hue},100%,60%,${glow})`;
    ctx.shadowBlur  = 12;
    // Card body
    ctx.fillStyle   = `hsla(${n.hue},40%,10%,0.55)`;
    ctx.strokeStyle = `hsla(${n.hue},80%,60%,${glow * 0.9})`;
    ctx.lineWidth   = 1;
    ctx.beginPath();
    ctx.roundRect(x, y, w, h, 5);
    ctx.fill(); ctx.stroke();
    // Header bar
    ctx.fillStyle = `hsla(${n.hue},70%,35%,0.55)`;
    ctx.beginPath();
    ctx.roundRect(x, y, w, 12, [5, 5, 0, 0]);
    ctx.fill();
    // Input sockets (left side)
    for (let i = 0; i < n.inputs; i++) {
      ctx.beginPath();
      ctx.arc(x - 4, y + 20 + i * 10, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${n.hue},90%,65%,0.8)`;
      ctx.fill();
    }
    // Output sockets (right side)
    for (let i = 0; i < n.outputs; i++) {
      ctx.beginPath();
      ctx.arc(x + w + 4, y + 20 + i * 10, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${n.hue},90%,65%,0.8)`;
      ctx.fill();
    }
    ctx.restore();
  }

  /** Draw a simple glowing dot */
  _drawDot(ctx, n, t) {
    const a = 0.35 + 0.25 * Math.sin(n.pulse + t * n.pulseSpeed);
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
    ctx.fillStyle   = `hsla(${n.hue},90%,65%,${a})`;
    ctx.shadowColor = `hsla(${n.hue},100%,60%,${a * 0.7})`;
    ctx.shadowBlur  = 10;
    ctx.fill();
  }

  _draw(t) {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.W, this.H);

    // ── Edges (bezier wires with travelling data packets) ──
    for (const e of this.edges) {
      const a = this.nodes[e.a], b = this.nodes[e.b];
      const alpha = Math.max(0, 1 - e.dist / 200) * 0.3;
      if (alpha < 0.01) continue;

      // Control points for S-curve (ComfyUI style)
      const cp1x = a.x + (b.x - a.x) * 0.5, cp1y = a.y;
      const cp2x = a.x + (b.x - a.x) * 0.5, cp2y = b.y;

      // Gradient wire
      const g = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
      g.addColorStop(0, `hsla(${a.hue},80%,60%,${alpha})`);
      g.addColorStop(1, `hsla(${b.hue},80%,60%,${alpha})`);
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, b.x, b.y);
      ctx.strokeStyle = g;
      ctx.lineWidth   = 1;
      ctx.shadowBlur  = 0;
      ctx.stroke();

      // Animated data packet (dot travelling along the bezier)
      const progress = (t * 0.0004 + e.a * 0.13) % 1;
      const px = Math.pow(1-progress,3)*a.x + 3*Math.pow(1-progress,2)*progress*cp1x
               + 3*(1-progress)*Math.pow(progress,2)*cp2x + Math.pow(progress,3)*b.x;
      const py = Math.pow(1-progress,3)*a.y + 3*Math.pow(1-progress,2)*progress*cp1y
               + 3*(1-progress)*Math.pow(progress,2)*cp2y + Math.pow(progress,3)*b.y;
      ctx.beginPath();
      ctx.arc(px, py, 2, 0, Math.PI * 2);
      ctx.fillStyle   = `hsla(${a.hue},100%,80%,${alpha * 2})`;
      ctx.shadowColor = `hsla(${a.hue},100%,80%,0.8)`;
      ctx.shadowBlur  = 6;
      ctx.fill();
    }

    ctx.shadowBlur = 0;

    // ── Nodes ──
    for (const n of this.nodes) {
      n.x += n.vx; n.y += n.vy;
      if (n.x < 0 || n.x > this.W) n.vx *= -1;
      if (n.y < 0 || n.y > this.H) n.vy *= -1;
      if (n.type === 'box') this._drawBox(ctx, n, t);
      else                  this._drawDot(ctx, n, t);
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
