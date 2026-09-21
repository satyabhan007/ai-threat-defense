/**
 * AI Threat Defense — Curriculum Site
 * ─────────────────────────────────────
 * • ComfyUI-style animated node-graph canvas background
 * • Smooth page / section transitions
 * • TypeSafe Jev API integration (Score + Noul primitives)
 *   → rates each chapter for relevance, production-readiness, and
 *     industry-fit against the job-requirement topic chosen by the user
 */

/* ════════════════════════════════════════════════════════════════════════
   1. ComfyUI Node-Graph Canvas
   ════════════════════════════════════════════════════════════════════════ */
class NodeGraph {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.nodes = [];
    this.edges = [];
    this.raf = null;
    this.resize();
    this.generate();
    window.addEventListener('resize', () => { this.resize(); this.generate(); });
  }

  resize() {
    this.canvas.width  = window.innerWidth;
    this.canvas.height = window.innerHeight;
    this.W = this.canvas.width;
    this.H = this.canvas.height;
  }

  generate() {
    const N = Math.floor((this.W * this.H) / 28000);
    this.nodes = Array.from({ length: N }, () => ({
      x: Math.random() * this.W,
      y: Math.random() * this.H,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      r: 3 + Math.random() * 4,
      hue: [186, 262, 142, 28, 322][Math.floor(Math.random() * 5)],
      pulse: Math.random() * Math.PI * 2,
      pulseSpeed: 0.012 + Math.random() * 0.02,
      type: Math.random() > 0.7 ? 'box' : 'dot',
      // ComfyUI-style node sockets
      inputs:  Math.floor(Math.random() * 3),
      outputs: Math.floor(Math.random() * 3),
    }));
    // Build edges (connect nodes within 200px)
    this.edges = [];
    for (let i = 0; i < this.nodes.length; i++) {
      for (let j = i + 1; j < this.nodes.length; j++) {
        const dx = this.nodes[i].x - this.nodes[j].x;
        const dy = this.nodes[i].y - this.nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 200 && this.edges.length < N * 2) {
          this.edges.push({ a: i, b: j, dist });
        }
      }
    }
  }

  drawComfyNode(ctx, n, t) {
    const w = 70, h = 44;
    const x = n.x - w / 2, y = n.y - h / 2;
    const glow = 0.3 + 0.2 * Math.sin(n.pulse + t * n.pulseSpeed);

    // Node body
    ctx.save();
    ctx.shadowColor = `hsla(${n.hue},100%,60%,${glow})`;
    ctx.shadowBlur = 12;
    ctx.strokeStyle = `hsla(${n.hue},80%,60%,${glow * 0.9})`;
    ctx.lineWidth = 1;
    ctx.fillStyle = `hsla(${n.hue},40%,10%,0.55)`;
    ctx.beginPath();
    ctx.roundRect(x, y, w, h, 5);
    ctx.fill();
    ctx.stroke();
    ctx.restore();

    // Header bar
    ctx.fillStyle = `hsla(${n.hue},70%,35%,0.55)`;
    ctx.beginPath();
    ctx.roundRect(x, y, w, 12, [5, 5, 0, 0]);
    ctx.fill();

    // Socket dots — inputs left, outputs right
    for (let i = 0; i < n.inputs; i++) {
      const sy = y + 20 + i * 10;
      ctx.beginPath();
      ctx.arc(x - 4, sy, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${n.hue},90%,65%,0.8)`;
      ctx.fill();
    }
    for (let i = 0; i < n.outputs; i++) {
      const sy = y + 20 + i * 10;
      ctx.beginPath();
      ctx.arc(x + w + 4, sy, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${n.hue},90%,65%,0.8)`;
      ctx.fill();
    }
  }

  drawDot(ctx, n, t) {
    const a = 0.35 + 0.25 * Math.sin(n.pulse + t * n.pulseSpeed);
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
    ctx.fillStyle = `hsla(${n.hue},90%,65%,${a})`;
    ctx.shadowColor = `hsla(${n.hue},100%,60%,${a * 0.7})`;
    ctx.shadowBlur = 10;
    ctx.fill();
  }

  draw(t) {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.W, this.H);

    // Edges (bezier wires like ComfyUI)
    for (const e of this.edges) {
      const a = this.nodes[e.a], b = this.nodes[e.b];
      const alpha = Math.max(0, 1 - e.dist / 200) * 0.3;
      if (alpha < 0.01) continue;
      const cp1x = a.x + (b.x - a.x) * 0.5, cp1y = a.y;
      const cp2x = a.x + (b.x - a.x) * 0.5, cp2y = b.y;
      const g = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
      g.addColorStop(0, `hsla(${a.hue},80%,60%,${alpha})`);
      g.addColorStop(1, `hsla(${b.hue},80%,60%,${alpha})`);
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, b.x, b.y);
      ctx.strokeStyle = g;
      ctx.lineWidth = 1;
      ctx.shadowBlur = 0;
      ctx.stroke();

      // Animated packet
      const progress = (t * 0.0004 + e.a * 0.13) % 1;
      const px = Math.pow(1 - progress, 3) * a.x + 3 * Math.pow(1 - progress, 2) * progress * cp1x
               + 3 * (1 - progress) * Math.pow(progress, 2) * cp2x + Math.pow(progress, 3) * b.x;
      const py = Math.pow(1 - progress, 3) * a.y + 3 * Math.pow(1 - progress, 2) * progress * cp1y
               + 3 * (1 - progress) * Math.pow(progress, 2) * cp2y + Math.pow(progress, 3) * b.y;
      ctx.beginPath();
      ctx.arc(px, py, 2, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${a.hue},100%,80%,${alpha * 2})`;
      ctx.shadowColor = `hsla(${a.hue},100%,80%,0.8)`;
      ctx.shadowBlur = 6;
      ctx.fill();
    }

    ctx.shadowBlur = 0;

    // Nodes
    for (const n of this.nodes) {
      n.x += n.vx;
      n.y += n.vy;
      if (n.x < 0 || n.x > this.W) n.vx *= -1;
      if (n.y < 0 || n.y > this.H) n.vy *= -1;
      if (n.type === 'box') {
        this.drawComfyNode(ctx, n, t);
      } else {
        this.drawDot(ctx, n, t);
      }
    }
  }

  start() {
    const loop = (t) => {
      this.draw(t);
      this.raf = requestAnimationFrame(loop);
    };
    this.raf = requestAnimationFrame(loop);
  }
}

/* ════════════════════════════════════════════════════════════════════════
   2. Page Transitions
   ════════════════════════════════════════════════════════════════════════ */
const overlay = document.getElementById('pageTransition');

function triggerTransition(callback) {
  overlay.classList.add('active');
  setTimeout(() => {
    callback();
    setTimeout(() => overlay.classList.remove('active'), 300);
  }, 280);
}

/* ════════════════════════════════════════════════════════════════════════
   3. Navbar + Scroll Spy
   ════════════════════════════════════════════════════════════════════════ */
const navbar = document.getElementById('navbar');
const navLinks = document.querySelectorAll('.nav-link');
const sections = document.querySelectorAll('.section');

// Navbar shadow on scroll
window.addEventListener('scroll', () => {
  navbar.classList.toggle('scrolled', window.scrollY > 40);
});

// Intersection observer for section reveal + nav active state
const sectionObserver = new IntersectionObserver(
  (entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        const id = entry.target.id;
        navLinks.forEach(l => l.classList.toggle('active', l.dataset.page === id));
      }
    });
  },
  { threshold: 0.15 }
);
sections.forEach(s => sectionObserver.observe(s));

// Smooth scroll for CTA / nav links
document.querySelectorAll('[data-scroll], .nav-link').forEach(el => {
  el.addEventListener('click', e => {
    const target = el.dataset.scroll || el.dataset.page;
    if (!target) return;
    const dest = document.getElementById(target);
    if (!dest) return;
    e.preventDefault();
    triggerTransition(() => dest.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  });
});

/* ════════════════════════════════════════════════════════════════════════
   4. Result bar animation
   ════════════════════════════════════════════════════════════════════════ */
const barObserver = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.querySelectorAll('.result-bar-fill').forEach(bar => {
        bar.style.width = bar.style.width; // trigger reflow
      });
    }
  });
}, { threshold: 0.3 });
document.querySelectorAll('.results-section').forEach(s => barObserver.observe(s));

/* ════════════════════════════════════════════════════════════════════════
   5. TypeSafe Jev Analysis
   ════════════════════════════════════════════════════════════════════════ */

/**
 * Chapter metadata — each chapter is evaluated by Jev against:
 *   - relevance_to_topic   (Score, 0–3)
 *   - production_readiness (Score, 0–3)
 *   - industry_fit         (Noul)
 */
const CHAPTERS = [
  {
    id: 'ch01',
    num: '01',
    icon: '🔬',
    title: 'Threat Modeling & NLP Classification',
    description: `OWASP Top 10 for LLMs × MITRE ATLAS taxonomy. Baseline signature scanner 
      running in <0.26ms. N-gram classifier with zero external dependencies. 
      Covers prompt injection, jailbreaks, system prompt extraction, credential harvesting.`,
    technologies: 'Python, NLP, OWASP, MITRE ATLAS, n-gram, regex scanning',
  },
  {
    id: 'ch02',
    num: '02',
    icon: '🧠',
    title: 'PyTorch & Transformer Fine-Tuning',
    description: `LoRA PEFT adapter with rank decomposition math. 32% parameter reduction. 
      Stratified train/val/test splits. Adversarial mutation generator. 
      Hugging Face Transformers integration. Error analysis and confusion matrices.`,
    technologies: 'PyTorch, HuggingFace Transformers, LoRA, PEFT, scikit-learn',
  },
  {
    id: 'ch03',
    num: '03',
    icon: '🔒',
    title: 'DLP, PII & Secret Redaction',
    description: `Shannon entropy scanner for AWS/OpenAI/Anthropic API keys. HMAC-salted 
      pseudonym replacement. GDPR, HIPAA, DPDP Act 2023 compliant. 
      Aadhaar, PAN, SSN, email, phone detection via regex.`,
    technologies: 'Python, regex, Shannon entropy, HMAC, GDPR, HIPAA, DLP, PII',
  },
  {
    id: 'ch04',
    num: '04',
    icon: '⚡',
    title: 'Low-Latency ONNX Model Serving',
    description: `INT8 dynamic quantization yielding 4× memory reduction. P95 latency 0.071ms local, 
      4.2ms ONNX. Sub-15ms HTTP SLA. ONNX export with dynamic axes. FastAPI serving daemon. 
      Benchmark harness with P50/P95/P99 percentiles.`,
    technologies: 'ONNX Runtime, INT8, quantization, FastAPI, Python, latency benchmarking',
  },
  {
    id: 'ch05',
    num: '05',
    icon: '🦫',
    title: 'Go Inline Security Gateway',
    description: `Concurrent race-free HTTP reverse proxy in Go 1.22+. Multi-tier policy engine 
      (Allow, Block, Quarantine, Audit). Prompt extraction for OpenAI JSON format. 
      6/6 tests with Go race detector. sub-millisecond policy check.`,
    technologies: 'Go 1.22, net/http, reverse proxy, policy engine, concurrency, race detector',
  },
  {
    id: 'ch06',
    num: '06',
    icon: '🎯',
    title: 'Adversarial Evaluation Discipline',
    description: `Evasion attack generator: Cyrillic/Greek homoglyphs, zero-width space injection, 
      leetspeak, base64 smuggling. Benchmark harness with ROC-AUC 1.00. 
      Dataset design, error analysis, adversarial testing discipline.`,
    technologies: 'Python, adversarial ML, ROC-AUC, homoglyphs, evasion attacks, evaluation',
  },
  {
    id: 'ch07',
    num: '07',
    icon: '☸️',
    title: 'Containerization & Kubernetes',
    description: `Multi-stage Docker builds. Distroless Go image <15MB. Non-root Python model server. 
      Kubernetes Deployment, ClusterIP Service, HPA (3–20 replicas), 
      readiness/liveness probes, security contexts.`,
    technologies: 'Docker, Kubernetes, HPA, distroless, multi-stage build, security context',
  },
  {
    id: 'ch08',
    num: '08',
    icon: '🤖',
    title: 'AI-First Engineering Playbook',
    description: `Agentic red-teamer using TypeSafe Jev & LLM agent loops. AST code auditor 
      checking for hardcoded credentials, ReDoS, exception suppression. 
      Claude Code and Antigravity IDE as force multipliers.`,
    technologies: 'TypeSafe Jev, Claude Code, AST, agentic workflows, AI-first engineering',
  },
];

const TOPICS = {
  ml_security: {
    label: 'ML Security & Threat Detection',
    description: `Building and deploying ML models for security use cases: threat classification, 
      adversarial robustness, prompt injection detection, NLP-based security, DLP, 
      ONNX serving, Go gateway, and production ML pipelines.`,
  },
  llm_engineering: {
    label: 'LLM Engineering & Agentic Systems',
    description: `Building production LLM pipelines: fine-tuning, serving, guardrails, 
      agentic loops, prompt injection defense, evaluation, and AI-first engineering workflows.`,
  },
  backend_go: {
    label: 'Senior Backend Engineering (Go)',
    description: `Senior backend engineering in Go: concurrent HTTP servers, reverse proxies, 
      policy engines, API design, performance benchmarking, Docker, Kubernetes, microservices.`,
  },
  mlops: {
    label: 'MLOps & Production ML',
    description: `Production ML deployment: model serving, quantization, containerization, 
      Kubernetes scaling, CI/CD, monitoring, latency optimization, Docker, cloud infrastructure.`,
  },
};

// ── State ──────────────────────────────────────────────────────────────
let jevApiKey = localStorage.getItem('jev_api_key') || '';
let currentTopic = 'ml_security';
let isAnalyzing = false;
let analysisResults = {}; // { [chId]: { score, confidence, probabilities, noul } }

// ── DOM Refs ───────────────────────────────────────────────────────────
const jevSection   = document.getElementById('jev-analysis');
const jevGate      = document.getElementById('jev-gate');
const jevKeyInput  = document.getElementById('jev-key-input');
const jevRunBtn    = document.getElementById('jev-run-btn');
const jevPanel     = document.getElementById('jev-panel');
const jevLoading   = document.getElementById('jev-loading');
const jevResults   = document.getElementById('jev-results');
const jevTopicSel  = document.getElementById('jev-topic-select');
const jevRerunBtn  = document.getElementById('jev-rerun-btn');
const jevSummary   = document.getElementById('jev-summary');

// ── Gate logic ─────────────────────────────────────────────────────────
function showGate() {
  jevGate.classList.remove('hidden');
  jevPanel.classList.add('hidden');
  if (jevApiKey) jevKeyInput.value = jevApiKey;
}

function showPanel() {
  jevGate.classList.add('hidden');
  jevPanel.classList.remove('hidden');
}

jevRunBtn?.addEventListener('click', () => {
  const key = jevKeyInput.value.trim();
  if (!key) { jevKeyInput.focus(); return; }
  jevApiKey = key;
  localStorage.setItem('jev_api_key', key);
  showPanel();
  runAnalysis();
});

jevKeyInput?.addEventListener('keydown', e => {
  if (e.key === 'Enter') jevRunBtn?.click();
});

jevRerunBtn?.addEventListener('click', () => {
  currentTopic = jevTopicSel.value;
  runAnalysis();
});

jevTopicSel?.addEventListener('change', () => {
  currentTopic = jevTopicSel.value;
});

/* ── TypeSafe Jev API call (single chapter) ───────────────────────────
 *
 * We send one request per chapter with THREE questions in parallel (fan-out):
 *
 *   relevance_to_topic  → Score (0-3)
 *     How relevant is this chapter to the selected engineering topic?
 *
 *   production_readiness → Score (0-3)
 *     How production-ready is the code / knowledge in this chapter?
 *
 *   industry_fit → Noul
 *     Would a senior engineer hiring for this role consider this chapter
 *     directly relevant on a resume or in an interview?
 */
async function askJev(chapter, topic) {
  const topicInfo = TOPICS[topic];

  const body = {
    model: 'jev-latest',
    state: {
      chapter_title: chapter.title,
      chapter_description: chapter.description,
      chapter_technologies: chapter.technologies,
      hiring_topic: topicInfo.label,
      hiring_description: topicInfo.description,
    },
    questions: {
      relevance_to_topic: {
        type: 'score',
        instructions: 'How relevant is this curriculum chapter to the specified engineering hiring topic?',
        criteria: [
          'Completely unrelated — different domain, no overlap with the hiring topic',
          'Adjacent — some shared concepts but not the core focus of the hiring topic',
          'Directly relevant — covers key skills or technologies from the hiring topic',
          'Core strength — this chapter is a flagship demonstration of the hiring topic\'s most critical requirements',
        ],
      },
      production_readiness: {
        type: 'score',
        instructions: 'How production-ready is the knowledge and code demonstrated in this chapter?',
        criteria: [
          'Toy / tutorial level — educational but not representative of production code',
          'Prototype quality — shows the concept but missing production concerns (error handling, scale, observability)',
          'Production-grade — covers real production concerns: benchmarks, error handling, tests, deployment',
          'Industry-leading — goes beyond standard production practices with advanced techniques (quantization, race detectors, adversarial evals, distroless images)',
        ],
      },
      industry_fit: {
        type: 'noul',
        instructions: 'Would a senior engineering hiring manager consider this chapter directly impactful on a candidate\'s application for the specified role?',
      },
    },
  };

  const response = await fetch('https://api.typesafe.ai/v1/systemone', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${jevApiKey}`,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Jev API error ${response.status}: ${text}`);
  }

  const data = await response.json();
  return data.answers;
}

/* ── Composite score: weighted average of relevance + readiness ──────── */
function compositeScore(answers) {
  // relevance 0-3 → 0-100, production_readiness 0-3 → 0-100
  // weights: relevance 60%, readiness 40%
  const rel  = (answers.relevance_to_topic.score  / 3) * 100;
  const prod = (answers.production_readiness.score / 3) * 100;
  return Math.round(rel * 0.6 + prod * 0.4);
}

/* ── Render a single scored card ─────────────────────────────────────── */
function scoreColor(score) {
  // score is 0-100
  if (score >= 80) return 'hsl(142,80%,55%)';
  if (score >= 55) return 'hsl(186,100%,55%)';
  if (score >= 35) return 'hsl(28,95%,60%)';
  return 'hsl(0,80%,55%)';
}

function confidenceClass(c) {
  if (c >= 0.65) return 'conf-high';
  if (c >= 0.35) return 'conf-medium';
  return 'conf-low';
}

function renderScoreCard(ch, answers) {
  const card = document.getElementById(`jev-card-${ch.id}`);
  if (!card) return;

  const comp  = compositeScore(answers);
  const rel   = answers.relevance_to_topic;
  const prod  = answers.production_readiness;
  const noul  = answers.industry_fit;
  const color = scoreColor(comp);
  const relConf = rel.confidence;
  const avgConf = ((relConf + prod.confidence) / 2);

  // Ring: dashoffset = circumference - (score/100) * circumference
  const circ = 163;
  const offset = circ - (comp / 100) * circ;

  // Probability bars for relevance
  const relProbs = Object.entries(rel.probabilities)
    .map(([k, v]) => ({ level: parseInt(k), pct: Math.round(v * 100) }));
  const relLevels = ['Unrelated', 'Adjacent', 'Direct', 'Core'];

  const probBarsHTML = relProbs.map(p => `
    <div class="jev-prob-row">
      <span class="jev-prob-label">${relLevels[p.level] || p.level}</span>
      <div class="jev-prob-bar-wrap">
        <div class="jev-prob-bar-fill" style="width:${p.pct}%;background:${color}"></div>
      </div>
      <span class="jev-prob-pct">${p.pct}%</span>
    </div>
  `).join('');

  const noulYes  = noul.probability_yes ?? noul.probability ?? 0.5;
  const noulPct  = Math.round(noulYes * 100);
  const noulIsYes = noulYes >= 0.5;

  card.innerHTML = `
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
            stroke="${color}"
            style="stroke-dashoffset:${offset}"/>
        </svg>
        <div class="jev-ring-label">
          <span class="jev-ring-score">${comp}</span>
          <span class="jev-ring-max">/100</span>
        </div>
      </div>
    </div>

    <div class="jev-prob-bars">${probBarsHTML}</div>

    <div class="jev-confidence-row">
      <span class="jev-confidence-label">Jev Confidence</span>
      <span class="jev-confidence-pill ${confidenceClass(avgConf)}">${(avgConf * 100).toFixed(0)}%</span>
    </div>

    <div class="jev-noul-verdict ${noulIsYes ? 'yes' : 'no'}">
      <span class="noul-icon">${noulIsYes ? '✅' : '⚠️'}</span>
      <span>${noulIsYes ? 'Resume-impactful for this role' : 'Less central to this role'}</span>
      <span class="noul-prob">p(yes)=${noulPct}%</span>
    </div>
  `;

  card.classList.add('scored');
  return comp;
}

/* ── Render skeleton cards ───────────────────────────────────────────── */
function renderSkeletons() {
  const grid = document.getElementById('jev-scores-grid');
  if (!grid) return;
  grid.innerHTML = CHAPTERS.map(ch => `
    <div class="jev-score-card jev-skeleton" id="jev-card-${ch.id}">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px">
        <div style="flex:1">
          <div class="skeleton-line short" style="margin-bottom:6px"></div>
          <div class="skeleton-line medium"></div>
        </div>
        <div class="skeleton-ring"></div>
      </div>
      <div class="skeleton-line"></div>
      <div class="skeleton-line medium"></div>
      <div class="skeleton-line short"></div>
    </div>
  `).join('');
}

/* ── Main analysis runner ────────────────────────────────────────────── */
async function runAnalysis() {
  if (isAnalyzing) return;
  isAnalyzing = true;

  // Reset UI
  jevResults.classList.remove('hidden');
  jevSummary.classList.add('hidden');
  document.getElementById('jev-loading-topic').textContent = TOPICS[currentTopic]?.label || currentTopic;
  jevLoading.classList.remove('hidden');

  // Show skeleton grid immediately
  renderSkeletons();

  jevLoading.classList.add('hidden');

  // Fan-out: analyze all chapters in parallel (Jev is fast, batch them)
  const scores = [];
  const errors = [];

  await Promise.all(CHAPTERS.map(async (ch, idx) => {
    try {
      // Stagger requests slightly to avoid rate limits
      await new Promise(r => setTimeout(r, idx * 120));

      const card = document.getElementById(`jev-card-${ch.id}`);
      if (card) {
        // Show "analyzing..." pulse while loading
        card.style.opacity = '0.7';
        card.style.borderColor = 'rgba(139,92,246,0.35)';
      }

      const answers = await askJev(ch, currentTopic);
      analysisResults[ch.id] = answers;

      // Remove skeleton class and render real data
      const el = document.getElementById(`jev-card-${ch.id}`);
      if (el) {
        el.classList.remove('jev-skeleton');
        el.style.opacity = '';
        el.style.borderColor = '';
      }

      const comp = renderScoreCard(ch, answers);
      scores.push(comp);
    } catch (err) {
      console.error(`Jev error for ${ch.id}:`, err);
      errors.push({ ch, err });
      renderErrorCard(ch, err.message);
    }
  }));

  // Overall summary
  if (scores.length > 0) {
    renderSummary(scores, currentTopic);
  }

  isAnalyzing = false;
}

function renderErrorCard(ch, msg) {
  const card = document.getElementById(`jev-card-${ch.id}`);
  if (!card) return;
  card.classList.remove('jev-skeleton');
  card.innerHTML = `
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:10px">
      <span style="font-size:1.3rem">${ch.icon}</span>
      <h4 style="font-size:0.88rem;font-weight:700">${ch.title}</h4>
    </div>
    <div style="font-size:0.78rem;color:hsl(0,80%,65%);background:rgba(255,77,77,0.08);
                border:1px solid rgba(255,77,77,0.2);border-radius:8px;padding:10px 12px">
      ⚠️ ${msg.includes('401') ? 'Invalid API key. Check your TypeSafe key.' : msg.slice(0, 120)}
    </div>
  `;
}

function renderSummary(scores, topic) {
  const avg = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  const max = Math.max(...scores);
  const topChapter = CHAPTERS[scores.indexOf(max)];
  const topicLabel = TOPICS[topic]?.label || topic;

  const verdictText = avg >= 80
    ? `This curriculum is an <strong>exceptional match</strong> for the ${topicLabel} role. Every chapter directly reinforces the core competencies required.`
    : avg >= 60
    ? `This curriculum is a <strong>strong match</strong> for ${topicLabel}. Most chapters are highly relevant, with a few providing supporting context.`
    : avg >= 40
    ? `This curriculum has <strong>moderate relevance</strong> to ${topicLabel}. Key chapters align well; some are adjacent.`
    : `This curriculum has <strong>some overlap</strong> with ${topicLabel} but the primary focus is elsewhere.`;

  document.getElementById('jev-summary-num').textContent = avg;
  document.getElementById('jev-summary-verdict').innerHTML = verdictText;
  document.getElementById('jev-summary-best').textContent =
    `Top chapter: ${topChapter.icon} ${topChapter.title} (${max}/100)`;

  jevSummary.classList.remove('hidden');
}

/* ════════════════════════════════════════════════════════════════════════
   6. Boot
   ════════════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  // Start ComfyUI node canvas
  const canvas = document.getElementById('nodeCanvas');
  if (canvas) {
    const graph = new NodeGraph(canvas);
    graph.start();
  }

  // Section reveal — trigger for already-visible sections
  sections.forEach(s => {
    if (s.getBoundingClientRect().top < window.innerHeight) {
      s.classList.add('visible');
    }
  });

  // Jev gate / panel init
  if (jevApiKey) {
    showPanel();
    // Auto-run on load if key exists
    runAnalysis();
  } else {
    showGate();
  }

  // Populate topic select
  if (jevTopicSel) {
    Object.entries(TOPICS).forEach(([key, t]) => {
      const opt = document.createElement('option');
      opt.value = key;
      opt.textContent = t.label;
      if (key === currentTopic) opt.selected = true;
      jevTopicSel.appendChild(opt);
    });
  }

  // Hamburger
  const ham = document.getElementById('hamburger');
  const navLinksEl = document.querySelector('.nav-links');
  ham?.addEventListener('click', () => {
    navLinksEl?.classList.toggle('open');
  });
});
