<?php
require_once __DIR__ . '/includes/auth.php';
$pageTitle = 'Home';
require_once __DIR__ . '/includes/header.php';
?>

<!-- ============ HERO ============ -->
<section class="hero cl-screen lp">
  <div class="container-fluid px-0">
    <div class="row align-items-center g-4 g-lg-5 w-100 mx-0">
      <div class="col-lg-7 px-3">
        <div class="lp-pill reveal" style="--d:0ms">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" style="vertical-align:-1px;margin-right:5px"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>
          Secure Cloud Storage · CSP650
        </div>
        <h1 class="lp-hero-title reveal" style="--d:60ms">
          Triple-Layered<br>
          <span class="lp-gradient">Secure Cloud</span><br>
          Storage
        </h1>
        <p class="lead mt-4 lp-subtle reveal" style="--d:120ms">
          Cloudie scans every upload with an AI malware analyzer trained on
          thousands of PDF samples, then encrypts the file with AES-256
          before it ever touches storage. Only you, with your key, can read it back.
        </p>
        <div class="mt-4 d-flex flex-wrap gap-3 reveal" style="--d:180ms">
          <?php if (current_user()): ?>
            <a href="upload.php" class="btn btn-cloudie">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none"><path d="M12 16V4m0 0L8 8m4-4l4 4" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 17v2a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
              Upload a file
            </a>
            <a href="dashboard.php" class="btn btn-cloudie-outline">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none"><path d="M3 11l9-7 9 7M5 10v9h14v-9" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>
              My files
            </a>
          <?php else: ?>
            <a href="register.php" class="btn btn-cloudie">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>
              Get started — it's free
            </a>
            <a href="login.php" class="btn btn-cloudie-outline">Log in</a>
          <?php endif; ?>
        </div>
        <div class="mt-5 reveal" style="--d:240ms">
          <a href="#learn-more" class="scroll-cue">
            Discover how it works
            <span class="scroll-arrow">↓</span>
          </a>
        </div>
      </div>
      <div class="col-lg-5 d-none d-lg-block">
        <div class="lp-card lp-hero-card reveal" style="--d:160ms">
          <h4 class="lp-card-title">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" style="color:var(--lp-accent)"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            How it works
          </h4>
          <ol class="lp-howto mb-0">
            <li><span>You upload a file — any PDF, image, document, or archive.</span></li>
            <li><span>Our Random Forest analyzer extracts 33 static features and predicts whether it's malicious.</span></li>
            <li><span>VirusTotal cross-checks the result across 70+ antivirus engines.</span></li>
            <li><span>If clean, a fresh AES-256 key is generated and the file is encrypted in memory.</span></li>
            <li><span>You receive the key + a QR code. Without it, nobody can decrypt your data — not even us.</span></li>
          </ol>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ============ THE PROBLEM ============ -->
<section id="learn-more" class="cl-section cl-screen lp">
  <div class="w-100 container-fluid px-3">
    <div class="lp-head reveal">
      <span class="lp-eyebrow">The problem</span>
      <h2 class="lp-title">Cloud storage trusts files it never inspects</h2>
    </div>
    <div class="row g-4 g-lg-5 mt-1">
      <div class="col-md-4 reveal" style="--d:0ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-icon">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none"><path d="M12 3l9 16H3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
          </div>
          <h5 class="lp-feature-title">Malware slips through</h5>
          <p class="lp-feature-text mb-0">PDFs are a common delivery vehicle for embedded JavaScript, launch actions and exploits. Most storage platforms accept them blindly.</p>
        </div>
      </div>
      <div class="col-md-4 reveal" style="--d:90ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-icon">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none"><rect x="5" y="11" width="14" height="10" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M8 11V7a4 4 0 0 1 7.75-1.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="16" r="1.5" fill="currentColor"/></svg>
          </div>
          <h5 class="lp-feature-title">Files sit unencrypted</h5>
          <p class="lp-feature-text mb-0">Even when "encrypted at rest," the provider usually holds the keys — meaning they, or anyone who breaches them, can read your data.</p>
        </div>
      </div>
      <div class="col-md-4 reveal" style="--d:180ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-icon">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.8"/><path d="m20 20-3-3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M11 8v3m0 3h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
          </div>
          <h5 class="lp-feature-title">No second opinion</h5>
          <p class="lp-feature-text mb-0">A single scan engine can miss novel or evasive samples. There's rarely a fusion of independent detection signals.</p>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ============ THE APPROACH ============ -->
<section class="cl-section cl-screen lp">
  <div class="w-100 container-fluid px-3">
    <div class="lp-head reveal">
      <span class="lp-eyebrow">The approach</span>
      <h2 class="lp-title">Three independent layers of defense</h2>
    </div>
    <div class="row g-4 g-lg-5 mt-1">
      <div class="col-md-4 reveal" style="--d:0ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-step-wrap">
            <div class="lp-step">01</div>
            <div class="lp-step-icon">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/><path d="M8 12l3 3 5-5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </div>
          </div>
          <h5 class="lp-feature-title mt-3">AI malware detection</h5>
          <p class="lp-feature-text mb-0">A Random Forest classifier trained on the CIC-Evasive-PDFMal2022 dataset extracts 33 structural features from each PDF and predicts malicious vs. benign before storage.</p>
        </div>
      </div>
      <div class="col-md-4 reveal" style="--d:90ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-step-wrap">
            <div class="lp-step">02</div>
            <div class="lp-step-icon">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </div>
          </div>
          <h5 class="lp-feature-title mt-3">VirusTotal corroboration</h5>
          <p class="lp-feature-text mb-0">The verdict engine cross-checks the AI result against VirusTotal's 70+ signature-based engines. Agreement raises confidence; disagreement is surfaced as a fusion signal.</p>
        </div>
      </div>
      <div class="col-md-4 reveal" style="--d:180ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-step-wrap">
            <div class="lp-step">03</div>
            <div class="lp-step-icon">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none"><rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="1.7"/></svg>
            </div>
          </div>
          <h5 class="lp-feature-title mt-3">AES-256-CBC encryption</h5>
          <p class="lp-feature-text mb-0">Clean files are encrypted in memory with a freshly generated AES-256 key. You hold the key — without it, the data cannot be decrypted by anyone, including the server.</p>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ============ RESULTS ============ -->
<section class="cl-section cl-screen lp">
  <div class="w-100 container-fluid px-3">
    <div class="lp-head reveal">
      <span class="lp-eyebrow">Results</span>
      <h2 class="lp-title">Measured, not assumed</h2>
      <p class="lp-subtle mt-2" style="font-size:.97rem">Numbers from the CIC-Evasive-PDFMal2022 dataset, validated on a held-out test split.</p>
    </div>
    <div class="row g-4 g-lg-5 mt-1">
      <div class="col-6 col-lg-3 reveal" style="--d:0ms">
        <div class="lp-stat">
          <div class="lp-stat-icon">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <div class="lp-stat-value">99.8%</div>
          <div class="lp-stat-label">Validation accuracy</div>
        </div>
      </div>
      <div class="col-6 col-lg-3 reveal" style="--d:90ms">
        <div class="lp-stat">
          <div class="lp-stat-icon">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="1.7"/></svg>
          </div>
          <div class="lp-stat-value">18,126</div>
          <div class="lp-stat-label">Training samples</div>
        </div>
      </div>
      <div class="col-6 col-lg-3 reveal" style="--d:180ms">
        <div class="lp-stat">
          <div class="lp-stat-icon">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2v-4M9 21H5a2 2 0 0 1-2-2v-4m0 0h18" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <div class="lp-stat-value">33</div>
          <div class="lp-stat-label">Structural features</div>
        </div>
      </div>
      <div class="col-6 col-lg-3 reveal" style="--d:270ms">
        <div class="lp-stat">
          <div class="lp-stat-icon">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none"><rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="1.7"/></svg>
          </div>
          <div class="lp-stat-value">AES-256</div>
          <div class="lp-stat-label">Encryption standard</div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ============ TECH STACK ============ -->
<section class="cl-section cl-screen lp">
  <div class="w-100 container-fluid px-3">
    <div class="lp-head reveal">
      <span class="lp-eyebrow">Under the hood</span>
      <h2 class="lp-title">Technology stack</h2>
    </div>
    <div class="lp-card reveal mt-1">
      <div class="row g-4 g-lg-5">
        <div class="col-sm-6 col-lg-3">
          <h6 class="lp-stack-key">/ Frontend</h6>
          <div class="lp-tech-badges">
            <span class="lp-tbadge lp-tbadge-cyan">PHP</span>
            <span class="lp-tbadge lp-tbadge-violet">Apache</span>
            <span class="lp-tbadge lp-tbadge-amber">Bootstrap</span>
          </div>
        </div>
        <div class="col-sm-6 col-lg-3">
          <h6 class="lp-stack-key">/ Backend</h6>
          <div class="lp-tech-badges">
            <span class="lp-tbadge lp-tbadge-cyan">Python</span>
            <span class="lp-tbadge lp-tbadge-violet">Flask</span>
            <span class="lp-tbadge lp-tbadge-amber">REST API</span>
          </div>
        </div>
        <div class="col-sm-6 col-lg-3">
          <h6 class="lp-stack-key">/ Machine Learning</h6>
          <div class="lp-tech-badges">
            <span class="lp-tbadge lp-tbadge-cyan">scikit-learn</span>
            <span class="lp-tbadge lp-tbadge-violet">Random Forest</span>
            <span class="lp-tbadge lp-tbadge-amber">pandas</span>
          </div>
        </div>
        <div class="col-sm-6 col-lg-3">
          <h6 class="lp-stack-key">/ Data &amp; Security</h6>
          <div class="lp-tech-badges">
            <span class="lp-tbadge lp-tbadge-cyan">MySQL</span>
            <span class="lp-tbadge lp-tbadge-violet">AES-256-CBC</span>
            <span class="lp-tbadge lp-tbadge-amber">VirusTotal v3</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ============ CREDITS ============ -->
<section class="cl-section cl-screen lp">
  <div class="w-100 container-fluid px-3">
    <div class="lp-head reveal">
      <span class="lp-eyebrow">Credits</span>
      <h2 class="lp-title">About the developer</h2>
    </div>
    <div class="lp-card reveal mt-1">
      <div class="row align-items-center g-4 g-lg-5">
        <div class="col-lg-8">
          <h4 class="lp-dev-name">Aqeef Azhar</h4>
          <p class="lp-role">BSc (Hons) Netcentric Computing &mdash; Universiti Teknologi MARA (UiTM)</p>
          <p class="lp-feature-text mb-4">
            Cloudie is my Final Year Project (CSP650), built to explore how AI-based
            malware detection and strong client-side encryption can work together in a
            single, usable cloud-storage workflow. Supervised by
            <strong>Dr. Fakariah Hani Binti Mohd Ali</strong>.
          </p>
          <div class="d-flex flex-wrap gap-2">
            <a href="https://github.com/your-username" target="_blank" rel="noopener" class="btn btn-cloudie-outline btn-sm">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
              GitHub
            </a>
            <a href="https://www.linkedin.com/in/your-handle" target="_blank" rel="noopener" class="btn btn-cloudie-outline btn-sm">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-4 0v7h-4v-7a6 6 0 0 1 6-6zM2 9h4v12H2z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><circle cx="4" cy="4" r="2" stroke="currentColor" stroke-width="1.8"/></svg>
              LinkedIn
            </a>
            <a href="mailto:you@example.com" class="btn btn-cloudie-outline btn-sm">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none"><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z" stroke="currentColor" stroke-width="1.8"/><path d="M22 6l-10 7L2 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
              Email
            </a>
          </div>
        </div>
        <div class="col-lg-4">
          <ul class="lp-fact-list mb-0">
            <li><span>Project</span> Cloudie</li>
            <li><span>Course</span> CSP650</li>
            <li><span>Faculty</span> Computer &amp; Math Sciences</li>
            <li><span>Year</span> 2026</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ============ LANDING-PAGE STYLES ============ -->
<style>
  html { scroll-behavior: smooth; }

  :root, [data-theme="dark"] {
    --lp-title:       #f3f6ff;
    --lp-subtle:      #a3aacc;
    --lp-card-bg:     rgba(255,255,255,0.04);
    --lp-card-bg-2:   rgba(255,255,255,0.06);
    --lp-card-border: rgba(255,255,255,0.10);
    --lp-card-text:   #c9d0ee;
    --lp-card-head:   #ffffff;
    --lp-accent:      #19e3ff;
    --lp-accent-2:    #45a8ff;
    --lp-violet:      #9b7bff;
    --lp-pill-bg:     rgba(25,227,255,0.10);
    --lp-pill-border: rgba(25,227,255,0.35);
    --lp-divider:     rgba(255,255,255,0.12);
    --lp-shadow:      0 24px 70px rgba(0,0,0,.45);
    --lp-tbadge-cyan-bg:    rgba(25,227,255,.12);  --lp-tbadge-cyan-c:    #19e3ff; --lp-tbadge-cyan-b:    rgba(25,227,255,.28);
    --lp-tbadge-violet-bg:  rgba(155,123,255,.12); --lp-tbadge-violet-c:  #9b7bff; --lp-tbadge-violet-b:  rgba(155,123,255,.28);
    --lp-tbadge-amber-bg:   rgba(255,194,75,.12);  --lp-tbadge-amber-c:   #ffc24b; --lp-tbadge-amber-b:   rgba(255,194,75,.28);
  }
  [data-theme="light"] {
    --lp-title:       #121634;
    --lp-subtle:      #5a6188;
    --lp-card-bg:     #ffffff;
    --lp-card-bg-2:   #f7f9ff;
    --lp-card-border: rgba(18,22,52,0.10);
    --lp-card-text:   #444b73;
    --lp-card-head:   #1c2046;
    --lp-accent:      #0c84a6;
    --lp-accent-2:    #1f9fd0;
    --lp-violet:      #6b2bd9;
    --lp-pill-bg:     rgba(12,132,166,0.08);
    --lp-pill-border: rgba(12,132,166,0.30);
    --lp-divider:     rgba(18,22,52,0.10);
    --lp-shadow:      0 18px 50px rgba(18,22,52,.12);
    --lp-tbadge-cyan-bg:    rgba(12,132,166,.10);  --lp-tbadge-cyan-c:    #0c84a6; --lp-tbadge-cyan-b:    rgba(12,132,166,.25);
    --lp-tbadge-violet-bg:  rgba(107,43,217,.10);  --lp-tbadge-violet-c:  #6b2bd9; --lp-tbadge-violet-b:  rgba(107,43,217,.25);
    --lp-tbadge-amber-bg:   rgba(180,120,0,.10);   --lp-tbadge-amber-c:   #b47800; --lp-tbadge-amber-b:   rgba(180,120,0,.25);
  }

  /* GRID & SPACING (utilities the shared shell doesn't define) */
  .lp .px-0 { padding-left: 0; padding-right: 0; }
  .lp .px-3 { padding-left: 1rem; padding-right: 1rem; }
  .lp .mx-0 { margin-left: 0; margin-right: 0; }
  .lp .mt-1 { margin-top: .25rem; }
  .lp .mt-5 { margin-top: 3rem; }
  .lp .gap-3 { gap: 1rem; }
  .lp .h-100 { height: 100%; }
  .lp .row { row-gap: 1.5rem; }
  .lp .col-6, .lp .col-sm-6 { flex: 0 0 50%; max-width: 50%; }
  .lp .col-lg-4 { flex: 0 0 100%; max-width: 100%; }
  @media (min-width: 1001px) {
    .lp .col-lg-3 { flex: 0 0 25%; max-width: 25%; }
    .lp .col-lg-4 { flex: 0 0 33.33%; max-width: 33.33%; }
    .lp .d-none.d-lg-block { display: block; }
  }
  @media (max-width: 768px) {
    .lp .col-md-4 { flex: 0 0 100%; max-width: 100%; }
  }
  @media (max-width: 576px) {
    .lp .col-sm-6 { flex: 0 0 100%; max-width: 100%; }
  }

  /* FULL-SCREEN SECTIONS */
  .cl-screen { min-height: 100vh; display: flex; align-items: center;
    padding-top: clamp(3rem,8vh,6rem); padding-bottom: clamp(3rem,8vh,6rem); }
  .hero.cl-screen { padding-top: clamp(2rem,6vh,4rem); }
  @media (max-height:680px) { .cl-screen { min-height: auto; } }

  /* HERO PILL */
  .lp-pill { display: inline-flex; align-items: center; padding: .35rem .9rem; border-radius: 999px;
    font-size: .78rem; font-weight: 700; letter-spacing: .04em;
    color: var(--lp-accent); background: var(--lp-pill-bg); border: 1px solid var(--lp-pill-border);
    margin-bottom: 1.1rem; }

  /* HERO TITLE */
  .lp-hero-title { font-family: 'Space Grotesk', sans-serif; font-weight: 800;
    letter-spacing: -.03em; font-size: clamp(2.2rem, 5vw, 3.6rem);
    line-height: 1.08; color: var(--lp-title); margin: 0; }
  .lp-gradient { background: linear-gradient(90deg, var(--lp-accent), var(--lp-accent-2));
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; }
  .lp-subtle { color: var(--lp-subtle); max-width: 580px; }

  /* SCROLL CUE */
  .scroll-cue { display: inline-flex; align-items: center; gap: .6rem; color: var(--lp-subtle);
    text-decoration: none; font-size: .9rem; font-weight: 500; transition: color .2s, gap .2s; }
  .scroll-cue:hover { color: var(--lp-accent); gap: .85rem; text-decoration: none; }
  .scroll-arrow { display: inline-block; animation: clBounce 1.6s infinite; }
  @keyframes clBounce { 0%,100% { transform: translateY(0); } 50% { transform: translateY(5px); } }

  /* SECTION HEADS */
  .lp-head { max-width: 740px; margin-bottom: 2.25rem; }
  .lp-eyebrow { display: block; text-transform: uppercase; letter-spacing: .2em;
    font-size: .76rem; font-weight: 700; color: var(--lp-accent); margin-bottom: .6rem; }
  .lp-title { font-weight: 800; color: var(--lp-title);
    font-size: clamp(1.6rem, 4vw, 2.4rem); line-height: 1.22; letter-spacing: -.02em; margin: 0; }

  /* CARDS */
  .lp-card { background: var(--lp-card-bg); border: 1px solid var(--lp-card-border);
    border-radius: 18px; padding: clamp(1.4rem,2.5vw,2rem);
    box-shadow: var(--lp-shadow); backdrop-filter: blur(6px); }
  .lp-hero-card { background: var(--lp-card-bg-2); }
  .lp-card-title { color: var(--lp-card-head); font-weight: 800; margin-bottom: 1.1rem;
    padding-bottom: .75rem; border-bottom: 1px solid var(--lp-divider);
    display: flex; align-items: center; gap: 10px; }
  .lp-howto { list-style: none; counter-reset: step; padding: 0; margin: 0; }
  .lp-howto li { position: relative; padding-left: 2.4rem; margin-bottom: 1.05rem;
    color: var(--lp-card-text); line-height: 1.5; }
  .lp-howto li:last-child { margin-bottom: 0; }
  .lp-howto li::before { counter-increment: step; content: counter(step);
    position: absolute; left: 0; top: -1px; width: 1.7rem; height: 1.7rem;
    display: grid; place-items: center; border-radius: 50%;
    font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: .8rem;
    color: var(--lp-accent); background: var(--lp-pill-bg); border: 1px solid var(--lp-pill-border); }

  /* FEATURE CARDS */
  .lp-feature { transition: transform .2s ease, box-shadow .25s ease, border-color .25s ease; }
  .lp-feature:hover { transform: translateY(-5px); border-color: var(--lp-pill-border); }
  .lp-icon { width: 2.8rem; height: 2.8rem; display: grid; place-items: center;
    border-radius: 13px; margin-bottom: 1rem;
    color: var(--lp-accent); background: var(--lp-pill-bg); border: 1px solid var(--lp-pill-border); }
  .lp-step-wrap { display: flex; align-items: center; gap: .8rem; }
  .lp-step { font-family: 'Space Grotesk', sans-serif; font-size: .85rem; font-weight: 800;
    color: var(--lp-violet); background: var(--lp-card-bg-2); border: 1px solid var(--lp-card-border);
    border-radius: 9px; padding: .25rem .65rem; letter-spacing: .05em; }
  .lp-step-icon { width: 2.2rem; height: 2.2rem; display: grid; place-items: center;
    border-radius: 10px; color: var(--lp-violet);
    background: rgba(155,123,255,.10); border: 1px solid rgba(155,123,255,.22); }
  [data-theme="light"] .lp-step-icon { background: rgba(107,43,217,.08); border-color: rgba(107,43,217,.20); }
  .lp-feature-title { color: var(--lp-card-head); font-weight: 700; margin-bottom: .55rem; }
  .lp-feature-text  { color: var(--lp-card-text); line-height: 1.55; }

  /* STAT TILES */
  .lp-stat { background: var(--lp-card-bg); border: 1px solid var(--lp-card-border);
    border-radius: 18px; padding: clamp(1.5rem,4vw,2.3rem) 1rem;
    text-align: center; height: 100%;
    display: flex; flex-direction: column; align-items: center; gap: .4rem;
    transition: transform .2s ease, border-color .2s ease; }
  .lp-stat:hover { transform: translateY(-4px); border-color: var(--lp-pill-border); }
  .lp-stat-icon { width: 2.2rem; height: 2.2rem; display: grid; place-items: center;
    border-radius: 10px; margin-bottom: .3rem;
    color: var(--lp-accent); background: var(--lp-pill-bg); border: 1px solid var(--lp-pill-border); }
  .lp-stat-value { font-family: 'Space Grotesk', sans-serif; font-weight: 800;
    font-size: clamp(1.8rem,4vw,2.6rem); line-height: 1.1; letter-spacing: -.02em;
    color: var(--lp-accent); }
  @supports ((-webkit-background-clip: text) or (background-clip: text)) {
    .lp-stat-value { background: linear-gradient(90deg, var(--lp-accent), var(--lp-accent-2));
      -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; }
  }
  .lp-stat-label { color: var(--lp-subtle); font-size: .88rem; font-weight: 500; margin-top: .1rem; }

  /* TECH STACK */
  .lp-stack-key { font-family: 'Space Grotesk', sans-serif; color: var(--lp-accent);
    font-weight: 700; margin-bottom: .75rem; font-size: .88rem; letter-spacing: .02em; }
  .lp-tech-badges { display: flex; flex-wrap: wrap; gap: 6px; }
  .lp-tbadge { display: inline-block; font-size: .78rem; font-weight: 600;
    padding: .28rem .72rem; border-radius: 999px; }
  .lp-tbadge-cyan   { background: var(--lp-tbadge-cyan-bg);   color: var(--lp-tbadge-cyan-c);   border: 1px solid var(--lp-tbadge-cyan-b); }
  .lp-tbadge-violet { background: var(--lp-tbadge-violet-bg); color: var(--lp-tbadge-violet-c); border: 1px solid var(--lp-tbadge-violet-b); }
  .lp-tbadge-amber  { background: var(--lp-tbadge-amber-bg);  color: var(--lp-tbadge-amber-c);  border: 1px solid var(--lp-tbadge-amber-b); }

  /* CREDITS */
  .lp-dev-name { color: var(--lp-accent); font-weight: 800; margin-bottom: .25rem; }
  .lp-role { color: var(--lp-violet); font-weight: 600; font-size: .98rem; margin-bottom: 1rem; }
  .lp-fact-list { list-style: none; padding: 0; margin: 0; }
  .lp-fact-list li { display: flex; justify-content: space-between; gap: 1rem;
    padding: .7rem 0; border-bottom: 1px solid var(--lp-divider);
    color: var(--lp-card-head); font-weight: 600; font-size: .92rem; }
  .lp-fact-list li:last-child { border-bottom: none; }
  .lp-fact-list li span { color: var(--lp-subtle); font-weight: 400; }

  /* SCROLL REVEAL */
  .reveal { opacity: 0; transform: translateY(22px);
    transition: opacity .65s cubic-bezier(.16,1,.3,1), transform .65s cubic-bezier(.16,1,.3,1);
    transition-delay: var(--d, 0ms); will-change: opacity, transform; }
  .reveal.is-visible { opacity: 1; transform: none; }
  @media (prefers-reduced-motion: reduce) {
    html { scroll-behavior: auto; }
    .reveal { opacity: 1; transform: none; transition: none; }
    .scroll-arrow { animation: none; }
  }
</style>

<!-- ============ SCRIPTS ============ -->
<script>
(function () {
  var items = document.querySelectorAll('.reveal');
  if (!('IntersectionObserver' in window) || items.length === 0) {
    items.forEach(function (el) { el.classList.add('is-visible'); });
    return;
  }
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        io.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -30px 0px' });
  items.forEach(function (el) { io.observe(el); });
})();
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
