<?php
require_once __DIR__ . '/includes/auth.php';
$pageTitle = 'Home';
require_once __DIR__ . '/includes/header.php';
?>

<div class="lp-progress" id="lpProgress" aria-hidden="true"></div>

<!-- ============ HERO ============ -->
<section class="hero cl-screen lp">
  <div class="lp-aurora" aria-hidden="true"></div>
  <div class="lp-grid-bg" aria-hidden="true"></div>
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
          Cloudie checks every upload with VirusTotal first, then reads <strong>how the file is built</strong>:
          rule-based structure checks for PDF, Office, ZIP, CSV and image files, plus a Random Forest
          analyzer for PDFs that also says when a file is unlike anything it was trained on. The file is then
          encrypted on the server with AES-256-CBC. Only a SHA-256 hash of your key is kept, so you need your
          key to read the file back.
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
        <div class="lp-trust reveal" style="--d:220ms" aria-label="What protects your files">
          <span><i></i>VirusTotal &middot; 70+ engines</span>
          <span><i></i>Structure checks &middot; no signature needed</span>
          <span><i></i>Random Forest &middot; 32 features</span>
          <span><i></i>AES-256-CBC</span>
          <span><i></i>2-step login</span>
        </div>
        <div class="mt-5 reveal" style="--d:260ms">
          <a href="#learn-more" class="scroll-cue">
            Discover how it works
            <span class="scroll-arrow">↓</span>
          </a>
        </div>
      </div>
      <div class="col-lg-5 px-3">
        <div class="lp-card lp-demo reveal" style="--d:160ms" id="lpDemo">
          <div class="lp-demo-head">
            <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
            <span class="lp-demo-title">UPLOAD PIPELINE &middot; ILLUSTRATION</span>
          </div>
          <div class="lp-demo-body">
            <div class="lp-demo-file">
              <span class="ico"><svg viewBox="0 0 24 24" width="20" height="20" fill="none"><path d="M7 3h7l5 5v13H7z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M14 3v5h5" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg></span>
              <div><b id="demoName">invoice_q3.pdf</b><small id="demoMeta">PDF &middot; 214 KB</small></div>
              <span class="lp-chip" id="demoChip">SCANNING</span>
            </div>
            <ol class="lp-demo-steps" id="demoSteps">
              <li><span class="si"></span><span>Upload</span><span class="st">&nbsp;</span></li>
              <li><span class="si"></span><span>VirusTotal <em>(primary)</em></span><span class="st">&nbsp;</span></li>
              <li><span class="si"></span><span>Structure checks <em>(+ AI for PDF)</em></span><span class="st">&nbsp;</span></li>
              <li><span class="si"></span><span>Encrypt on the server</span><span class="st">&nbsp;</span></li>
              <li><span class="si"></span><span>Store</span><span class="st">&nbsp;</span></li>
            </ol>
            <div class="lp-demo-bar"><span id="demoBar"></span></div>
            <p class="lp-demo-note">Example files, not a real scan. The file is sent to VirusTotal for the primary check; only a SHA-256 hash of your key is stored, so you need your key to read a file back.</p>
          </div>
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
      <div class="col-md-4 reveal" data-fx="left" style="--d:0ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-icon">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none"><path d="M12 3l9 16H3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
          </div>
          <div class="fx fx-slip" aria-hidden="true">
            <span class="fx-file"><svg viewBox="0 0 24 30" fill="none"><path d="M3 1h12l6 6v22H3z" fill="currentColor" fill-opacity=".12" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M15 1v6h6" stroke="currentColor" stroke-width="1.6"/></svg><i></i></span>
            <span class="fx-box"><svg viewBox="0 0 24 24" fill="none"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="1.6"/></svg>Storage</span>
            <span class="fx-tick">&#10003; accepted</span>
            <em>no inspection</em>
          </div>
          <h5 class="lp-feature-title">Malware slips through</h5>
          <p class="lp-feature-text mb-0">PDFs are a common delivery vehicle for embedded JavaScript, launch actions and exploits. Most storage platforms accept them blindly.</p>
        </div>
      </div>
      <div class="col-md-4 reveal" data-fx="zoom" style="--d:90ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-icon">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none"><rect x="5" y="11" width="14" height="10" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M8 11V7a4 4 0 0 1 7.75-1.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="16" r="1.5" fill="currentColor"/></svg>
          </div>
          <div class="fx fx-read" aria-hidden="true">
            <span class="l"></span><span class="l w2"></span><span class="l w3"></span>
            <span class="scan"></span>
            <em>readable by the provider</em>
          </div>
          <h5 class="lp-feature-title">Files sit unencrypted</h5>
          <p class="lp-feature-text mb-0">Even when "encrypted at rest," the provider usually holds the keys — meaning they, or anyone who breaches them, can read your data.</p>
        </div>
      </div>
      <div class="col-md-4 reveal" data-fx="right" style="--d:180ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-icon">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.8"/><path d="m20 20-3-3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M11 8v3m0 3h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
          </div>
          <div class="fx fx-radar" aria-hidden="true">
            <span class="ring"></span><span class="ring r2"></span><span class="sweep"></span><span class="blip"></span>
            <em>one engine, one blind spot</em>
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
    <div class="row g-4 g-lg-5 mt-1 lp-flow">
      <span class="lp-flow-dot" aria-hidden="true"></span>
      <div class="col-md-4 reveal" data-fx="zoom" style="--d:0ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-step-wrap">
            <div class="lp-step">01</div>
            <div class="lp-step-icon">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/><path d="M8 12l3 3 5-5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </div>
          </div>
          <h5 class="lp-feature-title mt-3">VirusTotal first</h5>
          <p class="lp-feature-text mb-0">VirusTotal's 70+ signature-based engines give the primary verdict. Two or more engines block a file, a single engine only warns, and if VirusTotal gives no answer the upload is refused (fail closed).</p>
        </div>
      </div>
      <div class="col-md-4 reveal" data-fx="zoom" style="--d:90ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-step-wrap">
            <div class="lp-step">02</div>
            <div class="lp-step-icon">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </div>
          </div>
          <h5 class="lp-feature-title mt-3">Structure checks + explainable AI</h5>
          <p class="lp-feature-text mb-0">Signatures know the past; structure reads the file. Rule-based checks catch what has no signature yet: a macro inside a .docx, hidden PDF scripts, zip slip, programs disguised as documents, data hidden in images, CSV formula injection. For PDFs a Random Forest (32 features) adds an explained score and says when a file is unlike its training data. A finding stores the file tagged Suspicious, with the reason.</p>
        </div>
      </div>
      <div class="col-md-4 reveal" data-fx="zoom" style="--d:180ms">
        <div class="lp-card lp-feature h-100">
          <div class="lp-step-wrap">
            <div class="lp-step">03</div>
            <div class="lp-step-icon">
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none"><rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="1.7"/></svg>
            </div>
          </div>
          <h5 class="lp-feature-title mt-3">AES-256-CBC encryption</h5>
          <p class="lp-feature-text mb-0">Clean and suspicious files are encrypted on the server with a freshly generated AES-256-CBC key. Cloudie keeps only a SHA-256 hash of the key, so you need your key to read the file back.</p>
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
      <div class="col-6 col-lg-3 reveal" data-fx="zoom" style="--d:0ms">
        <div class="lp-stat">
          <div class="lp-ring" aria-hidden="true">
            <svg viewBox="0 0 44 44"><circle class="bg" cx="22" cy="22" r="19" pathLength="100"/><circle class="fg" cx="22" cy="22" r="19" pathLength="100" style="--off:0.13"/></svg>
            <svg class="chk" viewBox="0 0 24 24" width="18" height="18" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <div class="lp-stat-value">99.87%</div>
          <div class="lp-stat-label">Hold-out accuracy (size-based: 99.46%)</div>
        </div>
      </div>
      <div class="col-6 col-lg-3 reveal" data-fx="zoom" style="--d:90ms">
        <div class="lp-stat">
          <div class="lp-stat-icon">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="1.7"/></svg>
          </div>
          <div class="lp-stat-value">18,126</div>
          <div class="lp-stat-label">Training samples</div>
        </div>
      </div>
      <div class="col-6 col-lg-3 reveal" data-fx="zoom" style="--d:180ms">
        <div class="lp-stat">
          <div class="lp-stat-icon">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2v-4M9 21H5a2 2 0 0 1-2-2v-4m0 0h18" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <div class="lp-stat-value">32</div>
          <div class="lp-stat-label">Structural features</div>
        </div>
      </div>
      <div class="col-6 col-lg-3 reveal" data-fx="zoom" style="--d:270ms">
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

<!-- ============ FRAMEWORKS ============ -->
<section class="cl-section cl-screen lp">
  <div class="w-100 container-fluid px-3">
    <div class="lp-head reveal">
      <span class="lp-eyebrow">Standards</span>
      <h2 class="lp-title">Mapped to recognised frameworks</h2>
      <p class="lp-subtle mt-2" style="font-size:.97rem">Each control is mapped to the code that implements it. Mapped, not certified.</p>
    </div>
    <div class="row g-4 g-lg-5 mt-1">
      <div class="col-md-6 col-lg-3 reveal" data-fx="zoom" style="--d:0ms">
        <div class="lp-card lp-feature h-100">
          <h6 class="lp-stack-key">MITRE ATT&amp;CK</h6>
          <p class="lp-feature-text mb-3">The structure checks detect named attack techniques.</p>
          <div class="lp-tech-badges">
            <span class="lp-tbadge lp-tbadge-cyan">T1027 Obfuscation</span>
            <span class="lp-tbadge lp-tbadge-violet">T1221 Template injection</span>
            <span class="lp-tbadge lp-tbadge-amber">T1559.002 DDE</span>
            <span class="lp-tbadge lp-tbadge-cyan">T1036 Masquerading</span>
            <span class="lp-tbadge lp-tbadge-violet">T1059.005 Macros</span>
          </div>
        </div>
      </div>
      <div class="col-md-6 col-lg-3 reveal" data-fx="zoom" style="--d:90ms">
        <div class="lp-card lp-feature h-100">
          <h6 class="lp-stack-key">NIST CSF 2.0</h6>
          <p class="lp-feature-text mb-3">Controls across the framework's functions.</p>
          <div class="lp-tech-badges">
            <span class="lp-tbadge lp-tbadge-cyan">Identify: threat model</span>
            <span class="lp-tbadge lp-tbadge-violet">Protect: AES-256, OTP</span>
            <span class="lp-tbadge lp-tbadge-amber">Detect: every upload scanned</span>
            <span class="lp-tbadge lp-tbadge-cyan">Respond: block or tag</span>
            <span class="lp-tbadge lp-tbadge-violet">Recover: daily backups</span>
          </div>
        </div>
      </div>
      <div class="col-md-6 col-lg-3 reveal" data-fx="zoom" style="--d:180ms">
        <div class="lp-card lp-feature h-100">
          <h6 class="lp-stack-key">ISO/IEC 27001:2022</h6>
          <p class="lp-feature-text mb-3">Technical controls from Annex A.</p>
          <div class="lp-tech-badges">
            <span class="lp-tbadge lp-tbadge-cyan">8.7 Malware protection</span>
            <span class="lp-tbadge lp-tbadge-violet">8.24 Cryptography</span>
            <span class="lp-tbadge lp-tbadge-amber">8.5 Secure authentication</span>
            <span class="lp-tbadge lp-tbadge-cyan">8.15 Logging</span>
            <span class="lp-tbadge lp-tbadge-violet">8.13 Backup</span>
          </div>
        </div>
      </div>
      <div class="col-md-6 col-lg-3 reveal" data-fx="zoom" style="--d:270ms">
        <div class="lp-card lp-feature h-100">
          <h6 class="lp-stack-key">OWASP &amp; NIST SP 800-63B</h6>
          <p class="lp-feature-text mb-3">Web application and password guidance.</p>
          <div class="lp-tech-badges">
            <span class="lp-tbadge lp-tbadge-cyan">File Upload Cheat Sheet</span>
            <span class="lp-tbadge lp-tbadge-violet">A03 Injection</span>
            <span class="lp-tbadge lp-tbadge-amber">A07 Authentication</span>
            <span class="lp-tbadge lp-tbadge-cyan">800-63B password rules</span>
          </div>
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
            <span class="lp-tbadge lp-tbadge-amber">HTML/CSS</span>
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
    <?php $lpStack = ['PHP', 'Apache', 'Python', 'Flask', 'scikit-learn', 'Random Forest', 'pandas', 'MySQL',
                      'AES-256-CBC', 'VirusTotal v3', 'Google Cloud Run', 'Cloud SQL', 'Cloud Storage',
                      'Secret Manager', 'PHPMailer']; ?>
    <div class="lp-marquee reveal" aria-hidden="true">
      <div class="lp-marquee-track">
        <?php for ($lpK = 0; $lpK < 2; $lpK++): foreach ($lpStack as $lpItem): ?>
          <span<?= $lpK ? ' class="dup"' : '' ?>><?= htmlspecialchars($lpItem, ENT_QUOTES, 'UTF-8') ?></span>
        <?php endforeach; endfor; ?>
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
    <div class="lp-card lp-dev reveal mt-1">
      <div class="lp-avatar-wrap">
        <div class="lp-avatar">
          <img src="assets/img/developer.webp" alt="Portrait of Aqeef Azhar, the developer of Cloudie"
               width="240" height="240" loading="lazy" decoding="async">
        </div>
      </div>
      <div class="lp-dev-body">
        <h4 class="lp-dev-name">Aqeef Azhar</h4>
        <p class="lp-role">BSc (Hons) Netcentric Computing &mdash; Universiti Teknologi MARA (UiTM)</p>
        <p class="lp-feature-text mb-0">
          Cloudie is my Final Year Project (CSP650), built to explore how malware
          detection (VirusTotal plus structure checks and an AI analyzer) and AES encryption can work together in a
          single, usable cloud-storage workflow. Supervised by
          <strong>Dr. Fakariah Hani Binti Mohd Ali</strong>.
        </p>
        <div class="lp-links">
          <a class="lp-link" href="https://github.com/aqeeflew/cloudie" target="_blank" rel="noopener noreferrer">
            <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.52-1.33-1.28-1.69-1.28-1.69-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a10.9 10.9 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.42-2.69 5.39-5.26 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5z"/></svg>
            <span>Source code</span>
          </a>
          <a class="lp-link" href="https://www.linkedin.com/in/aqeefazhar" target="_blank" rel="noopener noreferrer">
            <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M20.45 20.45h-3.56v-5.57c0-1.33-.03-3.04-1.85-3.04-1.86 0-2.14 1.45-2.14 2.94v5.67H9.35V9h3.41v1.56h.05c.48-.9 1.64-1.85 3.37-1.85 3.6 0 4.27 2.37 4.27 5.46v6.28zM5.34 7.43a2.06 2.06 0 1 1 0-4.12 2.06 2.06 0 0 1 0 4.12zM7.12 20.45H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 1.78-1.73V1.73C24 .77 23.2 0 22.22 0z"/></svg>
            <span>LinkedIn</span>
          </a>
          <a class="lp-link" href="mailto:aqeef1303@gmail.com">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="m4 7 8 6 8-6"/></svg>
            <span>Email</span>
          </a>
        </div>
        <div class="lp-facts">
          <div class="lp-fact"><span>Project</span>Cloudie</div>
          <div class="lp-fact"><span>Course</span>CSP650</div>
          <div class="lp-fact"><span>Faculty</span>Computer &amp; Math Sciences</div>
          <div class="lp-fact"><span>Year</span>2026</div>
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
  .lp-gradient { background: linear-gradient(90deg, var(--lp-accent), var(--lp-violet), var(--lp-accent-2), var(--lp-accent));
    background-size: 300% 100%; animation: lpShimmer 9s linear infinite;
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; }
  @keyframes lpShimmer { to { background-position: -300% 0; } }
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
  .lp-links { display: flex; flex-wrap: wrap; gap: .6rem; margin-top: 1.1rem; }
  .lp-link { display: inline-flex; align-items: center; gap: .5rem; padding: .5rem .95rem;
    border-radius: 999px; border: 1px solid var(--lp-card-border); color: var(--lp-accent);
    font-weight: 600; font-size: .9rem; text-decoration: none; transition: .15s; }
  .lp-link:hover, .lp-link:focus-visible { background: rgba(25,227,255,.14); border-color: var(--lp-accent); text-decoration: none; }
  .lp-link svg { width: 17px; height: 17px; flex: none; }
  .lp-fact-list { list-style: none; padding: 0; margin: 0; }
  .lp-fact-list li { display: flex; justify-content: space-between; gap: 1rem;
    padding: .7rem 0; border-bottom: 1px solid var(--lp-divider);
    color: var(--lp-card-head); font-weight: 600; font-size: .92rem; }
  .lp-fact-list li:last-child { border-bottom: none; }
  .lp-fact-list li span { color: var(--lp-subtle); font-weight: 400; }

  /* ---------- HERO BACKGROUND ---------- */
  /* overflow: clip (not just hidden) so the decorative layers can never make the hero scrollable */
  .hero.lp { position: relative; overflow: hidden; overflow: clip; isolation: isolate; }
  /* The aurora fades out before the hero's bottom edge (the hero clips it), so the hero blends into the next
     section instead of ending in a visible line. */
  .lp-aurora { position: absolute; inset: -15% -10% 0 -10%; z-index: -2; pointer-events: none;
    background:
      radial-gradient(40% 38% at 18% 28%, rgba(25,227,255,.24), transparent 70%),
      radial-gradient(34% 32% at 82% 18%, rgba(155,123,255,.24), transparent 70%),
      radial-gradient(32% 30% at 62% 68%, rgba(69,168,255,.18), transparent 70%);
    -webkit-mask-image: radial-gradient(ellipse at 50% 50%, #000 35%, transparent 78%), linear-gradient(#000 0, #000 58%, transparent 88%);
            mask-image: radial-gradient(ellipse at 50% 50%, #000 35%, transparent 78%), linear-gradient(#000 0, #000 58%, transparent 88%);
    -webkit-mask-composite: source-in; mask-composite: intersect;
    animation: lpDrift 20s ease-in-out infinite alternate; }
  [data-theme="light"] .lp-aurora { opacity: .55; }
  @keyframes lpDrift { from { transform: translate3d(-2%,0,0) scale(1); } to { transform: translate3d(2%,3%,0) scale(1.08); } }
  .lp-grid-bg { position: absolute; inset: 0; z-index: -1; pointer-events: none; opacity: .45;
    background-image: linear-gradient(var(--lp-divider) 1px, transparent 1px),
                      linear-gradient(90deg, var(--lp-divider) 1px, transparent 1px);
    background-size: 56px 56px;
    -webkit-mask-image: radial-gradient(ellipse at 50% 30%, #000 18%, transparent 72%);
            mask-image: radial-gradient(ellipse at 50% 30%, #000 18%, transparent 72%); }

  /* ---------- TRUST CHIPS ---------- */
  .lp-trust { display: flex; flex-wrap: wrap; gap: .55rem; margin-top: 1.7rem; }
  .lp-trust span { display: inline-flex; align-items: center; gap: .45rem; font-size: .78rem; font-weight: 600;
    padding: .34rem .8rem; border-radius: 999px; color: var(--lp-card-text);
    background: var(--lp-card-bg); border: 1px solid var(--lp-card-border); backdrop-filter: blur(6px); }
  .lp-trust i { width: 7px; height: 7px; border-radius: 50%; background: var(--lp-accent);
    box-shadow: 0 0 10px var(--lp-accent); animation: lpPulse 2.4s ease-in-out infinite; }
  @keyframes lpPulse { 50% { opacity: .35; } }

  /* keep the hero inside the viewport: the section is a flex box, so without this the
     container shrink-wraps to the widest child (the pipeline card) on small screens */
  .hero.lp > .container-fluid { width: 100%; min-width: 0; }
  .hero.lp .row > [class*="col-"] { min-width: 0; }

  /* ---------- PIPELINE ILLUSTRATION ---------- */
  .lp-demo { position: relative; padding: 0; overflow: hidden; background: var(--lp-card-bg-2); }
  .lp-demo::before { content: ''; position: absolute; inset: 0; padding: 1px; border-radius: 18px; pointer-events: none;
    background: linear-gradient(135deg, rgba(25,227,255,.6), rgba(155,123,255,.4) 45%, transparent 75%);
    -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
    -webkit-mask-composite: xor; mask-composite: exclude; }
  .lp-demo-head { display: flex; align-items: center; gap: .45rem; padding: .8rem 1.1rem;
    border-bottom: 1px solid var(--lp-divider); }
  .lp-demo-head .dot { width: 10px; height: 10px; border-radius: 50%; }
  .lp-demo-head .r { background: #ff5d6c; } .lp-demo-head .y { background: #ffc24b; } .lp-demo-head .g { background: #34e0a1; }
  .lp-demo-title { margin-left: .5rem; font-size: .7rem; color: var(--lp-subtle); font-weight: 700; letter-spacing: .12em; }
  .lp-demo-body { padding: 1.2rem 1.3rem 1.25rem; }
  .lp-demo-file { display: flex; align-items: center; gap: .8rem; margin-bottom: 1.1rem; }
  .lp-demo-file .ico { width: 2.7rem; height: 2.7rem; border-radius: 12px; display: grid; place-items: center; flex: none;
    color: var(--lp-accent); background: var(--lp-pill-bg); border: 1px solid var(--lp-pill-border); }
  .lp-demo-file > div { min-width: 0; }
  .lp-demo-file b { display: block; color: var(--lp-card-head); font-size: .95rem; font-family: 'JetBrains Mono', monospace;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .lp-demo-file small { color: var(--lp-subtle); font-size: .78rem; }
  .lp-chip { margin-left: auto; font-size: .7rem; font-weight: 800; letter-spacing: .1em; padding: .3rem .75rem;
    border-radius: 999px; border: 1px solid var(--lp-card-border); color: var(--lp-subtle); transition: all .35s; white-space: nowrap; }
  .lp-chip.clean { color: #34e0a1; border-color: rgba(52,224,161,.45); background: rgba(52,224,161,.12); }
  .lp-chip.warn  { color: #ffc24b; border-color: rgba(255,194,75,.45); background: rgba(255,194,75,.12); }
  .lp-chip.bad   { color: #ff5d6c; border-color: rgba(255,93,108,.45); background: rgba(255,93,108,.12); }
  [data-theme="light"] .lp-chip.clean { color: #0d8f63; }
  [data-theme="light"] .lp-chip.warn  { color: #a86a00; }
  [data-theme="light"] .lp-chip.bad   { color: #c0283a; }
  .lp-demo-steps { list-style: none; margin: 0; padding: 0; display: grid; gap: .5rem; }
  .lp-demo-steps li { display: flex; align-items: center; gap: .75rem; padding: .55rem .7rem; border-radius: 12px;
    border: 1px solid transparent; color: var(--lp-subtle); opacity: .55; font-size: .9rem; transition: all .35s; }
  .lp-demo-steps em { font-style: normal; color: var(--lp-subtle); font-size: .78rem; }
  .lp-demo-steps .si { width: 1.7rem; height: 1.7rem; border-radius: 50%; display: grid; place-items: center; flex: none;
    border: 1.5px solid var(--lp-card-border); font-size: .74rem; font-weight: 800; }
  .lp-demo-steps .st { margin-left: auto; font-size: .74rem; font-family: 'JetBrains Mono', monospace; text-align: right; }
  .lp-demo-steps li.active { opacity: 1; background: var(--lp-pill-bg); border-color: var(--lp-pill-border); color: var(--lp-card-head); }
  .lp-demo-steps li.active .si { border-color: var(--lp-accent); border-top-color: transparent; animation: lpSpin .8s linear infinite; }
  .lp-demo-steps li.ok, .lp-demo-steps li.warn, .lp-demo-steps li.fail { opacity: 1; color: var(--lp-card-head); }
  .lp-demo-steps li.ok .si   { border-color: rgba(52,224,161,.6); background: rgba(52,224,161,.14); color: #34e0a1; }
  .lp-demo-steps li.ok .si::before   { content: '\2713'; }
  .lp-demo-steps li.warn .si { border-color: rgba(255,194,75,.6); background: rgba(255,194,75,.14); color: #ffc24b; }
  .lp-demo-steps li.warn .si::before { content: '!'; }
  .lp-demo-steps li.fail .si { border-color: rgba(255,93,108,.6); background: rgba(255,93,108,.14); color: #ff5d6c; }
  .lp-demo-steps li.fail .si::before { content: '\2715'; }
  .lp-demo-steps li.skip { opacity: .35; }
  .lp-demo-steps li.skip .st { text-decoration: line-through; }
  [data-theme="light"] .lp-demo-steps li.ok .si { color: #0d8f63; }
  [data-theme="light"] .lp-demo-steps li.warn .si { color: #a86a00; }
  [data-theme="light"] .lp-demo-steps li.fail .si { color: #c0283a; }
  .lp-demo-bar { height: 4px; border-radius: 99px; background: var(--lp-divider); margin-top: 1.1rem; overflow: hidden; }
  .lp-demo-bar span { display: block; height: 100%; width: 0; border-radius: 99px;
    background: linear-gradient(90deg, var(--lp-accent), var(--lp-violet)); transition: width .55s ease; }
  .lp-demo-note { font-size: .72rem; line-height: 1.45; color: var(--lp-subtle); margin: .85rem 0 0; }
  @keyframes lpSpin { to { transform: rotate(360deg); } }

  /* ---------- CARD SPOTLIGHT (follows the pointer) ---------- */
  .lp-feature, .lp-stat { position: relative; overflow: hidden; }
  .lp-feature::after, .lp-stat::after { content: ''; position: absolute; inset: 0; pointer-events: none; opacity: 0;
    transition: opacity .3s;
    background: radial-gradient(260px circle at var(--mx, 50%) var(--my, 50%), rgba(25,227,255,.14), transparent 62%); }
  .lp-feature:hover::after, .lp-stat:hover::after { opacity: 1; }

  /* ---------- DEVELOPER CARD ---------- */
  .lp-dev { display: grid; grid-template-columns: minmax(200px, 290px) 1fr; gap: clamp(1.5rem, 4vw, 3rem); align-items: center; }
  .lp-avatar-wrap { display: flex; justify-content: center; }
  .lp-avatar { position: relative; width: min(250px, 62vw); aspect-ratio: 1; border-radius: 50%; padding: 5px;
    background: conic-gradient(from 140deg, var(--lp-accent), var(--lp-violet), var(--lp-accent-2), var(--lp-accent));
    box-shadow: 0 0 0 7px var(--lp-pill-bg), 0 22px 60px rgba(25,227,255,.22);
    animation: lpFloat 6s ease-in-out infinite; }
  .lp-avatar::after { content: ''; position: absolute; inset: -14px; border-radius: 50%; pointer-events: none;
    border: 1px dashed var(--lp-pill-border); animation: lpSpin 40s linear infinite; }
  .lp-avatar img { width: 100%; height: 100%; object-fit: cover; object-position: 50% 22%; border-radius: 50%; display: block; }
  @keyframes lpFloat { 50% { transform: translateY(-7px); } }
  .lp-dev-name { font-size: clamp(1.5rem, 3vw, 2rem); }
  .lp-facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(128px, 1fr)); gap: .7rem; margin-top: 1.4rem; }
  .lp-fact { padding: .7rem .9rem; border-radius: 14px; background: var(--lp-card-bg-2); border: 1px solid var(--lp-card-border);
    color: var(--lp-card-head); font-weight: 700; font-size: .9rem; line-height: 1.3; }
  .lp-fact span { display: block; color: var(--lp-subtle); font-weight: 500; font-size: .7rem; text-transform: uppercase;
    letter-spacing: .12em; margin-bottom: .2rem; }
  @media (max-width: 820px) { .lp-dev { grid-template-columns: 1fr; text-align: center; }
    .lp-dev .lp-links { justify-content: center; } }

  /* ---------- SCROLL PROGRESS ---------- */
  .lp-progress { position: fixed; top: 0; left: 0; right: 0; height: 3px; z-index: 100; pointer-events: none;
    transform-origin: 0 50%; transform: scaleX(0);
    background: linear-gradient(90deg, var(--lp-accent), var(--lp-violet), var(--lp-accent-2));
    box-shadow: 0 0 12px rgba(25,227,255,.55); }

  /* ---------- REVEAL VARIANTS ---------- */
  .reveal[data-fx="left"]  { transform: translateX(-38px); }
  .reveal[data-fx="right"] { transform: translateX(38px); }
  .reveal[data-fx="zoom"]  { transform: scale(.9) translateY(14px); }
  .reveal[data-fx].is-visible { transform: none; }
  /* sideways entrances must never widen the page: clip each section, and go vertical-only on phones */
  section.lp { overflow-x: clip; }
  @media (max-width: 768px) {
    .reveal[data-fx="left"], .reveal[data-fx="right"] { transform: translateY(22px); }
  }

  /* ---------- HEADING ACCENT LINE ---------- */
  .lp-eyebrow::after { content: ''; display: inline-block; width: 0; height: 2px; margin-left: .75rem; vertical-align: middle;
    border-radius: 2px; background: linear-gradient(90deg, var(--lp-accent), transparent); }
  .reveal.is-visible .lp-eyebrow::after { width: 64px; transition: width 1s cubic-bezier(.16,1,.3,1) .35s; }

  /* ---------- PROBLEM: mini scenes ---------- */
  .fx { position: relative; height: 96px; margin: .1rem 0 1.1rem; border-radius: 14px; overflow: hidden;
    background: var(--lp-card-bg-2); border: 1px solid var(--lp-card-border); }
  .fx em { position: absolute; left: 12px; bottom: 7px; font-style: normal; font-size: .64rem; font-weight: 800;
    letter-spacing: .1em; color: var(--lp-subtle); text-transform: uppercase; }
  .reveal:not(.is-visible) .fx * { animation-play-state: paused; }

  .fx-slip .fx-box { position: absolute; right: 14px; top: 40%; transform: translateY(-50%); display: flex; flex-direction: column;
    align-items: center; gap: 2px; color: var(--lp-accent); font-size: .64rem; font-weight: 800; letter-spacing: .06em; }
  .fx-slip .fx-box svg { width: 34px; height: 34px; }
  .fx-slip .fx-file { position: absolute; left: 14px; top: 40%; margin-top: -17px; width: 26px; height: 32px;
    color: var(--lp-card-head); animation: fxSlip 3.8s ease-in-out infinite; }
  .fx-slip .fx-file svg { width: 100%; height: 100%; display: block; }
  .fx-slip .fx-file i { position: absolute; right: -4px; top: -4px; width: 10px; height: 10px; border-radius: 50%;
    background: #ff5d6c; animation: fxPing 1.3s ease-out infinite; }
  .fx-slip .fx-tick { position: absolute; right: 12px; bottom: 7px; font-size: .66rem; font-weight: 800; color: #34e0a1;
    opacity: 0; animation: fxTick 3.8s ease-in-out infinite; }
  [data-theme="light"] .fx-slip .fx-tick { color: #0d8f63; }
  @keyframes fxSlip { 0% { left: 14px; opacity: 0; } 10% { opacity: 1; } 62% { left: 56%; opacity: 1; }
    74% { left: 62%; opacity: 0; } 100% { left: 62%; opacity: 0; } }
  @keyframes fxTick { 0%, 62% { opacity: 0; } 72%, 92% { opacity: 1; } 100% { opacity: 0; } }
  @keyframes fxPing { 0% { box-shadow: 0 0 0 0 rgba(255,93,108,.7); } 100% { box-shadow: 0 0 0 9px rgba(255,93,108,0); } }

  .fx-read { padding: 16px 16px 28px; display: flex; flex-direction: column; gap: 9px; justify-content: center; }
  .fx-read .l { height: 8px; width: 92%; border-radius: 6px;
    background: linear-gradient(90deg, var(--lp-card-border), rgba(155,123,255,.4)); }
  .fx-read .w2 { width: 70%; } .fx-read .w3 { width: 84%; }
  .fx-read .scan { position: absolute; top: 0; bottom: 0; width: 56px; left: -70px;
    background: linear-gradient(90deg, transparent, rgba(255,93,108,.3), transparent); animation: fxScan 3.2s ease-in-out infinite; }
  @keyframes fxScan { to { left: 105%; } }

  .fx-radar { display: grid; place-items: center; }
  .fx-radar .ring, .fx-radar .sweep { position: absolute; border-radius: 50%; width: 72px; height: 72px; top: 8px; }
  .fx-radar .ring { border: 1px solid var(--lp-pill-border); }
  .fx-radar .r2 { width: 44px; height: 44px; top: 22px; }
  .fx-radar .sweep { background: conic-gradient(from 0deg, transparent 0deg, rgba(25,227,255,.42) 70deg, transparent 71deg);
    animation: lpSpin 3s linear infinite; }
  .fx-radar .blip { position: absolute; top: 18px; left: calc(50% + 14px); width: 8px; height: 8px; border-radius: 50%;
    background: #ff5d6c; opacity: .2; animation: fxBlip 3s ease-in-out infinite; }
  @keyframes fxBlip { 0%, 100% { opacity: .15; } 40% { opacity: .55; } }

  /* ---------- APPROACH: flow line with a travelling packet ---------- */
  .lp-flow { position: relative; }
  .lp-flow .lp-card { position: relative; z-index: 1; }
  .lp-flow::before { content: ''; position: absolute; left: 5%; right: 5%; top: 3.2rem; height: 2px; z-index: 0;
    background: linear-gradient(90deg, transparent, var(--lp-pill-border) 12%, var(--lp-pill-border) 88%, transparent); }
  .lp-flow-dot { position: absolute; top: calc(3.2rem - 5px); left: 5%; width: 12px; height: 12px; border-radius: 50%; z-index: 0;
    background: var(--lp-accent); box-shadow: 0 0 18px var(--lp-accent); opacity: 0; animation: lpTravel 5.4s ease-in-out infinite; }
  @keyframes lpTravel { 0% { left: 5%; opacity: 0; } 8% { opacity: 1; } 92% { opacity: 1; } 100% { left: 95%; opacity: 0; } }
  .lp-flow .lp-step-icon { animation: lpGlow 5.4s ease-in-out infinite; }
  .lp-flow > .col-md-4:nth-of-type(2) .lp-step-icon { animation-delay: 1.8s; }
  .lp-flow > .col-md-4:nth-of-type(3) .lp-step-icon { animation-delay: 3.6s; }
  @keyframes lpGlow { 0%, 22%, 100% { box-shadow: 0 0 0 0 rgba(155,123,255,0); transform: none; }
    10% { box-shadow: 0 0 0 8px rgba(155,123,255,.22); transform: scale(1.12); } }
  @media (max-width: 768px) { .lp-flow::before, .lp-flow-dot { display: none; } }

  /* ---------- RESULTS: gauge ring + floating icons ---------- */
  .lp-ring { position: relative; width: 62px; height: 62px; display: grid; place-items: center; margin-bottom: .3rem; color: var(--lp-accent); }
  .lp-ring > svg:first-child { position: absolute; inset: 0; width: 100%; height: 100%; transform: rotate(-90deg); }
  .lp-ring circle { fill: none; stroke-width: 3.2; }
  .lp-ring .bg { stroke: var(--lp-divider); }
  .lp-ring .fg { stroke: var(--lp-accent); stroke-linecap: round; stroke-dasharray: 100; stroke-dashoffset: 100;
    filter: drop-shadow(0 0 4px rgba(25,227,255,.55)); }
  .reveal.is-visible .lp-ring .fg { stroke-dashoffset: var(--off, 0); transition: stroke-dashoffset 1.8s cubic-bezier(.16,1,.3,1) .25s; }
  .lp-stat-icon { animation: fxFloat 4.2s ease-in-out infinite; }
  .col-lg-3:nth-child(3) .lp-stat-icon { animation-delay: .7s; } .col-lg-3:nth-child(4) .lp-stat-icon { animation-delay: 1.4s; }
  @keyframes fxFloat { 50% { transform: translateY(-5px); } }

  /* ---------- TECH: badges pop in, stack ticker ---------- */
  .lp-card.reveal:not(.is-visible) .lp-tbadge { opacity: 0; transform: translateY(8px) scale(.9); }
  .lp-card.reveal.is-visible .lp-tbadge { animation: lpPop .55s cubic-bezier(.16,1,.3,1) both; }
  .lp-tech-badges .lp-tbadge:nth-child(1) { animation-delay: .25s; }
  .lp-tech-badges .lp-tbadge:nth-child(2) { animation-delay: .38s; }
  .lp-tech-badges .lp-tbadge:nth-child(3) { animation-delay: .51s; }
  @keyframes lpPop { from { opacity: 0; transform: translateY(8px) scale(.9); } to { opacity: 1; transform: none; } }
  .lp-marquee { margin-top: 1.8rem; overflow: hidden;
    -webkit-mask-image: linear-gradient(90deg, transparent, #000 10%, #000 90%, transparent);
            mask-image: linear-gradient(90deg, transparent, #000 10%, #000 90%, transparent); }
  .lp-marquee-track { display: flex; width: max-content; animation: fxMarquee 42s linear infinite; }
  .lp-marquee:hover .lp-marquee-track { animation-play-state: paused; }
  .lp-marquee span { white-space: nowrap; margin-right: .7rem; font-family: 'Space Grotesk', sans-serif; font-weight: 700;
    font-size: 1rem; color: var(--lp-subtle); padding: .5rem 1.15rem; border-radius: 999px;
    border: 1px solid var(--lp-card-border); background: var(--lp-card-bg); }
  @keyframes fxMarquee { to { transform: translateX(-50%); } }

  @media (prefers-reduced-motion: reduce) {
    .lp-progress { display: none; }
    .reveal[data-fx] { transform: none; }
    .fx *, .lp-flow-dot, .lp-flow .lp-step-icon, .lp-stat-icon, .lp-marquee-track { animation: none !important; }
    .fx-slip .fx-file { left: 40%; opacity: 1; } .fx-slip .fx-tick { opacity: 1; }
    .fx-read .scan { display: none; }
    .lp-ring .fg { stroke-dashoffset: var(--off, 0); transition: none; }
    .lp-eyebrow::after { width: 64px; transition: none; }
    .lp-card.reveal .lp-tbadge { animation: none; opacity: 1; transform: none; }
    .lp-marquee-track { width: auto; flex-wrap: wrap; justify-content: center; row-gap: .6rem; }
    .lp-marquee span.dup { display: none; }
    .lp-marquee { -webkit-mask-image: none; mask-image: none; }
  }

  /* SCROLL REVEAL */
  .reveal { opacity: 0; transform: translateY(22px);
    transition: opacity .65s cubic-bezier(.16,1,.3,1), transform .65s cubic-bezier(.16,1,.3,1);
    transition-delay: var(--d, 0ms); will-change: opacity, transform; }
  .reveal.is-visible { opacity: 1; transform: none; }
  @media (prefers-reduced-motion: reduce) {
    html { scroll-behavior: auto; }
    .reveal { opacity: 1; transform: none; transition: none; }
    .scroll-arrow { animation: none; }
    .lp-aurora, .lp-gradient, .lp-trust i, .lp-avatar, .lp-avatar::after { animation: none; }
    .lp-demo-steps li.active .si { animation: none; }
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

(function () {
  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ----- pipeline illustration: three example files cycle through the real stages ----- */
  var box = document.getElementById('lpDemo');
  if (box) {
    var nameEl = document.getElementById('demoName'), metaEl = document.getElementById('demoMeta'),
        chip = document.getElementById('demoChip'), bar = document.getElementById('demoBar'),
        steps = Array.prototype.slice.call(document.querySelectorAll('#demoSteps li'));
    var scenarios = [
      { name: 'invoice_q3.pdf',   meta: 'PDF · 214 KB', chip: ['CLEAN', 'clean'],
        res: [['ok', 'received'], ['ok', '0 / 70 engines'], ['ok', 'no findings'], ['ok', 'AES-256-CBC'], ['ok', 'stored']] },
      { name: 'order_form.pdf',   meta: 'PDF · 96 KB',  chip: ['SUSPICIOUS', 'warn'],
        res: [['ok', 'received'], ['ok', '0 / 70 engines'], ['warn', 'hidden JavaScript'], ['ok', 'AES-256-CBC'], ['warn', 'stored, tagged']] },
      { name: 'report.docx',      meta: 'Word · 48 KB', chip: ['SUSPICIOUS', 'warn'],
        res: [['ok', 'received'], ['ok', '0 / 70 engines'], ['warn', 'macro in a .docx'], ['ok', 'AES-256-CBC'], ['warn', 'stored, tagged']] },
      { name: 'setup_update.zip', meta: 'ZIP · 2.4 MB', chip: ['BLOCKED', 'bad'],
        res: [['ok', 'received'], ['fail', '14 / 70 engines'], ['skip', 'not run'], ['skip', 'not run'], ['skip', 'not stored']] }
    ];
    var idx = 0, timer = null, running = false;

    function paint(i, state, text) {
      var li = steps[i];
      li.className = state;
      li.querySelector('.st').textContent = text || '\u00a0';
    }
    function reset(sc) {
      nameEl.textContent = sc.name; metaEl.textContent = sc.meta;
      chip.textContent = 'SCANNING'; chip.className = 'lp-chip';
      bar.style.width = '0%';
      steps.forEach(function (li) { li.className = ''; li.querySelector('.st').textContent = '\u00a0'; });
    }
    function showFinal(sc) {
      sc.res.forEach(function (r, i) { paint(i, r[0], r[1]); });
      chip.textContent = sc.chip[0]; chip.className = 'lp-chip ' + sc.chip[1];
      bar.style.width = '100%';
    }
    function play() {
      if (!running) return;
      var sc = scenarios[idx % scenarios.length], i = 0;
      reset(sc);
      (function next() {
        if (!running) return;
        if (document.hidden) { timer = setTimeout(next, 600); return; }
        if (i >= sc.res.length) {
          chip.textContent = sc.chip[0]; chip.className = 'lp-chip ' + sc.chip[1];
          bar.style.width = '100%';
          idx++; timer = setTimeout(play, 2800); return;
        }
        paint(i, 'active', '');
        timer = setTimeout(function () {
          var r = sc.res[i];
          paint(i, r[0], r[1]);
          bar.style.width = Math.round(((i + 1) / sc.res.length) * 100) + '%';
          i++; timer = setTimeout(next, 260);
        }, 720);
      })();
    }

    if (reduce || !('IntersectionObserver' in window)) {
      reset(scenarios[0]); showFinal(scenarios[0]);
    } else {
      new IntersectionObserver(function (e) {
        var on = e[0].isIntersecting;
        if (on && !running) { running = true; play(); }
        if (!on && running) { running = false; clearTimeout(timer); }
      }, { threshold: 0.25 }).observe(box);
    }
  }

  /* ----- count-up for the result numbers ----- */
  function countUp(el) {
    var txt = el.textContent.trim();
    var m = txt.match(/^([\d,]+(?:\.\d+)?)(%?)$/);
    if (!m || reduce) return;
    var target = parseFloat(m[1].replace(/,/g, '')),
        dec = (m[1].split('.')[1] || '').length, comma = m[1].indexOf(',') > -1, t0 = null;
    function frame(ts) {
      if (t0 === null) t0 = ts;
      var p = Math.min(1, (ts - t0) / 1100), v = target * (1 - Math.pow(1 - p, 3));
      el.textContent = (comma ? Math.round(v).toLocaleString('en-US') : v.toFixed(dec)) + m[2];
      if (p < 1) requestAnimationFrame(frame); else el.textContent = txt;
    }
    requestAnimationFrame(frame);
  }
  var stats = document.querySelectorAll('.lp-stat-value');
  if ('IntersectionObserver' in window && stats.length) {
    var sio = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { countUp(en.target); sio.unobserve(en.target); } });
    }, { threshold: 0.6 });
    stats.forEach(function (el) { sio.observe(el); });
  }

  /* ----- pointer spotlight on cards ----- */
  if (!reduce) {
    document.querySelectorAll('.lp-feature, .lp-stat').forEach(function (c) {
      c.addEventListener('pointermove', function (e) {
        var r = c.getBoundingClientRect();
        c.style.setProperty('--mx', (e.clientX - r.left) + 'px');
        c.style.setProperty('--my', (e.clientY - r.top) + 'px');
      });
    });
  }
})();

(function () {
  /* scroll progress bar (rAF-throttled, passive listener) */
  var bar = document.getElementById('lpProgress');
  if (!bar) return;
  var ticking = false;
  function update() {
    var doc = document.documentElement;
    var max = (doc.scrollHeight - window.innerHeight) || 1;
    var p = Math.max(0, Math.min(1, (window.scrollY || doc.scrollTop) / max));
    bar.style.transform = 'scaleX(' + p.toFixed(4) + ')';
    ticking = false;
  }
  function onScroll() { if (!ticking) { ticking = true; requestAnimationFrame(update); } }
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll, { passive: true });
  update();
})();
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
