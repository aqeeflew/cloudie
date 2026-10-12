<?php
/**
 * includes/header.php
 * -------------------
 * Shared page shell for Cloudie. Carries the full theme (dark/light),
 * the sidebar, top bar, and all .cl-card / .btn-cloudie styling so every
 * page stays visually consistent.
 *
 * Pages set $pageTitle before including this file.
 */

if (session_status() === PHP_SESSION_NONE) session_start();

// --- theme persistence (cookie, survives reloads & logins) ---
if (isset($_GET['theme']) && in_array($_GET['theme'], ['dark', 'light'], true)) {
    setcookie('cloudie_theme', $_GET['theme'], time() + 60 * 60 * 24 * 365, '/');
    // reload to current page without the ?theme param
    $self = strtok($_SERVER['REQUEST_URI'], '?');
    header('Location: ' . $self);
    exit;
}
$theme = $_COOKIE['cloudie_theme'] ?? 'dark';

// who's logged in (function provided by auth.php; guard in case it's absent)
$cu = function_exists('current_user') ? current_user() : null;

// current page filename, for nav highlighting
$cur = basename($_SERVER['SCRIPT_NAME']);

// theme toggle link points back to the same page
$toggleHref = htmlspecialchars(strtok($_SERVER['REQUEST_URI'], '?'))
            . '?theme=' . ($theme === 'dark' ? 'light' : 'dark');

// Fetch sidebar folders for all authenticated pages
$sidebarFolders = [];
$storageUsed    = 0;
if ($cu) {
    db_ensure_folders();
    try {
        $sfs = db()->prepare(
            "SELECT f.folder_id, f.folder_name, f.color,
                    COUNT(fi.file_id) AS file_count
             FROM folders f
             LEFT JOIN files fi ON fi.folder_id = f.folder_id
             WHERE f.user_id = ?
             GROUP BY f.folder_id, f.folder_name, f.color
             ORDER BY f.created_at ASC"
        );
        $sfs->execute([$cu['user_id']]);
        $sidebarFolders = $sfs->fetchAll();
    } catch (Throwable $t) {
        $sidebarFolders = [];
    }

    // total encrypted bytes, for the sidebar storage meter
    try {
        $su = db()->prepare("SELECT COALESCE(SUM(file_size),0) FROM files WHERE user_id = ?");
        $su->execute([$cu['user_id']]);
        $storageUsed = (int)$su->fetchColumn();
    } catch (Throwable $t) {
        $storageUsed = 0;
    }
}
$storagePct = STORAGE_QUOTA_BYTES > 0
            ? min(100, $storageUsed / STORAGE_QUOTA_BYTES * 100)
            : 0;

if (!function_exists('cl_fmt_bytes')) {
    function cl_fmt_bytes(int $b): string {
        if ($b >= 1024 ** 3) return rtrim(rtrim(number_format($b / 1024 ** 3, 2), '0'), '.') . ' GB';
        if ($b >= 1024 ** 2) return number_format($b / 1024 ** 2, 1) . ' MB';
        if ($b >= 1024)      return number_format($b / 1024, 1)      . ' KB';
        return $b . ' B';
    }
}
?>
<!DOCTYPE html>
<html lang="en" data-theme="<?= htmlspecialchars($theme) ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= isset($pageTitle) ? htmlspecialchars($pageTitle) . ' · Cloudie' : 'Cloudie' ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;450;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  /* dark (default) */
  --ink:#0a0e1a; --panel:#0f1426; --panel-2:#141b30;
  --line:rgba(255,255,255,.07); --line-2:rgba(255,255,255,.12);
  --txt:#e8ecf6; --txt-dim:#8a93ad; --txt-faint:#59617a;
  --glow-1:rgba(123,92,255,.16); --glow-2:rgba(39,211,224,.13);
  --shadow:0 8px 24px rgba(39,211,224,.3);
  --cyan:#27d3e0; --cyan-deep:#0fa9c4; --violet:#7b5cff;
  --green:#34e0a1; --amber:#ffc24b; --red:#ff5d6c;
  --radius:18px;
}
:root[data-theme="light"]{
  --ink:#f4f6fb; --panel:#ffffff; --panel-2:#eef2f9;
  --line:rgba(15,25,55,.09); --line-2:rgba(15,25,55,.16);
  --txt:#13192b; --txt-dim:#54607a; --txt-faint:#8a93ad;
  --glow-1:rgba(123,92,255,.10); --glow-2:rgba(39,211,224,.12);
  --shadow:0 8px 22px rgba(39,211,224,.28);
  --cyan:#0aa6bd; --cyan-deep:#0c8ba0; --violet:#6a45f5;
  --green:#11a974; --amber:#cf8b00; --red:#e23748;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  font-family:'Inter',sans-serif;
  background:
    radial-gradient(1100px 600px at 88% -8%, var(--glow-1), transparent 60%),
    radial-gradient(900px 520px at -6% 8%, var(--glow-2), transparent 55%),
    var(--ink);
  color:var(--txt); -webkit-font-smoothing:antialiased;
  min-height:100vh;
  transition:background .3s ease,color .3s ease;
}
a{color:var(--cyan);text-decoration:none}
a:hover{text-decoration:underline}

/* ---------- APP LAYOUT ---------- */
.app{display:grid;grid-template-columns:248px 1fr;min-height:100vh}
.side,.search,.icon-btn,.cl-card,.folder,.file-table,.frow,.fhead{
  transition:background .3s ease,border-color .3s ease,color .3s ease}

/* ---------- SIDEBAR ---------- */
.side{border-right:1px solid var(--line);padding:22px 16px;display:flex;
  flex-direction:column;gap:6px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:11px;padding:4px 8px 18px;text-decoration:none}
.brand:hover{text-decoration:none}
.logo{width:36px;height:36px;border-radius:11px;flex:none;
  background:linear-gradient(135deg,var(--cyan),var(--violet));
  display:grid;place-items:center;box-shadow:0 6px 22px rgba(39,211,224,.35)}
.logo svg{width:20px;height:20px}
.brand-name{font-family:'Space Grotesk';font-weight:700;font-size:20px;
  letter-spacing:-.02em;color:var(--txt)}
.brand-name b{color:var(--cyan)}

.newbtn{margin:6px 4px 16px;display:flex;align-items:center;gap:10px;
  padding:13px 16px;border-radius:14px;cursor:pointer;border:none;text-decoration:none;
  font-family:'Space Grotesk';font-weight:600;font-size:14.5px;color:#04141b;
  background:linear-gradient(135deg,var(--cyan),var(--cyan-deep));
  box-shadow:var(--shadow);transition:.18s}
.newbtn:hover{transform:translateY(-1px);text-decoration:none;color:#04141b}
.newbtn svg{width:18px;height:18px}

.nav-label{font-size:11px;letter-spacing:.13em;text-transform:uppercase;
  color:var(--txt-faint);padding:14px 12px 7px;font-weight:600}
.nav{display:flex;flex-direction:column;gap:2px}
.nav a{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:11px;
  color:var(--txt-dim);font-size:14px;font-weight:450;transition:.14s}
.nav a:hover{background:var(--panel);color:var(--txt);text-decoration:none}
.nav a svg{width:18px;height:18px;flex:none;opacity:.85}
.nav a.active{background:linear-gradient(90deg,rgba(39,211,224,.14),rgba(39,211,224,.03));color:var(--cyan)}
.nav a.active svg{opacity:1}
.nav .count{margin-left:auto;font-size:11px;color:var(--txt-faint);font-family:'JetBrains Mono'}

.storage{margin-top:auto;padding:16px 12px 6px}
.storage-top{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:9px}
.storage-top span:first-child{font-size:12.5px;color:var(--txt-dim);font-weight:500}
.storage-top span:last-child{font-size:11.5px;color:var(--txt-faint);font-family:'JetBrains Mono'}
.bar{height:7px;border-radius:99px;background:var(--line-2);overflow:hidden}
.bar i{display:block;height:100%;border-radius:99px;
  background:linear-gradient(90deg,var(--cyan),var(--violet));
  transition:width .5s cubic-bezier(.4,0,.2,1)}
.bar i.bar-warn{background:linear-gradient(90deg,var(--amber),var(--red))}
.storage small{display:block;margin-top:9px;font-size:11.5px;color:var(--txt-faint)}

/* ---------- MAIN / TOPBAR ---------- */
.main{padding:24px 34px 60px;min-width:0}
.topbar{display:flex;align-items:center;gap:14px;margin-bottom:28px}
.search{flex:1;max-width:520px;display:flex;align-items:center;gap:11px;
  background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:11px 16px}
.search svg{width:18px;height:18px;color:var(--txt-faint)}
.search input{background:none;border:none;outline:none;color:var(--txt);
  font-size:14px;width:100%;font-family:'Inter'}
.search input::placeholder{color:var(--txt-faint)}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:12px}
.icon-btn{width:40px;height:40px;border-radius:11px;border:1px solid var(--line);
  background:var(--panel);display:grid;place-items:center;cursor:pointer;
  color:var(--txt-dim);transition:.14s}
.icon-btn:hover{color:var(--txt);border-color:var(--line-2);text-decoration:none}
.icon-btn svg{width:18px;height:18px}
.menu-btn{display:none;flex:none}
.menu-backdrop{display:none}
.avatar{width:40px;height:40px;border-radius:12px;
  background:linear-gradient(135deg,var(--violet),var(--cyan));display:grid;
  place-items:center;font-family:'Space Grotesk';font-weight:700;color:#fff;font-size:15px}
/* ---------- USER MENU (topbar avatar dropdown) ---------- */
.umenu{position:relative}
.umenu-btn{border:none;padding:0;cursor:pointer;transition:.15s}
.umenu-btn:hover{box-shadow:0 0 0 3px rgba(39,211,224,.35);transform:translateY(-1px)}
.umenu-btn.active,.umenu.open .umenu-btn{box-shadow:0 0 0 3px rgba(39,211,224,.5)}
.umenu-panel{position:absolute;right:0;top:calc(100% + 10px);min-width:235px;z-index:60;
  background:linear-gradient(160deg,var(--panel-2),var(--panel));
  border:1px solid var(--line-2);border-radius:14px;padding:6px;
  box-shadow:0 18px 50px rgba(0,0,0,.35);
  opacity:0;transform:translateY(-6px);pointer-events:none;transition:.16s}
.umenu.open .umenu-panel{opacity:1;transform:none;pointer-events:auto}
.umenu-head{padding:10px 12px 9px;border-bottom:1px solid var(--line);margin-bottom:6px}
.umenu-name{font-family:'Space Grotesk';font-weight:700;font-size:14.5px;color:var(--txt)}
.umenu-mail{font-size:12px;color:var(--txt-faint);margin-top:2px;word-break:break-all}
.umenu-panel a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:9px;
  font-size:13.5px;font-weight:500;color:var(--txt-dim);transition:.13s}
.umenu-panel a:hover{background:var(--panel);color:var(--txt);text-decoration:none}
.umenu-panel a svg{width:16px;height:16px;flex:none}
.umenu-panel a.umenu-danger:hover{background:rgba(255,93,108,.1);color:var(--red)}

/* ---------- HEADINGS ---------- */
h1,h2,h3,h4,h5{font-family:'Space Grotesk';letter-spacing:-.02em;color:var(--txt)}
.text-muted{color:var(--txt-dim)!important}
.text-danger{color:var(--red)!important}

/* ---------- CARD (replaces old .cl-card) ---------- */
.cl-card{background:linear-gradient(160deg,var(--panel-2),var(--panel));
  border:1px solid var(--line);border-radius:var(--radius);padding:26px 28px;
  box-shadow:0 18px 50px rgba(0,0,0,.18)}
.cl-card h2,.cl-card h3{margin-bottom:.4rem}
.cl-card label{font-weight:600;color:var(--txt-dim);font-size:13.5px;display:block;margin-bottom:6px}
.cl-card .form-text,.cl-card .small,.small{color:var(--txt-faint);font-size:12.5px}

/* form controls */
.form-control{width:100%;background:var(--panel);border:1px solid var(--line-2);
  border-radius:11px;padding:11px 14px;color:var(--txt);font-size:14px;
  font-family:'Inter';outline:none;transition:.14s}
.form-control:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(39,211,224,.15)}
.form-control::placeholder{color:var(--txt-faint)}

/* buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  font-family:'Space Grotesk';font-weight:600;font-size:14px;border-radius:11px;
  padding:11px 18px;cursor:pointer;border:1px solid transparent;transition:.16s;
  text-decoration:none}
.btn:hover{text-decoration:none;transform:translateY(-1px)}
.btn-sm{padding:7px 12px;font-size:12.5px;border-radius:9px}
.btn-cloudie{background:linear-gradient(135deg,var(--cyan),var(--cyan-deep));
  color:#04141b;box-shadow:var(--shadow)}
.btn-cloudie:hover{color:#04141b}
.btn-cloudie-outline{background:var(--panel);border-color:var(--line-2);color:var(--txt)}
.btn-cloudie-outline:hover{border-color:var(--cyan);color:var(--cyan)}
.btn-danger{background:rgba(255,93,108,.14);border-color:rgba(255,93,108,.3);color:var(--red)}
.btn-danger:hover{background:rgba(255,93,108,.22);color:var(--red)}
.w-100{width:100%}.me-2{margin-right:.6rem}.m-0{margin:0}

/* alerts */
.alert{border-radius:12px;padding:12px 16px;font-size:14px;margin-bottom:16px;border:1px solid}
.alert-danger{background:rgba(255,93,108,.1);border-color:rgba(255,93,108,.3);color:var(--red)}
.alert-success{background:rgba(52,224,161,.1);border-color:rgba(52,224,161,.3);color:var(--green)}

/* ---------- FILE TABLE (dashboard) ---------- */
.file-table{background:var(--panel);border:1px solid var(--line);
  border-radius:var(--radius);overflow-x:auto;-webkit-overflow-scrolling:touch}
.file-table table{width:100%;border-collapse:collapse}
.file-table th{background:transparent;text-align:left;padding:13px 20px;
  font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--txt-faint);font-weight:600;border-bottom:1px solid var(--line)}
.file-row td{padding:14px 20px;border-bottom:1px solid var(--line);
  vertical-align:middle;font-size:14px;color:var(--txt)}
.file-row:last-child td{border-bottom:none}
.file-row:hover{background:var(--panel-2)}
.file-actions a{margin-left:.35rem}

.verdict{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;
  border-radius:99px;font-size:12px;font-weight:600}
.verdict svg{width:13px;height:13px}
.v-clean{background:rgba(52,224,161,.12);color:var(--green)}
.v-flag{background:rgba(255,93,108,.12);color:var(--red)}
.lock{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;
  color:var(--cyan);font-weight:500}
.lock svg{width:13px;height:13px}

/* ---------- HERO (index) ---------- */
.hero h1{font-size:44px;line-height:1.05}
.hero .lead{font-size:17px;color:var(--txt-dim);max-width:560px}

/* ---------- DROPZONE (upload) ---------- */
.dropzone{border:2px dashed var(--line-2);border-radius:16px;padding:48px 20px;
  text-align:center;cursor:pointer;transition:.15s;color:var(--txt-dim);display:block}
.dropzone:hover,.dropzone.hover{background:var(--panel-2);border-color:var(--cyan)}

/* ---------- QR / KEY (scan success) ---------- */
.qr-card img{background:#fff;padding:10px;border-radius:14px}
.success-banner{color:var(--green)}
.key-box{font-family:'JetBrains Mono';font-size:13px;word-break:break-all;
  background:var(--panel);border:1px solid var(--line-2);border-radius:12px;
  padding:14px 16px;color:var(--cyan)}

/* ---------- bootstrap-ish helpers used by your pages ---------- */
.row{display:flex;flex-wrap:wrap;margin:0 -12px}
.row>[class*="col-"]{padding:0 12px}
.col-lg-5{flex:0 0 41.66%;max-width:41.66%}
.col-lg-6{flex:0 0 50%;max-width:50%}
.col-lg-7{flex:0 0 58.33%;max-width:58.33%}
.col-lg-8{flex:0 0 66.66%;max-width:66.66%}
.col-lg-9{flex:0 0 75%;max-width:75%}
.col-md-6{flex:0 0 50%;max-width:50%}
.justify-content-center{justify-content:center}
.justify-content-between{justify-content:space-between}
.align-items-center{align-items:center}
.d-flex{display:flex}.d-block{display:block}.d-none{display:none}
.flex-wrap{flex-wrap:wrap}.gap-2{gap:.6rem}
.text-center{text-align:center}.text-end{text-align:right}
.mt-2{margin-top:.6rem}.mt-3{margin-top:1rem}.mt-4{margin-top:1.6rem}
.mb-1{margin-bottom:.4rem}.mb-2{margin-bottom:.7rem}.mb-3{margin-bottom:1.1rem}
.mb-4{margin-bottom:1.6rem}.my-3{margin:1rem 0}.fw-bold{font-weight:700}
ol,ul{padding-left:1.2rem}ol li,ul li{margin-bottom:.5rem;color:var(--txt-dim)}

@media(max-width:1000px){
  .app{grid-template-columns:1fr}
  .side{display:none}
  .side.open{display:flex;position:fixed;inset:0 auto 0 0;width:82%;max-width:300px;
    z-index:200;background:var(--panel);box-shadow:0 20px 60px rgba(0,0,0,.45);
    overflow-y:auto}
  .menu-btn{display:grid}
  .menu-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:150}
  .menu-backdrop.open{display:block}
  .main{padding:18px}
  .col-lg-5,.col-lg-6,.col-lg-7,.col-lg-8,.col-lg-9,.col-md-6{flex:0 0 100%;max-width:100%}
  .d-lg-block{display:none!important}
  .hero h1{font-size:34px}
}

/* ---------- FILE TABLE → stacked cards on phones ---------- */
@media(max-width:700px){
  .file-table{overflow:visible}
  .file-table thead{display:none}
  .file-table table,.file-table tbody,.file-table tr,.file-table td{display:block;width:100%}
  .file-row{padding:14px 16px;border-bottom:1px solid var(--line)}
  .file-row:last-child{border-bottom:none}
  .file-row td{border-bottom:none;padding:4px 0}
  .file-row td[data-label]{display:flex;align-items:center;justify-content:space-between;gap:10px}
  .file-row td[data-label]::before{content:attr(data-label);font-size:11px;
    text-transform:uppercase;letter-spacing:.06em;color:var(--txt-faint);font-weight:600;flex:none}
  .file-row td[data-label="Name"],.file-row td[data-label="Actions"]{display:block}
  .file-row td[data-label="Name"]::before,.file-row td[data-label="Actions"]::before{content:none}
  .file-row td[data-label="Actions"]{margin-top:8px}
  .fa-group{justify-content:flex-start}
}

/* ======================================================
   SCAN REPORT STYLES
   ====================================================== */

/* Extra grid columns */
.col-lg-10{flex:0 0 83.33%;max-width:83.33%}
.col-md-3{flex:0 0 25%;max-width:25%}
.col-md-4{flex:0 0 33.33%;max-width:33.33%}
@media(max-width:1000px){.col-lg-10{flex:0 0 100%;max-width:100%}}

/* CSS-grid helpers (used inside .cl-card, so no negative-margin issue) */
.rpt-grid-summary{display:grid;grid-template-columns:2fr 1fr 1fr;gap:.9rem}
.rpt-grid-2{display:grid;grid-template-columns:1fr 1fr;gap:.9rem}
.rpt-grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:.9rem}
@media(max-width:780px){
  .rpt-grid-summary{grid-template-columns:1fr 1fr}
  .rpt-grid-4{grid-template-columns:1fr 1fr}
}
@media(max-width:520px){
  .rpt-grid-summary,.rpt-grid-2,.rpt-grid-4{grid-template-columns:1fr}
}

/* Section divider */
.rpt-section{font-size:.73rem;letter-spacing:.1em;text-transform:uppercase;
  color:var(--txt-faint);font-weight:600;display:flex;align-items:center;
  gap:8px;margin:1.8rem 0 .9rem}
.rpt-section::after{content:'';flex:1;height:1px;background:var(--line)}
.rpt-section svg{width:14px;height:14px;flex:none}
hr.rpt-hr{border:none;border-top:1px solid var(--line);margin:2rem 0}

/* Verdict banner */
.vbanner{border-radius:14px;padding:18px 22px;display:flex;align-items:center;gap:16px;border:1px solid}
.vbanner .vb-ico{width:46px;height:46px;border-radius:12px;display:grid;place-items:center;flex:none}
.vbanner .vb-ico svg{width:24px;height:24px}
.vbanner .vb-main{font-family:'Space Grotesk';font-weight:700;font-size:20px;letter-spacing:-.02em}
.vbanner .vb-sub{font-size:13px;color:var(--txt-dim);margin-top:3px}
.vb-ok{background:rgba(52,224,161,.07);border-color:rgba(52,224,161,.22)}
.vb-ok .vb-ico{background:rgba(52,224,161,.14);color:var(--green)}
.vb-ok .vb-main{color:var(--green)}
.vb-danger{background:rgba(255,93,108,.07);border-color:rgba(255,93,108,.22)}
.vb-danger .vb-ico{background:rgba(255,93,108,.14);color:var(--red)}
.vb-danger .vb-main{color:var(--red)}
.vb-warn{background:rgba(255,194,75,.07);border-color:rgba(255,194,75,.22)}
.vb-warn .vb-ico{background:rgba(255,194,75,.14);color:var(--amber)}
.vb-warn .vb-main{color:var(--amber)}
.vb-info{background:rgba(39,211,224,.06);border-color:rgba(39,211,224,.18)}
.vb-info .vb-ico{background:rgba(39,211,224,.12);color:var(--cyan)}
.vb-info .vb-main{color:var(--cyan)}

/* Report tiles */
.rt{background:var(--panel);border:1px solid var(--line-2);border-radius:14px;padding:1rem 1.2rem;height:100%}
.rt.rt-ok{border-color:rgba(52,224,161,.22);background:rgba(52,224,161,.04)}
.rt.rt-danger{border-color:rgba(255,93,108,.22);background:rgba(255,93,108,.04)}
.rt.rt-warn{border-color:rgba(255,194,75,.22);background:rgba(255,194,75,.04)}
.rt-lbl{font-size:.73rem;color:var(--txt-faint);text-transform:uppercase;letter-spacing:.08em;font-weight:600}
.rt-val{font-size:1.55rem;font-weight:700;font-family:'Space Grotesk';margin-top:.25rem}
.rt-ok .rt-val{color:var(--green)}
.rt-danger .rt-val{color:var(--red)}
.rt-warn .rt-val{color:var(--amber)}

/* Progress bars */
.rpt-progress{height:8px;border-radius:99px;background:var(--line-2);overflow:hidden;margin-top:.8rem}
.rpt-bar{display:block;height:100%;border-radius:99px;transition:width .7s cubic-bezier(.4,0,.2,1)}
.rpt-bar-red{background:linear-gradient(90deg,var(--red),rgba(255,93,108,.55))}
.rpt-bar-green{background:linear-gradient(90deg,var(--green),rgba(52,224,161,.55))}

/* Metadata / features table */
.rpt-table-wrap{border:1px solid var(--line);border-radius:12px;overflow:hidden}
.rpt-table{width:100%;border-collapse:collapse}
.rpt-table th,.rpt-table td{padding:9px 14px;border-bottom:1px solid var(--line);font-size:13.5px;text-align:left}
.rpt-table th{color:var(--txt-dim);font-weight:600;background:rgba(0,0,0,.12);width:36%;white-space:nowrap}
.rpt-table td{color:var(--txt)}
.rpt-table tr:last-child th,.rpt-table tr:last-child td{border-bottom:none}
.mono{font-family:'JetBrains Mono',monospace;font-size:.8rem;word-break:break-all;color:var(--cyan)}

/* Badges */
.rpt-badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:99px;
  font-size:11px;font-weight:600;font-family:'Space Grotesk';letter-spacing:.02em}
.rpt-badge-src{background:rgba(39,211,224,.12);color:var(--cyan);border:1px solid rgba(39,211,224,.2)}
.rpt-badge-cnt{background:var(--panel-2);color:var(--txt-dim);border:1px solid var(--line-2);
  font-family:'JetBrains Mono';font-size:11px}

/* Indicator list */
.ind-list{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:.35rem}
.ind-item{padding:.6rem .9rem;background:rgba(255,93,108,.05);
  border:1px solid rgba(255,93,108,.15);border-radius:10px;
  display:flex;align-items:baseline;gap:.6rem;flex-wrap:wrap}
.ind-name{font-weight:700;color:var(--red);font-family:'JetBrains Mono',monospace;font-size:.8rem;flex:none}
.ind-desc{color:var(--txt-dim);font-size:.88rem}

/* VT flagged-engine list */
.vt-eng-list{list-style:none;padding:0;margin:.7rem 0 0;display:flex;flex-direction:column;gap:.3rem}
.vt-eng-item{display:flex;align-items:center;justify-content:space-between;
  padding:.5rem .85rem;background:var(--panel-2);border:1px solid var(--line);
  border-radius:9px;font-size:13px;gap:.8rem;flex-wrap:wrap}
.vt-eng-name{font-weight:600;color:var(--txt)}
.vt-eng-result{color:var(--red);font-family:'JetBrains Mono';font-size:.78rem}
.vt-eng-cat{font-size:11px;color:var(--amber);background:rgba(255,194,75,.1);
  border:1px solid rgba(255,194,75,.2);padding:2px 7px;border-radius:99px}

/* Collapse */
.rpt-collapse{display:none}
.rpt-collapse.open{display:block}

/* Misc */
.rpt-note{padding:.85rem 1rem;background:var(--panel);border:1px solid var(--line);
  border-radius:12px;color:var(--txt-dim);font-size:13.5px}
.rpt-empty{color:var(--txt-dim);font-size:13.5px;display:flex;align-items:center;gap:6px;padding:.4rem 0}
.rpt-empty svg{width:15px;height:15px;color:var(--green);flex:none}
.rpt-meta-row{font-size:12.5px;color:var(--txt-faint);display:flex;flex-wrap:wrap;gap:.9rem;
  align-items:center;margin-top:.75rem}
.rpt-meta-row strong{color:var(--txt-dim)}
.rpt-meta-row a{color:var(--cyan);display:inline-flex;align-items:center;gap:3px}
.ms-1{margin-left:.3rem}.ms-2{margin-left:.6rem}

/* ---------- FOLDER SIDEBAR ---------- */
.nav-label-row{display:flex;align-items:center;justify-content:space-between;padding-right:4px}
.nav-folder-add{background:none;border:none;cursor:pointer;color:var(--txt-faint);
  width:22px;height:22px;border-radius:6px;display:grid;place-items:center;
  padding:0;flex:none;transition:.14s}
.nav-folder-add:hover{color:var(--cyan);background:var(--panel-2)}
.nav-folder-form{overflow:hidden;max-height:0;transition:max-height .3s ease;padding:0 4px}
.nav-folder-form.open{max-height:220px;padding-bottom:4px}
.nav-fi{width:100%;background:var(--panel);border:1px solid var(--line-2);border-radius:8px;
  padding:8px 10px;color:var(--txt);font-size:13px;outline:none;font-family:'Inter';
  margin-bottom:8px;transition:.14s;display:block;box-sizing:border-box}
.nav-fi:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(39,211,224,.12)}
.nav-fcolors{display:flex;gap:7px;margin-bottom:8px;padding:0 2px}
.nav-fdot{cursor:pointer}
.nav-fdot input{position:absolute;opacity:0;width:0;height:0}
.nav-fdot span{display:block;width:17px;height:17px;border-radius:50%;
  border:2px solid transparent;transition:.15s}
.nav-fdot input:checked + span{border-color:rgba(255,255,255,.75);transform:scale(1.2)}
[data-theme="light"] .nav-fdot input:checked + span{border-color:rgba(0,0,0,.45)}
.nav-fcreate{background:var(--panel);border:1px solid var(--line-2);border-radius:8px;
  padding:6px 0;color:var(--cyan);font-size:12.5px;font-weight:600;cursor:pointer;
  font-family:'Space Grotesk';width:100%;transition:.14s}
.nav-fcreate:hover{border-color:var(--cyan);background:rgba(39,211,224,.07)}
.nav-folder-empty{font-size:11.5px;color:var(--txt-faint);padding:5px 12px;font-style:italic}
.folder-chip{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:500;
  padding:2px 7px;border-radius:99px;margin-left:8px;text-decoration:none;transition:.12s}
.folder-chip:hover{text-decoration:none;opacity:.8}

/* ---------- CURSOR SPOTLIGHT ---------- */
.cg{position:relative;overflow:hidden}
.cg::before{content:'';position:absolute;inset:0;opacity:0;pointer-events:none;
  border-radius:inherit;transition:opacity .4s ease;
  background:radial-gradient(380px circle at var(--cg-x,50%) var(--cg-y,50%),rgba(39,211,224,.09),transparent 65%)}
[data-theme="light"] .cg::before{background:radial-gradient(380px circle at var(--cg-x,50%) var(--cg-y,50%),rgba(12,132,166,.08),transparent 65%)}
.cg:hover::before{opacity:1}
</style>
<script>
(function(){
  function initCg(el){
    el.classList.add('cg');
    el.addEventListener('mousemove',function(e){
      var r=el.getBoundingClientRect();
      el.style.setProperty('--cg-x',((e.clientX-r.left)/r.width*100).toFixed(1)+'%');
      el.style.setProperty('--cg-y',((e.clientY-r.top)/r.height*100).toFixed(1)+'%');
    });
  }
  document.addEventListener('DOMContentLoaded',function(){
    document.querySelectorAll('.scard,.lp-card,.lp-stat,.cl-card').forEach(initCg);
    // folder creation form toggle
    var fab=document.getElementById('folderAddBtn'),
        ff =document.getElementById('folderFormWrap');
    if(fab&&ff){
      fab.addEventListener('click',function(){
        ff.classList.toggle('open');
        if(ff.classList.contains('open')) ff.querySelector('.nav-fi').focus();
      });
    }
    // user menu (topbar avatar)
    var um=document.getElementById('userMenu');
    if(um){
      var ub=um.querySelector('.umenu-btn');
      ub.addEventListener('click',function(e){
        e.stopPropagation();
        um.classList.toggle('open');
        ub.setAttribute('aria-expanded', um.classList.contains('open')?'true':'false');
      });
      document.addEventListener('click',function(e){
        if(!um.contains(e.target)) um.classList.remove('open');
      });
      document.addEventListener('keydown',function(e){
        if(e.key==='Escape') um.classList.remove('open');
      });
    }
    // mobile sidebar drawer
    var menuBtn = document.getElementById('mobileMenuBtn'),
        sideEl  = document.querySelector('.side'),
        backdrop = document.getElementById('menuBackdrop');
    if (menuBtn && sideEl && backdrop) {
      menuBtn.addEventListener('click', function(){
        sideEl.classList.toggle('open');
        backdrop.classList.toggle('open');
      });
      backdrop.addEventListener('click', function(){
        sideEl.classList.remove('open');
        backdrop.classList.remove('open');
      });
      document.addEventListener('keydown', function(e){
        if (e.key === 'Escape') {
          sideEl.classList.remove('open');
          backdrop.classList.remove('open');
        }
      });
    }
  });
})();
</script>
</head>
<body>
<div class="app">

  <div class="menu-backdrop" id="menuBackdrop"></div>

  <!-- SIDEBAR -->
  <aside class="side">
    <a class="brand" href="index.php">
      <div class="logo">
        <svg viewBox="0 0 24 24" fill="none"><path d="M7 18a4 4 0 0 1-.5-7.97A5.5 5.5 0 0 1 17 9.5a3.5 3.5 0 0 1 .5 6.97" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/><rect x="9.2" y="11" width="5.6" height="5" rx="1.3" stroke="#fff" stroke-width="1.6"/><path d="M10.6 11v-1a1.4 1.4 0 0 1 2.8 0v1" stroke="#fff" stroke-width="1.6"/></svg>
      </div>
      <div class="brand-name">Cloud<b>ie</b></div>
    </a>

    <?php if ($cu): ?>
      <a class="newbtn" href="upload.php">
        <svg viewBox="0 0 24 24" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>
        Upload &amp; Scan
      </a>
      <nav class="nav">
        <a href="dashboard.php" class="<?= $cur==='dashboard.php'?'active':'' ?>"><svg viewBox="0 0 24 24" fill="none"><path d="M3 11l9-7 9 7M5 10v9h14v-9" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>My files</a>
        <a href="upload.php" class="<?= $cur==='upload.php'?'active':'' ?>"><svg viewBox="0 0 24 24" fill="none"><path d="M12 16V4m0 0L8 8m4-4l4 4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 17v2a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>Upload</a>
      </nav>
      <div class="nav-label nav-label-row">
        <span>My Folders</span>
        <button class="nav-folder-add" id="folderAddBtn" title="New folder" type="button">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>
        </button>
      </div>

      <div class="nav-folder-form" id="folderFormWrap">
        <form method="POST" action="create_folder.php">
          <input type="hidden" name="csrf" value="<?= csrf_token() ?>">
          <input type="text" name="folder_name" class="nav-fi" placeholder="Folder name…" maxlength="50" required autocomplete="off">
          <div class="nav-fcolors">
            <?php
            $colorDefs = ['cyan'=>'var(--cyan)','violet'=>'var(--violet)','green'=>'var(--green)','amber'=>'var(--amber)','red'=>'var(--red)'];
            foreach ($colorDefs as $cn => $cv):
            ?>
            <label class="nav-fdot">
              <input type="radio" name="color" value="<?= $cn ?>" <?= $cn==='cyan'?'checked':'' ?>>
              <span style="background:<?= $cv ?>"></span>
            </label>
            <?php endforeach; ?>
          </div>
          <button type="submit" class="nav-fcreate">Create folder</button>
        </form>
      </div>

      <nav class="nav">
        <?php
        $colorMap = ['cyan'=>'var(--cyan)','violet'=>'var(--violet)','green'=>'var(--green)','amber'=>'var(--amber)','red'=>'var(--red)'];
        $colorBg  = ['cyan'=>'rgba(39,211,224,.14)','violet'=>'rgba(123,92,255,.15)','green'=>'rgba(52,224,161,.13)','amber'=>'rgba(255,194,75,.14)','red'=>'rgba(255,93,108,.13)'];
        if (empty($sidebarFolders)):
        ?>
          <div class="nav-folder-empty">No folders yet — create one above.</div>
        <?php else: foreach ($sidebarFolders as $sf):
          $fc  = $colorMap[$sf['color']] ?? 'var(--cyan)';
          $fcb = $colorBg[$sf['color']]  ?? 'rgba(39,211,224,.14)';
          $isActive = ($cur==='folder.php' && (int)($_GET['id']??0)===(int)$sf['folder_id']);
        ?>
          <a href="folder.php?id=<?= (int)$sf['folder_id'] ?>" class="<?= $isActive?'active':'' ?>">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" style="color:<?= $fc ?>;opacity:1">
              <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>
            </svg>
            <?= e($sf['folder_name']) ?>
            <span class="count"><?= (int)$sf['file_count'] ?></span>
          </a>
        <?php endforeach; endif; ?>
      </nav>

      <div class="nav-label">Security</div>
      <nav class="nav">
        <a href="dashboard.php" class="<?= $cur==='dashboard.php'&&!isset($_GET['id'])?'active':'' ?>"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>Scan reports</a>
      </nav>
      <div class="storage">
        <div class="storage-top">
          <span>Encrypted storage</span>
          <span><?= number_format($storagePct, $storagePct > 0 && $storagePct < 1 ? 1 : 0) ?>%</span>
        </div>
        <div class="bar">
          <i class="<?= $storagePct >= 80 ? 'bar-warn' : '' ?>"
             style="width:<?= $storageUsed > 0 ? max(2, round($storagePct, 1)) : 0 ?>%"></i>
        </div>
        <small><?= e(cl_fmt_bytes($storageUsed)) ?> of <?= e(cl_fmt_bytes(STORAGE_QUOTA_BYTES)) ?> · AES-256-CBC</small>
      </div>
    <?php else: ?>
      <nav class="nav" style="margin-top:8px">
        <a href="login.php" class="<?= $cur==='login.php'?'active':'' ?>"><svg viewBox="0 0 24 24" fill="none"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" stroke="currentColor" stroke-width="1.7"/><path d="M10 17l5-5-5-5M15 12H3" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>Log in</a>
        <a href="register.php" class="<?= $cur==='register.php'?'active':'' ?>"><svg viewBox="0 0 24 24" fill="none"><circle cx="9" cy="8" r="3.2" stroke="currentColor" stroke-width="1.7"/><path d="M3 20a6 6 0 0 1 12 0M18 8v6M21 11h-6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>Sign up</a>
      </nav>
      <div class="storage">
        <small>Secure cloud storage with AI malware analysis &amp; AES-256.</small>
      </div>
    <?php endif; ?>
  </aside>

  <!-- MAIN -->
  <main class="main">
    <div class="topbar">
      <button type="button" class="icon-btn menu-btn" id="mobileMenuBtn" aria-label="Open menu">
        <svg viewBox="0 0 24 24" fill="none"><path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
      </button>
      <?php if ($cur === 'dashboard.php'): ?>
      <div class="search">
        <svg viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.8"/><path d="m20 20-3.2-3.2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
        <input id="vaultSearch" placeholder="Search your encrypted vault…" autocomplete="off">
      </div>
      <?php endif; ?>
      <div class="topbar-right">
        <a class="icon-btn" href="<?= $toggleHref ?>" title="Toggle theme">
          <?php if ($theme === 'dark'): ?>
            <svg viewBox="0 0 24 24" fill="none"><path d="M20 14.5A8 8 0 1 1 9.5 4 6.5 6.5 0 0 0 20 14.5z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>
          <?php else: ?>
            <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="4.2" stroke="currentColor" stroke-width="1.8"/><path d="M12 2v2.4M12 19.6V22M4.2 4.2l1.7 1.7M18.1 18.1l1.7 1.7M2 12h2.4M19.6 12H22M4.2 19.8l1.7-1.7M18.1 5.9l1.7-1.7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
          <?php endif; ?>
        </a>
        <?php if ($cu): ?>
          <div class="umenu" id="userMenu">
            <button type="button"
                    class="avatar umenu-btn <?= $cur === 'profile.php' ? 'active' : '' ?>"
                    aria-haspopup="true" aria-expanded="false" title="Account">
              <?= strtoupper(substr($cu['username'] ?? 'U', 0, 1)) ?>
            </button>
            <div class="umenu-panel">
              <div class="umenu-head">
                <div class="umenu-name"><?= e($cu['username'] ?? '') ?></div>
                <div class="umenu-mail"><?= e($cu['email'] ?? '') ?></div>
              </div>
              <a href="profile.php">
                <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8" r="3.4" stroke="currentColor" stroke-width="1.7"/><path d="M5.5 19.5a6.5 6.5 0 0 1 13 0" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
                My profile
              </a>
              <a href="logout.php" class="umenu-danger">
                <svg viewBox="0 0 24 24" fill="none"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" stroke="currentColor" stroke-width="1.7"/><path d="M16 17l5-5-5-5M21 12H9" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
                Log out
              </a>
            </div>
          </div>
        <?php endif; ?>
      </div>
    </div>

    <?php
    // flash messages (if your flash_set/flash_get helpers exist)
    if (function_exists('flash_get')) {
        foreach (['success', 'error'] as $type) {
            $msg = flash_get($type);
            if ($msg) {
                $cls = $type === 'success' ? 'alert-success' : 'alert-danger';
                echo '<div class="alert ' . $cls . '">' . htmlspecialchars($msg) . '</div>';
            }
        }
    }
    ?>