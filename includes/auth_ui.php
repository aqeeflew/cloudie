<?php
/**
 * includes/auth_ui.php
 * --------------------
 * Shared styling + small JS for the login / register split-panel layout.
 * Included once near the end of login.php and register.php (before footer).
 * All colors come from the theme tokens defined in header.php, so this
 * adapts to dark/light automatically.
 */
?>
<style>
  /* center the auth card in the available space */
  .auth-wrap{
    min-height:calc(100vh - 120px);
    display:flex; align-items:center; justify-content:center;
    padding:1rem 0;
  }

  /* the split card: brand aside + form */
  .auth-card{
    width:100%; max-width:940px;
    display:grid; grid-template-columns:1.05fr 1fr;
    background:linear-gradient(160deg,var(--panel-2),var(--panel));
    border:1px solid var(--line);
    border-radius:calc(var(--radius) + 4px);
    box-shadow:0 30px 80px rgba(0,0,0,.28);
    overflow:hidden;
  }

  /* ---- left / brand panel ---- */
  .auth-aside{
    position:relative;
    padding:40px 38px;
    background:
      radial-gradient(420px 320px at 120% -10%, var(--glow-2), transparent 60%),
      linear-gradient(160deg, rgba(123,92,255,.10), transparent 70%);
    border-right:1px solid var(--line);
    display:flex; align-items:center;
    overflow:hidden;
  }
  .auth-aside-glow{
    position:absolute; inset:auto -40% -50% auto;
    width:380px; height:380px; border-radius:50%;
    background:radial-gradient(circle, var(--glow-1), transparent 65%);
    pointer-events:none;
  }
  .auth-aside-inner{ position:relative; z-index:1; }
  .auth-badge{
    display:inline-block; padding:.35rem .85rem; margin-bottom:1.4rem;
    font-size:.72rem; font-weight:700; letter-spacing:.04em;
    color:var(--cyan); background:rgba(39,211,224,.10);
    border:1px solid rgba(39,211,224,.32); border-radius:999px;
  }
  .auth-aside-title{
    font-family:'Space Grotesk'; font-weight:700;
    font-size:clamp(1.8rem,3.5vw,2.6rem); line-height:1.05;
    color:var(--txt); margin-bottom:1rem; letter-spacing:-.02em;
  }
  .auth-aside-sub{ color:var(--txt-dim); font-size:14.5px; line-height:1.55;
    max-width:330px; margin-bottom:1.6rem; }
  .auth-points{ list-style:none; padding:0; margin:0; display:flex;
    flex-direction:column; gap:.85rem; }
  .auth-points li{ display:flex; align-items:center; gap:.7rem; margin:0;
    color:var(--txt-dim); font-size:13.5px; font-weight:500; }
  .auth-points svg{ width:20px; height:20px; flex:none; color:var(--cyan); }

  /* ---- right / form panel ---- */
  .auth-form{ padding:44px 42px; display:flex; flex-direction:column;
    justify-content:center; }
  .auth-form-head h1{ font-family:'Space Grotesk'; font-weight:700;
    font-size:1.7rem; color:var(--txt); margin-bottom:.3rem; }
  .auth-form-head p{ color:var(--txt-dim); font-size:14px; margin-bottom:1.6rem; }

  .field{ margin-bottom:1.1rem; }
  .field label{ display:block; font-weight:600; color:var(--txt-dim);
    font-size:13px; margin-bottom:7px; }

  /* input with leading icon (+ optional trailing toggle) */
  .input-icon{ position:relative; }
  .input-icon > svg{ position:absolute; left:13px; top:50%;
    transform:translateY(-50%); width:18px; height:18px;
    color:var(--txt-faint); pointer-events:none; }
  .input-icon .form-control{ padding-left:40px; }
  .input-icon .form-control[id]{ padding-right:42px; } /* room for toggle */
  .pw-toggle{ position:absolute; right:8px; top:50%; transform:translateY(-50%);
    width:30px; height:30px; display:grid; place-items:center;
    background:none; border:none; cursor:pointer; color:var(--txt-faint);
    border-radius:8px; transition:.14s; }
  .pw-toggle:hover{ color:var(--cyan); background:var(--panel-2); }
  .pw-toggle svg{ width:18px; height:18px; }

  .auth-submit{ margin-top:.4rem; padding:13px; font-size:14.5px; }
  .auth-alt{ margin-top:1.3rem; margin-bottom:0; color:var(--txt-dim);
    font-size:13.5px; text-align:center; }

  /* two-column rows inside register, with consistent gap */
  .field-row{ display:grid; grid-template-columns:1fr 1fr; gap:1rem; }

  @media(max-width:820px){
    .auth-card{ grid-template-columns:1fr; max-width:480px; }
    .auth-aside{ display:none; }   /* hide brand panel on small screens */
    .auth-form{ padding:34px 26px; }
  }
</style>

<script>
  document.querySelectorAll('.pw-toggle').forEach(function(btn){
    btn.addEventListener('click', function(){
      var input = document.getElementById(btn.dataset.target);
      if(!input) return;
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  });
</script>
