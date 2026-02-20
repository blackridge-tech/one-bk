// divine/script.js — global shortcut handler + animated background (dark-only)
// Note: Theme toggle removed. Site is always dark now.

(function(){
  "use strict";

  //
  // 1) Animated background (canvas stars + occasional meteors)
  //
  // - Purely decorative (pointer-events: none)
  // - Respects prefers-reduced-motion
  // - Sits behind everything
  //
  (function initAnimatedBackground(){
    try {
      const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (reduceMotion) return;

      // Avoid duplicate canvas if script runs twice
      if (document.getElementById("__divine_bg_canvas")) return;

      const canvas = document.createElement("canvas");
      canvas.id = "__divine_bg_canvas";
      canvas.setAttribute("aria-hidden", "true");
      canvas.style.position = "fixed";
      canvas.style.inset = "0";
      canvas.style.width = "100vw";
      canvas.style.height = "100vh";
      canvas.style.zIndex = "0";
      canvas.style.pointerEvents = "none";
      canvas.style.opacity = "0.9";

      // Put it as the first element in body so everything else layers above
      // (Your CSS already uses z-index > 0 for .container and banner)
      document.body.prepend(canvas);

      const ctx = canvas.getContext("2d", { alpha: true });

      // DPR-aware sizing
      function resize(){
        const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1)); // cap at 2 for perf
        canvas.width = Math.floor(window.innerWidth * dpr);
        canvas.height = Math.floor(window.innerHeight * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      }
      resize();
      window.addEventListener("resize", resize, { passive: true });

      // Star field
      const STAR_COUNT = Math.min(260, Math.floor((window.innerWidth * window.innerHeight) / 6000));
      const stars = [];
      const meteors = [];

      function rand(min, max){ return Math.random() * (max - min) + min; }

      // Colors tuned for gold/purple/ice theme but subtle
      const STAR_BASE = "255,255,255";
      const PURPLE_GLOW = "163,75,255";
      const ICE_GLOW = "79,176,229";

      for (let i = 0; i < STAR_COUNT; i++) {
        stars.push({
          x: Math.random() * window.innerWidth,
          y: Math.random() * window.innerHeight,
          r: rand(0.6, 1.7),
          tw: rand(0.003, 0.012),
          ph: rand(0, Math.PI * 2),
          driftX: rand(-0.015, 0.02),
          driftY: rand(-0.01, 0.015),
          tint: Math.random() < 0.10 ? "purple" : (Math.random() < 0.10 ? "ice" : "white")
        });
      }

      function spawnMeteor(){
        const side = Math.floor(Math.random() * 4);
        let x, y, ang;
        const w = window.innerWidth;
        const h = window.innerHeight;

        if (side === 0) { // top
          x = rand(0, w); y = -40; ang = rand(Math.PI * 0.25, Math.PI * 0.75);
        } else if (side === 1) { // right
          x = w + 40; y = rand(0, h); ang = rand(Math.PI * 0.75, Math.PI * 1.25);
        } else if (side === 2) { // bottom
          x = rand(0, w); y = h + 40; ang = rand(Math.PI * 1.25, Math.PI * 1.75);
        } else { // left
          x = -40; y = rand(0, h); ang = rand(Math.PI * -0.25, Math.PI * 0.25);
        }

        meteors.push({
          x, y,
          vx: Math.cos(ang) * rand(6, 10),
          vy: Math.sin(ang) * rand(6, 10),
          life: 0,
          maxLife: rand(40, 70),
          width: rand(120, 220),
          hue: Math.random() < 0.5 ? PURPLE_GLOW : ICE_GLOW
        });
      }

      // Spawn meteors occasionally
      let nextMeteorAt = performance.now() + rand(1400, 3200);

      // Mouse parallax (gentle)
      let parX = 0, parY = 0, tgtX = 0, tgtY = 0;
      window.addEventListener("mousemove", (e) => {
        const x = (e.clientX / window.innerWidth) - 0.5;
        const y = (e.clientY / window.innerHeight) - 0.5;
        tgtX = x * 12;
        tgtY = y * 10;
      }, { passive: true });

      function drawStar(s, t){
        // twinkle 0.35..0.95
        const tw = 0.65 + 0.30 * Math.sin(t * s.tw + s.ph);
        let rgb = STAR_BASE;
        let glowRgb = STAR_BASE;

        if (s.tint === "purple") { glowRgb = PURPLE_GLOW; }
        else if (s.tint === "ice") { glowRgb = ICE_GLOW; }

        ctx.beginPath();
        ctx.fillStyle = `rgba(${rgb},${tw})`;
        ctx.shadowColor = `rgba(${glowRgb},${0.35 * tw})`;
        ctx.shadowBlur = 10;
        ctx.arc(s.x + parX, s.y + parY, s.r, 0, Math.PI * 2);
        ctx.fill();
      }

      function drawMeteor(m){
        // trail gradient
        const x2 = m.x - m.vx * 10;
        const y2 = m.y - m.vy * 10;
        const grad = ctx.createLinearGradient(m.x, m.y, x2, y2);
        grad.addColorStop(0, `rgba(${m.hue},0.95)`);
        grad.addColorStop(1, `rgba(${m.hue},0.0)`);

        ctx.save();
        ctx.lineWidth = 2;
        ctx.strokeStyle = grad;
        ctx.shadowColor = `rgba(${m.hue},0.45)`;
        ctx.shadowBlur = 18;

        ctx.beginPath();
        ctx.moveTo(m.x + parX, m.y + parY);
        ctx.lineTo((m.x + parX) - (m.vx * (m.width / 40)), (m.y + parY) - (m.vy * (m.width / 40)));
        ctx.stroke();
        ctx.restore();
      }

      function tick(t){
        // move parallax smoothly
        parX += (tgtX - parX) * 0.03;
        parY += (tgtY - parY) * 0.03;

        ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);

        // Stars drift
        for (const s of stars) {
          s.x += s.driftX;
          s.y += s.driftY;

          if (s.x < -10) s.x = window.innerWidth + 10;
          if (s.x > window.innerWidth + 10) s.x = -10;
          if (s.y < -10) s.y = window.innerHeight + 10;
          if (s.y > window.innerHeight + 10) s.y = -10;

          drawStar(s, t);
        }

        // Meteor spawn scheduling
        if (t > nextMeteorAt) {
          // burst 1–3 meteors
          const burst = Math.random() < 0.65 ? 1 : (Math.random() < 0.85 ? 2 : 3);
          for (let i = 0; i < burst; i++) spawnMeteor();
          nextMeteorAt = t + rand(1800, 5200);
        }

        // Meteors update/draw
        for (let i = meteors.length - 1; i >= 0; i--) {
          const m = meteors[i];
          m.x += m.vx;
          m.y += m.vy;
          m.life += 1;

          drawMeteor(m);

          // off-screen or dead
          if (m.life > m.maxLife ||
              m.x < -400 || m.x > window.innerWidth + 400 ||
              m.y < -400 || m.y > window.innerHeight + 400) {
            meteors.splice(i, 1);
          }
        }

        requestAnimationFrame(tick);
      }

      requestAnimationFrame(tick);
    } catch (e) {
      // If canvas fails for any reason, do nothing (site still works)
    }
  })();


  //
  // 2) Shortcut handling (site-wide)
  //
  // Reads config from localStorage key 'divine.settings.shortcut'
  //
  const SHORTCUT_STORAGE = 'divine.settings.shortcut';

  function loadShortcutCfg() {
    try {
      const raw = localStorage.getItem(SHORTCUT_STORAGE);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch (e) {
      return null;
    }
  }

  function deleteAccessCookie() {
    // Legacy cookie cleanup (still useful if you keep cookie-based gating somewhere)
    const name = 'divine_access';
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/divine; SameSite=Strict';
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; SameSite=Strict';
  }

  function activateShortcut(cfg) {
    if (!cfg) return;

    if (cfg.removeAccess) {
      deleteAccessCookie();
      try {
        localStorage.removeItem('divine_failed_attempts');
        localStorage.removeItem('divine_lock_until');
      } catch (e) { /* ignore */ }
    }

    const target = cfg.url || '/divine/';
    location.href = target;
  }

  function globalShortcutListener(e) {
    const cfg = loadShortcutCfg();
    if (!cfg || !cfg.key) return;

    // ignore typing in inputs/textareas/contenteditable
    const active = document.activeElement;
    if (active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA' || active.isContentEditable)) return;

    // require modifiers if configured
    if (cfg.ctrl && !e.ctrlKey) return;
    if (cfg.alt && !e.altKey) return;
    if (cfg.shift && !e.shiftKey) return;
    if (cfg.search) {
      const hasSearch = e.metaKey || (typeof e.getModifierState === 'function' && e.getModifierState('Search')) || e.key === 'Search';
      if (!hasSearch) return;
    }

    if (!e.key || e.key.length !== 1) return;
    if (e.repeat) return;

    if (e.key.toLowerCase() !== String(cfg.key).toLowerCase()) return;

    try {
      e.preventDefault();
      e.stopPropagation();
    } catch (ex) {}

    activateShortcut(cfg);
  }

  window.addEventListener('keydown', globalShortcutListener, true);

  // Debug helper
  window.__divine_shortcut_cfg = loadShortcutCfg;


  //
  // 3) Home auth gate popup (for /divine when not logged in)
  //
  (function initHomeAuthGate() {
    const gate = document.getElementById('authGate');
    if (!gate) return;

    function showGate() {
      gate.hidden = false;
      document.body.style.overflow = 'hidden';
    }

    function hideGate() {
      gate.hidden = true;
      document.body.style.overflow = '';
    }

    async function checkLoginState() {
      try {
        const res = await fetch('/api/me', {
          method: 'GET',
          headers: { 'Accept': 'application/json' },
          credentials: 'same-origin'
        });

        if (!res.ok) {
          showGate();
          return;
        }

        const json = await res.json().catch(() => ({}));
        if (!json || !json.ok || !json.user) {
          showGate();
          return;
        }

        hideGate();
      } catch (e) {
        showGate();
      }
    }

    checkLoginState();
  })();


  //
  // 4) DM Badge Updates (unread count + pending requests)
  //
  (function initDmBadges() {
    const badgeDotReq = document.getElementById('badgeDotReq');
    const badgeCount = document.getElementById('badgeCount');
    
    if (!badgeDotReq || !badgeCount) return; // Not on home page

    let ws = null;

    // Fetch and update badge counts
    async function updateBadges() {
      try {
        // Fetch unread count
        const unreadRes = await fetch('/api/dm/unread-count');
        if (unreadRes.ok) {
          const unreadData = await unreadRes.json();
          if (unreadData.ok) {
            const count = unreadData.count || 0;
            if (count > 0) {
              badgeCount.textContent = count > 9 ? '9+' : count;
              badgeCount.style.display = 'flex';
            } else {
              badgeCount.style.display = 'none';
            }
          }
        }

        // Fetch pending requests count
        const reqRes = await fetch('/api/dm/pending-requests');
        if (reqRes.ok) {
          const reqData = await reqRes.json();
          if (reqData.ok) {
            const reqCount = reqData.count || 0;
            if (reqCount > 0) {
              badgeDotReq.style.display = 'block';
            } else {
              badgeDotReq.style.display = 'none';
            }
          }
        }
      } catch (e) {
        // Silently fail - user might not be logged in or DMs disabled
        console.debug('Failed to update DM badges:', e);
      }
    }

    // Connect to WebSocket for realtime updates
    function connectWebSocket() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;
      
      try {
        ws = new WebSocket(wsUrl);
        
        ws.onopen = () => {
          console.debug('DM badge WebSocket connected');
        };
        
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            
            // Update badges on relevant events
            if (data.type === 'new_request' || 
                data.type === 'new_message' || 
                data.type === 'unread_update' ||
                data.type === 'request_accepted') {
              updateBadges();
            }
          } catch (e) {
            console.debug('WS message parse error:', e);
          }
        };
        
        ws.onclose = () => {
          console.debug('DM badge WebSocket closed, reconnecting...');
          setTimeout(connectWebSocket, 5000);
        };
        
        ws.onerror = (err) => {
          console.debug('DM badge WebSocket error:', err);
        };
      } catch (e) {
        console.debug('Failed to connect DM badge WebSocket:', e);
      }
    }

    // Initialize
    updateBadges();
    connectWebSocket();
  })();

})();
