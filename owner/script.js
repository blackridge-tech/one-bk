(function(){
  "use strict";

  // -------- Elements --------
  const pinOverlay = document.getElementById("pinOverlay");
  const ownerPin = document.getElementById("ownerPin");
  const pinEnterBtn = document.getElementById("pinEnterBtn");
  const pinExitBtn = document.getElementById("pinExitBtn");
  const pinMsg = document.getElementById("pinMsg");

  const statusText = document.getElementById("statusText");
  const refreshBtn = document.getElementById("refreshBtn");
  const homeBtn = document.getElementById("homeBtn");
  const relockBtn = document.getElementById("relockBtn");

  const navItems = Array.from(document.querySelectorAll(".navItem[data-view]"));
  const views = Array.from(document.querySelectorAll(".view"));

  // Overview
  const statActive = document.getElementById("statActive");
  const statBanned = document.getElementById("statBanned");
  const statLockdown = document.getElementById("statLockdown");
  const recentActivityBody = document.getElementById("recentActivityBody");
  const loadActivityBtn = document.getElementById("loadActivityBtn");

  // Users
  const userSearch = document.getElementById("userSearch");
  const loadUsersBtn = document.getElementById("loadUsersBtn");
  const usersBody = document.getElementById("usersBody");

  // Broadcast
  const bcUserRow = document.getElementById("bcUserRow");
  const bcUser = document.getElementById("bcUser");
  const bcMsg = document.getElementById("bcMsg");
  const sendBroadcastBtn = document.getElementById("sendBroadcastBtn");
  const clearBroadcastBtn = document.getElementById("clearBroadcastBtn");

  // Activity
  const loadAllActivityBtn = document.getElementById("loadAllActivityBtn");
  const clearActivityBtn = document.getElementById("clearActivityBtn");
  const activityBody = document.getElementById("activityBody");

  // Bans
  const loadBansBtn = document.getElementById("loadBansBtn");
  const openBanModalBtn = document.getElementById("openBanModalBtn");
  const bansBody = document.getElementById("bansBody");

  // DM Bans
  const loadDmBansBtn = document.getElementById("loadDmBansBtn");
  const openDmBanModalBtn = document.getElementById("openDmBanModalBtn");
  const dmBansBody = document.getElementById("dmBansBody");

  // Reports
  const loadReportsBtn = document.getElementById("loadReportsBtn");
  const clearReportsBtn = document.getElementById("clearReportsBtn");
  const reportsList = document.getElementById("reportsList");

  // DM Appeals
  const loadDmAppealsBtn = document.getElementById("loadDmAppealsBtn");
  const clearDmAppealsBtn = document.getElementById("clearDmAppealsBtn");
  const dmAppealsList = document.getElementById("dmAppealsList");

  // Lockdown
  const lockLight = document.getElementById("lockLight");
  const lockTitle = document.getElementById("lockTitle");
  const lockSub = document.getElementById("lockSub");
  const toggleLockdownBtn = document.getElementById("toggleLockdownBtn");
  const simulateLockdownUiBtn = document.getElementById("simulateLockdownUiBtn");

  // Modal
  const banModal = document.getElementById("banModal");
  const banUser = document.getElementById("banUser");
  const banDuration = document.getElementById("banDuration");
  const banReason = document.getElementById("banReason");
  const banSubmitBtn = document.getElementById("banSubmitBtn");
  const banMsg = document.getElementById("banMsg");

  // DM Ban Modal
  const dmBanModal = document.getElementById("dmBanModal");
  const dmBanUser = document.getElementById("dmBanUser");
  const dmBanDuration = document.getElementById("dmBanDuration");
  const dmBanReason = document.getElementById("dmBanReason");
  const dmBanSubmitBtn = document.getElementById("dmBanSubmitBtn");
  const dmBanMsg = document.getElementById("dmBanMsg");

  // Toast
  const toastEl = document.getElementById("toast");
  let toastTimer = null;

  // -------- State --------
  let unlocked = false;
  let fakeLockdown = false; // UI-only simulation until backend exists

  // -------- Helpers --------
  function toast(text){
    try {
      toastEl.textContent = text || "";
      toastEl.classList.add("show");
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => toastEl.classList.remove("show"), 2300);
    } catch {}
  }

  function setPinMsg(text, kind){
    pinMsg.textContent = text || "";
    pinMsg.className = "msg" + (kind ? (" " + kind) : "");
  }

  function showOverlay(){
    pinOverlay.style.display = "flex";
    ownerPin.value = "";
    setPinMsg("", "");
    statusText.textContent = "Locked";
    unlocked = false;
    // focus
    setTimeout(() => ownerPin.focus(), 50);
  }

  function hideOverlay(){
    pinOverlay.style.display = "none";
    statusText.textContent = "Unlocked";
    unlocked = true;
  }

  function selectView(name){
    navItems.forEach(b => b.classList.toggle("active", b.dataset.view === name));
    views.forEach(v => v.classList.toggle("active", v.id === "view-" + name));
  }

  function esc(s){
    return String(s || "")
      .replaceAll("&","&amp;")
      .replaceAll("<","&lt;")
      .replaceAll(">","&gt;")
      .replaceAll('"',"&quot;")
      .replaceAll("'","&#39;");
  }

  async function postJson(url, body){
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify(body || {})
    });
    const json = await res.json().catch(() => ({}));
    return { res, json };
  }

  async function getJson(url){
    const res = await fetch(url, { method: "GET" });
    const json = await res.json().catch(() => ({}));
    return { res, json };
  }

  // -------- PIN verify --------
  async function verifyOwnerPin(){
    const pinAttempt = (ownerPin.value || "").trim();
    if (!pinAttempt) { setPinMsg("Enter PIN.", "err"); return; }

    pinEnterBtn.disabled = true;
    ownerPin.disabled = true;
    setPinMsg("Verifying...", "");

    try {
      const { res, json } = await postJson("/owner/pin", { pinAttempt });
      if (!res.ok || !json || !json.ok) {
        setPinMsg((json && json.error) ? json.error : "Denied", "err");
        return;
      }
      hideOverlay();
      toast("Owner unlocked for this load.");
      // attempt to load overview stats if possible
      await loadOverview();
    } catch (e) {
      setPinMsg("Request failed", "err");
    } finally {
      pinEnterBtn.disabled = false;
      ownerPin.disabled = false;
    }
  }

  // -------- Data loaders (graceful when API missing) --------
  async function loadOverview(){
    // Try a few possible endpoints. If missing, keep placeholders.
    // You can later implement any of these endpoints server-side.
    const candidates = [
      "/api/owner/overview",
      "/api/owner/state",
      "/owner/state"
    ];

    for (const url of candidates) {
      try {
        const { res, json } = await getJson(url);
        if (!res.ok || !json) continue;

        // expected shapes:
        // { ok:true, activeUsers, bannedUsers, lockdownEnabled }
        // or { ok:true, stats:{...} }
        const active = json.activeUsers ?? (json.stats && json.stats.activeUsers);
        const banned = json.bannedUsers ?? (json.stats && json.stats.bannedUsers);
        const lockdown = json.lockdownEnabled ?? (json.lockdown && json.lockdown.enabled) ?? (json.stats && json.stats.lockdownEnabled);

        if (active !== undefined) statActive.textContent = String(active);
        if (banned !== undefined) statBanned.textContent = String(banned);
        if (lockdown !== undefined) statLockdown.textContent = lockdown ? "ON" : "OFF";

        if (lockdown !== undefined) setLockdownUi(Boolean(lockdown), "Live");
        return;
      } catch {}
    }

    // fallback (no API)
    statActive.textContent = "—";
    statBanned.textContent = "—";
    statLockdown.textContent = fakeLockdown ? "ON" : "OFF";
    setLockdownUi(fakeLockdown, "Simulated (no API)");
  }

  function setLockdownUi(enabled, subtitle){
    lockLight.style.background = enabled ? "rgba(255,59,59,0.95)" : "rgba(255,255,255,0.25)";
    lockLight.style.boxShadow = enabled ? "0 0 26px rgba(255,59,59,0.35)" : "0 0 26px rgba(255,255,255,0.18)";
    lockTitle.textContent = "Lockdown: " + (enabled ? "ENABLED" : "DISABLED");
    lockSub.textContent = subtitle || "";
  }

  async function loadRecentActivity(){
    // endpoint candidates
    const candidates = [
      "/api/owner/activity?limit=8",
      "/api/owner/activity/recent",
      "/api/activity?limit=8"
    ];

    for (const url of candidates) {
      try {
        const { res, json } = await getJson(url);
        if (!res.ok || !json || !json.ok) continue;
        const items = json.items || json.activity || [];
        renderRecentActivity(items);
        return;
      } catch {}
    }
    toast("Activity API not implemented yet.");
  }

  function renderRecentActivity(items){
    const rows = (items || []).slice(0, 8);
    if (!rows.length) {
      recentActivityBody.innerHTML = `<tr><td colspan="3" class="muted">No activity.</td></tr>`;
      return;
    }

    recentActivityBody.innerHTML = rows.map((it) => {
      const t = esc(it.time || it.created_at || it.timestamp || "");
      const u = esc(it.username || it.user || it.userName || "");
      const a = esc(it.action || it.page || it.path || it.message || "");
      return `<tr><td>${t}</td><td>${u}</td><td>${a}</td></tr>`;
    }).join("");
  }

  async function loadUsers(){
    const candidates = [
      "/api/owner/users",
      "/api/users"
    ];

    for (const url of candidates) {
      try {
        const { res, json } = await getJson(url);
        if (!res.ok || !json || !json.ok) continue;
        const users = json.users || json.items || [];
        renderUsers(users);
        return;
      } catch {}
    }
    toast("Users API not implemented yet.");
  }

  function renderUsers(users){
    const q = (userSearch.value || "").trim().toLowerCase();
    const rows = (users || []).filter(u => {
      if (!q) return true;
      return String(u.username || "").toLowerCase().includes(q);
    });

    if (!rows.length) {
      usersBody.innerHTML = `<tr><td colspan="5" class="muted">No users found.</td></tr>`;
      return;
    }

    usersBody.innerHTML = rows.map(u => {
      const username = esc(u.username || "(unknown)");
      const id = esc(u.id || u.userId || "");
      const ip = esc(u.last_ip || u.lastIp || "");
      const banned = Boolean(u.banned || u.isBanned || (u.banned_until && Date.now() < Number(u.banned_until)));
      const status = banned ? `<span style="color:rgba(255,59,59,0.92);font-weight:1100">BANNED</span>` : `<span style="color:rgba(34,197,94,0.92);font-weight:1100">OK</span>`;

      // Actions: ↩️ 🔗 👁️ 🛑
      return `
<tr>
  <td>${username}</td>
  <td class="muted">${id}</td>
  <td class="muted">${ip}</td>
  <td>${status}</td>
  <td style="text-align:right">
    <div class="row" style="justify-content:flex-end">
      <button class="btn ghost small" data-act="revoke" data-user="${esc(username)}" title="Revoke access">↩️</button>
      <button class="btn ghost small" data-act="redirect" data-user="${esc(username)}" title="Redirect user">🔗</button>
      <button class="btn ghost small" data-act="view" data-user="${esc(username)}" title="View activity">👁️</button>
      <button class="btn danger small" data-act="ban" data-user="${esc(username)}" title="Ban user">🛑</button>
    </div>
  </td>
</tr>`;
    }).join("");
  }

  async function sendBroadcast(){
    const scope = (document.querySelector('input[name="bcScope"]:checked') || {}).value || "global";
    const msg = (bcMsg.value || "").trim();
    const user = (bcUser.value || "").trim();

    if (!msg) { toast("Write a message first."); return; }
    if (scope === "user" && !user) { toast("Enter a target username."); return; }

    const candidates = [
      "/api/owner/broadcast",
      "/api/broadcast"
    ];

    for (const url of candidates) {
      try {
        const { res, json } = await postJson(url, { scope, username: user, message: msg });
        if (!res.ok || !json || !json.ok) continue;
        toast("Broadcast sent.");
        return;
      } catch {}
    }

    toast("Broadcast API not implemented yet.");
  }

  async function loadAllActivity(){
    const candidates = [
      "/api/owner/activity",
      "/api/activity"
    ];
    for (const url of candidates) {
      try {
        const { res, json } = await getJson(url);
        if (!res.ok || !json || !json.ok) continue;
        const items = json.items || json.activity || [];
        renderActivity(items);
        return;
      } catch {}
    }
    toast("Activity API not implemented yet.");
  }

  function renderActivity(items){
    const rows = (items || []);
    if (!rows.length) {
      activityBody.innerHTML = `<tr><td colspan="4" class="muted">No activity.</td></tr>`;
      return;
    }

    activityBody.innerHTML = rows.map((it) => {
      const t = esc(it.time || it.created_at || it.timestamp || "");
      const u = esc(it.username || it.user || it.userName || "");
      const p = esc(it.page || it.path || it.action || "");
      const x = esc(it.extra || it.meta || it.ip || "");
      return `<tr><td>${t}</td><td>${u}</td><td>${p}</td><td class="muted">${x}</td></tr>`;
    }).join("");
  }

  async function loadBans(){
    const candidates = [
      "/api/owner/bans",
      "/api/bans"
    ];
    for (const url of candidates) {
      try {
        const { res, json } = await getJson(url);
        if (!res.ok || !json || !json.ok) continue;
        const items = json.items || json.bans || [];
        renderBans(items);
        return;
      } catch {}
    }
    toast("Bans API not implemented yet.");
  }

  function renderBans(items){
    const rows = (items || []);
    if (!rows.length) {
      bansBody.innerHTML = `<tr><td colspan="5" class="muted">No bans.</td></tr>`;
      return;
    }

    bansBody.innerHTML = rows.map((b) => {
      const username = esc(b.username || "");
      const id = esc(b.userId || b.id || "");
      const ends = esc(b.ends || b.until || b.banned_until || "—");
      const reason = esc(b.reason || b.ban_reason || "");
      return `
<tr>
  <td>${username}</td>
  <td class="muted">${id}</td>
  <td class="muted">${ends}</td>
  <td>${reason}</td>
  <td style="text-align:right">
    <button class="btn ghost small" data-ban-act="unban" data-user="${username}">Unban</button>
  </td>
</tr>`;
    }).join("");
  }

  async function loadReports(){
    const candidates = [
      "/api/owner/reports",
      "/api/reports"
    ];
    for (const url of candidates) {
      try {
        const { res, json } = await getJson(url);
        if (!res.ok || !json || !json.ok) continue;
        const items = json.items || json.reports || [];
        renderReports(items);
        return;
      } catch {}
    }
    toast("Reports API not implemented yet.");
  }

  function renderReports(items){
    const rows = (items || []);
    if (!rows.length) {
      reportsList.innerHTML = `<div class="muted">No reports.</div>`;
      return;
    }

    reportsList.innerHTML = rows.map((r, idx) => {
      const title = esc(r.title || `Report #${idx+1}`);
      const body = esc(r.body || r.message || r.text || "");
      const who = esc(r.reporter || r.reporterUsername || "");
      const target = esc(r.target || r.targetUsername || "");
      return `
<div class="report">
  <div class="reportTop">
    <div>
      <div class="reportTitle">${title}</div>
      <div class="mini muted">From: ${who || "?"} • Target: ${target || "?"}</div>
    </div>
    <button class="xbtn" data-report-act="dismiss" data-report-id="${esc(r.id || idx)}" title="Dismiss">✕</button>
  </div>
  <div class="reportBody">${body}</div>
  <div class="row" style="margin-top:10px;justify-content:flex-end">
    <button class="btn danger small" data-report-act="ban" data-target="${target}">Ban</button>
  </div>
</div>`;
    }).join("");
  }

  async function toggleLockdown(){
    // Try to toggle via API; if missing, do UI simulation only.
    const candidates = [
      "/api/owner/lockdown",
      "/api/lockdown"
    ];

    for (const url of candidates) {
      try {
        const { res, json } = await postJson(url, { toggle: true });
        if (!res.ok || !json || !json.ok) continue;

        const enabled = Boolean(json.enabled ?? json.lockdownEnabled ?? (json.lockdown && json.lockdown.enabled));
        setLockdownUi(enabled, "Live");
        toast(enabled ? "Lockdown enabled." : "Lockdown disabled.");
        return;
      } catch {}
    }

    // fallback simulation
    fakeLockdown = !fakeLockdown;
    setLockdownUi(fakeLockdown, "Simulated (no API)");
    statLockdown.textContent = fakeLockdown ? "ON" : "OFF";
    toast(fakeLockdown ? "Simulated lockdown ON." : "Simulated lockdown OFF.");
  }

  // -------- Events --------
  pinEnterBtn.addEventListener("click", verifyOwnerPin);
  ownerPin.addEventListener("keyup", (e) => { if (e.key === "Enter") verifyOwnerPin(); });

  pinExitBtn.addEventListener("click", () => location.href = "/");

  refreshBtn.addEventListener("click", async () => {
    if (!unlocked) { showOverlay(); return; }
    toast("Refreshing…");
    await loadOverview();
  });

  homeBtn.addEventListener("click", () => location.href = "/divine/");

  relockBtn.addEventListener("click", () => {
    showOverlay();
    toast("Locked.");
  });

  navItems.forEach(btn => {
    btn.addEventListener("click", () => {
      if (!unlocked) { showOverlay(); return; }
      selectView(btn.dataset.view);
    });
  });

  // Overview
  loadActivityBtn.addEventListener("click", async () => {
    if (!unlocked) return showOverlay();
    await loadRecentActivity();
  });

  // Users
  loadUsersBtn.addEventListener("click", async () => {
    if (!unlocked) return showOverlay();
    await loadUsers();
  });
  userSearch.addEventListener("input", () => {
    // re-filter existing table by hiding rows is annoying; simplest: re-load if already loaded
    // We'll just do a soft re-render if users are loaded in future. For now, no-op.
  });

  usersBody.addEventListener("click", async (e) => {
    const b = e.target && e.target.closest && e.target.closest("button[data-act]");
    if (!b) return;
    const act = b.getAttribute("data-act");
    const username = b.getAttribute("data-user") || "";
    if (!act) return;

    if (act === "ban") {
      banUser.value = username;
      banDuration.value = "1h";
      banReason.value = "";
      banMsg.textContent = "";
      try { banModal.showModal(); } catch { toast("Your browser doesn't support <dialog>."); }
      return;
    }

    if (act === "revoke") {
      if (!confirm(`Revoke token for ${username}? They'll be logged out immediately.`)) return;
      try {
        const res = await fetch("/api/owner/users/revoke", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username })
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          toast(data.error || "Revoke failed");
          return;
        }
        toast(`Token revoked for ${username}`);
        await refreshUsers();
      } catch (e) {
        toast("Network error");
      }
      return;
    }
    if (act === "redirect") {
      const url = prompt("Redirect URL (next page load only):", "https://example.com");
      if (!url) return;
      try {
        const res = await fetch("/api/owner/users/redirect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, url })
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          toast(data.error || "Redirect failed");
          return;
        }
        toast(`Redirect set for ${username}`);
      } catch (e) {
        toast("Network error");
      }
      return;
    }
    if (act === "view") {
      selectView("activity");
      try {
        const res = await fetch(`/api/owner/activity?user=${encodeURIComponent(username)}`);
        const data = await res.json();
        if (!res.ok || !data.ok) {
          toast(data.error || "Failed to load activity");
          return;
        }
        renderActivityTable(data.activity || []);
        toast(`Showing activity for ${username}`);
      } catch (e) {
        toast("Network error");
      }
      return;
    }
  });

  // Broadcast
  document.querySelectorAll('input[name="bcScope"]').forEach(r => {
    r.addEventListener("change", () => {
      const v = (document.querySelector('input[name="bcScope"]:checked') || {}).value;
      bcUserRow.hidden = (v !== "user");
    });
  });
  sendBroadcastBtn.addEventListener("click", async () => {
    if (!unlocked) return showOverlay();
    await sendBroadcast();
  });
  clearBroadcastBtn.addEventListener("click", () => {
    bcUser.value = "";
    bcMsg.value = "";
    toast("Cleared.");
  });

  // Activity
  loadAllActivityBtn.addEventListener("click", async () => {
    if (!unlocked) return showOverlay();
    await loadAllActivity();
  });
  clearActivityBtn.addEventListener("click", () => {
    activityBody.innerHTML = `<tr><td colspan="4" class="muted">Cleared.</td></tr>`;
  });

  // Bans
  loadBansBtn.addEventListener("click", async () => {
    if (!unlocked) return showOverlay();
    await loadBans();
  });
  openBanModalBtn.addEventListener("click", () => {
    banUser.value = "";
    banDuration.value = "1h";
    banReason.value = "";
    banMsg.textContent = "";
    try { banModal.showModal(); } catch { toast("Your browser doesn't support <dialog>."); }
  });

  // Unban button handler (event delegation)
  bansBody.addEventListener("click", async (e) => {
    const btn = e.target && e.target.closest && e.target.closest("button[data-ban-act='unban']");
    if (!btn) return;
    const username = btn.getAttribute("data-user");
    if (!username || !confirm(`Unban ${username}?`)) return;
    
    toast("Unbanning...");
    try {
      const res = await fetch("/api/owner/unban", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username })
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        toast(data.error || "Unban failed");
        return;
      }
      toast(`Unbanned ${username}`);
      await loadBans();
    } catch (e) {
      toast("Network error");
    }
  });

  banSubmitBtn.addEventListener("click", async () => {
    const u = (banUser.value || "").trim();
    const d = (banDuration.value || "").trim();
    const r = (banReason.value || "").trim();

    if (!u || !d) {
      banMsg.textContent = "Username + duration required.";
      banMsg.className = "msg err";
      return;
    }

    banSubmitBtn.disabled = true;
    banMsg.textContent = "Submitting...";
    banMsg.className = "msg";

    // expected: POST /api/owner/ban { username, duration, reason }
    const candidates = ["/api/owner/ban", "/api/owner/bans/ban", "/api/ban"];
    for (const url of candidates) {
      try {
        const { res, json } = await postJson(url, { username: u, duration: d, reason: r });
        if (!res.ok || !json || !json.ok) continue;
        banMsg.textContent = "Banned.";
        banMsg.className = "msg ok";
        toast("User banned.");
        banModal.close();
        banSubmitBtn.disabled = false;
        return;
      } catch {}
    }

    banMsg.textContent = "Ban API not implemented yet.";
    banMsg.className = "msg err";
    banSubmitBtn.disabled = false;
  });

  // Reports
  loadReportsBtn.addEventListener("click", async () => {
    if (!unlocked) return showOverlay();
    await loadReports();
  });
  clearReportsBtn.addEventListener("click", () => {
    reportsList.innerHTML = `<div class="muted">Cleared.</div>`;
  });

  reportsList.addEventListener("click", async (e) => {
    const btn = e.target && e.target.closest && e.target.closest("button[data-report-act]");
    if (!btn) return;
    const act = btn.getAttribute("data-report-act");
    if (act === "dismiss") {
      const id = btn.getAttribute("data-report-id");
      if (!id || !confirm("Dismiss this report?")) return;
      
      toast("Dismissing...");
      try {
        const res = await fetch("/api/owner/reports/dismiss", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: parseInt(id, 10) })
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          toast(data.error || "Dismiss failed");
          return;
        }
        toast("Report dismissed");
        await loadReports();
      } catch (e) {
        toast("Network error");
      }
      return;
    }
    if (act === "ban") {
      const target = btn.getAttribute("data-target") || "";
      banUser.value = target;
      banDuration.value = "1d";
      banReason.value = "From report";
      try { banModal.showModal(); } catch {}
      return;
    }
  });

  // Lockdown
  toggleLockdownBtn.addEventListener("click", async () => {
    if (!unlocked) return showOverlay();
    await toggleLockdown();
  });
  simulateLockdownUiBtn.addEventListener("click", () => {
    fakeLockdown = !fakeLockdown;
    setLockdownUi(fakeLockdown, "Simulated (no API)");
    statLockdown.textContent = fakeLockdown ? "ON" : "OFF";
    toast(fakeLockdown ? "Simulated lockdown ON." : "Simulated lockdown OFF.");
  });

  // -------- Start --------
  // Always require PIN on load (your spec)
  showOverlay();

  // If user clicks outside pin card, do nothing (don’t dismiss)
})();

  // -------- Tab Switching --------
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      const targetTab = tab.dataset.tab;
      const parentSection = tab.closest("section");
      
      // Update tab states
      parentSection.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      
      // Show/hide panels
      if (parentSection.id === "view-bans") {
        document.getElementById("panel-site-bans").style.display = targetTab === "site-bans" ? "block" : "none";
        document.getElementById("panel-dm-bans").style.display = targetTab === "dm-bans" ? "block" : "none";
      } else if (parentSection.id === "view-reports") {
        document.getElementById("panel-user-reports").style.display = targetTab === "user-reports" ? "block" : "none";
        document.getElementById("panel-dm-appeals").style.display = targetTab === "dm-appeals" ? "block" : "none";
      }
    });
  });

  function escHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // DM Bans
  async function loadDmBans() {
    try {
      const res = await fetch("/api/owner/dm-bans");
      if (!res.ok) { toast("Failed to load DM bans"); return; }
      const data = await res.json();
      if (!data.ok) { toast(data.error || "Failed"); return; }
      const items = data.items || [];
      if (items.length === 0) {
        dmBansBody.innerHTML = '<tr><td colspan="5" class="muted">No DM bans.</td></tr>';
        return;
      }
      dmBansBody.innerHTML = items.map(b => '<tr><td><strong>' + escHtml(b.username) + '</strong></td><td><code>' + escHtml(b.userId) + '</code></td><td>' + escHtml(b.ends) + '</td><td>' + escHtml(b.reason || "—") + '</td><td style="text-align:right"><button class="btn small ghost" data-dm-unban="' + escHtml(b.username) + '">Unban</button></td></tr>').join("");
    } catch (e) { toast("Network error"); }
  }

  loadDmBansBtn.addEventListener("click", async () => { if (!unlocked) return showOverlay(); await loadDmBans(); });

  openDmBanModalBtn.addEventListener("click", () => {
    dmBanUser.value = ""; dmBanDuration.value = ""; dmBanReason.value = "";
    dmBanMsg.textContent = ""; dmBanMsg.className = "msg";
    try { dmBanModal.showModal(); } catch {}
  });

  dmBanSubmitBtn.addEventListener("click", async () => {
    const username = (dmBanUser.value || "").trim();
    const duration = (dmBanDuration.value || "").trim();
    const reason = (dmBanReason.value || "").trim();
    if (!username || !duration) { dmBanMsg.textContent = "Username and duration required."; dmBanMsg.className = "msg err"; return; }
    dmBanSubmitBtn.disabled = true; dmBanMsg.textContent = "Submitting..."; dmBanMsg.className = "msg";
    try {
      const res = await fetch("/api/owner/dm-ban", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, duration, reason }) });
      const data = await res.json();
      if (!res.ok || !data.ok) { dmBanMsg.textContent = data.error || "Failed"; dmBanMsg.className = "msg err"; dmBanSubmitBtn.disabled = false; return; }
      dmBanMsg.textContent = "DM ban applied!"; dmBanMsg.className = "msg ok"; toast('DM banned ' + username);
      setTimeout(() => { try { dmBanModal.close(); } catch {} loadDmBans(); }, 1200);
    } catch (e) { dmBanMsg.textContent = "Network error"; dmBanMsg.className = "msg err"; dmBanSubmitBtn.disabled = false; }
  });

  dmBansBody.addEventListener("click", async (e) => {
    const btn = e.target && e.target.closest && e.target.closest("button[data-dm-unban]");
    if (!btn) return;
    const username = btn.getAttribute("data-dm-unban");
    if (!username || !confirm('DM unban ' + username + '?')) return;
    toast("Unbanning...");
    try {
      const res = await fetch("/api/owner/dm-unban", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username }) });
      const data = await res.json();
      if (data.ok) { toast('DM unbanned ' + username); await loadDmBans(); } else { toast(data.error || "Failed"); }
    } catch (e) { toast("Network error"); }
  });

  // DM Appeals
  async function loadDmAppeals() {
    try {
      const res = await fetch("/api/owner/dm-appeals");
      if (!res.ok) { toast("Failed to load DM appeals"); return; }
      const data = await res.json();
      if (!data.ok) { toast(data.error || "Failed"); return; }
      const items = data.items || [];
      if (items.length === 0) { dmAppealsList.innerHTML = '<div class="muted">No DM appeals.</div>'; return; }
      dmAppealsList.innerHTML = items.map(r => '<div class="listItem"><div class="listHead"><div><div class="listTitle">' + escHtml(r.title) + '</div><div class="mini muted">User: <strong>' + escHtml(r.username) + '</strong></div></div><button data-appeal-act="dismiss" data-appeal-id="' + r.id + '">✕</button></div><div class="listBody"><div class="mini muted">Appeal:</div><div>' + escHtml(r.body) + '</div></div></div>').join("");
    } catch (e) { toast("Network error"); }
  }

  loadDmAppealsBtn.addEventListener("click", async () => { if (!unlocked) return showOverlay(); await loadDmAppeals(); });
  clearDmAppealsBtn.addEventListener("click", () => { dmAppealsList.innerHTML = '<div class="muted">Cleared.</div>'; });

  dmAppealsList.addEventListener("click", async (e) => {
    const btn = e.target && e.target.closest && e.target.closest("button[data-appeal-act]");
    if (!btn) return;
    const act = btn.getAttribute("data-appeal-act");
    const id = parseInt(btn.getAttribute("data-appeal-id"), 10);
    if (act === "dismiss") {
      try {
        const res = await fetch("/api/owner/dm-appeals/dismiss", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
        const data = await res.json();
        if (data.ok) { toast("Appeal dismissed"); await loadDmAppeals(); } else { toast(data.error || "Failed"); }
      } catch (e) { toast("Network error"); }
    }
  });

