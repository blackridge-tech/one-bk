(function(){
  const idVal = document.getElementById("idVal");
  const showId = document.getElementById("showId");
  const hideId = document.getElementById("hideId");

  const username = document.getElementById("username");
  const cooldown = document.getElementById("cooldown");
  const saveUsername = document.getElementById("saveUsername");
  const userMsg = document.getElementById("userMsg");

  const bio = document.getElementById("bio");
  const saveBio = document.getElementById("saveBio");
  const bioMsg = document.getElementById("bioMsg");

  const logout = document.getElementById("logout");

  let userId = "";

  function setMsg(el, text, kind){
    el.textContent = text || "";
    el.className = "msg" + (kind ? (" " + kind) : "");
  }

  async function getMe(){
    const res = await fetch("/api/me", { method: "GET" });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || !json.ok) throw new Error(json.error || "Failed");
    return json;
  }

  function setCooldownText(remainingMs){
    if (!remainingMs || remainingMs <= 0) {
      cooldown.textContent = "You can change your username now.";
      return;
    }
    const hrs = Math.ceil(remainingMs / 3600000);
    cooldown.textContent = `You can change again in ~${hrs}h.`;
  }

  async function load(){
    try {
      const me = await getMe();
      userId = String(me.user.id || "");
      bio.value = String(me.user.bio || "");
      setCooldownText(me.usernameChange ? me.usernameChange.remainingMs : 0);
    } catch (e) {
      cooldown.textContent = "Failed to load profile.";
    }
  }

  showId.addEventListener("click", () => {
    idVal.textContent = userId ? userId : "Unavailable";
    showId.hidden = true;
    hideId.hidden = false;
  });

  hideId.addEventListener("click", () => {
    idVal.textContent = "••••••••••••••••";
    showId.hidden = false;
    hideId.hidden = true;
  });

  saveBio.addEventListener("click", async () => {
    const v = (bio.value || "").trim();
    saveBio.disabled = true;
    setMsg(bioMsg, "Saving...", "");
    try {
      const res = await fetch("/api/me", {
        method: "POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({ bio: v })
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || !json.ok) { setMsg(bioMsg, json.error || "Failed", "err"); return; }
      setMsg(bioMsg, "Saved.", "ok");
    } catch {
      setMsg(bioMsg, "Request failed", "err");
    } finally {
      saveBio.disabled = false;
    }
  });

  saveUsername.addEventListener("click", async () => {
    const u = (username.value || "").trim();
    if (!u) { setMsg(userMsg, "Enter a username.", "err"); return; }

    saveUsername.disabled = true;
    setMsg(userMsg, "Saving...", "");
    try {
      const res = await fetch("/api/me/username", {
        method: "POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({ username: u })
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || !json.ok) { setMsg(userMsg, json.error || "Failed", "err"); return; }
      setMsg(userMsg, "Username updated.", "ok");
      username.value = "";
      await load();
    } catch {
      setMsg(userMsg, "Request failed", "err");
    } finally {
      saveUsername.disabled = false;
    }
  });

  logout.addEventListener("click", async () => {
    logout.disabled = true;
    try { await fetch("/api/logout", { method: "POST" }); } catch {}
    location.href = "/";
  });

  load();
})();
