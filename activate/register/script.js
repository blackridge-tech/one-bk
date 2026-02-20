(function(){
  const back = document.getElementById("back");

  const tabLogin = document.getElementById("tab-login");
  const tabRegister = document.getElementById("tab-register");
  const tabRecover = document.getElementById("tab-recover");

  const panelLogin = document.getElementById("panel-login");
  const panelRegister = document.getElementById("panel-register");
  const panelRecover = document.getElementById("panel-recover");

  function select(which){
    const isLogin = which === "login";
    const isReg = which === "register";
    const isRec = which === "recover";

    tabLogin.setAttribute("aria-selected", isLogin ? "true" : "false");
    tabRegister.setAttribute("aria-selected", isReg ? "true" : "false");
    tabRecover.setAttribute("aria-selected", isRec ? "true" : "false");

    panelLogin.hidden = !isLogin;
    panelRegister.hidden = !isReg;
    panelRecover.hidden = !isRec;
  }

  tabLogin.addEventListener("click", () => select("login"));
  tabRegister.addEventListener("click", () => select("register"));
  tabRecover.addEventListener("click", () => select("recover"));

  (function selectInitialTab(){
    const q = new URLSearchParams(location.search);
    const tab = String(q.get("tab") || "").toLowerCase();
    if (tab === "register") return select("register");
    if (tab === "recover") return select("recover");
    return select("login");
  })();

  back.addEventListener("click", () => location.href = "/");

  function setMsg(el, text, kind){
    el.textContent = text || "";
    el.className = "msg" + (kind ? (" " + kind) : "");
  }

  async function post(url, body){
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify(body || {})
    });
    const json = await res.json().catch(() => ({}));
    return { res, json };
  }

  // Login
  const loginUser = document.getElementById("login-user");
  const loginPass = document.getElementById("login-pass");
  const loginBtn = document.getElementById("login-btn");
  const loginMsg = document.getElementById("login-msg");

  loginBtn.addEventListener("click", async () => {
    const username = (loginUser.value || "").trim();
    const password = (loginPass.value || "").trim();
    if (!username || !password) { setMsg(loginMsg, "Missing fields.", "err"); return; }

    loginBtn.disabled = true;
    setMsg(loginMsg, "Working...", "");
    try {
      const { res, json } = await post("/api/login", { username, password });
      if (!res.ok || !json.ok) { setMsg(loginMsg, json.error || "Login failed", "err"); return; }
      setMsg(loginMsg, "Logged in. Redirecting…", "ok");
      setTimeout(() => (location.href = "/divine/"), 250);
    } catch {
      setMsg(loginMsg, "Request failed", "err");
    } finally {
      loginBtn.disabled = false;
    }
  });

  // Register
  const regUser = document.getElementById("reg-user");
  const regEmail = document.getElementById("reg-email");
  const regPass = document.getElementById("reg-pass");
  const regPass2 = document.getElementById("reg-pass2");
  const regConsent = document.getElementById("reg-consent");
  const regEmails = document.getElementById("reg-emails");
  const regBtn = document.getElementById("reg-btn");
  const regMsg = document.getElementById("reg-msg");

  regBtn.addEventListener("click", async () => {
    const username = (regUser.value || "").trim();
    const email = (regEmail.value || "").trim();
    const password = (regPass.value || "").trim();
    const password2 = (regPass2.value || "").trim();

    if (!username || !email || !password) { setMsg(regMsg, "Missing fields.", "err"); return; }
    if (password !== password2) { setMsg(regMsg, "Passwords do not match.", "err"); return; }
    if (!regConsent.checked) { setMsg(regMsg, "You must consent to the agreement.", "err"); return; }

    regBtn.disabled = true;
    setMsg(regMsg, "Creating...", "");
    try {
      const { res, json } = await post("/api/register", {
        username, email, password,
        wantsEmails: !!regEmails.checked,
        consent: true
      });
      if (!res.ok || !json.ok) { setMsg(regMsg, json.error || "Register failed", "err"); return; }
      setMsg(regMsg, "Created. Redirecting…", "ok");
      setTimeout(() => (location.href = "/divine/"), 250);
    } catch {
      setMsg(regMsg, "Request failed", "err");
    } finally {
      regBtn.disabled = false;
    }
  });

  // Recover
  const recId = document.getElementById("rec-id");
  const recPass = document.getElementById("rec-pass");
  const recBtn = document.getElementById("rec-btn");
  const recMsg = document.getElementById("rec-msg");

  recBtn.addEventListener("click", async () => {
    const userId = (recId.value || "").trim();
    const newPassword = (recPass.value || "").trim();
    if (!userId || !newPassword) { setMsg(recMsg, "Missing fields.", "err"); return; }

    recBtn.disabled = true;
    setMsg(recMsg, "Updating...", "");
    try {
      const { res, json } = await post("/api/recover", { userId, newPassword });
      if (!res.ok || !json.ok) { setMsg(recMsg, json.error || "Recover failed", "err"); return; }
      setMsg(recMsg, "Password updated. Switch to Login.", "ok");
      setTimeout(() => select("login"), 600);
    } catch {
      setMsg(recMsg, "Request failed", "err");
    } finally {
      recBtn.disabled = false;
    }
  });
})();
