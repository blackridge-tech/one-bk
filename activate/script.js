(function(){
  const pin = document.getElementById("pin");
  const go = document.getElementById("go");
  const back = document.getElementById("back");
  const msg = document.getElementById("msg");

  function setMsg(text, kind){
    msg.textContent = text || "";
    msg.className = "msg" + (kind ? (" " + kind) : "");
  }

  back.addEventListener("click", () => location.href = "/");

  async function submit(){
    const pinAttempt = (pin.value || "").trim();
    if (!pinAttempt) { setMsg("Enter PIN.", "err"); return; }

    go.disabled = true;
    pin.disabled = true;
    setMsg("Verifying...", "");

    try {
      const res = await fetch("/api/activate", {
        method: "POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({ pinAttempt })
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || !json || !json.ok) {
        setMsg((json && json.error) ? json.error : "Denied", "err");
        return;
      }
      setMsg("Verified. Redirecting…", "ok");
      setTimeout(() => (location.href = "/divine/"), 250);
    } catch (e) {
      setMsg("Request failed", "err");
    } finally {
      go.disabled = false;
      pin.disabled = false;
    }
  }

  go.addEventListener("click", submit);
  pin.addEventListener("keyup", (e) => { if (e.key === "Enter") submit(); });
})();
