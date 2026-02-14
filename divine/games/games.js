// Divine Games — restyled from GN-Math with permission
const container = document.getElementById('container');
const zoneViewer = document.getElementById('zoneViewer');
let zoneFrame = document.getElementById('zoneFrame');
const searchBar = document.getElementById('searchBar');
const sortOptions = document.getElementById('sortOptions');
const filterOptions = document.getElementById('filterOptions');

const zonesurls = [
  "https://cdn.jsdelivr.net/gh/gn-math/assets@main/zones.json",
  "https://cdn.jsdelivr.net/gh/gn-math/assets@latest/zones.json",
  "https://cdn.jsdelivr.net/gh/gn-math/assets@master/zones.json",
  "https://cdn.jsdelivr.net/gh/gn-math/assets/zones.json"
];
let zonesURL = zonesurls[Math.floor(Math.random() * zonesurls.length)];
const coverURL = "https://cdn.jsdelivr.net/gh/gn-math/covers@main";
const htmlURL = "https://cdn.jsdelivr.net/gh/gn-math/html@main";
let zones = [];
let popularityData = {};
const featuredContainer = document.getElementById('featuredZones');

function toTitleCase(str) {
  return str.replace(/\w\S*/g, t => t.charAt(0).toUpperCase() + t.substring(1).toLowerCase());
}

async function listZones() {
  try {
    let sharesponse;
    try {
      sharesponse = await fetch("https://api.github.com/repos/gn-math/assets/commits?t=" + Date.now());
    } catch (e) {}
    if (sharesponse && sharesponse.status === 200) {
      try {
        const shajson = await sharesponse.json();
        const sha = shajson[0]['sha'];
        if (sha) zonesURL = `https://cdn.jsdelivr.net/gh/gn-math/assets@${sha}/zones.json`;
      } catch (e) {
        try {
          let sec = await fetch("https://raw.githubusercontent.com/gn-math/xml/refs/heads/main/sha.txt?t=" + Date.now());
          if (sec && sec.status === 200) {
            const sha = (await sec.text()).trim();
            if (sha) zonesURL = `https://cdn.jsdelivr.net/gh/gn-math/assets@${sha}/zones.json`;
          }
        } catch (e) {}
      }
    }

    const response = await fetch(zonesURL + "?t=" + Date.now());
    const json = await response.json();
    zones = json;
    zones[0].featured = true;

    await Promise.all([
      fetchPopularity("year"), fetchPopularity("month"),
      fetchPopularity("week"), fetchPopularity("day")
    ]);
    sortZones();

    try {
      const search = new URLSearchParams(window.location.search);
      const id = search.get('id');
      if (id) {
        const zone = zones.find(z => z.id + '' == id + '');
        if (zone) openZone(zone);
      }
    } catch (e) {}

    let alltags = [];
    for (const obj of json) {
      if (Array.isArray(obj.special)) alltags.push(...obj.special);
    }
    alltags = [...new Set(alltags)];
    const filteroption = document.getElementById("filterOptions");
    while (filteroption.children.length > 1) filteroption.removeChild(filteroption.lastElementChild);
    for (const tag of alltags) {
      const opt = document.createElement("option");
      opt.value = tag;
      opt.textContent = toTitleCase(tag);
      filteroption.appendChild(opt);
    }
  } catch (error) {
    console.error(error);
    container.innerHTML = `<p style="color:var(--gold)">Error loading games: ${error}</p>`;
  }
}

async function fetchPopularity(duration) {
  try {
    if (!popularityData[duration]) popularityData[duration] = {};
    const response = await fetch(
      "https://data.jsdelivr.com/v1/stats/packages/gh/gn-math/html@main/files?period=" + duration
    );
    const data = await response.json();
    data.forEach(file => {
      const m = file.name.match(/\/(\d+)\.html$/);
      if (m) popularityData[duration][parseInt(m[1])] = file.hits?.total ?? 0;
    });
  } catch (e) {
    if (!popularityData[duration]) popularityData[duration] = {};
  }
}

function sortZones() {
  const s = sortOptions.value;
  if (s === 'name') zones.sort((a, b) => a.name.localeCompare(b.name));
  else if (s === 'id') zones.sort((a, b) => a.id - b.id);
  else if (s === 'popular') zones.sort((a, b) => (popularityData['year']?.[b.id] ?? 0) - (popularityData['year']?.[a.id] ?? 0));
  else if (s === 'trendingMonth') zones.sort((a, b) => (popularityData['month']?.[b.id] ?? 0) - (popularityData['month']?.[a.id] ?? 0));
  else if (s === 'trendingWeek') zones.sort((a, b) => (popularityData['week']?.[b.id] ?? 0) - (popularityData['week']?.[a.id] ?? 0));
  else if (s === 'trendingDay') zones.sort((a, b) => (popularityData['day']?.[b.id] ?? 0) - (popularityData['day']?.[a.id] ?? 0));
  zones.sort((a, b) => (a.id === -1 ? -1 : b.id === -1 ? 1 : 0));

  if (featuredContainer.innerHTML === "" || featuredContainer.innerHTML === "Loading...") {
    displayFeaturedZones(zones.filter(z => z.featured));
  }
  displayZones(zones);
}

function createZoneCard(file, parentEl) {
  const item = document.createElement("div");
  item.className = "zone-item";
  item.onclick = () => openZone(file);

  const img = document.createElement("img");
  img.dataset.src = file.cover.replace("{COVER_URL}", coverURL).replace("{HTML_URL}", htmlURL);
  img.alt = file.name;
  img.loading = "lazy";
  img.className = "lazy-zone-img";
  item.appendChild(img);

  const btn = document.createElement("button");
  btn.textContent = file.name;
  btn.onclick = (e) => { e.stopPropagation(); openZone(file); };
  item.appendChild(btn);

  parentEl.appendChild(item);
}

function observeLazy(root) {
  const imgs = root.querySelectorAll('img.lazy-zone-img');
  const obs = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const img = entry.target;
        img.src = img.dataset.src;
        img.classList.remove("lazy-zone-img");
        observer.unobserve(img);
      }
    });
  }, { rootMargin: "200px", threshold: 0.1 });
  imgs.forEach(img => obs.observe(img));
}

function displayFeaturedZones(featured) {
  featuredContainer.innerHTML = "";
  featured.forEach(f => createZoneCard(f, featuredContainer));
  if (featuredContainer.innerHTML === "") {
    featuredContainer.innerHTML = "<p style='color:var(--muted)'>No featured games.</p>";
  } else {
    document.getElementById("allZonesSummary").textContent = `Featured Games (${featured.length})`;
  }
  observeLazy(featuredContainer);
}

function displayZones(list) {
  container.innerHTML = "";
  list.forEach(f => createZoneCard(f, container));
  if (container.innerHTML === "") {
    container.innerHTML = "<p style='color:var(--muted)'>No games found.</p>";
  } else {
    document.getElementById("allSummary").textContent = `All Games (${list.length})`;
  }
  observeLazy(container);
}

function filterZones() {
  const q = searchBar.value.toLowerCase();
  const filtered = zones.filter(z => z.name.toLowerCase().includes(q));
  if (q.length) document.getElementById("featuredZonesWrapper").removeAttribute("open");
  displayZones(filtered);
}

function filterZones2() {
  const q = filterOptions.value;
  if (q === "none") { displayZones(zones); return; }
  const filtered = zones.filter(z => z.special?.includes(q));
  document.getElementById("featuredZonesWrapper").removeAttribute("open");
  displayZones(filtered);
}

function openZone(file) {
  if (file.url.startsWith("http")) {
    window.open(file.url, "_blank");
    return;
  }
  const url = file.url.replace("{COVER_URL}", coverURL).replace("{HTML_URL}", htmlURL);
  fetch(url + "?t=" + Date.now()).then(r => r.text()).then(html => {
    if (zoneFrame.contentDocument === null) {
      zoneFrame = document.createElement("iframe");
      zoneFrame.id = "zoneFrame";
      zoneViewer.appendChild(zoneFrame);
    }
    zoneFrame.contentDocument.open();
    zoneFrame.contentDocument.write(html);
    zoneFrame.contentDocument.close();
    document.getElementById('zoneName').textContent = file.name;
    document.getElementById('zoneId').textContent = file.id;
    document.getElementById('zoneAuthor').textContent = "by " + file.author;
    if (file.authorLink) document.getElementById('zoneAuthor').href = file.authorLink;
    zoneViewer.style.display = "flex";
    try {
      const u = new URL(window.location);
      u.searchParams.set('id', file.id);
      history.pushState(null, '', u.toString());
    } catch (e) {}
  }).catch(err => alert("Failed to load game: " + err));
}

function aboutBlank() {
  const win = window.open("about:blank", "_blank");
  const zone = zones.find(z => z.id + '' === document.getElementById('zoneId').textContent);
  if (!zone) return;
  const url = zone.url.replace("{COVER_URL}", coverURL).replace("{HTML_URL}", htmlURL);
  fetch(url + "?t=" + Date.now()).then(r => r.text()).then(html => {
    if (win) { win.document.open(); win.document.write(html); win.document.close(); }
  });
}

function closeZone() {
  zoneViewer.style.display = "none";
  if (zoneFrame && zoneFrame.parentNode) {
    zoneFrame.parentNode.removeChild(zoneFrame);
    zoneFrame = document.createElement("iframe");
    zoneFrame.id = "zoneFrame";
    zoneViewer.appendChild(zoneFrame);
  }
  try {
    const u = new URL(window.location);
    u.searchParams.delete('id');
    history.pushState(null, '', u.toString());
  } catch (e) {}
}

function downloadZone() {
  const zone = zones.find(z => z.id + '' === document.getElementById('zoneId').textContent);
  if (!zone) return;
  fetch(zone.url.replace("{HTML_URL}", htmlURL) + "?t=" + Date.now())
    .then(r => r.text()).then(text => {
      const blob = new Blob([text], { type: "text/html;charset=utf-8" });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = zone.name + ".html";
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
    });
}

function fullscreenZone() {
  const el = zoneFrame;
  if (el.requestFullscreen) el.requestFullscreen();
  else if (el.webkitRequestFullscreen) el.webkitRequestFullscreen();
  else if (el.mozRequestFullScreen) el.mozRequestFullScreen();
  else if (el.msRequestFullscreen) el.msRequestFullscreen();
}

// === Stats ===
let _statsCache = null;
async function getAllStats() {
  if (_statsCache) return _statsCache;
  const BASE = "https://data.jsdelivr.com/v1/stats/packages/gh/gn-math/html@main/files";
  let page = 1, done = false;
  const map = Object.create(null);
  while (!done) {
    const pages = Array.from({ length: 5 }, (_, i) => page + i);
    const responses = await Promise.all(
      pages.map(p => fetch(`${BASE}?period=year&page=${p}&limit=100`).then(r => r.ok ? r.json() : []))
    );
    for (const data of responses) {
      if (!Array.isArray(data) || !data.length) { done = true; break; }
      for (const item of data) {
        if (!item?.name) continue;
        const m = item.name.match(/^\/(\d+)([.-])/);
        if (!m) continue;
        const id = m[1];
        if (!map[id]) map[id] = { hits: 0, bandwidth: 0 };
        map[id].hits += item.hits?.total ?? 0;
        map[id].bandwidth += item.bandwidth?.total ?? 0;
      }
    }
    page += 5;
  }
  _statsCache = map;
  return map;
}

function showZoneInfo() {
  const id = Number(document.getElementById('zoneId').textContent);
  document.getElementById('popupTitle').textContent = "Info";
  const body = document.getElementById('popupBody');
  body.innerHTML = `<p>Loading...</p>`;
  document.getElementById('popupOverlay').style.display = "flex";

  fetch(`https://api.github.com/repos/gn-math/html/commits?path=${id}.html`)
    .then(r => r.json()).then(async json => {
      const stats = (await getAllStats())[id]?.hits ?? 0;
      const info = zones.find(z => z.id === id);
      document.getElementById('popupTitle').textContent = `${info.name} Info`;
      const date = new Date(json.at(-1).commit.author.date);
      const fmt = new Intl.DateTimeFormat("en-US", {
        month: "long", day: "numeric", year: "numeric",
        hour: "numeric", minute: "2-digit", hour12: true
      }).format(date);
      body.innerHTML = `
        <p>
          <b>Id</b>: ${id}<br>
          <b>Name</b>: ${info.name}<br>
          ${info.author ? `<b>Author</b>: ${info.author}<br>` : ""}
          ${info.authorLink ? `<b>Author Link</b>: <a style="color:var(--gold)" href="${info.authorLink}" target="_blank">${info.authorLink}</a><br>` : ""}
          ${info.special ? `<b>Tags</b>: ${info.special}<br>` : ""}
          <b>Added by</b>: ${json.at(-1).commit.author.name}<br>
          <b>Date Added</b>: ${fmt}<br>
          <b>Times Played</b>: ${Number(stats).toLocaleString("en-US")}
        </p>`;
    });
}

// === Settings / Tab Cloak ===
function cloakIcon(url) {
  let link = document.querySelector("link[rel~='icon']");
  if (!link) { link = document.createElement('link'); link.rel = 'icon'; document.head.appendChild(link); }
  link.href = url.trim() || '/favicon.ico';
}
function cloakName(str) {
  document.title = str.trim() || 'Divine Games';
}
function tabCloak() {
  closePopup();
  document.getElementById('popupTitle').textContent = "Tab Cloak";
  document.getElementById('popupBody').innerHTML = `
    <label style="font-weight:700;color:var(--gold)">Tab Title:</label><br>
    <input type="text" placeholder="Enter new tab name..." oninput="cloakName(this.value)">
    <label style="font-weight:700;color:var(--gold)">Tab Icon URL:</label><br>
    <input type="text" placeholder="Enter icon URL..." oninput="cloakIcon(this.value)">
  `;
  document.getElementById('popupOverlay').style.display = "flex";
}

document.getElementById('settings').addEventListener('click', () => {
  document.getElementById('popupTitle').textContent = "Settings";
  document.getElementById('popupBody').innerHTML = `
    <button class="settings-button" onclick="tabCloak()">Tab Cloak</button>
  `;
  document.getElementById('popupOverlay').style.display = "flex";
});

function showContact() {
  document.getElementById('popupTitle').textContent = "Contact";
  document.getElementById('popupBody').innerHTML = `
    <p style="color:var(--text)">Have questions? Reach out!</p>
  `;
  document.getElementById('popupOverlay').style.display = "flex";
}

function closePopup() {
  document.getElementById('popupOverlay').style.display = "none";
}

// === Data Export / Import ===
function sanitizeData(obj, maxStr = 1000, maxArr = 100) {
  if (typeof obj === 'string') return obj.length > maxStr ? obj.slice(0, maxStr) + '...' : obj;
  if (obj instanceof Uint8Array) return obj.length > maxArr ? `[Uint8Array too large]` : obj;
  if (Array.isArray(obj)) return obj.map(i => sanitizeData(i, maxStr, maxArr));
  if (obj && typeof obj === 'object') {
    const o = {};
    for (const k in obj) if (obj.hasOwnProperty(k)) o[k] = sanitizeData(obj[k], maxStr, maxArr);
    return o;
  }
  return obj;
}

async function saveData() {
  alert("Exporting data — please wait...");
  const result = {};
  result.cookies = document.cookie;
  result.localStorage = { ...localStorage };
  result.sessionStorage = { ...sessionStorage };
  result.indexedDB = {};

  const dbs = await indexedDB.databases();
  for (const dbInfo of dbs) {
    if (!dbInfo.name) continue;
    result.indexedDB[dbInfo.name] = {};
    await new Promise((resolve, reject) => {
      const req = indexedDB.open(dbInfo.name, dbInfo.version);
      req.onerror = () => reject(req.error);
      req.onsuccess = () => {
        const db = req.result;
        const stores = Array.from(db.objectStoreNames);
        if (!stores.length) { resolve(); return; }
        const tx = db.transaction(stores, "readonly");
        const ps = stores.map(name => {
          result.indexedDB[dbInfo.name][name] = [];
          const r = tx.objectStore(name).getAll();
          return new Promise((res, rej) => {
            r.onsuccess = () => { result.indexedDB[dbInfo.name][name] = sanitizeData(r.result); res(); };
            r.onerror = () => rej(r.error);
          });
        });
        Promise.all(ps).then(resolve);
      };
    });
  }

  result.caches = {};
  const cacheNames = await caches.keys();
  for (const name of cacheNames) {
    const cache = await caches.open(name);
    const reqs = await cache.keys();
    result.caches[name] = [];
    for (const req of reqs) {
      const resp = await cache.match(req);
      if (!resp) continue;
      const ct = resp.headers.get('content-type') || '';
      let body;
      try {
        if (ct.includes('json')) body = await resp.clone().json();
        else if (ct.includes('text') || ct.includes('javascript')) body = await resp.clone().text();
        else body = btoa(String.fromCharCode(...new Uint8Array(await resp.clone().arrayBuffer())));
      } catch (e) { body = '[unreadable]'; }
      result.caches[name].push({ url: req.url, body, contentType: ct });
    }
  }

  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(result)], { type: "application/octet-stream" }));
  a.download = `divine-games-${Date.now()}.data`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  alert("Export complete!");
}

async function loadData(event) {
  const file = event.target.files[0];
  if (!file) return;
  alert("Importing data — please wait...");
  const reader = new FileReader();
  reader.onload = async (e) => {
    const data = JSON.parse(e.target.result);
    if (data.cookies) data.cookies.split(';').forEach(c => document.cookie = c.trim());
    if (data.localStorage) for (const k in data.localStorage) localStorage.setItem(k, data.localStorage[k]);
    if (data.sessionStorage) for (const k in data.sessionStorage) sessionStorage.setItem(k, data.sessionStorage[k]);
    if (data.indexedDB) {
      for (const dbName in data.indexedDB) {
        const stores = data.indexedDB[dbName];
        await new Promise((resolve, reject) => {
          const req = indexedDB.open(dbName, 1);
          req.onupgradeneeded = e => {
            const db = e.target.result;
            for (const s in stores) if (!db.objectStoreNames.contains(s)) db.createObjectStore(s, { keyPath: 'id', autoIncrement: true });
          };
          req.onsuccess = e => {
            const db = e.target.result;
            const tx = db.transaction(Object.keys(stores), 'readwrite');
            let pending = Object.keys(stores).length;
            for (const s in stores) {
              const os = tx.objectStore(s);
              os.clear().onsuccess = () => {
                for (const item of stores[s]) os.put(item);
                if (--pending === 0) resolve();
              };
            }
          };
          req.onerror = () => reject(req.error);
        });
      }
    }
    if (data.caches) {
      for (const name in data.caches) {
        const cache = await caches.open(name);
        await cache.keys().then(keys => Promise.all(keys.map(k => cache.delete(k))));
        for (const entry of data.caches[name]) {
          let body;
          if (entry.contentType.includes('json')) body = JSON.stringify(entry.body);
          else if (entry.contentType.includes('text') || entry.contentType.includes('javascript')) body = entry.body;
          else {
            const bin = atob(entry.body);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            body = bytes.buffer;
          }
          await cache.put(entry.url, new Response(body, { headers: { 'content-type': entry.contentType } }));
        }
      }
    }
    alert("Data imported!");
  };
  reader.readAsText(file);
}

// === Parallax bg ===
(function () {
  const bg = document.querySelector(".bg");
  if (!bg) return;
  let tx = 0, ty = 0, cx = 0, cy = 0;
  function onMove(e) {
    tx = ((e.clientX / window.innerWidth) - 0.5) * 10;
    ty = ((e.clientY / window.innerHeight) - 0.5) * 10;
  }
  function tick() {
    cx += (tx - cx) * 0.06;
    cy += (ty - cy) * 0.06;
    bg.style.transform = `translate3d(${cx}px,${cy}px,0)`;
    requestAnimationFrame(tick);
  }
  window.addEventListener("mousemove", onMove, { passive: true });
  tick();
})();

// === Init ===
listZones();
