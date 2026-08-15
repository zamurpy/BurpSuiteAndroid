const API = "";

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("panel-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "history") loadHistory();
    if (tab.dataset.tab === "intercept") loadPending();
  });
});

async function refreshStatus() {
  const r = await fetch(API + "/api/proxy/status");
  const s = await r.json();
  document.getElementById("proxyStatusText").textContent =
    `Proxy: ${s.running ? "RUNNING" : "STOPPED"} (${s.host}:${s.port})`;
  const btn = document.getElementById("btnStartStop");
  btn.textContent = s.running ? "STOP" : "START";
  btn.classList.toggle("stop", s.running);
  document.getElementById("interceptToggle").checked = s.intercept;
}

document.getElementById("btnStartStop").addEventListener("click", async () => {
  const running = document.getElementById("btnStartStop").textContent === "STOP";
  await fetch(API + (running ? "/api/proxy/stop" : "/api/proxy/start"), { method: "POST" });
  refreshStatus();
});

document.getElementById("btnCaInfo").addEventListener("click", async () => {
  const r = await fetch(API + "/api/proxy/ca");
  const d = await r.json();
  if (!d.available) {
    alert("Module cryptography belum terinstall, HTTPS intercept tidak aktif.\nInstall: pip install cryptography");
  } else {
    alert("Root CA cert:\n" + d.cert_path +
      "\n\nInstall cert ini sebagai Trusted CA di device/browser yang traffic-nya mau diuji (hanya device milikmu sendiri).");
  }
});

const HISTORY_PAGE_SIZE = 15;
let historyPage = 0; // 0-indexed
let historyHostFilter = "";

async function loadHostFilterOptions() {
  const r = await fetch(API + "/api/history/hosts");
  const hosts = await r.json();
  const select = document.getElementById("historyHostFilter");
  const currentValue = select.value;
  select.innerHTML = '<option value="">Semua Host</option>';
  hosts.forEach(h => {
    const opt = document.createElement("option");
    opt.value = h.host;
    opt.textContent = `${h.host} (${h.count})`;
    select.appendChild(opt);
  });
  select.value = currentValue;
}

document.getElementById("historyHostFilter").addEventListener("change", (e) => {
  historyHostFilter = e.target.value;
  historyPage = 0;
  loadHistory();
});

async function loadHistory() {
  const offset = historyPage * HISTORY_PAGE_SIZE;
  const hostParam = historyHostFilter ? `&host=${encodeURIComponent(historyHostFilter)}` : "";
  const r = await fetch(`${API}/api/history?limit=${HISTORY_PAGE_SIZE}&offset=${offset}${hostParam}`);
  const data = await r.json();
  const rows = data.items;
  const total = data.total;
  const totalPages = Math.max(1, Math.ceil(total / HISTORY_PAGE_SIZE));

  // kalau halaman sekarang jadi kosong (misal abis clear/delete/filter), mundur otomatis
  if (rows.length === 0 && historyPage > 0) {
    historyPage = Math.max(0, totalPages - 1);
    return loadHistory();
  }

  const list = document.getElementById("historyList");
  list.innerHTML = "";
  rows.forEach(row => {
    const div = document.createElement("div");
    div.className = "history-item";
    div.innerHTML = `
      <span class="h-id">#${row.id}</span>
      <span class="h-method">${row.method}</span>
      <span class="h-url">${row.url}</span>
      <span class="h-status">${row.status}</span>
      <span class="h-size">${row.resp_body ? row.resp_body.length : 0}B</span>
    `;
    div.addEventListener("click", () => showHistoryDetail(row.id, div));
    list.appendChild(div);
  });
  if (rows.length === 0) {
    list.innerHTML = '<div class="empty-hint">Belum ada history untuk filter ini.</div>';
  }

  document.getElementById("pageInfo").textContent = `${historyPage + 1} / ${totalPages}`;
  document.getElementById("btnPrevPage").disabled = historyPage <= 0;
  document.getElementById("btnNextPage").disabled = historyPage >= totalPages - 1;

  loadHostFilterOptions();
}

document.getElementById("btnPrevPage").addEventListener("click", () => {
  if (historyPage > 0) { historyPage--; loadHistory(); }
});
document.getElementById("btnNextPage").addEventListener("click", () => {
  historyPage++; loadHistory();
});

let currentDetailTab = "response";

async function showHistoryDetail(id, el) {
  document.querySelectorAll(".history-item").forEach(x => x.classList.remove("selected"));
  el.classList.add("selected");
  const r = await fetch(API + "/api/history/" + id);
  const row = await r.json();
  window._currentDetail = row;
  renderDetail();
}

function renderDetail() {
  const row = window._currentDetail;
  if (!row) return;
  const el = document.getElementById("historyDetail");
  const reqActive = currentDetailTab === "request" ? "active" : "";
  const respActive = currentDetailTab === "response" ? "active" : "";
  const content = currentDetailTab === "request"
    ? (row.req_headers + (row.req_body || ""))
    : (row.resp_headers + "\n" + (row.resp_body || ""));

  el.innerHTML = `
    <div class="detail-tabs">
      <span class="${reqActive}" data-dt="request">REQUEST</span>
      <span class="${respActive}" data-dt="response">RESPONSE</span>
      <span class="link-orange" id="toRepeaterBtn">↺</span>
      <span class="link-orange" id="toIntruderBtn">🐞</span>
    </div>
    <pre class="mono-box response-box">${escapeHtml(content)}</pre>
  `;
  el.querySelectorAll("[data-dt]").forEach(s => {
    s.addEventListener("click", () => { currentDetailTab = s.dataset.dt; renderDetail(); });
  });
  document.getElementById("toRepeaterBtn").addEventListener("click", () => sendToRepeater(row));
  document.getElementById("toIntruderBtn").addEventListener("click", () => sendToIntruder(row));
}

function escapeHtml(s) {
  return (s || "").replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

function sendToRepeater(row) {
  document.querySelector('.tab[data-tab="repeater"]').click();
  document.getElementById("rHost").value = row.host;
  document.getElementById("rPort").value = row.scheme === "https" ? 443 : 80;
  document.getElementById("rTls").checked = row.scheme === "https";
  document.getElementById("repeaterRequest").value = row.req_headers + (row.req_body || "");
}

function sendToIntruder(row) {
  document.querySelector('.tab[data-tab="intruder"]').click();
  document.getElementById("iHost").value = row.host;
  document.getElementById("iPort").value = row.scheme === "https" ? 443 : 80;
  document.getElementById("iTls").checked = row.scheme === "https";
  document.getElementById("intruderTemplate").value = row.req_headers + (row.req_body || "");
}

document.getElementById("interceptToggle").addEventListener("change", async () => {
  await fetch(API + "/api/intercept/toggle", { method: "POST" });
  loadPending();
});

async function loadPending() {
  // Jangan refresh kalau user lagi fokus/edit di salah satu textarea intercept
  const active = document.activeElement;
  const isEditing = active && active.tagName === "TEXTAREA" && active.closest("#interceptBody");
  document.getElementById("pauseHint").style.display = isEditing ? "block" : "none";
  if (isEditing) {
    return;
  }

  const r = await fetch(API + "/api/intercept/pending");
  const items = await r.json();
  const body = document.getElementById("interceptBody");
  if (items.length === 0) {
    body.innerHTML = '<div class="empty-hint">Tidak ada request yang tertahan.</div>';
    return;
  }
  body.innerHTML = "";
  items.forEach(item => {
    const card = document.createElement("div");
    card.className = "intercept-card";
    card.innerHTML = `
      <div class="intercept-card-header">REQUEST TO SERVER</div>
      <div class="intercept-card-body">
        <textarea class="mono-box" rows="10">${escapeHtml(item.raw)}</textarea>
      </div>
      <div class="intercept-actions">
        <span class="repeater-link">↺ To Repeater</span>
        <span class="intruder-link">🐞 To Intruder</span>
      </div>
      <div class="intercept-buttons">
        <button class="btn-drop">DROP</button>
        <button class="btn-forward">FORWARD</button>
      </div>
    `;
    const textarea = card.querySelector("textarea");
    card.querySelector(".btn-drop").addEventListener("click", async () => {
      await fetch(`${API}/api/intercept/${item.id}/drop`, { method: "POST" });
      loadPending();
    });
    card.querySelector(".btn-forward").addEventListener("click", async () => {
      await fetch(`${API}/api/intercept/${item.id}/forward`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw: textarea.value }),
      });
      loadPending();
    });
    card.querySelector(".repeater-link").addEventListener("click", () => {
      document.querySelector('.tab[data-tab="repeater"]').click();
      document.getElementById("rHost").value = item.host;
      document.getElementById("repeaterRequest").value = textarea.value;
    });
    card.querySelector(".intruder-link").addEventListener("click", () => {
      document.querySelector('.tab[data-tab="intruder"]').click();
      document.getElementById("iHost").value = item.host;
      document.getElementById("intruderTemplate").value = textarea.value;
    });
    body.appendChild(card);
  });
}
setInterval(() => {
  if (document.getElementById("panel-intercept").classList.contains("active")) loadPending();
}, 2000);

document.getElementById("btnNewManual").addEventListener("click", () => {
  document.getElementById("rHost").value = "";
  document.getElementById("rPort").value = "80";
  document.getElementById("rTls").checked = false;
  document.getElementById("repeaterRequest").value = "GET / HTTP/1.1\nHost: example.com\n\n";
  document.getElementById("repeaterResponse").textContent = "";
});

document.getElementById("btnSend").addEventListener("click", async () => {
  const host = document.getElementById("rHost").value.trim();
  const port = parseInt(document.getElementById("rPort").value || "80");
  const tls = document.getElementById("rTls").checked;
  const raw = document.getElementById("repeaterRequest").value;
  const out = document.getElementById("repeaterResponse");
  out.textContent = "Mengirim...";
  try {
    const r = await fetch(API + "/api/repeater/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host, port, tls, raw }),
    });
    const d = await r.json();
    if (!d.ok) { out.textContent = "Error: " + d.error; return; }
    out.textContent = `(${d.elapsed_ms} ms)\n\n` + d.response;
  } catch (e) {
    out.textContent = "Error: " + e;
  }
});

document.getElementById("iThreads").addEventListener("input", e => {
  document.getElementById("iThreadsVal").textContent = e.target.value;
});

document.getElementById("btnAttack").addEventListener("click", async () => {
  const host = document.getElementById("iHost").value.trim();
  const port = parseInt(document.getElementById("iPort").value || "80");
  const tls = document.getElementById("iTls").checked;
  const template = document.getElementById("intruderTemplate").value;
  const payloads = document.getElementById("intruderPayloads").value;
  const threads = parseInt(document.getElementById("iThreads").value || "5");

  const tbody = document.getElementById("intruderResults");
  tbody.innerHTML = '<tr><td colspan="5">Menjalankan attack...</td></tr>';

  try {
    const r = await fetch(API + "/api/intruder/attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host, port, tls, template, payloads, threads }),
    });
    const d = await r.json();
    if (!d.ok) { tbody.innerHTML = `<tr><td colspan="5">Error: ${d.error}</td></tr>`; return; }
    tbody.innerHTML = "";
    d.results.forEach((res, i) => {
      const tr = document.createElement("tr");
      const statusClass = res.error ? "status-err" : "status-ok";
      const statusVal = res.error ? "ERR" : res.status;
      tr.innerHTML = `
        <td>${i + 1}</td>
        <td>${escapeHtml(res.payload)}</td>
        <td class="${statusClass}">${statusVal}</td>
        <td>${res.length}</td>
        <td>${res.time_ms}ms</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5">Error: ${e}</td></tr>`;
  }
});

document.querySelectorAll(".btn-pill").forEach(btn => {
  btn.addEventListener("click", async () => {
    const text = document.getElementById("decInput").value;
    const r = await fetch(API + "/api/decoder", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ op: btn.dataset.op, text }),
    });
    const d = await r.json();
    document.getElementById("decOutput").value = d.result;
  });
});

document.getElementById("btnCopyDec").addEventListener("click", () => {
  const out = document.getElementById("decOutput");
  out.select();
  document.execCommand("copy");
});

document.getElementById("btnClearHistory").addEventListener("click", async () => {
  if (!confirm("Hapus semua HTTP history? Tindakan ini tidak bisa dibatalkan.")) return;
  await fetch(API + "/api/history/clear", { method: "POST" });
  window._currentDetail = null;
  historyPage = 0;
  historyHostFilter = "";
  document.getElementById("historyHostFilter").value = "";
  document.getElementById("historyDetail").innerHTML = '<div class="empty-hint">Select an item to view details.</div>';
  loadHistory();
});

refreshStatus();
loadHistory();
setInterval(refreshStatus, 4000);
setInterval(() => {
  if (document.getElementById("panel-history").classList.contains("active") && historyPage === 0) loadHistory();
}, 5000);
