const state = { selected: null, sending: false, view: "monitor" };

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&" + "amp;")
    .replace(/</g, "&" + "lt;")
    .replace(/>/g, "&" + "gt;")
    .replace(/"/g, "&" + "quot;")
    .replace(/'/g, "&#" + "39;");
}

function identity(trap) {
  if (trap.version === "v3") return `${trap.user || "—"} · ${trap.securityLevel || "v3"}`;
  return trap.community || "—";
}

function ago(iso) {
  const then = Date.parse(iso);
  if (!then) return "";
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${iso.slice(11, 19)} UTC`;
}

async function tick() {
  try {
    const response = await fetch("/api/state");
    if (!response.ok) throw new Error("status");
    render(await response.json());
  } catch (_err) {
    const text = document.getElementById("status-text");
    const dot = document.getElementById("status-dot");
    if (text) text.textContent = "Console lost the gateway";
    if (dot) dot.className = "dot bad";
  }
}

function render(data) {
  window.__trapsnmp = data;
  const snmp = data.snmp || {};
  const opc = data.opcua || {};
  const dot = document.getElementById("status-dot");
  const text = document.getElementById("status-text");
  if (snmp.listening && opc.ready) {
    dot.className = "dot live";
    text.textContent = `Listening on UDP ${snmp.port}`;
  } else if (snmp.error || opc.error) {
    dot.className = "dot bad";
    text.textContent = snmp.error || opc.error;
  } else if (snmp.listening) {
    dot.className = "dot";
    text.textContent = `UDP ${snmp.port} is up, OPC UA is still opening`;
  } else {
    dot.className = "dot";
    text.textContent = "Opening the trap receiver";
  }
  const note = document.getElementById("snmp-note");
  const base = "The bench sends a real UDP trap into the same receiver agents use.";
  if (note) note.textContent = snmp.note ? `${base} ${snmp.note}` : base;
  const pathSnmp = document.getElementById("path-snmp");
  const pathOpc = document.getElementById("path-opc");
  if (pathSnmp) pathSnmp.textContent = snmp.listening ? `UDP ${snmp.port}` : "Down";
  if (pathOpc) pathOpc.textContent = opc.ready ? "Publishing" : "Starting";
  document.getElementById("count-traps").textContent = data.counts?.traps ?? 0;
  document.getElementById("count-informs").textContent = data.counts?.informs ?? 0;
  document.getElementById("count-events").textContent = data.counts?.events ?? 0;
  document.getElementById("count-forward").textContent = data.upstream?.forwarded ?? 0;

  const chips = document.getElementById("communities");
  const chipSig = (snmp.communities || []).join("|");
  if (chips.dataset.sig !== chipSig) {
    chips.dataset.sig = chipSig;
    chips.innerHTML = (snmp.communities || []).map((name) => `<span class="chip">${esc(name)}</span>`).join("");
  }
  renderUsers(snmp.users || []);

  document.getElementById("opc-endpoint").textContent = opc.ready ? opc.endpoint : (opc.error || "Starting");
  document.getElementById("opc-ns").textContent = opc.namespace || "urn:trapsnmp:snmp";
  document.getElementById("opc-node").textContent = opc.nodes?.trapOid || "—";
  document.getElementById("opc-object").textContent = opc.nodes?.object || "—";
  document.getElementById("up-status").textContent = data.upstream?.enabled
    ? `${data.upstream.status} · ${data.upstream.forwarded} written`
    : (data.upstream?.status || "Not forwarding");
  document.getElementById("up-status").className = data.upstream?.status && /fail|error|Bad/i.test(data.upstream.status)
    ? "note bad"
    : "note";

  const traps = data.traps || [];
  if (state.selected == null && traps[0]) state.selected = traps[0].id;
  if (state.selected != null && !traps.some((trap) => trap.id === state.selected)) {
    state.selected = traps[0] ? traps[0].id : null;
  }
  const feed = document.getElementById("feed");
  const scroll = feed.scrollTop;
  feed.innerHTML = traps.length
    ? traps.map((trap) => `
        <button type="button" class="trap ${esc(trap.severity)} ${trap.id === state.selected ? "selected" : ""}" data-id="${trap.id}">
          <span class="trap-name">${esc(trap.trapName)}</span>
          <span class="sev ${esc(trap.severity)}">${esc(trap.severity)}</span>
          <span class="trap-meta">${esc(trap.source)} · ${esc(identity(trap))} · ${esc(trap.version)} ${esc(trap.kind)} · ${esc(ago(trap.receivedAt))}</span>
          <span class="trap-oid">${esc(trap.trapOid)}</span>
        </button>
      `).join("")
    : '<p class="empty">No traps yet.</p>';
  feed.scrollTop = scroll;
  renderReadback(data.readback);
  renderDetail(traps.find((trap) => trap.id === state.selected));
  const trace = document.getElementById("trace");
  const lines = data.trace || [];
  trace.innerHTML = lines.length
    ? lines.map((line) => `<li>${esc(line)}</li>`).join("")
    : "<li>The path log fills as traps move from SNMP into OPC UA.</li>";
}

function renderReadback(readback) {
  const host = document.getElementById("readback");
  if (!readback || !readback.ok) {
    host.innerHTML = `<p class="empty">${esc(readback?.error || "Waiting for the OPC UA server.")}</p>`;
    return;
  }
  if (!readback.trapOid) {
    host.innerHTML = '<p class="empty">No value published yet. A client Read of Latest would still succeed, with empty strings.</p>';
    return;
  }
  const rows = [
    ["Trap name", readback.trapName],
    ["Trap OID", readback.trapOid],
    ["Source", readback.source],
    ["Security", readback.version === "v3" ? `${readback.user} · ${readback.securityLevel}` : readback.community],
    ["Version", `${readback.version} ${readback.kind}`],
    ["Severity", `${readback.severity} (${readback.severityCode})`],
    ["Message", readback.message],
    ["Received", readback.receivedAt],
    ["Trap count", readback.trapCount],
  ];
  host.innerHTML = `<dl class="kv">${rows.map(([label, value]) => `<dt>${esc(label)}</dt><dd class="mono">${esc(value)}</dd>`).join("")}</dl>`;
}

function renderDetail(trap) {
  const host = document.getElementById("detail");
  if (!trap) {
    host.innerHTML = '<p class="empty">Choose a trap, or send one from the bench.</p>';
    return;
  }
  const binds = (trap.varbinds || []).map((row) => `
    <tr>
      <td>${esc(row.name)}</td>
      <td class="oid">${esc(row.oid)}</td>
      <td>${esc(row.type)}</td>
      <td>${esc(row.display)}</td>
    </tr>
  `).join("");
  const opc = trap.opcua || {};
  const hop = opc.error
    ? `OPC UA error: ${opc.error}`
    : `${opc.written || 0} nodes written${opc.event ? ", event fired" : ""}${opc.upstream === "ok" ? ", forwarded" : ""}`;
  host.innerHTML = `
    <div class="summary-line">
      <h3>${esc(trap.trapName)}</h3>
      <span class="sev ${esc(trap.severity)}">${esc(trap.severity)} ${esc(trap.severityCode)}</span>
    </div>
    <p class="hint">${esc(trap.message)} · ${esc(hop)}</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>OID</th><th>Type</th><th>Value</th></tr></thead>
        <tbody>${binds}</tbody>
      </table>
    </div>
  `;
}

async function post(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function setBench(message, bad) {
  for (const id of ["flash", "bench-note"]) {
    const note = document.getElementById(id);
    if (!note) continue;
    note.textContent = message || "";
    note.className = id === "flash"
      ? (bad ? "note flash bad" : "note flash")
      : (bad ? "note bad" : "note");
  }
}

function showView(name) {
  state.view = name;
  document.querySelectorAll("[data-view-panel]").forEach((panel) => {
    panel.hidden = panel.getAttribute("data-view-panel") !== name;
  });
  document.querySelectorAll(".nav-btn").forEach((button) => {
    const on = button.dataset.view === name;
    button.classList.toggle("active", on);
    button.setAttribute("aria-selected", on ? "true" : "false");
  });
}

function renderUsers(users) {
  const chips = document.getElementById("users");
  const hint = document.getElementById("user-hint");
  const select = document.getElementById("v3-user");
  const sig = users.map((user) => [user.name, user.level, user.auth, user.priv].join(":")).join("|");
  if (chips.dataset.sig === sig) return;
  chips.dataset.sig = sig;
  chips.innerHTML = users.map((user) => {
    const suite = user.level === "noAuthNoPriv" ? "noAuth" : `${user.auth}/${user.priv}`;
    return `<span class="chip">${esc(user.name)} · ${esc(user.level)} · ${esc(suite)}</span>`;
  }).join("");
  const current = select.value;
  select.innerHTML = users.map((user) => `<option value="${esc(user.name)}">${esc(user.name)}</option>`).join("");
  if ([...select.options].some((option) => option.value === current)) select.value = current;
  const first = users[0];
  if (!first) {
    hint.textContent = "No SNMPv3 user is configured.";
    return;
  }
  if (first.level === "noAuthNoPriv") {
    hint.textContent = `Agents can send v3 traps as ${first.name} with noAuthNoPriv. Any engine ID is accepted.`;
  } else if (first.level === "authNoPriv") {
    hint.textContent = `Agents can send v3 traps as ${first.name}, ${first.auth} passphrase ${first.authKey}. Any engine ID is accepted.`;
  } else {
    hint.textContent = `Agents can send v3 traps as ${first.name}, ${first.auth} passphrase ${first.authKey}, ${first.priv} passphrase ${first.privKey}. Any engine ID is accepted.`;
  }
}

document.getElementById("presets").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-preset]");
  if (!button || state.sending) return;
  state.sending = true;
  button.disabled = true;
  setBench(`Sending ${button.querySelector(".preset-name")?.textContent || "trap"}…`);
  try {
    const data = await post("/api/inject", { preset: button.dataset.preset });
    state.selected = data.trap?.id ?? state.selected;
    setBench(`${data.trap?.trapName || "Trap"} arrived and was published.`);
    showView("monitor");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  } finally {
    state.sending = false;
    button.disabled = false;
  }
});

document.getElementById("feed").addEventListener("click", (event) => {
  const button = event.target.closest("[data-id]");
  if (!button) return;
  state.selected = Number(button.dataset.id);
  if (window.__trapsnmp) render(window.__trapsnmp);
});

document.getElementById("community-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = event.currentTarget.elements.community;
  try {
    await post("/api/community", { community: input.value });
    input.value = "";
    setBench("Community added.");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

function bindRow() {
  const row = document.createElement("div");
  row.className = "bind";
  row.innerHTML = `
    <label class="field"><span>OID</span><input name="oid" spellcheck="false" placeholder="1.3.6.1.2.1.1.5.0" /></label>
    <label class="field"><span>Type</span>
      <select name="type">
        <option value="string">string</option>
        <option value="integer">integer</option>
        <option value="gauge">gauge</option>
        <option value="counter">counter</option>
        <option value="timeticks">timeticks</option>
        <option value="oid">oid</option>
        <option value="ip">ip</option>
      </select>
    </label>
    <label class="field"><span>Value</span><input name="value" placeholder="value" /></label>
    <button type="button" class="ghost remove">Remove</button>
  `;
  row.querySelector(".remove").addEventListener("click", () => row.remove());
  return row;
}

document.getElementById("add-bind").addEventListener("click", () => {
  document.getElementById("binds").appendChild(bindRow());
});

document.getElementById("custom-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.sending) return;
  const form = event.currentTarget;
  const varbinds = [...form.querySelectorAll(".bind")].map((row) => ({
    oid: row.querySelector('[name="oid"]').value.trim(),
    type: row.querySelector('[name="type"]').value,
    value: row.querySelector('[name="value"]').value,
  })).filter((row) => row.oid || row.value);
  state.sending = true;
  setBench("Sending custom trap…");
  try {
    const data = await post("/api/inject", {
      community: form.elements.community.value,
      version: form.elements.version.value,
      trapOid: form.elements.trapOid.value.trim(),
      varbinds,
      user: form.elements.version.value === "3" ? form.elements.user.value : "",
    });
    state.selected = data.trap?.id ?? state.selected;
    setBench(`${data.trap?.trapName || "Trap"} arrived and was published.`);
    showView("monitor");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  } finally {
    state.sending = false;
  }
});

document.getElementById("use-inbox").addEventListener("click", () => {
  const data = window.__trapsnmp;
  if (!data?.opcua) return;
  document.getElementById("up-endpoint").value = data.opcua.endpoint || "";
  document.getElementById("up-node").value = data.opcua.nodes?.inbox || "";
});

document.getElementById("forward-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await post("/api/upstream", {
      enabled: true,
      endpoint: document.getElementById("up-endpoint").value.trim(),
      nodeId: document.getElementById("up-node").value.trim(),
    });
    await tick();
  } catch (err) {
    const note = document.getElementById("up-status");
    note.textContent = err.message;
    note.className = "note bad";
  }
});

document.getElementById("stop-forward").addEventListener("click", async () => {
  try {
    await post("/api/upstream", {
      enabled: false,
      endpoint: document.getElementById("up-endpoint").value.trim(),
      nodeId: document.getElementById("up-node").value.trim(),
    });
    await tick();
  } catch (err) {
    const note = document.getElementById("up-status");
    note.textContent = err.message;
    note.className = "note bad";
  }
});

document.getElementById("version").addEventListener("change", (event) => {
  const v3 = event.target.value === "3";
  document.getElementById("community-field").hidden = v3;
  document.getElementById("user-field").hidden = !v3;
});

document.getElementById("user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    await post("/api/user", {
      name: form.elements.name.value,
      level: form.elements.level.value,
      auth: form.elements.auth.value,
      authKey: form.elements.authKey.value,
      priv: form.elements.priv.value,
      privKey: form.elements.privKey.value,
    });
    form.elements.name.value = "";
    form.elements.authKey.value = "";
    form.elements.privKey.value = "";
    setBench("SNMPv3 user added.");
    await tick();
  } catch (err) {
    setBench(err.message, true);
  }
});

function syncUserFields() {
  const level = document.getElementById("user-level").value;
  document.getElementById("auth-fields").hidden = level === "noAuthNoPriv";
  document.getElementById("priv-fields").hidden = level !== "authPriv";
}

document.getElementById("user-level").addEventListener("change", syncUserFields);

document.querySelector(".nav").addEventListener("click", (event) => {
  const button = event.target.closest("[data-view]");
  if (!button) return;
  showView(button.dataset.view);
});

const initial = (location.hash || "").replace("#", "");
if (["monitor", "send", "access", "publish"].includes(initial)) showView(initial);

tick();
setInterval(tick, 1000);
