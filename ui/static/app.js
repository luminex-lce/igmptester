"use strict";

// ====================================================================== helpers
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-IGMP-UI": "1" },
    body: JSON.stringify(body),
  };
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) {
    const err = new Error(data.error || `${res.status} ${res.statusText}`);
    err.data = data;
    throw err;
  }
  return data;
}

let toastTimer;
function toast(message, isError = false) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.toggle("error", isError);
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), isError ? 6000 : 3000);
}

function fmtDuration(seconds) {
  if (seconds == null) return "";
  seconds = Math.max(0, seconds);
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  const m = Math.floor(seconds / 60), s = Math.floor(seconds % 60);
  if (m < 60) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

function fmtRunId(id) {
  const m = /^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/.exec(id || "");
  return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]}` : id;
}

const FINAL = new Set(["passed", "failed", "error", "skipped", "stopped", "not run", "not found"]);
const statusClass = s => "s-" + String(s).replace(/\s+/g, "-");

function fileUrl(runId, name, download) {
  const path = [runId, name].map(encodeURIComponent).join("/");
  return `/files/${path}${download ? "?download" : ""}`;
}

async function openPath(path, reveal = false) {
  try {
    const res = await api("/api/open", { path, reveal });
    toast(`Opened ${res.path}`);
  } catch (e) {
    toast(e.message, true);
  }
}

// ====================================================================== tabs
function showView(name) {
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.view === name));
  $$(".view").forEach(v => v.classList.toggle("hidden", v.id !== `view-${name}`));
  if (name === "config") loadConfig();
}
$$(".tab").forEach(t => t.addEventListener("click", () => showView(t.dataset.view)));
document.addEventListener("click", e => {
  const goto = e.target.closest("[data-goto]");
  if (goto) { e.preventDefault(); showView(goto.dataset.goto); }
});

// ====================================================================== state
const S = {
  tests: [],
  selection: null,          // Set of node ids
  view: null,               // run currently displayed
  liveId: null,             // id of the run being polled
  logNext: 0,
  open: new Set(),          // expanded result rows
  resultsSig: "",
  pollTimer: null,
  lastPromptId: null,
  config: null,             // {settings, values, errors}
  interfaces: null,
  configIface: null,
};

// ====================================================================== test list
async function loadTests(refresh = false) {
  const tree = $("#test-tree");
  tree.innerHTML = `<p class="muted">${refresh ? "Reloading" : "Loading"} tests…</p>`;
  try {
    const data = await api("/api/tests" + (refresh ? "?refresh" : ""));
    S.tests = data.tests || [];
    if (data.error) {
      tree.innerHTML = `<p class="muted">pytest could not collect the tests:</p><pre class="error-box">${esc(data.error)}</pre>`;
      if (!S.tests.length) { updateStart(); return; }
    }
    const saved = JSON.parse(localStorage.getItem("igmp-selection") || "null");
    const ids = new Set(S.tests.map(t => t.nodeid));
    if (S.selection === null) {
      S.selection = saved ? new Set(saved.filter(id => ids.has(id))) : new Set(ids);
      if (saved && !S.selection.size) S.selection = new Set(ids);
    } else {
      S.selection = new Set([...S.selection].filter(id => ids.has(id)));
    }
    renderTree(data.error);
  } catch (e) {
    tree.innerHTML = `<pre class="error-box">${esc(e.message)}</pre>`;
  }
  updateStart();
}

const SUITE_INFO = {
  "test_configuration.py": { title: "Configuration check" },
  "test_igmp.py": { title: "IGMPv2" },
  "test_igmp_v3.py": { title: "IGMPv3" },
  "test_igmp_manual.py": { title: "Manual tests", tag: "operator needed" },
  "test_pcap.py": { title: "Capture file analysis", tag: "needs PCAP_FILE" },
};

function suites() {
  const groups = new Map();
  for (const t of S.tests) {
    if (!groups.has(t.file)) groups.set(t.file, []);
    groups.get(t.file).push(t);
  }
  return groups;
}

function renderTree(error) {
  const tree = $("#test-tree");
  let html = error ? `<pre class="error-box">${esc(error)}</pre>` : "";
  for (const [file, tests] of suites()) {
    const base = file.split("/").pop();
    const info = SUITE_INFO[base] || { title: base };
    const selected = tests.filter(t => S.selection.has(t.nodeid)).length;
    html += `<div class="suite" data-file="${esc(file)}">
      <label class="suite-head">
        <input type="checkbox" class="suite-cb" ${selected === tests.length ? "checked" : ""}
               data-indeterminate="${selected > 0 && selected < tests.length}">
        ${esc(info.title)}${info.tag ? `<span class="tag">${esc(info.tag)}</span>` : ""}
        <span class="count">${selected}/${tests.length}</span>
      </label>
      ${tests.map(t => `
        <label class="test-item" title="${esc((t.summary + "\n\n" + t.details).trim())}">
          <input type="checkbox" class="test-cb" value="${esc(t.nodeid)}" ${S.selection.has(t.nodeid) ? "checked" : ""}>
          <div><div class="t-name">${esc(t.name)}</div>${t.summary ? `<div class="t-sum">${esc(t.summary)}</div>` : ""}</div>
        </label>`).join("")}
    </div>`;
  }
  tree.innerHTML = html || `<p class="muted">No tests found.</p>`;
  $$(".suite-cb", tree).forEach(cb => { cb.indeterminate = cb.dataset.indeterminate === "true"; });
}

$("#test-tree").addEventListener("change", e => {
  if (e.target.classList.contains("test-cb")) {
    e.target.checked ? S.selection.add(e.target.value) : S.selection.delete(e.target.value);
  } else if (e.target.classList.contains("suite-cb")) {
    const file = e.target.closest(".suite").dataset.file;
    for (const t of S.tests.filter(t => t.file === file)) {
      e.target.checked ? S.selection.add(t.nodeid) : S.selection.delete(t.nodeid);
    }
  } else return;
  saveSelection();
  renderTree();
  updateStart();
});

function saveSelection() {
  localStorage.setItem("igmp-selection", JSON.stringify([...S.selection]));
}

$("#sel-all").addEventListener("click", () => {
  S.selection = new Set(S.tests.map(t => t.nodeid)); saveSelection(); renderTree(); updateStart();
});
$("#sel-none").addEventListener("click", () => {
  S.selection = new Set(); saveSelection(); renderTree(); updateStart();
});
$("#refresh-tests").addEventListener("click", () => loadTests(true));

function isRunning() {
  return S.view && S.view.id === S.liveId && ["starting", "running"].includes(S.view.status);
}

function updateStart() {
  const n = S.selection ? S.selection.size : 0;
  $("#sel-count").textContent = S.tests.length ? `${n} of ${S.tests.length} selected` : "";
  $("#start-btn").disabled = !n || isRunning();
  $("#start-btn").textContent = isRunning() ? "Test running…" : "▶ Start test";
}

$("#start-btn").addEventListener("click", async () => {
  const ordered = S.tests.map(t => t.nodeid).filter(id => S.selection.has(id));
  $("#start-btn").disabled = true;
  try {
    const data = await api("/api/run", { tests: ordered });
    S.liveId = data.run.id;
    S.logNext = 0;
    S.open.clear();
    document.title = "IGMP Tester";
    $("#console").textContent = "";
    showRun(data.run);
    poll();
  } catch (e) {
    toast(e.message, true);
    updateStart();
  }
});

// ====================================================================== live run
async function poll() {
  clearTimeout(S.pollTimer);
  try {
    const data = await api(`/api/run?log_from=${S.logNext}`);
    const run = data.run;
    if (!run || run.id !== S.liveId) return;
    appendLog(run.log || []);
    S.logNext = run.log_next;
    const watching = !S.view || S.view.id === run.id;
    if (watching) showRun(run);
    handlePrompt(run);
    if (["starting", "running"].includes(run.status)) {
      S.pollTimer = setTimeout(poll, 1000);
    } else {
      onRunFinished(run);
    }
  } catch (e) {
    S.pollTimer = setTimeout(poll, 3000);
  }
  updateStart();
}

function onRunFinished(run) {
  loadHistory();
  updateStart();
  const c = run.counts || {};
  const failed = (c.failed || 0) + (c.error || 0);
  document.title = failed ? `✗ ${failed} failed – IGMP Tester` : "✓ Done – IGMP Tester";
  toast(run.status === "stopped" ? "Test run stopped" :
        failed ? `Test run finished: ${failed} failed` : "Test run finished");
  notify(failed ? `${failed} test(s) failed` : "All tests passed", "Test run finished");
}

function appendLog(lines) {
  if (!lines.length) return;
  const el = $("#console");
  const frag = document.createDocumentFragment();
  for (const line of lines) {
    const span = document.createElement("span");
    if (/ PASSED|passed/.test(line) && !/failed/.test(line)) span.className = "l-pass";
    else if (/FAILED|ERROR|Error|failed/.test(line)) span.className = "l-fail";
    else if (/SKIPPED|skipped/.test(line)) span.className = "l-skip";
    else if (/^\[(igmp-ui|waiting|operator)/.test(line) || line.startsWith("$ ")) span.className = "l-ui";
    span.textContent = line + "\n";
    frag.appendChild(span);
  }
  el.appendChild(frag);
  if ($("#autoscroll").checked) el.scrollTop = el.scrollHeight;
}

// ====================================================================== prompt
function handlePrompt(run) {
  const overlay = $("#prompt-overlay");
  if (!run.prompt) { overlay.classList.add("hidden"); return; }
  $("#prompt-text").textContent = run.prompt.text || "Press continue when ready.";
  $("#prompt-test").textContent = run.prompt.nodeid || "";
  overlay.dataset.id = run.prompt.id;
  overlay.classList.remove("hidden");
  if (S.lastPromptId !== `${run.id}/${run.prompt.id}`) {
    S.lastPromptId = `${run.id}/${run.prompt.id}`;
    beep();
    notify(run.prompt.text, "IGMP Tester – action required");
    $("#prompt-continue").focus();
  }
}

$("#prompt-continue").addEventListener("click", async () => {
  const overlay = $("#prompt-overlay");
  overlay.classList.add("hidden");
  try {
    await api("/api/run/prompt", { id: Number(overlay.dataset.id) });
  } catch (e) { toast(e.message, true); }
});
$("#prompt-stop").addEventListener("click", () => { $("#prompt-overlay").classList.add("hidden"); stopRun(); });

function beep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.frequency.value = 880; g.gain.value = 0.08;
    o.connect(g); g.connect(ctx.destination);
    o.start(); o.stop(ctx.currentTime + 0.25);
  } catch (_) { /* audio not available */ }
}

function notify(body, title) {
  if (!("Notification" in window) || document.hasFocus()) return;
  if (Notification.permission === "granted") new Notification(title, { body });
}

// ====================================================================== stop
async function stopRun() {
  if (!confirm("Stop the running test? The current test will be aborted.")) return;
  try { await api("/api/run/stop", {}); toast("Stopping…"); } catch (e) { toast(e.message, true); }
}
$("#stop-btn").addEventListener("click", stopRun);

// ====================================================================== run display
function showRun(run) {
  const firstShow = !S.view || S.view.id !== run.id;
  S.view = run;
  if (firstShow) S.resultsSig = "";
  $("#empty-state").classList.add("hidden");
  $("#run-panel").classList.remove("hidden");
  $$("#history .run-item").forEach(li => li.classList.toggle("selected", li.dataset.id === run.id));

  const running = ["starting", "running"].includes(run.status);
  const tests = run.tests || [];
  const total = tests.length;
  const done = tests.filter(t => FINAL.has(t.status)).length;
  const c = run.counts || {};
  const failed = (c.failed || 0) + (c.error || 0);

  let label = run.status;
  let cls = statusClass(run.status);
  if (run.status === "finished") { label = failed ? "failed" : "passed"; cls = failed ? "s-failed" : "s-passed"; }
  const pill = $("#run-status");
  pill.className = `status-pill ${cls}`;
  pill.textContent = label;
  $("#run-name").textContent = `Run ${fmtRunId(run.id)}`;
  $("#stop-btn").classList.toggle("hidden", !running || run.id !== S.liveId);

  const cur = tests.find(t => t.nodeid === run.current);
  const curFraction = running && cur ? testFraction(cur.progress) : null;

  const bar = $("#progress-bar");
  bar.style.width = total ? `${((done + (curFraction || 0)) / total) * 100}%` : "0";
  bar.classList.toggle("indeterminate", running && !done && !run.current);
  bar.classList.toggle("done-pass", !running && !failed);
  bar.classList.toggle("done-fail", !running && failed > 0);
  $("#progress-text").textContent = total ? `${done} of ${total} tests done` : "Collecting tests…";
  const end = run.ended || Date.now() / 1000;
  $("#elapsed").textContent = `${running ? "Elapsed" : "Duration"}: ${fmtDuration(end - run.started)}`;

  const ct = $("#current-test");
  if (running && cur) {
    ct.classList.remove("hidden");
    const idx = tests.indexOf(cur) + 1;
    ct.innerHTML = `<div class="ct-name"><span class="spinner"></span>${esc(cur.name)}
        <span class="muted small">(${idx}/${total}, running ${fmtDuration(Date.now() / 1000 - cur.started)})</span></div>
      ${cur.summary ? `<div class="ct-sum">${esc(cur.summary)}</div>` : ""}
      ${testProgressHtml(cur.progress)}`;
  } else if (running) {
    ct.classList.remove("hidden");
    ct.innerHTML = `<div class="ct-name"><span class="spinner"></span>Starting pytest…</div>`;
  } else {
    ct.classList.add("hidden");
  }

  const order = ["passed", "failed", "error", "skipped", "running", "pending", "stopped", "not run", "not found"];
  $("#counts").innerHTML = order.filter(k => c[k]).map(k =>
    `<span class="count-chip ${statusClass(k)}">${c[k]} ${esc(k)}</span>`).join("");

  const links = [];
  if (!running) {
    if (run.has_junit) links.push(`<a href="${fileUrl(run.id, "result.junit")}" target="_blank">JUnit report</a>`);
    links.push(`<a href="${fileUrl(run.id, "console.log")}" target="_blank">Console log</a>`);
  }
  links.push(`<span class="muted">Folder: <code>${esc(run.dir || "output/" + run.id)}</code></span>`);
  $("#run-links").innerHTML = links.join("");

  const ce = $("#collect-errors");
  ce.classList.toggle("hidden", !(run.collect_errors || []).length);
  ce.textContent = (run.collect_errors || []).join("\n\n");

  renderResults(run);
}

// Progress inside a long test, reported by src/lib/progress.py. Each step has an
// expected duration, so the bar moves with time inside a step and stays just short
// of its end until the test reports the next step.
function testProgressState(p) {
  if (!p || !p.total_seconds) return null;
  const inStep = Math.min(p.step_seconds, Math.max(0, Date.now() / 1000 - p.time));
  const fraction = Math.min(0.99, (p.done_seconds + inStep) / p.total_seconds);
  const remaining = Math.max(0, p.total_seconds - p.done_seconds - inStep);
  return { fraction, remaining, stepLeft: Math.max(0, p.step_seconds - inStep) };
}

function testFraction(p) {
  const st = testProgressState(p);
  return st ? st.fraction : null;
}

function testProgressHtml(p) {
  const st = testProgressState(p);
  if (!st) return "";
  const pct = Math.floor(st.fraction * 100);
  const step = p.steps > 1 ? `Step ${p.index} of ${p.steps}: ` : "";
  const left = st.remaining >= 1 ? `about ${fmtDuration(st.remaining)} left` : "finishing…";
  return `<div class="tp"><div class="tp-bar" style="width:${st.fraction * 100}%"></div></div>
    <div class="tp-meta">
      <span>${esc(step + p.label)}${st.stepLeft >= 1 ? ` <span class="muted">(${fmtDuration(st.stepLeft)})</span>` : ""}</span>
      <span>${pct}% · ${left}</span>
    </div>`;
}

function renderResults(run) {
  const tests = run.tests || [];
  const onlyProblems = $("#only-problems").checked;
  const sig = JSON.stringify([onlyProblems, [...S.open], tests.map(t => [t.status, t.duration, t.pcaps.length])]);
  if (sig === S.resultsSig) return;
  S.resultsSig = sig;

  const shown = tests.filter(t => !onlyProblems || ["failed", "error"].includes(t.status));
  const el = $("#results");
  if (!shown.length) {
    el.innerHTML = `<p class="muted">${onlyProblems ? "No failures." : "No tests yet."}</p>`;
    return;
  }
  el.innerHTML = shown.map(t => {
    const isOpen = S.open.has(t.nodeid);
    const msgCls = t.status === "skipped" ? "r-msg skip" : "r-msg";
    const statusLabel = t.status === "running" ? `<span class="spinner"></span>running` : esc(t.status);
    return `<div class="result ${isOpen ? "open" : ""}" data-id="${esc(t.nodeid)}">
      <div class="result-row">
        <span class="status-pill ${statusClass(t.status)}">${statusLabel}</span>
        <div>
          <div class="r-name">${esc(t.name)}</div>
          <div class="r-file">${esc(t.file)}${t.summary ? " – " + esc(t.summary) : ""}</div>
          ${t.message ? `<div class="${msgCls}">${esc(t.message.split("\n")[0])}</div>` : ""}
        </div>
        <span class="r-pcap">${t.pcaps.length ? `📄 ${t.pcaps.length} capture${t.pcaps.length > 1 ? "s" : ""}` : ""}</span>
        <span class="r-dur">${fmtDuration(t.duration)}</span>
      </div>
      <div class="result-detail">${isOpen ? resultDetail(run, t) : ""}</div>
    </div>`;
  }).join("");
}

function resultDetail(run, t) {
  let html = "";
  if (t.summary || t.details) {
    html += `<h3>About this test</h3><p>${esc(t.summary)}${t.details ? "\n" + esc(t.details) : ""}</p>`;
  }
  if (t.pcaps.length) {
    html += `<h3>Captures</h3><ul class="pcap-list">${t.pcaps.map(p => `
      <li><span class="p-name">${esc(p)}</span>
        <button class="btn sm" data-open="${esc(run.id + "/" + p)}" title="Open with the default application, e.g. Wireshark">Open</button>
        <button class="btn sm" data-reveal="${esc(run.id + "/" + p)}">Show in folder</button>
        <a class="btn sm" href="${fileUrl(run.id, p, true)}">Download</a>
      </li>`).join("")}</ul>`;
  }
  if (t.warnings && t.warnings.length) {
    html += `<h3>Warnings</h3>${t.warnings.map(w => `<div class="warn">${esc(w)}</div>`).join("")}`;
  }
  if (t.longrepr) html += `<h3>Failure</h3><pre class="fail">${esc(t.longrepr)}</pre>`;
  else if (t.message && t.status === "skipped") html += `<h3>Skip reason</h3><p>${esc(t.message)}</p>`;
  else if (t.message) html += `<h3>Message</h3><p>${esc(t.message)}</p>`;
  if (t.output) html += `<h3>Output</h3><pre>${esc(t.output)}</pre>`;
  if (!html) html = `<p class="muted">${t.status === "running" ? "Test is running…" : "No details."}</p>`;
  return html;
}

$("#results").addEventListener("click", e => {
  const openBtn = e.target.closest("[data-open]");
  const revealBtn = e.target.closest("[data-reveal]");
  if (openBtn) return openPath(openBtn.dataset.open);
  if (revealBtn) return openPath(revealBtn.dataset.reveal, true);
  const row = e.target.closest(".result-row");
  if (!row) return;
  const id = row.parentElement.dataset.id;
  S.open.has(id) ? S.open.delete(id) : S.open.add(id);
  S.resultsSig = "";
  renderResults(S.view);
});
$("#only-problems").addEventListener("change", () => { S.resultsSig = ""; renderResults(S.view); });
$("#open-run-dir").addEventListener("click", () => S.view && openPath(S.view.id));
$("#open-output").addEventListener("click", () => openPath(""));

// ====================================================================== history
async function loadHistory() {
  try {
    const { runs } = await api("/api/runs");
    const el = $("#history");
    if (!runs.length) { el.innerHTML = `<li class="muted">No runs yet</li>`; return; }
    el.innerHTML = runs.map(r => {
      const c = r.counts || {};
      const failed = (c.failed || 0) + (c.error || 0);
      const icon = r.status === "stopped" ? "⏹" : r.status === "error" ? "⚠" : failed ? "✗" : "✓";
      const color = failed || r.status === "error" ? "var(--fail)" : r.status === "stopped" ? "var(--skip)" : "var(--pass)";
      return `<li class="run-item ${S.view && S.view.id === r.id ? "selected" : ""}" data-id="${esc(r.id)}">
        <span style="color:${color}">${icon}</span>
        <span class="h-name">${esc(fmtRunId(r.id))}</span>
        <span class="h-counts muted">${c.passed || 0} ✓ · ${failed} ✗${c.skipped ? ` · ${c.skipped} skip` : ""}</span>
      </li>`;
    }).join("");
  } catch (_) { /* ignore */ }
}

$("#history").addEventListener("click", async e => {
  const li = e.target.closest(".run-item");
  if (!li) return;
  const id = li.dataset.id;
  if (id === S.liveId && S.view && S.view.id === id) return;
  try {
    const { run } = await api(`/api/runs/${encodeURIComponent(id)}`);
    S.open.clear();
    showRun(run);
    const consoleEl = $("#console");
    consoleEl.textContent = "";
    if (id === S.liveId) {
      // back to the live run: reload the whole console
      S.logNext = 0;
      poll();
    } else {
      try {
        const text = await (await fetch(fileUrl(id, "console.log"))).text();
        appendLog(text.split("\n"));
      } catch (_) { /* no console log */ }
    }
  } catch (e2) { toast(e2.message, true); }
});

// ====================================================================== configuration
const GROUP_ORDER = ["Network", "Test selection", "Limits and timing", "Offline analysis", "Other"];

async function loadConfig(force = false) {
  if (S.config && S.config.dirty && !force) return;  // don't throw away edits
  const form = $("#config-form");
  try {
    const [cfg, ifaces, caps] = await Promise.all([
      api("/api/config"), api("/api/interfaces"), api("/api/captures"),
    ]);
    S.interfaces = ifaces.interfaces;
    S.captures = caps.captures;
    $("#config-path").textContent = cfg.path;
    setConfig(cfg.settings);
  } catch (e) {
    form.innerHTML = `<pre class="error-box">${esc(e.message)}</pre>`;
  }
}

function setConfig(settings) {
  S.config = {
    settings,
    original: Object.fromEntries(settings.map(s => [s.name, s.value])),
    values: Object.fromEntries(settings.map(s => [s.name, s.value])),
    errors: {},
    dirty: false,
  };
  S.configIface = S.config.original.IFACE;
  renderConfig();
  updateIfaceChip();
}

function renderConfig() {
  const groups = new Map(GROUP_ORDER.map(g => [g, []]));
  for (const s of S.config.settings) {
    if (!groups.has(s.group)) groups.set(s.group, []);
    groups.get(s.group).push(s);
  }
  $("#config-form").innerHTML = [...groups].filter(([, list]) => list.length).map(([group, list]) =>
    `<section class="card group"><h2>${esc(group)}</h2>${list.map(fieldHtml).join("")}</section>`).join("");
  $$(".f-help").forEach(h => {
    if (h.scrollHeight > h.clientHeight + 4) {
      const more = document.createElement("button");
      more.className = "link-btn f-more"; more.textContent = "Show more"; more.type = "button";
      more.onclick = () => { const c = h.classList.toggle("clamped"); more.textContent = c ? "Show more" : "Show less"; };
      h.after(more);
    } else h.classList.remove("clamped");
  });
  updateConfigState();
}

function fieldHtml(s) {
  const v = S.config.values[s.name];
  const id = `f-${s.name}`;
  let control = "";
  switch (s.kind) {
    case "bool":
      control = `<label class="switch"><input type="checkbox" id="${id}" data-name="${s.name}" ${v ? "checked" : ""}>
        <span class="track"></span><span>${v ? "Yes" : "No"}</span></label>`;
      break;
    case "int": case "float":
      control = `<div class="f-row"><input type="number" id="${id}" data-name="${s.name}" value="${esc(v)}"
        ${s.min != null ? `min="${s.min}"` : ""} ${s.max != null ? `max="${s.max}"` : ""} step="${s.kind === "int" ? 1 : "any"}">
        ${s.unit ? `<span class="muted">${esc(s.unit)}</span>` : ""}
        ${s.min != null || s.max != null ? `<span class="muted small">${s.min ?? "…"} – ${s.max ?? "…"}</span>` : ""}</div>`;
      break;
    case "multicast":
      control = `<input type="text" id="${id}" data-name="${s.name}" value="${esc(v)}" placeholder="239.255.0.1" spellcheck="false">
        ${s.presets ? `<div class="f-row">${s.presets.map(p =>
          `<button type="button" class="preset" data-name="${s.name}" data-value="${esc(p.value)}">${esc(p.label)} · ${esc(p.value)}</button>`).join("")}</div>` : ""}`;
      break;
    case "interface":
      control = interfaceControl(s, v, id);
      break;
    case "pcap": {
      const on = v !== false && v !== null && v !== "";
      control = `<label class="switch"><input type="checkbox" class="pcap-toggle" data-name="${s.name}" ${on ? "checked" : ""}>
          <span class="track"></span><span>${on ? "Enabled" : "Disabled (tests run live against the device)"}</span></label>
        ${on ? `<input type="text" id="${id}" data-name="${s.name}" value="${esc(v)}" list="pcap-files" placeholder="output/my_capture.pcapng" spellcheck="false">
        <datalist id="pcap-files">${(S.captures || []).map(c => `<option value="${esc(c)}">`).join("")}</datalist>
        <span class="muted small">Path relative to the project folder. Run the "Capture file analysis" tests to analyse it.</span>` : ""}`;
      break;
    }
    default:
      control = `<input type="text" id="${id}" data-name="${s.name}" value="${esc(v)}" spellcheck="false">`;
  }
  const err = S.config.errors[s.name];
  const changed = JSON.stringify(v) !== JSON.stringify(S.config.original[s.name]);
  return `<div class="field ${err ? "invalid" : ""} ${changed ? "changed" : ""}" data-field="${s.name}">
    <div>
      <label class="f-label" for="${id}">${esc(s.label)}</label>
      <div class="f-var">${esc(s.name)}</div>
    </div>
    <div class="f-control">
      ${control}
      ${err ? `<div class="f-error">${esc(err)}</div>` : ""}
      ${s.help ? `<div class="f-help clamped">${esc(s.help)}</div>` : ""}
    </div>
  </div>`;
}

function interfaceControl(s, v, id) {
  if (!S.interfaces) {
    return `<input type="text" id="${id}" data-name="${s.name}" value="${esc(v)}" spellcheck="false">
      <span class="muted small">Install psutil to get a list of interfaces.</span>`;
  }
  const known = S.interfaces.some(i => i.name === v);
  const opts = S.interfaces.map(i => `
    <div class="iface-opt ${i.name === v ? "selected" : ""}" data-iface="${esc(i.name)}" tabindex="0">
      <input type="radio" name="iface" ${i.name === v ? "checked" : ""} tabindex="-1">
      <div>
        <div class="i-name">${esc(i.name)}</div>
        <div class="i-meta">${esc([i.ipv4.join(", "), i.mac].filter(Boolean).join(" · ") || "no address")}${i.speed ? ` · ${i.speed} Mb/s` : ""}</div>
      </div>
      <span class="i-state ${i.up ? "up" : "down"}">${i.up ? "LINK UP" : "DOWN"}</span>
    </div>`).join("");
  return `<div class="iface-list">${opts}</div>
    <div class="f-row"><span class="muted small">Or type a name:</span>
      <input type="text" id="${id}" data-name="${s.name}" value="${esc(v)}" spellcheck="false" style="max-width:260px">
      <button type="button" class="link-btn" id="reload-ifaces">Reload list</button></div>
    ${!known && v ? `<span class="f-error">“${esc(v)}” is not one of this computer's interfaces.</span>` : ""}`;
}

function setValue(name, value, rerender = true) {
  S.config.values[name] = value;
  delete S.config.errors[name];
  if (rerender) {
    const y = window.scrollY;
    renderConfig();
    window.scrollTo(0, y);
  } else {
    const field = $(`[data-field="${name}"]`);
    const changed = JSON.stringify(value) !== JSON.stringify(S.config.original[name]);
    field.classList.toggle("changed", changed);
    field.classList.remove("invalid");
    const errEl = $(".f-error", field);
    if (errEl && !errEl.textContent.includes("not one of")) errEl.remove();
    updateConfigState();
  }
}

function updateConfigState() {
  const dirty = Object.keys(S.config.values).some(k =>
    JSON.stringify(S.config.values[k]) !== JSON.stringify(S.config.original[k]));
  S.config.dirty = dirty;
  $("#config-save").disabled = !dirty;
  $("#config-revert").disabled = !dirty;
  $("#config-dirty").classList.toggle("hidden", !dirty);
}

const form = $("#config-form");
form.addEventListener("change", e => {
  const t = e.target, name = t.dataset.name;
  if (!name) return;
  if (t.classList.contains("pcap-toggle")) {
    const prev = S.config.original[name];
    setValue(name, t.checked ? (typeof prev === "string" ? prev : "") : false);
  } else if (t.type === "checkbox") {
    setValue(name, t.checked);
  } else if (t.type === "number") {
    setValue(name, t.value === "" ? "" : Number(t.value), false);
  } else if (name === "IFACE") {
    setValue(name, t.value.trim());
  }
});
form.addEventListener("input", e => {
  const t = e.target, name = t.dataset.name;
  if (!name || t.type === "checkbox") return;
  if (t.type === "number") setValue(name, t.value === "" ? "" : Number(t.value), false);
  else if (name !== "IFACE") setValue(name, t.value, false);
});
form.addEventListener("click", e => {
  const preset = e.target.closest(".preset");
  if (preset) return setValue(preset.dataset.name, preset.dataset.value);
  const opt = e.target.closest(".iface-opt");
  if (opt) return setValue("IFACE", opt.dataset.iface);
  if (e.target.id === "reload-ifaces") {
    api("/api/interfaces").then(d => { S.interfaces = d.interfaces; renderConfig(); updateIfaceChip(); });
  }
});
form.addEventListener("keydown", e => {
  const opt = e.target.closest(".iface-opt");
  if (opt && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); setValue("IFACE", opt.dataset.iface); }
});

$("#config-revert").addEventListener("click", () => setConfig(S.config.settings));
$("#config-save").addEventListener("click", async () => {
  const changes = {};
  for (const [k, v] of Object.entries(S.config.values)) {
    if (JSON.stringify(v) !== JSON.stringify(S.config.original[k])) changes[k] = v;
  }
  $("#config-save").disabled = true;
  try {
    const res = await api("/api/config", { values: changes });
    setConfig(res.settings);
    toast("Configuration saved");
    loadTests(true);
  } catch (e) {
    if (e.data && e.data.errors) {
      S.config.errors = e.data.errors;
      renderConfig();
      const first = $(".field.invalid");
      if (first) first.scrollIntoView({ behavior: "smooth", block: "center" });
    }
    toast(e.message, true);
    updateConfigState();
  }
});

window.addEventListener("beforeunload", e => {
  if (S.config && S.config.dirty) { e.preventDefault(); e.returnValue = ""; }
});

// ====================================================================== interface chip
async function refreshInterfaces() {
  try {
    const d = await api("/api/interfaces");
    S.interfaces = d.interfaces;
  } catch (_) { /* ignore */ }
  updateIfaceChip();
}

function updateIfaceChip() {
  const chip = $("#iface-chip");
  const name = S.configIface;
  if (!name) { chip.textContent = ""; return; }
  const info = (S.interfaces || []).find(i => i.name === name);
  chip.className = "iface-chip " + (info ? (info.up ? "up" : "down") : "");
  const state = !S.interfaces ? "" : !info ? " · not found" : info.up ? " · link up" : " · link down";
  chip.innerHTML = `<span class="dot"></span>${esc(name)}${esc(state)}`;
}

// ====================================================================== start up
async function init() {
  try {
    const st = await api("/api/status");
    if (st.admin === false) {
      const how = st.platform.startsWith("win") ? "an Administrator terminal" : "sudo";
      const b = $("#banner");
      b.innerHTML = `⚠ The UI is not running with elevated privileges. Sending and capturing packets will probably fail. Restart <code>python ui/server.py</code> from ${how}.`;
      b.classList.remove("hidden");
    }
    if (st.running) {
      const { run } = await api("/api/run?log_from=0");
      S.liveId = run.id;
      S.logNext = 0;
      poll();
    }
  } catch (e) {
    toast("Cannot reach the IGMP Tester server: " + e.message, true);
  }
  loadTests();
  loadHistory();
  try {
    const cfg = await api("/api/config");
    S.configIface = (cfg.settings.find(s => s.name === "IFACE") || {}).value;
  } catch (_) { /* shown in config tab */ }
  refreshInterfaces();
  setInterval(refreshInterfaces, 10000);
  setInterval(() => { if (isRunning()) showRun(S.view); }, 1000);
  if ("Notification" in window && Notification.permission === "default") {
    document.addEventListener("click", () => Notification.requestPermission(), { once: true });
  }
}

init();
