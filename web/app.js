(() => {
  "use strict";

  const ACTIONS = [
    { key: "flag_for_review", label: "Flag for review", tone: "review" },
    { key: "hold_for_verification", label: "Hold for verification", tone: "hold" },
    { key: "soft_decline", label: "Soft decline", tone: "decline" },
  ];

  const state = {
    records: [],
    search: "",
    activeActions: new Set(),
    showNoAction: false,
    liveOnly: false,
    sortKey: "event_timestamp",
    sortDir: "desc",
    expanded: new Set(),
  };

  const el = (id) => document.getElementById(id);

  function fmtMoney(n) {
    return "₹" + Math.round(n).toLocaleString("en-IN");
  }

  function fmtPct(n) {
    return (n * 100).toFixed(1) + "%";
  }

  function fmtTime(iso) {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    const hh = String(d.getUTCHours()).padStart(2, "0");
    const mm = String(d.getUTCMinutes()).padStart(2, "0");
    return `${months[d.getUTCMonth()]} ${d.getUTCDate()}, ${hh}:${mm}`;
  }

  function setSkeleton(on) {
    const ids = ["totalCost", "costBreakdown", "statPrecision", "statRecall", "statFpRate", "statActors"];
    ids.forEach((id) => {
      const e = el(id);
      e.classList.toggle("skeleton", on);
      if (on) e.textContent = "loading value";
    });
    el("headlineBand").setAttribute("aria-busy", on ? "true" : "false");
  }

  function setConn(state_, detail) {
    const c = el("connStatus");
    c.dataset.state = state_;
    c.querySelector(".conn-label").textContent =
      state_ === "ok" ? "Connected" : state_ === "error" ? "Disconnected" : "Connecting…";
    const banner = el("errorBanner");
    if (state_ === "error") {
      banner.hidden = false;
      if (detail) el("errorDetail").textContent = detail;
    } else {
      banner.hidden = true;
    }
  }

  async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `HTTP ${res.status}`);
    }
    return res.json();
  }

  async function loadMetrics() {
    try {
      const m = await fetchJSON("/metrics");
      const cm = m.confusion_matrix;
      const cost = m.cost;

      setSkeleton(false);
      el("totalCost").textContent = fmtMoney(cost.total_cost);
      el("statPrecision").textContent = cm.precision.toFixed(3);
      el("statRecall").textContent = cm.recall.toFixed(3);
      el("statFpRate").textContent = fmtPct(cm.fp_rate);
      el("statActors").textContent = m.n_actors.toLocaleString();

      el("cmTP").textContent = cm.tp.toLocaleString();
      el("cmFP").textContent = cm.fp.toLocaleString();
      el("cmTN").textContent = cm.tn.toLocaleString();
      el("cmFN").textContent = cm.fn.toLocaleString();

      el("costBreakdown").textContent =
        `${fmtMoney(cost.total_fp_cost)} from ${cost.fp_count} false positive${cost.fp_count === 1 ? "" : "s"} · ` +
        `${fmtMoney(cost.total_fn_cost)} from ${cost.fn_count} false negative${cost.fn_count === 1 ? "" : "s"}`;
      el("datasetNote").textContent = `${m.dataset_path} · ${m.n_actors.toLocaleString()} actors · computed ${fmtTime(m.computed_at)} UTC`;
      return true;
    } catch (e) {
      setSkeleton(false);
      setConn("error", e.message);
      return false;
    }
  }

  async function loadAudit() {
    try {
      const records = await fetchJSON("/audit?limit=5000");
      state.records = records;
      return true;
    } catch (e) {
      setConn("error", e.message);
      return false;
    }
  }

  function buildChips() {
    const wrap = el("actionChips");
    wrap.innerHTML = "";
    for (const a of ACTIONS) {
      const btn = document.createElement("button");
      btn.className = "chip";
      btn.dataset.tone = a.tone;
      btn.dataset.active = "false";
      btn.textContent = a.label;
      btn.addEventListener("click", () => {
        if (state.activeActions.has(a.key)) state.activeActions.delete(a.key);
        else state.activeActions.add(a.key);
        btn.dataset.active = state.activeActions.has(a.key) ? "true" : "false";
        renderTable();
      });
      wrap.appendChild(btn);
    }
  }

  function matchesFilters(r) {
    if (!state.showNoAction && r.action === "no_action") return false;
    if (state.activeActions.size && !state.activeActions.has(r.action)) return false;
    if (state.liveOnly && r.dry_run) return false;
    if (state.search) {
      const hay = (r.actor + " " + r.rules_fired.join(" ") + " " + (r.explanation || "") + " " + r.rationale).toLowerCase();
      if (!hay.includes(state.search)) return false;
    }
    return true;
  }

  function compareRecords(a, b) {
    let av, bv;
    if (state.sortKey === "confidence") { av = a.confidence; bv = b.confidence; }
    else if (state.sortKey === "action") { av = a.action; bv = b.action; }
    else { av = a.event_timestamp; bv = b.event_timestamp; }
    if (av < bv) return state.sortDir === "asc" ? -1 : 1;
    if (av > bv) return state.sortDir === "asc" ? 1 : -1;
    return 0;
  }

  const DECISION_COLOR = {
    no_action: "var(--good)",
    flag_for_review: "var(--review)",
    hold_for_verification: "var(--hold)",
    soft_decline: "var(--decline)",
  };
  const DECISION_LABEL = {
    no_action: "No action",
    flag_for_review: "Flag for review",
    hold_for_verification: "Hold for verification",
    soft_decline: "Soft decline",
  };

  const CARET_SVG = `<svg class="expand-caret" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>`;

  function renderEvidenceDetail(r) {
    const cards = r.rules_fired.length
      ? r.rules_fired
          .map((rule) => {
            const evidence = r.rule_evidence[rule] || {};
            const rows = Object.entries(evidence)
              .map(([k, v]) => `<div class="detail-evidence-row"><span>${escapeHtml(k)}</span><span>${escapeHtml(String(v))}</span></div>`)
              .join("");
            return `<div class="detail-evidence-card"><div class="rule-name">${escapeHtml(rule)}</div>${rows}</div>`;
          })
          .join("")
      : `<div class="detail-evidence-card"><div class="rule-name">no rules fired</div></div>`;
    return `
      <div class="detail-inner-pad">
        <div class="detail-rationale"><strong>Policy rationale:</strong> ${escapeHtml(r.rationale)}</div>
        <div class="detail-evidence">${cards}</div>
      </div>`;
  }

  function renderTable() {
    const tbody = el("tableBody");
    let rows = state.records.filter(matchesFilters);
    rows.sort(compareRecords);

    el("rowCount").textContent = `${rows.length.toLocaleString()} / ${state.records.length.toLocaleString()} events`;

    if (!rows.length) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No events match these filters.</td></tr>`;
      return;
    }

    const shown = rows.slice(0, 400);
    tbody.innerHTML = shown
      .map((r, i) => {
        const rules = r.rules_fired.length
          ? r.rules_fired.map((rule) => `<span class="rule-tag">${escapeHtml(rule)}</span>`).join("")
          : `<span class="rule-tag" style="opacity:.5">none</span>`;
        const pct = Math.max(0, Math.min(100, Math.round(r.confidence * 100)));
        const explanation = r.explanation
          ? `<div class="cell-explanation">${escapeHtml(r.explanation)}</div>`
          : `<div class="cell-explanation empty">no triage explanation logged</div>`;
        const delay = Math.min(i * 0.012, 0.3);
        const expanded = state.expanded.has(r.event_id);
        return `
        <tr data-expandable data-row-id="${r.event_id}" data-expanded="${expanded}" style="animation:riseIn 0.3s var(--ease) both; animation-delay:${delay}s">
          <td class="cell-time">${fmtTime(r.event_timestamp)}</td>
          <td class="cell-actor">${CARET_SVG}${escapeHtml(r.actor)}</td>
          <td><div class="rule-tags">${rules}</div></td>
          <td>
            <div class="cell-confidence">
              <span class="conf-value">${r.confidence.toFixed(2)}</span>
              <div class="conf-bar"><div class="conf-bar-fill" style="width:${pct}%; background:${DECISION_COLOR[r.action]}"></div></div>
            </div>
          </td>
          <td><span class="badge" data-action="${r.action}">${DECISION_LABEL[r.action]}</span></td>
          <td>
            <span class="cell-mode" data-mode="${r.dry_run ? "dry_run" : "live"}">
              <span class="mode-dot"></span>${r.dry_run ? "DRY-RUN" : "LIVE"}
            </span>
          </td>
          <td>${explanation}</td>
        </tr>
        <tr class="detail-row"><td colspan="7"><div class="detail-collapse"><div class="detail-inner">${renderEvidenceDetail(r)}</div></div></td></tr>`;
      })
      .join("");

    if (rows.length > shown.length) {
      tbody.insertAdjacentHTML(
        "beforeend",
        `<tr class="empty-row"><td colspan="7">Showing first ${shown.length.toLocaleString()} of ${rows.length.toLocaleString()} matching events — narrow the filters to see more.</td></tr>`
      );
    }

    document.querySelectorAll("th.sortable .sort-caret").forEach((c) => (c.textContent = ""));
    const activeTh = document.querySelector(`th[data-sort="${state.sortKey}"] .sort-caret`);
    if (activeTh) activeTh.textContent = state.sortDir === "desc" ? "▼" : "▲";
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function wireControls() {
    el("searchInput").addEventListener("input", (e) => {
      state.search = e.target.value.trim().toLowerCase();
      renderTable();
    });

    el("showNoAction").addEventListener("change", (e) => {
      state.showNoAction = e.target.checked;
      renderTable();
    });

    el("liveOnly").addEventListener("change", (e) => {
      state.liveOnly = e.target.checked;
      renderTable();
    });

    document.querySelectorAll("th.sortable").forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.dataset.sort;
        if (state.sortKey === key) {
          state.sortDir = state.sortDir === "desc" ? "asc" : "desc";
        } else {
          state.sortKey = key;
          state.sortDir = "desc";
        }
        renderTable();
      });
    });

    el("themeToggle").addEventListener("click", () => {
      const current = document.documentElement.dataset.theme;
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      try {
        localStorage.setItem("theme", next);
      } catch (e) {
        /* localStorage unavailable (private mode etc.) -- toggle still works for this page load */
      }
    });

    el("tableBody").addEventListener("click", (e) => {
      const row = e.target.closest("tr[data-expandable]");
      if (!row) return;
      const id = row.dataset.rowId;
      const nowExpanded = row.dataset.expanded !== "true";
      row.dataset.expanded = nowExpanded ? "true" : "false";
      if (nowExpanded) state.expanded.add(id);
      else state.expanded.delete(id);
    });
  }

  async function init() {
    buildChips();
    wireControls();
    setConn("loading");
    setSkeleton(true);

    const [metricsOk, auditOk] = await Promise.all([loadMetrics(), loadAudit()]);

    if (metricsOk && auditOk) {
      setConn("ok");
    }
    renderTable();
  }

  init();
})();
