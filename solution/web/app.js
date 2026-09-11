/* AgentRange 资产风险图谱前端（vanilla JS + cytoscape） */
const state = { graph: null, bom: null, risks: null, summary: null, cy: null };

const $ = (sel) => document.querySelector(sel);

async function loadAll() {
  const [graph, bom, risks, summary] = await Promise.all([
    fetch("/api/graph").then(r => r.json()),
    fetch("/api/bom").then(r => r.json()),
    fetch("/api/risks").then(r => r.json()),
    fetch("/api/summary").then(r => r.json()),
  ]);
  Object.assign(state, { graph, bom, risks, summary });
  renderStats();
  renderTypeFilters();
  initGraph();
  renderBom();
  renderRisks();
}

function renderStats() {
  const s = state.summary;
  $("#stats").innerHTML = `
    <span>服务 <b>${s.services}</b></span><span>MCP <b>${s.mcp_servers}</b></span>
    <span>工具 <b>${s.tools}</b><small>(${s.hidden_tools} 隐藏)</small></span>
    <span>技能 <b>${s.skills}</b></span><span>身份 <b>${s.identities}</b></span>
    <span>图谱 <b>${s.graph_nodes}</b> 节点 / <b>${s.graph_edges}</b> 边</span>`;
}

/* ---------------- 图谱视图 ---------------- */
const EDGE_COLORS = {
  mounts: "#2563eb", exposes: "#0d9488", declares_allowed: "#10b981",
  attached_to: "#475569", uses: "#06b6d4", authenticates: "#eab308",
  egress_to: "#ef4444", serves: "#64748b", configures: "#ec4899",
  has_script: "#047857",
};

function nodeStyleData(n) {
  return {
    id: n.id, label: n.name.length > 14 ? n.name.slice(0, 13) + "…" : n.name,
    color: n.color, severity: n.severity || "none", hidden: n.hidden,
  };
}

function initGraph() {
  const nodes = state.graph.nodes.map(n => ({
    data: nodeStyleData(n),
    classes: [n.severity, n.hidden ? "hid" : ""].join(" "),
  }));
  const edges = state.graph.edges.map(e => ({
    data: { id: e.id, source: e.source, target: e.target,
            etype: e.etype, color: EDGE_COLORS[e.etype] || "#64748b" },
  }));
  state.cy = cytoscape({
    container: $("#cy"),
    elements: [...nodes, ...edges],
    style: [
      { selector: "node", style: {
        "background-color": "data(color)",
        "label": "data(label)", "color": "#cbd5e1", "font-size": 9,
        "text-valign": "bottom", "text-margin-y": 5,
        "width": 26, "height": 26, "border-width": 2, "border-color": "#334155",
      }},
      { selector: "node.high", style: { "border-color": "#ef4444", "border-width": 4 }},
      { selector: "node.medium", style: { "border-color": "#f59e0b", "border-width": 3 }},
      { selector: "node.hid", style: { "border-style": "dashed", "border-color": "#ef4444" }},
      { selector: "node.risk-agent", style: { "width": 40, "height": 40 }},
      { selector: "edge", style: {
        "width": 1.5, "line-color": "data(color)", "opacity": 0.55,
        "curve-style": "bezier", "arrow-scale": 0.5,
      }},
      { selector: "edge:selected", style: { "width": 3, "opacity": 1 }},
      { selector: ":selected", style: { "overlay-opacity": 0 }},
    ],
    layout: { name: "cose", animate: false, nodeRepulsion: 9000,
              idealEdgeLength: 70, padding: 30 },
  });
  state.cy.on("tap", "node", (evt) => showNodeDetail(evt.target.id()));
  $("#cy").addEventListener("click", (e) => {
    if (e.target === $("#cy")) $("#sidebar").style.display = "none";
  });
}

function showNodeDetail(nid) {
  const n = state.graph.nodes.find(x => x.id === nid);
  if (!n) return;
  const bomAgent = state.bom.agents.find(a => a.identity.id === nid);
  const staticHits = (state.risks.static || []).filter(
    r => (r.target || "").includes(n.name) || r.target === nid.split(":").slice(1).join(":"));
  const envHits = (state.risks.envelope || []).filter(r => r.target === nid);
  const sb = $("#sidebar");
  sb.style.display = "block";
  sb.innerHTML = `
    <h2>${n.name}</h2>
    <span class="tag" style="color:${n.color}">${n.type_zh}</span>
    <span class="tag sev-${n.severity}">${sevText(n.severity)}</span>
    ${n.tier ? `<span class="tag tier t${n.tier[1]}">${n.tier}</span>` : ""}
    ${n.hidden ? `<span class="tag" style="color:#ef4444">隐藏工具</span>` : ""}
    ${n.score != null ? `<span class="tag">BOM 评分 ${n.score}</span>` : ""}
    <section><h4>声明面 (declared)</h4>
      <pre>${escapeHtml(JSON.stringify(prune(n.declared), null, 1))}</pre></section>
    ${n.observed && Object.keys(n.observed).length ? `<section><h4>观测面 (observed)</h4>
      <pre>${escapeHtml(JSON.stringify(prune(n.observed), null, 1))}</pre></section>` : ""}
    <section><h4>来源 (provenance)</h4>
      <pre>${n.provenance.join("\n")}</pre></section>
    ${n.risks && n.risks.length ? `<section><h4>关联风险规则</h4>
      <pre>${n.risks.join("\n")}</pre></section>` : ""}
    ${(envHits.length || staticHits.length) ? `<section><h4>风险发现</h4>
      ${[...envHits, ...staticHits].map(r =>
        `<div>· <b>${r.rule}</b> <span class="sev-${r.severity}">[${r.severity}]</span><br>
         <span style="color:var(--muted);font-size:11px">${escapeHtml(r.detail || "")}</span></div>`).join("")}
    </section>` : ""}
    ${bomAgent ? bomAgentSection(bomAgent, true) : ""}`;
}

function prune(obj, depth = 0) {
  if (depth > 2 || obj == null || typeof obj !== "object") return obj;
  const out = Array.isArray(obj) ? obj.slice(0, 6) : {};
  for (const [k, v] of Object.entries(obj).slice(0, 12)) {
    out[k] = (typeof v === "string" && v.length > 90) ? v.slice(0, 90) + "…" : v;
    if (typeof v === "object" && v !== null) out[k] = prune(v, depth + 1);
  }
  return out;
}

function renderTypeFilters() {
  const container = $("#type-filters");
  const types = [...new Set(state.graph.nodes.map(n => n.type))];
  container.innerHTML = types
    .map(t => {
      const meta = state.graph.nodes.find(n => n.type === t);
      return `<label><input type="checkbox" class="type-filter" value="${t}" checked>
        <span class="dot" style="background:${meta.color}"></span>${meta.type_zh}</label>`;
    }).join("");
  container.addEventListener("change", applyFilters);
  document.querySelectorAll(".sev-filter").forEach(el =>
    el.addEventListener("change", applyFilters));
}

function applyFilters() {
  const typesOn = new Set(
    [...document.querySelectorAll(".type-filter:checked")].map(e => e.value));
  const sevsOn = new Set(
    [...document.querySelectorAll(".sev-filter:checked")].map(e => e.value));
  state.cy.nodes().forEach(node => {
    const n = state.graph.nodes.find(x => x.id === node.id());
    const show = typesOn.has(n.type) && sevsOn.has(n.severity || "none");
    node.style("display", show ? "element" : "none");
  });
  state.cy.edges().forEach(edge => {
    const ok = edge.source().style("display") !== "none" &&
               edge.target().style("display") !== "none";
    edge.style("display", ok ? "element" : "none");
  });
}

/* ---------------- BOM 视图 ---------------- */
function sevText(s) { return { high: "高危", medium: "中危", info: "提示", null: "未标记" }[s] || s; }

function bomAgentSection(a, compact) {
  const ra = a.risk_assessment;
  const tools = [...a.tools].sort((x, y) => y.tier.localeCompare(x.tier));
  return `
    <div class="agent-card" ${compact ? 'style="padding:12px"' : ""}>
      <h2>${a.identity.name}
        <span class="badge ${ra.quadrant}">${ra.quadrant.toUpperCase()} · ${ra.score}分</span>
        <span class="badge">自主 ${a.autonomy.level}</span>
        <span class="badge">最高 ${ra.max_tool_tier}</span>
      </h2>
      <div class="score-line">
        <div class="score-bar"><i style="width:${ra.score}%"></i></div>
        <span style="color:var(--muted);font-size:12px">${a.identity.kind === "flow" ? "编排 Flow" : "Agent 应用"}</span>
      </div>
      <div class="grid2">
        <div class="tools-t"><h4>工具清单与风险分级</h4>
          <table><tr><th>分级</th><th>工具</th><th>依据</th></tr>
          ${tools.map(t => `<tr>
            <td><span class="tier t${t.tier[1]}">${t.tier}</span></td>
            <td>${t.server}.${t.name}${t.hidden ? ' <span class="warn">[隐藏]</span>' : ""}</td>
            <td style="color:var(--muted)">${escapeHtml(t.tier_reason)}</td></tr>`).join("")}
          </table></div>
        <div>
          <div class="kv"><h4>凭据范围</h4><ul>
            ${a.credential_scope.identities.map(i =>
              `<li>${i.user} <span>· ${i.role} · scope=${JSON.stringify(i.scope)}</span></li>`).join("")}
            ${a.credential_scope.service_account && a.credential_scope.service_account.token
              ? `<li class="warn">服务账号 <span>· ${escapeHtml(a.credential_scope.service_account.token)}</span></li>` : ""}
          </ul></div>
          <div class="kv"><h4>审批门</h4>
            <ul><li class="${a.approval_gates.count === 0 ? "warn" : ""}">
              ${a.approval_gates.count === 0 ? "无任何人工审批机制" : a.approval_gates.count + " 个"}</li></ul></div>
          <div class="kv"><h4>记忆 / 数据</h4><ul>
            <li>持久化 <span>· ${a.memory.persistence}</span></li>
            <li>RAG <span>· ${(a.memory.rag_sources || []).join(", ") || "无"}</span></li>
            <li>敏感数据 <span>· ${(a.memory.sensitive_data_refs || []).join(", ") || "无"}</span></li>
          </ul></div>
        </div>
      </div>
      <div class="ctrl"><h4>治理弱点 (${a.governance_weaknesses.length})</h4>
        <ul>${a.governance_weaknesses.map(w =>
          `<li>${w.kind} <span>· ${escapeHtml(w.detail)}</span></li>`).join("")}</ul></div>
      <div class="ctrl"><h4>建议控制 (${(ra.controls || []).length})</h4>
        <ul>${(ra.controls || []).map(c =>
          `<li><b>${c.family}</b> <span>· ${escapeHtml(c.description)}</span></li>`).join("")}</ul></div>
    </div>`;
}

function renderBom() {
  $("#view-bom").innerHTML = state.bom.agents.map(a => bomAgentSection(a)).join("");
}

/* ---------------- 风险视图 ---------------- */
function renderRisks() {
  const source = $("#risk-source").value, sev = $("#risk-sev").value,
        q = $("#risk-q").value.trim().toLowerCase();
  const all = [
    ...(state.risks.static || []).map(r => ({ ...r, source: "static" })),
    ...(state.risks.envelope || []).map(r => ({ ...r, source: "envelope" })),
    ...(state.risks.runtime || []).map(r => ({ ...r, source: "runtime" })),
    ...(state.risks.validator || []).map(r => ({ ...r, source: "validator" })),
  ].filter(r =>
    (source === "all" || r.source === source) &&
    (sev === "all" || r.severity === sev) &&
    (!q || [r.rule, r.target, r.tag, r.detail, r.ground_truth].join(" ").toLowerCase().includes(q)));
  $("#risk-list").innerHTML = all.length ? all.map(r => `
    <div class="risk-item ${r.severity}">
      <div class="risk-head">
        <b>${r.rule}</b>
        <span class="tag">${r.target}</span>
        <span class="sev-${r.severity}">[${sevText(r.severity)}]</span>
        <span class="tag">${{ static: "采集规则", envelope: "包络校验", runtime: "运行时实证", validator: "完整性校验" }[r.source] || r.source}</span>
        <span class="tag">${r.tag || ""}</span>
      </div>
      <div class="meta">${escapeHtml(r.detail || "")}</div>
      ${r.ground_truth ? `<div class="meta gt">对应标准答案：${r.ground_truth}</div>` : ""}
      <div class="meta">证据：${escapeHtml(r.evidence || "")}</div>
    </div>`).join("") : "<p style='color:var(--muted);padding:20px'>无匹配项</p>";
}

/* ---------------- 导航 ---------------- */
document.querySelectorAll("nav button").forEach(btn =>
  btn.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    ["graph", "bom", "risks"].forEach(v =>
      $("#view-" + v).classList.toggle("view-active", v === btn.dataset.view));
    if (btn.dataset.view === "graph" && state.cy)
      setTimeout(() => state.cy.resize(), 50);
  }));

["#risk-source", "#risk-sev"].forEach(s =>
  $(s).addEventListener("change", renderRisks));
$("#risk-q").addEventListener("input", renderRisks);

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g,
    c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

loadAll();
