/**
 * Orix — Report Panel (Webview)
 * Full-screen interactive HTML dashboard showing scan results.
 */

'use strict';

const vscode = require('vscode');

class ReportPanel {
  static currentPanel = undefined;
  static viewType = 'orixReport';

  static createOrShow(context, scanResult) {
    const column = vscode.window.activeTextEditor
      ? Math.min(vscode.window.activeTextEditor.viewColumn + 1, 3)
      : vscode.ViewColumn.Two;

    if (ReportPanel.currentPanel) {
      ReportPanel.currentPanel._panel.reveal(column);
      ReportPanel.currentPanel._update(scanResult);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      ReportPanel.viewType,
      'Orix Report',
      column,
      { enableScripts: true, retainContextWhenHidden: true }
    );

    ReportPanel.currentPanel = new ReportPanel(panel, context, scanResult);
  }

  constructor(panel, context, scanResult) {
    this._panel = panel;
    this._disposables = [];

    this._update(scanResult);

    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

    this._panel.webview.onDidReceiveMessage(msg => {
      if (msg.command === 'goToLine') {
        this._navigate(msg.file, msg.line, msg.column);
      }
    }, null, this._disposables);
  }

  _update(scanResult) {
    this._panel.webview.html = this._html(scanResult || {});
  }

  async _navigate(file, line, column) {
    if (!file) return;
    try {
      const uri = vscode.Uri.file(file);
      const doc = await vscode.workspace.openTextDocument(uri);
      const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
      const pos = new vscode.Position(line || 0, column || 0);
      editor.selection = new vscode.Selection(pos, pos);
      editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
    } catch (err) {
      vscode.window.showErrorMessage(`Orix: Could not open file — ${err.message}`);
    }
  }

  dispose() {
    ReportPanel.currentPanel = undefined;
    this._panel.dispose();
    while (this._disposables.length) this._disposables.pop().dispose();
  }

  // ── HTML ───────────────────────────────────────────────────────────────────

  _html(scanResult) {
    const { issues = [], stats = {}, meta = {} } = scanResult;

    const score  = _score(stats);
    const grade  = _grade(score);
    const scoreColor = score >= 75 ? '#00c896' : score >= 50 ? '#e8a838' : '#e8534a';

    const secIssues  = issues.filter(i => i.category === 'security');
    const slopIssues = issues.filter(i => i.category === 'ai-slop');
    const vibeIssues = issues.filter(i => i.category === 'vibe-code');

    const rows = issues.slice(0, 500).map(issue => {
      const sevClass = `sev-${issue.severity}`;
      const catLabel = { security: 'Security', 'ai-slop': 'AI Slop', 'vibe-code': 'Vibe' }[issue.category] || '';
      const fileName  = issue.file ? issue.file.split(/[/\\]/).pop() : '(current file)';
      const filePath  = esc(issue.file || '');
      const tags = (issue.tags || []).slice(0, 3).map(t => `<span class="tag">${esc(t)}</span>`).join('');
      return `<tr class="row" data-sev="${issue.severity}" data-cat="${esc(issue.category)}"
                  onclick="goTo('${esc(issue.file || '')}',${issue.line},${issue.column || 0})">
        <td><span class="badge ${sevClass}">${issue.severity}</span></td>
        <td><code>${esc(issue.ruleId)}</code></td>
        <td class="cat-cell">${esc(catLabel)}</td>
        <td class="name-cell">${esc(issue.name)}</td>
        <td class="msg-cell">${esc(issue.message.slice(0, 120))}${issue.message.length > 120 ? '…' : ''}</td>
        <td class="file-cell" title="${filePath}">${esc(fileName)}</td>
        <td class="ln-cell">${issue.line + 1}</td>
        <td>${tags}</td>
      </tr>`;
    }).join('');

    const topTags = Object.entries(stats.topTags || {})
      .sort((a, b) => b[1] - a[1]).slice(0, 8);

    const tagBars = topTags.map(([tag, n]) => {
      const w = Math.min(100, n * 8);
      return `<div class="tag-row"><span class="tag">${esc(tag)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${w}%"></div></div>
        <span class="tag-n">${n}</span></div>`;
    }).join('');

    const recs = _recommendations(stats, issues)
      .map(r => `<p class="rec">${esc(r)}</p>`).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Orix Report</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0e1016;--s1:#13161f;--s2:#191c28;--border:#252838;
  --text:#dde0f0;--muted:#60637a;--accent:#5b6af5;
  --red:#e8534a;--amber:#e8a838;--green:#00c896;--blue:#4a9de8;
  --mono:'JetBrains Mono','Fira Code',monospace;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;line-height:1.55}

/* HEADER */
.hdr{
  display:flex;align-items:center;justify-content:space-between;gap:24px;
  padding:22px 36px 18px;border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:50;background:var(--bg);
}
.hdr-left{display:flex;align-items:center;gap:20px}
.wordmark{font-size:18px;font-weight:700;letter-spacing:.5px;color:var(--text)}
.wordmark span{color:var(--accent)}
.meta{font-family:var(--mono);font-size:11px;color:var(--muted);line-height:1.9}
.score-ring{
  width:64px;height:64px;border-radius:50%;
  border:2.5px solid var(--score-color,var(--accent));
  display:flex;flex-direction:column;align-items:center;justify-content:center;
}
.score-n{font-size:20px;font-weight:700;color:var(--score-color,var(--accent))}
.score-g{font-size:10px;color:var(--muted);margin-top:1px}

/* STAT CARDS */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;padding:20px 36px}
.card{
  background:var(--s1);border:1px solid var(--border);border-radius:10px;
  padding:18px 16px;position:relative;overflow:hidden;
}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--c,var(--accent))}
.card-n{font-size:32px;font-weight:700;margin-top:6px;line-height:1}
.card-lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-top:4px}
.card-sub{font-size:11px;font-family:var(--mono);color:var(--muted);margin-top:6px}

/* INSIGHTS */
.insights{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:0 36px 20px}
.insight{background:var(--s1);border:1px solid var(--border);border-radius:10px;padding:16px 18px}
.insight-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);margin-bottom:14px}
.tag-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.bar-track{flex:1;height:3px;background:var(--border);border-radius:2px;overflow:hidden}
.bar-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--blue));border-radius:2px}
.tag-n{font-family:var(--mono);font-size:11px;color:var(--muted);min-width:20px;text-align:right}
.rec{margin-bottom:8px;line-height:1.6;font-size:12.5px}

/* FILTERS */
.filters{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:0 36px 14px}
.f-label{font-size:11px;color:var(--muted)}
.fbtn{
  padding:5px 12px;border-radius:16px;border:1px solid var(--border);
  background:var(--s1);color:var(--muted);cursor:pointer;font-size:11px;
  font-family:var(--sans);transition:all .12s;
}
.fbtn:hover,.fbtn.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.search{
  margin-left:auto;padding:5px 14px;border-radius:16px;
  border:1px solid var(--border);background:var(--s1);color:var(--text);
  font-size:11px;font-family:var(--mono);outline:none;min-width:200px;
}
.search:focus{border-color:var(--accent)}

/* TABLE */
.tbl-wrap{padding:0 36px 40px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{
  background:var(--s2);color:var(--muted);font-size:10px;text-transform:uppercase;
  letter-spacing:.4px;padding:9px 10px;text-align:left;
  border-bottom:1px solid var(--border);position:sticky;top:63px;z-index:4;
}
.row{border-bottom:1px solid rgba(255,255,255,.03);cursor:pointer;transition:background .1s}
.row:hover{background:var(--s1)}
td{padding:9px 10px;vertical-align:middle}

.badge{
  display:inline-block;padding:2px 7px;border-radius:4px;
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.3px;font-family:var(--mono);
}
.sev-error  {background:rgba(232,83,74,.12);color:var(--red);border:1px solid rgba(232,83,74,.25)}
.sev-warning{background:rgba(232,168,56,.12);color:var(--amber);border:1px solid rgba(232,168,56,.25)}
.sev-info   {background:rgba(74,157,232,.12);color:var(--blue);border:1px solid rgba(74,157,232,.25)}

code{font-family:var(--mono);font-size:11px;color:var(--muted)}
.cat-cell{color:var(--muted);font-size:11px}
.name-cell{font-weight:600}
.msg-cell{color:var(--muted);max-width:360px}
.file-cell{font-family:var(--mono);font-size:11px;color:var(--accent)}
.ln-cell{font-family:var(--mono);font-size:11px;color:var(--muted);text-align:right}
.tag{
  display:inline-block;background:rgba(91,106,245,.1);color:var(--accent);
  font-size:10px;padding:1px 5px;border-radius:3px;margin:1px;font-family:var(--mono);
}

.empty{text-align:center;padding:72px 32px;color:var(--muted)}
.empty h2{font-size:20px;font-weight:700;color:var(--text);margin-bottom:8px}
.hidden{display:none!important}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-left">
    <div class="wordmark"><span>Orix</span> — Code Scanner</div>
    <div class="meta">
      ${meta.files ? `Files: <strong>${meta.files}</strong><br>` : ''}
      ${meta.time ? `Time: <strong>${meta.time}ms</strong><br>` : ''}
      Issues: <strong>${issues.length}</strong>
    </div>
  </div>
  <div>
    <div class="score-ring" style="--score-color:${escJS(scoreColor)}">
      <div class="score-n" style="color:${escJS(scoreColor)}">${score}</div>
      <div class="score-g">${escJS(grade)}</div>
    </div>
  </div>
</div>

<div class="cards">
  <div class="card" style="--c:var(--red)">
    <div style="font-size:12px;color:var(--muted)">Security</div>
    <div class="card-n" style="color:var(--red)">${secIssues.length}</div>
    <div class="card-sub">${secIssues.filter(i=>i.severity==='error').length}E &nbsp; ${secIssues.filter(i=>i.severity==='warning').length}W</div>
  </div>
  <div class="card" style="--c:var(--amber)">
    <div style="font-size:12px;color:var(--muted)">AI Slop</div>
    <div class="card-n" style="color:var(--amber)">${slopIssues.length}</div>
    <div class="card-sub">${slopIssues.filter(i=>i.severity==='error').length}E &nbsp; ${slopIssues.filter(i=>i.severity==='warning').length}W</div>
  </div>
  <div class="card" style="--c:var(--blue)">
    <div style="font-size:12px;color:var(--muted)">Vibe Code</div>
    <div class="card-n" style="color:var(--blue)">${vibeIssues.length}</div>
    <div class="card-sub">${vibeIssues.filter(i=>i.severity==='error').length}E &nbsp; ${vibeIssues.filter(i=>i.severity==='warning').length}W</div>
  </div>
  <div class="card" style="--c:var(--red)">
    <div style="font-size:12px;color:var(--muted)">Critical Errors</div>
    <div class="card-n" style="color:var(--red)">${issues.filter(i=>i.severity==='error').length}</div>
    <div class="card-sub">Require immediate fix</div>
  </div>
</div>

${topTags.length || recs ? `
<div class="insights">
  ${topTags.length ? `<div class="insight"><div class="insight-title">Top Issue Tags</div>${tagBars}</div>` : ''}
  ${recs ? `<div class="insight"><div class="insight-title">Recommendations</div>${recs}</div>` : ''}
</div>` : ''}

<div class="filters">
  <span class="f-label">Filter:</span>
  <button class="fbtn on" onclick="filter('all',this)">All (${issues.length})</button>
  <button class="fbtn" onclick="filter('security',this)">Security (${secIssues.length})</button>
  <button class="fbtn" onclick="filter('ai-slop',this)">AI Slop (${slopIssues.length})</button>
  <button class="fbtn" onclick="filter('vibe-code',this)">Vibe Code (${vibeIssues.length})</button>
  <button class="fbtn" onclick="filter('error',this)">Errors only</button>
  <input class="search" type="search" placeholder="Search…" oninput="search(this.value)">
</div>

<div class="tbl-wrap">
${issues.length === 0 ? `
  <div class="empty">
    <h2>No issues found</h2>
    <p>Either the code is clean or no files have been scanned yet.</p>
  </div>` : `
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>Rule</th><th>Category</th><th>Issue</th>
        <th>Description</th><th>File</th><th>Line</th><th>Tags</th>
      </tr>
    </thead>
    <tbody id="tbody">${rows}</tbody>
  </table>`}
</div>

<script>
const vscode = acquireVsCodeApi();
let activeFilter = 'all';
let activeSearch = '';

function goTo(file, line, col) {
  vscode.postMessage({ command: 'goToLine', file, line, column: col });
}

function filter(f, btn) {
  activeFilter = f;
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  apply();
}

function search(v) {
  activeSearch = v.toLowerCase();
  apply();
}

function apply() {
  document.querySelectorAll('.row').forEach(row => {
    const cat = row.dataset.cat || '';
    const sev = row.dataset.sev || '';
    const txt = row.textContent.toLowerCase();
    let show = activeFilter === 'all' || cat === activeFilter || sev === activeFilter;
    if (activeSearch && !txt.includes(activeSearch)) show = false;
    row.classList.toggle('hidden', !show);
  });
}
</script>
</body>
</html>`;
  }
}

// ── Module-level helpers ────────────────────────────────────────────────────

function esc(str) {
  return String(str || '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function escJS(str) {
  return String(str || '').replace(/\\/g,'\\\\').replace(/'/g,"\\'");
}

function _score(stats) {
  if (!stats || !stats.total) return 100;
  const e = (stats.security?.error||0) + (stats['ai-slop']?.error||0) + (stats['vibe-code']?.error||0);
  const w = (stats.security?.warning||0) + (stats['ai-slop']?.warning||0) + (stats['vibe-code']?.warning||0);
  const i = (stats.security?.info||0) + (stats['ai-slop']?.info||0) + (stats['vibe-code']?.info||0);
  return Math.max(0, Math.round(100 - e*10 - w*3 - i*0.5));
}

function _grade(score) {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function _recommendations(stats, issues) {
  const recs = [];
  const secErrors = stats.security?.error || 0;
  const slopCount = (stats['ai-slop']?.error||0) + (stats['ai-slop']?.warning||0);
  const vibeCount = stats['vibe-code']?.warning || 0;

  if (secErrors > 0)
    recs.push(`Fix ${secErrors} critical security error(s) before any deployment.`);
  if (issues.some(i => i.ruleId === 'SEC001' || i.ruleId === 'SEC002'))
    recs.push('Rotate any exposed credentials immediately and audit git history.');
  if (issues.some(i => i.ruleId === 'SLOP008'))
    recs.push('AI preamble found in code — this file was not reviewed after generation.');
  if (slopCount > 5)
    recs.push(`${slopCount} AI slop issues — replace placeholders with real implementations.`);
  if (vibeCount > 10)
    recs.push('High vibe-code count — consider a structured refactor pass.');
  if (recs.length === 0)
    recs.push('No critical recommendations. Keep it up.');

  return recs;
}

module.exports = { ReportPanel };
