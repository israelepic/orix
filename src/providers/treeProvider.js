/**
 * Orix - Code Quality & Security Scanner — Tree View Provider
 * Powers the sidebar Issues and Summary panels.
 *
 * Key fix: TreeItem properties must be set directly on the instance,
 * NOT via Object.assign (which overwrites internal VS Code properties).
 */

'use strict';

const vscode = require('vscode');
const path = require('path');

// Use VS Code codicons ($(name)) for all icons — no emoji
const CATEGORY_CONFIG = {
  'security':   { label: 'Security Vulnerabilities', icon: 'lock' },
  'ai-slop':    { label: 'AI Slop / Lazy Code',       icon: 'robot' },
  'vibe-code':  { label: 'Vibe-Coded Traits',         icon: 'pulse' },
};

const SEVERITY_ICON = {
  error:   'error',
  warning: 'warning',
  info:    'info',
};

// ── ISSUES TREE ─────────────────────────────────────────────────────────────

class IssuesTreeProvider {
  constructor() {
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    /** @type {Map<string, Array>} filePath -> issues[] */
    this.issuesByFile = new Map();
    this.groupBy = 'category'; // 'category' | 'file' | 'severity'
    /** 'idle' | 'clean' | 'issues' | 'cleared' */
    this.state = 'idle';
  }

  refresh(issuesByFile) {
    if (issuesByFile !== undefined) {
      this.issuesByFile = issuesByFile;
      const total = [...issuesByFile.values()].reduce((s, v) => s + v.length, 0);
      this.state = total > 0 ? 'issues' : 'clean';
    }
    this._onDidChangeTreeData.fire(undefined);
  }

  clear() {
    this.issuesByFile = new Map();
    this.state = 'cleared';
    this._onDidChangeTreeData.fire(undefined);
  }

  setGroupBy(mode) {
    this.groupBy = mode;
    this._onDidChangeTreeData.fire(undefined);
  }

  // Called by VS Code to render each item
  getTreeItem(element) {
    return element;
  }

  // Called by VS Code to get children.
  // element === undefined means we want the root level.
  getChildren(element) {
    if (!element) {
      return this._buildRoots();
    }

    switch (element._orixType) {
      case 'category': return this._issuesForCategory(element._orixId);
      case 'file':     return this._issuesForFile(element._orixId);
      case 'severity': return this._issuesForSeverity(element._orixId);
      default:         return [];
    }
  }

  // ── Private ───────────────────────────────────────────────────────────────

  _buildRoots() {
    const all = this._allIssues();

    // ── Idle: extension just opened, nothing scanned yet ──
    if (this.state === 'idle') {
      return [
        this._actionItem(
          '$(search) Scan Current File',
          'orix.scanCurrentFile',
          'Click to scan the active editor'
        ),
        this._actionItem(
          '$(search-view-icon) Scan Entire Workspace',
          'orix.scanWorkspace',
          'Click to scan every file in the workspace'
        ),
      ];
    }

    // ── Cleared: user just hit Clear All ──
    if (this.state === 'cleared') {
      return [
        this._infoItem('$(trash) Diagnostics cleared.', 'shield'),
        this._actionItem(
          '$(search) Scan Current File',
          'orix.scanCurrentFile',
          'Re-scan the active editor'
        ),
        this._actionItem(
          '$(search-view-icon) Scan Entire Workspace',
          'orix.scanWorkspace',
          'Re-scan every file in the workspace'
        ),
      ];
    }

    // ── Clean: scan completed, no issues ──
    if (all.length === 0) {
      const item = new vscode.TreeItem('No issues found', vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon('pass');
      item.tooltip = 'Your code looks clean! Run another scan any time.';
      return [item];
    }

    // ── Issues found ──
    if (this.groupBy === 'category') {
      return Object.entries(CATEGORY_CONFIG)
        .map(([catId, cfg]) => {
          const issues = all.filter(i => i.category === catId);
          if (issues.length === 0) return null;
          return this._categoryNode(catId, cfg, issues);
        })
        .filter(Boolean);
    }

    if (this.groupBy === 'file') {
      return Array.from(this.issuesByFile.entries())
        .filter(([, issues]) => issues.length > 0)
        .map(([filePath, issues]) => this._fileNode(filePath, issues));
    }

    if (this.groupBy === 'severity') {
      return ['error', 'warning', 'info']
        .map(sev => {
          const issues = all.filter(i => i.severity === sev);
          if (issues.length === 0) return null;
          return this._severityNode(sev, issues);
        })
        .filter(Boolean);
    }

    return [];
  }

  /** A clickable item that fires a VS Code command */
  _actionItem(label, command, tooltip) {
    const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
    item.tooltip = tooltip;
    item.command = { command, title: label };
    return item;
  }

  /** A plain informational item with an icon */
  _infoItem(label, icon) {
    const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
    item.iconPath = new vscode.ThemeIcon(icon);
    return item;
  }

  _categoryNode(catId, cfg, issues) {
    const errors   = issues.filter(i => i.severity === 'error').length;
    const warnings = issues.filter(i => i.severity === 'warning').length;
    const infos    = issues.filter(i => i.severity === 'info').length;

    const item = new vscode.TreeItem(
      `${cfg.label} (${issues.length})`,
      vscode.TreeItemCollapsibleState.Expanded
    );
    item.iconPath = new vscode.ThemeIcon(cfg.icon);
    item.tooltip = `${errors} error(s), ${warnings} warning(s), ${infos} info`;
    item.contextValue = 'orixCategory';
    // Custom properties prefixed with _orix to avoid collisions with vscode internals
    item._orixType = 'category';
    item._orixId = catId;
    return item;
  }

  _fileNode(filePath, issues) {
    const item = new vscode.TreeItem(
      `${path.basename(filePath)} (${issues.length})`,
      vscode.TreeItemCollapsibleState.Collapsed
    );
    item.iconPath = vscode.ThemeIcon.File;
    item.description = path.relative(
      vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '',
      path.dirname(filePath)
    );
    item.tooltip = filePath;
    item.contextValue = 'orixFile';
    item._orixType = 'file';
    item._orixId = filePath;
    return item;
  }

  _severityNode(severity, issues) {
    const labels = { error: 'Errors', warning: 'Warnings', info: 'Info' };
    const item = new vscode.TreeItem(
      `${labels[severity]} (${issues.length})`,
      vscode.TreeItemCollapsibleState.Collapsed
    );
    item.iconPath = new vscode.ThemeIcon(SEVERITY_ICON[severity]);
    item._orixType = 'severity';
    item._orixId = severity;
    return item;
  }

  _issuesForCategory(categoryId) {
    return this._allIssues()
      .filter(i => i.category === categoryId)
      .slice(0, 300)
      .map(issue => this._issueLeaf(issue));
  }

  _issuesForFile(filePath) {
    return (this.issuesByFile.get(filePath) || [])
      .map(issue => this._issueLeaf(issue));
  }

  _issuesForSeverity(severity) {
    return this._allIssues()
      .filter(i => i.severity === severity)
      .slice(0, 300)
      .map(issue => this._issueLeaf(issue));
  }

  _issueLeaf(issue) {
    const label = `[${issue.ruleId}] ${issue.name}`;
    const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);

    item.iconPath = new vscode.ThemeIcon(SEVERITY_ICON[issue.severity] || 'circle-filled');
    item.description = `line ${issue.line + 1}`;
    item.contextValue = 'orixIssue';

    // Tooltip as MarkdownString for rich display on hover
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${issue.name}**\n\n`);
    md.appendMarkdown(`${issue.message}\n\n`);
    if (issue.lineText) md.appendCodeblock(issue.lineText.slice(0, 100), 'plaintext');
    if (issue.fix) md.appendMarkdown(`\n**Fix:** ${issue.fix}`);
    item.tooltip = md;

    // Command that fires when the user clicks the item
    item.command = {
      command: 'orix.goToIssue',
      title: 'Go to issue',
      arguments: [issue],
    };

    return item;
  }

  _allIssues() {
    const all = [];
    for (const issues of this.issuesByFile.values()) all.push(...issues);
    return all;
  }
}

// ── SUMMARY TREE ─────────────────────────────────────────────────────────────

class SummaryTreeProvider {
  constructor() {
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this.stats = null;
    this.scanMeta = null;
  }

  refresh(stats, scanMeta) {
    this.stats = stats;
    this.scanMeta = scanMeta;
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element) { return element; }

  getChildren(element) {
    // Summary is a flat list — no nested children
    if (element) return [];

    if (!this.stats) {
      const item = new vscode.TreeItem(
        'Scan a file or workspace to see results',
        vscode.TreeItemCollapsibleState.None
      );
      item.iconPath = new vscode.ThemeIcon('search');
      return [item];
    }

    const rows = [];

    // Score
    const score = this._score();
    const grade = this._grade(score);
    const scoreItem = new vscode.TreeItem(
      `Score: ${score} / 100  —  ${grade}`,
      vscode.TreeItemCollapsibleState.None
    );
    scoreItem.iconPath = new vscode.ThemeIcon(score >= 75 ? 'pass' : score >= 50 ? 'warning' : 'error');
    scoreItem.tooltip = 'Lower score = more issues. Score deducts 10pts per error, 3pts per warning, 0.5 per info.';
    rows.push(scoreItem);

    // Scan meta
    if (this.scanMeta) {
      if (this.scanMeta.files) {
        const fi = new vscode.TreeItem(`Files scanned: ${this.scanMeta.files}`, vscode.TreeItemCollapsibleState.None);
        fi.iconPath = new vscode.ThemeIcon('files');
        rows.push(fi);
      }
      if (this.scanMeta.time) {
        const ti = new vscode.TreeItem(`Scan time: ${this.scanMeta.time}ms`, vscode.TreeItemCollapsibleState.None);
        ti.iconPath = new vscode.ThemeIcon('clock');
        rows.push(ti);
      }
    }

    // Total
    const totalItem = new vscode.TreeItem(`Total issues: ${this.stats.total}`, vscode.TreeItemCollapsibleState.None);
    totalItem.iconPath = new vscode.ThemeIcon('issues');
    rows.push(totalItem);

    // Per-category breakdown
    for (const [catId, cfg] of Object.entries(CATEGORY_CONFIG)) {
      const s = this.stats[catId];
      if (!s) continue;
      const n = (s.error || 0) + (s.warning || 0) + (s.info || 0);
      if (n === 0) continue;

      const ci = new vscode.TreeItem(`${cfg.label}: ${n}`, vscode.TreeItemCollapsibleState.None);
      ci.iconPath = new vscode.ThemeIcon(cfg.icon);
      ci.description = `${s.error || 0}E  ${s.warning || 0}W  ${s.info || 0}I`;
      rows.push(ci);
    }

    // Top issue tags
    const topTags = Object.entries(this.stats.topTags || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);

    if (topTags.length > 0) {
      const header = new vscode.TreeItem('Top issue tags:', vscode.TreeItemCollapsibleState.None);
      header.iconPath = new vscode.ThemeIcon('tag');
      rows.push(header);

      for (const [tag, count] of topTags) {
        const ti = new vscode.TreeItem(`  ${tag}  (${count})`, vscode.TreeItemCollapsibleState.None);
        rows.push(ti);
      }
    }

    return rows;
  }

  _score() {
    if (!this.stats) return 100;
    const s = this.stats;
    const e = (s.security?.error || 0) + (s['ai-slop']?.error || 0) + (s['vibe-code']?.error || 0);
    const w = (s.security?.warning || 0) + (s['ai-slop']?.warning || 0) + (s['vibe-code']?.warning || 0);
    const i = (s.security?.info || 0) + (s['ai-slop']?.info || 0) + (s['vibe-code']?.info || 0);
    return Math.max(0, Math.round(100 - e * 10 - w * 3 - i * 0.5));
  }

  _grade(score) {
    if (score >= 95) return 'A+';
    if (score >= 85) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 40) return 'D';
    return 'F';
  }
}

module.exports = { IssuesTreeProvider, SummaryTreeProvider };
