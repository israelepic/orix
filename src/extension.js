/**
 * Orix - Code Quality & Security Scanner
 * Named after the all-seeing giant of Greek mythology.
 *
 * Main entry: registers all commands, providers, and event listeners.
 * This file must not throw during activation — all errors are caught and reported.
 */

'use strict';

const vscode = require('vscode');
const { scanDocument, scanWorkspace, computeStats } = require('./providers/diagnosticsProvider');
const { IssuesTreeProvider, SummaryTreeProvider } = require('./providers/treeProvider');
const { ReportPanel } = require('./panels/reportPanel');

/** @type {vscode.DiagnosticCollection} */
let diagnosticCollection;
/** @type {IssuesTreeProvider} */
let issuesTreeProvider;
/** @type {SummaryTreeProvider} */
let summaryTreeProvider;

// Shared state
const issuesByFile = new Map();
let autoScanEnabled = true;
let lastScanMeta = null;

/**
 * Extension activation.
 * VS Code calls this when any activation event fires (see package.json activationEvents).
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  try {
    _activate(context);
  } catch (err) {
    vscode.window.showErrorMessage(`Orix failed to activate: ${err.message}\n${err.stack}`);
    console.error('[Orix] Activation error:', err);
  }
}

function _activate(context) {
  // ── DIAGNOSTICS COLLECTION ──────────────────────────────────────────────
  // This is what powers the Problems panel (Cmd+Shift+M)
  diagnosticCollection = vscode.languages.createDiagnosticCollection('orix');
  context.subscriptions.push(diagnosticCollection);

  // ── CODE ACTIONS (AUTO-FIX) ──────────────────────────────────────────────
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider([{ scheme: 'file' }, { scheme: 'untitled' }], new OrixCodeActionProvider(), {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
    })
  );

  // ── TREE VIEW PROVIDERS ──────────────────────────────────────────────────
  // Create tree views to ensure they are properly registered
  issuesTreeProvider = new IssuesTreeProvider();
  summaryTreeProvider = new SummaryTreeProvider();

  const issuesView = vscode.window.createTreeView('orix.issuesView', {
    treeDataProvider: issuesTreeProvider
  });
  const summaryView = vscode.window.createTreeView('orix.summaryView', {
    treeDataProvider: summaryTreeProvider
  });

  context.subscriptions.push(issuesView, summaryView);

  // ── STATUS BAR ──────────────────────────────────────────────────────────
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'orix.scanCurrentFile';
  statusBar.text = '$(eye) Orix';
  statusBar.tooltip = 'Orix: Click to scan current file (Cmd+Shift+A)';
  statusBar.show();
  context.subscriptions.push(statusBar);

  // ── COMMANDS ─────────────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.commands.registerCommand('orix.scanCurrentFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('Orix: Open a file to scan it.');
        return;
      }
      await runFileScan(editor.document, { silent: false });
    }),

    vscode.commands.registerCommand('orix.scanWorkspace', async () => {
      if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
        vscode.window.showInformationMessage('Orix: Open a workspace folder to scan it.');
        return;
      }
      await runWorkspaceScan();
    }),

    vscode.commands.registerCommand('orix.showReport', () => {
      const allIssues = _getAllIssues();
      const stats = computeStats(allIssues);
      ReportPanel.createOrShow(context, { issues: allIssues, stats, meta: lastScanMeta || {} });
    }),

    vscode.commands.registerCommand('orix.clearDiagnostics', () => {
      diagnosticCollection.clear();
      issuesByFile.clear();
      issuesTreeProvider.clear();
      summaryTreeProvider.refresh(null, null);
      _updateStatusBar(statusBar, 0, 0);
      vscode.window.showInformationMessage('Orix: Diagnostics cleared.');
    }),

    vscode.commands.registerCommand('orix.toggleAutoScan', () => {
      autoScanEnabled = !autoScanEnabled;
      vscode.window.showInformationMessage(
        `Orix: Auto-scan ${autoScanEnabled ? 'enabled' : 'disabled'}.`
      );
    }),

    // Navigation from tree items
    vscode.commands.registerCommand('orix.goToIssue', async (issue) => {
      if (!issue || !issue.file) return;
      try {
        const uri = vscode.Uri.file(issue.file);
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
        const pos = new vscode.Position(Math.max(0, issue.line), Math.max(0, issue.column || 0));
        editor.selection = new vscode.Selection(pos, pos);
        editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
      } catch (err) {
        vscode.window.showErrorMessage(`Orix: Could not navigate to issue — ${err.message}`);
      }
    }),

    // Grouping commands
    vscode.commands.registerCommand('orix.groupByCategory', () => {
      issuesTreeProvider.setGroupBy('category');
    }),
    vscode.commands.registerCommand('orix.groupByFile', () => {
      issuesTreeProvider.setGroupBy('file');
    }),
    vscode.commands.registerCommand('orix.groupBySeverity', () => {
      issuesTreeProvider.setGroupBy('severity');
    })
  );

  // ── EVENT LISTENERS ──────────────────────────────────────────────────────

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      if (!autoScanEnabled) return;
      const config = vscode.workspace.getConfiguration('orix');
      if (config.get('autoScanOnSave', true)) {
        await runFileScan(document, { silent: true });
        _updateStatusBarFromFile(statusBar, document.uri.fsPath);
      }
    })
  );

  // Auto-scan on file open
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(async (editor) => {
      if (!editor || !autoScanEnabled) return;
      const config = vscode.workspace.getConfiguration('orix');
      if (config.get('autoScanOnOpen', true)) {
        await runFileScan(editor.document, { silent: true });
        _updateStatusBarFromFile(statusBar, editor.document.uri.fsPath);
      }
    })
  );

  // ── SCAN ON STARTUP ──────────────────────────────────────────────────────
  // Small delay to let VS Code finish initialising before we scan
  const activeEditor = vscode.window.activeTextEditor;
  if (activeEditor) {
    setTimeout(() => {
      runFileScan(activeEditor.document, { silent: true }).then(() => {
        _updateStatusBarFromFile(statusBar, activeEditor.document.uri.fsPath);
      });
    }, 1000);
  }
}

// ── SCAN FUNCTIONS ─────────────────────────────────────────────────────────

/**
 * Scan a single TextDocument.
 * @param {vscode.TextDocument} document
 * @param {{ silent?: boolean }} options
 */
async function runFileScan(document, options = {}) {
  const { silent = false } = options;

  let result;
  try {
    result = scanDocument(document, diagnosticCollection);
  } catch (err) {
    console.error('[Orix] Scan error:', err);
    if (!silent) vscode.window.showErrorMessage(`Orix scan failed: ${err.message}`);
    return;
  }

  if (result.stats?.skipped) {
    if (!silent) vscode.window.showInformationMessage(`Orix: Skipped — ${result.stats.reason}`);
    return;
  }

  // Attach file path to each issue so tree navigation works
  const filePath = document.uri.fsPath;
  const issuesWithFile = result.issues.map(i => ({ ...i, file: filePath }));
  issuesByFile.set(filePath, issuesWithFile);

  lastScanMeta = { files: issuesByFile.size, time: result.elapsed || 0 };

  // Refresh sidebar
  issuesTreeProvider.refresh(issuesByFile);
  summaryTreeProvider.refresh(computeStats(_getAllIssues()), lastScanMeta);

  if (!silent) {
    const count = issuesWithFile.length;
    const errors = issuesWithFile.filter(i => i.severity === 'error').length;
    if (count === 0) {
      vscode.window.showInformationMessage('Orix: No issues found in this file.');
    } else {
      const label = `Orix: ${count} issue(s) found (${errors} error(s)). Check the Problems panel or sidebar.`;
      const action = await vscode.window.showWarningMessage(label, 'View Report');
      if (action === 'View Report') vscode.commands.executeCommand('orix.showReport');
    }
  }
}

/**
 * Scan every eligible file in the workspace with a progress indicator.
 */
async function runWorkspaceScan() {
  const start = Date.now();

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Orix: Scanning workspace…',
      cancellable: true,
    },
    async (progress, token) => {
      diagnosticCollection.clear();
      issuesByFile.clear();

      let lastPct = 0;

      const result = await scanWorkspace(diagnosticCollection, ({ current, total, file }) => {
        if (token.isCancellationRequested) return;
        const pct = Math.round((current / total) * 100);
        if (pct > lastPct) {
          progress.report({
            increment: pct - lastPct,
            message: `${current}/${total} — ${file.split(/[/\\]/).pop()}`,
          });
          lastPct = pct;
        }
      });

      if (token.isCancellationRequested) return;

      // Group by file into shared state
      for (const issue of result.issues) {
        const key = issue.file;
        if (!issuesByFile.has(key)) issuesByFile.set(key, []);
        issuesByFile.get(key).push(issue);
      }

      const elapsed = Date.now() - start;
      lastScanMeta = { files: result.scanned, time: elapsed };

      const allIssues = _getAllIssues();
      const stats = computeStats(allIssues);

      issuesTreeProvider.refresh(issuesByFile);
      summaryTreeProvider.refresh(stats, lastScanMeta);

      const total = allIssues.length;
      const errors = allIssues.filter(i => i.severity === 'error').length;

      if (total === 0) {
        vscode.window.showInformationMessage(
          `Orix: Scanned ${result.scanned} file(s) — no issues found.`
        );
      } else {
        const label = `Orix: ${result.scanned} files scanned. ${total} issues (${errors} errors) in ${elapsed}ms.`;
        const action = await vscode.window.showWarningMessage(label, 'View Report');
        if (action === 'View Report') vscode.commands.executeCommand('orix.showReport');
      }
    }
  );
}

// ── HELPERS ────────────────────────────────────────────────────────────────

function _getAllIssues() {
  const all = [];
  for (const issues of issuesByFile.values()) {
    all.push(...issues);
  }
  return all;
}

function _updateStatusBar(bar, total, errors) {
  if (total === 0) {
    bar.text = '$(shield) Orix';
    bar.tooltip = 'Orix: No issues';
    bar.color = undefined;
  } else if (errors > 0) {
    bar.text = `$(error) Orix: ${errors} error(s)`;
    bar.color = new vscode.ThemeColor('statusBarItem.errorBackground');
  } else {
    bar.text = `$(warning) Orix: ${total} issue(s)`;
    bar.color = undefined;
  }
}

function _updateStatusBarFromFile(bar, filePath) {
  const issues = issuesByFile.get(filePath) || [];
  const errors = issues.filter(i => i.severity === 'error').length;
  _updateStatusBar(bar, issues.length, errors);
}

function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.dispose();
  }
}

class OrixCodeActionProvider {
  provideCodeActions(document, range, context, token) {
    const actions = [];
    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'Orix') continue;
      const action = this._createCodeAction(document, diagnostic);
      if (action) actions.push(action);
    }
    return actions;
  }

  _createCodeAction(document, diagnostic) {
    const ruleId = typeof diagnostic.code === 'object' ? diagnostic.code.value : diagnostic.code;
    if (!ruleId) return null;

    const line = document.lineAt(diagnostic.range.start.line);
    const text = document.getText(diagnostic.range);
    const fix = this._getFixForRule(document, diagnostic, line, text);
    if (!fix) return null;

    const action = new vscode.CodeAction(fix.title, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diagnostic];
    action.isPreferred = true;
    action.edit = fix.edit;
    return action;
  }

  _getFixForRule(document, diagnostic, line, text) {
    const edit = new vscode.WorkspaceEdit();
    let replacement = null;
    let title = '';

    switch (ruleIdFromDiagnostic(diagnostic)) {
      case 'SEC001':
        title = 'Replace hardcoded secret with process.env.PASSWORD';
        replacement = text.replace(/['"`][^'"`\s]{3,}['"`]/, 'process.env.PASSWORD');
        break;

      case 'SEC040':
        title = 'Use HTTPS instead of HTTP';
        replacement = text.replace(/http:/i, 'https:');
        break;

      case 'SEC031':
      case 'SEC032':
        title = 'Upgrade hash algorithm to SHA-256';
        replacement = text.replace(/md5|sha1/gi, 'sha256');
        break;

      case 'VIBE062':
        title = 'Use strict equality operators';
        replacement = text.replace(/!=/g, '!==').replace(/(^|[^!])==(?!=)/g, '$1===');
        break;

      case 'VIBE001':
      case 'VIBE002':
      case 'VIBE003':
      case 'VIBE004':
      case 'VIBE005':
      case 'VIBE006':
      case 'VIBE007':
      case 'SLOP030':
        title = 'Remove debug or suppression line';
        edit.delete(document.uri, line.rangeIncludingLineBreak);
        return { title, edit };

      default:
        return null;
    }

    if (!replacement || replacement === text) return null;

    edit.replace(document.uri, diagnostic.range, replacement);
    return { title, edit };
  }
}

function ruleIdFromDiagnostic(diagnostic) {
  return typeof diagnostic.code === 'object' ? diagnostic.code.value : diagnostic.code;
}

module.exports = { activate, deactivate };
