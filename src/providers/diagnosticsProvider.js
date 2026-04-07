/**
 * Orix — Diagnostics Provider
 * Runs all three analyzers on a document and writes results to VS Code's Problems panel.
 */

'use strict';

const vscode = require('vscode');
const { analyzeSecurityIssues } = require('../analyzers/securityAnalyzer');
const { analyzeAISlopIssues } = require('../analyzers/aiSlopAnalyzer');
const { analyzeVibeCodeIssues } = require('../analyzers/vibeCodeAnalyzer');

/**
 * File extensions to scan. Anything not in this list is skipped silently.
 */
const SCANNABLE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.php', '.rb', '.java', '.c', '.cpp', '.cc',
  '.cs', '.go', '.rs', '.swift', '.kt', '.kts',
  '.html', '.vue', '.svelte', '.erb',
]);

/**
 * Convert our severity string to VS Code's DiagnosticSeverity enum.
 */
function toVSCodeSeverity(severity) {
  switch (severity) {
    case 'error':   return vscode.DiagnosticSeverity.Error;
    case 'warning': return vscode.DiagnosticSeverity.Warning;
    case 'info':    return vscode.DiagnosticSeverity.Information;
    default:        return vscode.DiagnosticSeverity.Hint;
  }
}

/**
 * Scan a single TextDocument.
 * Returns an array of Argus issue objects and updates the DiagnosticCollection.
 *
 * @param {vscode.TextDocument} document
 * @param {vscode.DiagnosticCollection} collection
 * @returns {{ issues: Array, stats: object, elapsed: number }}
 */
function scanDocument(document, collection) {
  const config = vscode.workspace.getConfiguration('orix');
  const maxKB   = config.get('maxFileSizeKB', 500);
  const doSec   = config.get('enableSecurity', true);
  const doSlop  = config.get('enableAISlop', true);
  const doVibe  = config.get('enableVibeCode', true);
  const threshold = config.get('severityThreshold', 'info');

  const filePath = document.uri.fsPath;
  const ext = filePath.slice(filePath.lastIndexOf('.')).toLowerCase();

  // Skip files we can't meaningfully analyse (binary, config-only, etc.)
  if (!SCANNABLE_EXTENSIONS.has(ext)) {
    return { issues: [], stats: {}, elapsed: 0, skipped: true, reason: `Unsupported file type (${ext})` };
  }

  const text = document.getText();

  if (text.length > maxKB * 1024) {
    collection.delete(document.uri);
    return { issues: [], stats: {}, elapsed: 0, skipped: true, reason: `File exceeds ${maxKB}KB limit` };
  }

  const start = Date.now();

  let raw = [];
  if (doSec)  raw = raw.concat(analyzeSecurityIssues(text, filePath));
  if (doSlop) raw = raw.concat(analyzeAISlopIssues(text, filePath));
  if (doVibe) raw = raw.concat(analyzeVibeCodeIssues(text, filePath));

  // Filter by severity threshold
  const order = { error: 3, warning: 2, info: 1 };
  const minOrder = order[threshold] || 0;
  const filtered = raw.filter(i => (order[i.severity] || 0) >= minOrder);

  // Deduplicate: same rule on the same line only reported once
  const seen = new Set();
  const deduped = filtered.filter(issue => {
    const key = `${issue.ruleId}:${issue.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Convert to VS Code Diagnostic objects
  const diagnostics = deduped.map(issue => {
    const lineNum   = Math.min(Math.max(0, issue.line), document.lineCount - 1);
    const lineLen   = document.lineAt(lineNum).text.length;
    const colStart  = Math.min(Math.max(0, issue.column || 0), lineLen);
    const colEnd    = Math.min(Math.max(colStart, issue.endColumn || lineLen), lineLen);

    const range = new vscode.Range(lineNum, colStart, lineNum, colEnd);
    const diag  = new vscode.Diagnostic(
      range,
      `[${issue.ruleId}] ${issue.message}`,
      toVSCodeSeverity(issue.severity)
    );

    // Source label shown in Problems panel (e.g. "Orix(SEC001)")
    diag.source = 'Orix';
    diag.code   = issue.ruleId;

    // Mark dead code (commented-out blocks) with the Unnecessary tag so VS Code
    // can render them faded rather than underlined.
    if (issue.tags && issue.tags.includes('dead-code')) {
      diag.tags = [vscode.DiagnosticTag.Unnecessary];
    }

    return diag;
  });

  collection.set(document.uri, diagnostics);

  const elapsed = Date.now() - start;
  const stats = computeStats(deduped);

  return { issues: deduped, diagnostics, stats, elapsed };
}

/**
 * Scan all eligible files in the workspace.
 * Calls onProgress({ current, total, file }) after each file.
 *
 * @param {vscode.DiagnosticCollection} collection
 * @param {Function} onProgress
 */
async function scanWorkspace(collection, onProgress) {
  const config = vscode.workspace.getConfiguration('orix');
  const excludePatterns = config.get('excludePatterns', [
    '**/node_modules/**', '**/dist/**', '**/build/**',
    '**/.git/**', '**/vendor/**', '**/*.min.js', '**/*.bundle.js',
  ]);

  const excludeGlob = `{${excludePatterns.join(',')}}`;
  const includeGlob = '**/*.{js,jsx,ts,tsx,mjs,cjs,py,php,rb,java,c,cpp,cs,go,rs,swift,kt,html,vue,svelte}';

  const files = await vscode.workspace.findFiles(includeGlob, excludeGlob, 1000);

  const allIssues = [];
  let scanned = 0;

  for (const uri of files) {
    try {
      const doc    = await vscode.workspace.openTextDocument(uri);
      const result = scanDocument(doc, collection);
      if (!result.skipped) {
        allIssues.push(
          ...result.issues.map(i => ({ ...i, file: uri.fsPath }))
        );
      }
    } catch (_) {
      // Skip files that can't be opened (binary, permission denied, etc.)
    }

    scanned++;
    if (onProgress) {
      onProgress({ current: scanned, total: files.length, file: uri.fsPath });
    }
  }

  return { issues: allIssues, scanned, total: files.length };
}

/**
 * Summarise an array of Argus issues into counts by category and severity.
 */
function computeStats(issues) {
  const stats = {
    total: issues.length,
    security:  { error: 0, warning: 0, info: 0 },
    'ai-slop': { error: 0, warning: 0, info: 0 },
    'vibe-code': { error: 0, warning: 0, info: 0 },
    byRule: {},
    topTags: {},
  };

  for (const issue of issues) {
    const cat = stats[issue.category];
    if (cat && issue.severity in cat) cat[issue.severity]++;

    stats.byRule[issue.ruleId] = (stats.byRule[issue.ruleId] || 0) + 1;

    for (const tag of (issue.tags || [])) {
      stats.topTags[tag] = (stats.topTags[tag] || 0) + 1;
    }
  }

  return stats;
}

module.exports = { scanDocument, scanWorkspace, computeStats };
