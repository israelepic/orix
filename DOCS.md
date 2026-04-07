# Orix - Code Quality & Security Scanner
## How It Works & Installation Guide

Named after Argus Panoptes, the all-seeing giant of Greek mythology with a hundred eyes.

---

## What It Does

Orix reads your source files as plain text and applies three separate scanners to each one. Results appear in the VS Code Problems panel (the same place as TypeScript errors), in a sidebar panel, and in a full report view.

The three scanners are:

**Security** — Finds patterns that are known to cause exploits. Hardcoded passwords, SQL injection risks, `eval()` calls, disabled TLS verification, weak hashes, and so on. These are flagged as errors when they are actively dangerous, warnings when they are risky, and info when they are worth noting.

**AI Slop** — Finds traces of low-effort or unreviewed AI-generated code. This includes placeholder variable names (`foo`, `bar`, `temp`), empty catch blocks, comments that just restate what the code does, copy-pasted duplicate blocks, step-by-step comment chains, and raw AI preamble text that was never removed.

**Vibe Code** — Finds patterns that suggest the code was written by feel rather than with discipline. Debug statements left in (`console.log`, `debugger`), magic numbers, deeply nested code, god functions that are too long, async functions missing error handling, `==` instead of `===`, and similar issues.

---

## Installation

**Requirements:** VS Code 1.85 or later. No Node.js install required — the extension is pure JavaScript.

### Step 1 — Place the folder

Extract the zip and copy the `orix` folder into your VS Code extensions directory:

| Platform | Path |
|---|---|
| macOS | `~/.vscode/extensions/orix` |
| Windows | `%USERPROFILE%\.vscode\extensions\orix` |
| Linux | `~/.vscode/extensions/orix` |

The final path should look like `~/.vscode/extensions/orix/package.json`.

### Step 2 — Reload VS Code

Open the Command Palette with `Cmd+Shift+P` and run:
```
Developer: Reload Window
```

### Step 3 — Verify it loaded

Open the Command Palette and type `Orix`. You should see commands listed. If you see nothing, check the Extensions panel (`Cmd+Shift+X`) and look for Orix in the installed list.

---

## Using the Extension

### Scan a single file

- Keyboard: `Cmd+Shift+A` while the file is focused
- Right-click in the editor and choose **Orix: Scan Current File**
- Click the shield icon in the top-right of the editor tab

Results appear immediately in:
- The **Problems panel** (`Cmd+Shift+M`) — inline with your code, same as TypeScript errors
- The **Orix sidebar** — click the shield icon in the Activity Bar on the left
- **Squiggly underlines** directly in the editor

### Auto-Fixes (Quick Fixes)
Orix natively supports VS Code's Quick Fix feature (`Cmd+.` on Mac or `Ctrl+.` on Windows) for several easily rectifiable issues. For example, it can automatically upgrade `http` to `https`, convert `==` to `===`, upgrade `md5` hashes to `sha256`, or remove leftover debug statements with a single click.

### Scan an entire workspace

- Keyboard: `Cmd+Shift+Alt+A`
- Command Palette: `Orix: Scan Entire Workspace`
- Right-click a folder in the file explorer

A progress notification appears while it runs. It scans up to 1,000 files and skips `node_modules`, `dist`, `build`, `.git`, and minified files by default.

### The full report

After any scan, click **View Report** in the notification, or run `Orix: Show Full Report` from the Command Palette. This opens a panel with:
- A health score (0–100) and letter grade
- Issue counts per category
- A table of all issues you can filter and click to navigate
- A top tags chart
- Recommendations

---

## The Sidebar

Click the Orix icon (shield) in the Activity Bar on the left.

**Issues panel** — lists all findings. By default grouped by category. Use the icons at the top of the panel to group by file or by severity instead. Click any item to jump to that line.

**Summary panel** — shows your health score, files scanned, scan time, per-category counts, and the most frequent issue tags.

---

## Auto-Scan

By default, Orix scans a file when you open it and again when you save it. You can turn this off:
- Command Palette: `Orix: Toggle Auto-Scan on Save`
- Or in Settings: search `orix.autoScanOnSave` and set to false

---

## Configuration

Open VS Code Settings (`Cmd+,`) and search for **orix**.

| Setting | Default | What it does |
|---|---|---|
| `orix.autoScanOnSave` | `true` | Scan on every save |
| `orix.autoScanOnOpen` | `true` | Scan when a file is opened |
| `orix.enableSecurity` | `true` | Toggle the security scanner |
| `orix.enableAISlop` | `true` | Toggle the AI slop scanner |
| `orix.enableVibeCode` | `true` | Toggle the vibe code scanner |
| `orix.maxFileSizeKB` | `500` | Skip files larger than this |
| `orix.severityThreshold` | `info` | Set to `warning` or `error` to reduce noise |
| `orix.excludePatterns` | see below | Glob patterns skipped during workspace scan |

Default exclude patterns:
```
**/node_modules/**
**/dist/**
**/build/**
**/.git/**
**/vendor/**
**/*.min.js
**/*.bundle.js
```

---

## How the Scanners Work (Technical)

Each scanner is a plain JavaScript file in `src/analyzers/`. They receive the file's text as a string and return an array of issue objects. They have no dependency on VS Code — you can run them in Node.js directly if you want.

### Two types of rules

**Regex rules** — most rules are a single regular expression applied to the full file text. When a match is found, the line number is computed from the character offset, and an issue is created. Example:

```js
{
  id: 'SEC010',
  name: 'eval() Usage',
  severity: 'error',
  pattern: /\beval\s*\(/g,
  message: () => 'eval() executes arbitrary code...',
  tags: ['injection'],
}
```

**Custom check rules** — a few rules need to look at multiple lines together (nesting depth, function length, comment density, copy-paste). These use a `customCheck` function that receives all lines as an array:

```js
{
  id: 'VIBE020',
  name: 'Deep Nesting',
  severity: 'warning',
  customCheck: (lines) => {
    // measure indent depth per line
    // return [{ line: number, message: string }]
  }
}
```

### The diagnostics bridge

`src/providers/diagnosticsProvider.js` runs all three analyzers, deduplicates results (same rule on the same line only reported once), converts issues to VS Code `Diagnostic` objects, and writes them to a `DiagnosticCollection`. That collection is what powers the squiggly underlines and the Problems panel.

### The sidebar

`src/providers/treeProvider.js` provides two tree data providers registered with `registerTreeDataProvider`. They read from the same in-memory issue map that the diagnostics provider populates.

### The report panel

`src/panels/reportPanel.js` is a VS Code Webview — a sandboxed HTML page rendered inside VS Code. It receives the issue data as a JavaScript object embedded in the HTML, and posts messages back to the extension when the user clicks a row (to navigate to that line).

---

## Adding Your Own Rules

Open any file in `src/analyzers/` and add an entry to the rules array at the top of the file. Use an ID prefix that matches the file:
- `SEC` for security rules
- `SLOP` for AI slop rules  
- `VIBE` for vibe code rules

The extension will pick it up automatically — no registration needed.

---

## File Structure

```
argus/
├── package.json                    — Extension manifest, commands, settings
├── src/
│   ├── extension.js                — Activation, commands, event listeners
│   ├── analyzers/
│   │   ├── securityAnalyzer.js     — 30+ security rules
│   │   ├── aiSlopAnalyzer.js       — 18+ AI slop rules
│   │   └── vibeCodeAnalyzer.js     — 25+ vibe code rules
│   ├── providers/
│   │   ├── diagnosticsProvider.js  — Runs analyzers, writes to Problems panel
│   │   └── treeProvider.js         — Sidebar tree views (Issues + Summary)
│   └── panels/
│       └── reportPanel.js          — Full report webview
└── media/
    └── argus-icon.svg
```

---

## Troubleshooting

**"No data provider registered"** — The extension did not activate. Open the Output panel (`Cmd+Shift+U`), select **Argus** from the dropdown, and look for errors. Most likely cause: the folder was placed in the wrong location or VS Code was not reloaded after installation.

**No squiggles in editor** — Check that the file extension is supported (`.js`, `.ts`, `.py`, `.php`, etc.). Plain text and JSON files are not scanned. Also check `argus.severityThreshold` — if set to `error`, warnings and info items will not appear.

**Workspace scan is slow** — Reduce the scope by adding patterns to `argus.excludePatterns`, or lower `argus.maxFileSizeKB` to skip large generated files.

**Too much noise** — Set `argus.severityThreshold` to `warning` to hide informational items, or disable individual categories (`argus.enableVibeCode: false`).

---

## Changelog

### 1.1.0 (current)
- Renamed from Sentinel to Argus
- Fixed "no data provider registered" error — activation events now include the view IDs, and tree providers use `registerTreeDataProvider` (more reliable than `createTreeView`)
- Fixed `Object.assign` on `vscode.TreeItem` overwriting internal VS Code properties — tree item properties are now set directly
- Fixed sidebar navigation for single-file scans — file path is now correctly attached to each issue
- Removed emoji from all sidebar labels and tree items — VS Code codicons used throughout
- Added `elapsed` timing to `scanDocument` return value
- Status bar now updates per-file after each scan and shows error count
- `autoScanOnOpen` setting added separately from `autoScanOnSave`
- `.min.js` and `.bundle.js` excluded from workspace scans by default
- Workspace scan limit raised from 500 to 1,000 files
- Content Security Policy added to the report webview

### 1.0.0 (initial release)
- Three-category scanner: Security, AI Slop, Vibe Code
- 70+ detection rules across all categories
- Problems panel integration
- Sidebar Issues and Summary panels
- Full report webview with filtering and navigation
- Auto-scan on save and file open
- Workspace-wide scan with progress indicator
