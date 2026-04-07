# Orix - Code Quality & Security Scanner

Orix is a powerful VS Code extension that scans your code for security vulnerabilities, AI-generated "slop" code, and vibe-coded traits — helping you maintain clean, secure, and disciplined code.

## What It Does

Orix reads your source files and applies three specialized scanners:

### Security
Finds patterns that cause exploits:
- Hardcoded passwords and secrets
- SQL injection and script injection risks
- Weak or broken cryptography
- Insecure TLS/SSL configurations
- And 30+ more security checks

### AI Slop Detection
Identifies low-effort or unreviewed AI-generated code:
- Placeholder variable names (`foo`, `bar`, `temp`)
- Empty catch blocks
- Redundant comments
- Copy-pasted duplicate blocks
- Raw AI preamble text left in code

### Vibe Code Detection
Flags code written by feel rather than discipline:
- Debug statements left in production
- Magic numbers without explanation
- Deep nesting (4+ levels)
- Missing error handling in async functions
- Loose equality (`==`) instead of strict (`===`)
- And 30+ more quality issues

## Quick Start

### Scan Current File
- **Keyboard:** `Cmd+Shift+A` (Mac) or `Ctrl+Shift+A` (Windows/Linux)
- **Right-click:** Editor context menu → **Orix: Scan Current File**
- **Click:** Shield icon in editor tab

### Scan Entire Workspace
- **Keyboard:** `Cmd+Shift+Alt+A` (Mac) or `Ctrl+Shift+Alt+A` (Windows/Linux)
- **Command Palette:** `Orix: Scan Entire Workspace`
- **Right-click:** Explorer context menu

### View Results
Results appear in three places:
- **Problems Panel** (`Cmd+Shift+M`) — inline with code, like TypeScript errors
- **Orix Sidebar** — click the shield icon in the Activity Bar
- **Full Report** — click "View Report" or run `Orix: Show Full Report`

## Auto-Fix Support

Press `Cmd+.` (Mac) or `Ctrl+.` (Windows/Linux) to apply quick fixes for:
- Security: Harden URLs, upgrade crypto, replace secrets with env vars
- Code Quality: Remove debug statements, convert `==` to `===`, clean up suppressions

## Configuration

Open VS Code Settings (`Cmd+,`) and search for **orix**:

| Setting | Default | Purpose |
|---------|---------|---------|
| `orix.autoScanOnSave` | `true` | Scan files when saved |
| `orix.autoScanOnOpen` | `true` | Scan files when opened |
| `orix.enableSecurity` | `true` | Enable security checks |
| `orix.enableAISlop` | `true` | Enable AI slop detection |
| `orix.enableVibeCode` | `true` | Enable vibe code detection |
| `orix.maxFileSizeKB` | `500` | Skip files larger than this |
| `orix.severityThreshold` | `info` | Minimum severity level to report |
| `orix.excludePatterns` | *see below* | Folders to skip in workspace scan |

Default exclude patterns: `node_modules`, `dist`, `build`, `.git`, `vendor`, minified files.

## Features

- Real-time scanning — Instant feedback as you code
- Workspace scanning — Check entire projects (up to 1,000 files)
- Smart grouping — View issues by category, file, or severity
- Health score — Get a 0–100 code quality grade
- Full report — Detailed analysis with filtering and recommendations
- Quick fixes — One-click remediation for common issues
- Customizable — Toggle scanners and adjust severity thresholds
- No dependencies — Pure JavaScript, no Node.js install required

## Requirements

- VS Code 1.85 or later
- No additional software or dependencies required

## Publisher

**Orix**

- GitHub: [orixcode](https://github.com/orixcode)
- Issues: [GitHub Issues](https://github.com/orixcode/orix/issues)
- Discord: [Join our Discord](https://discord.gg/hWD9Tt2M)

## License

MIT License — See LICENSE file for details.

---

**Found an issue?** [Report it on GitHub](https://github.com/orixcode/issues)
**Have a feature request?** [Create a discussion](https://github.com/orixcode/discussions)
