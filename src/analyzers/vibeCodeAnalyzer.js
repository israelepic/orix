/**
 * Orix - Code Quality & Security Scanner — Vibe Code Analyzer
 * Detects "vibe coding" traits: code written by feel rather than engineering discipline.
 */

'use strict';

const VIBE_RULES = [
  // ─── DEBUG LEFTOVERS ──────────────────────────────────────────────────────
  {
    id: 'VIBE001',
    name: 'console.log / console.debug Left In',
    severity: 'warning',
    pattern: /\bconsole\.(?:log|debug|info|dir|table)\s*\(/g,
    message: () => 'Debug console statement left in code. Remove before shipping or replace with a proper logger.',
    tags: ['debug', 'cleanup'],
  },
  {
    id: 'VIBE002',
    name: 'Python print() Debug Statement',
    severity: 'warning',
    pattern: /^\s*print\s*\(/gm,
    message: () => 'Debug print() statement. Use the logging module instead of print in production code.',
    tags: ['debug', 'python'],
  },
  {
    id: 'VIBE003',
    name: 'debugger Statement',
    severity: 'error',
    pattern: /\bdebugger\s*;/g,
    message: () => 'debugger statement halts execution in dev tools. Must be removed before committing.',
    tags: ['debug', 'cleanup'],
  },
  {
    id: 'VIBE004',
    name: 'var_dump / die() — PHP Debug',
    severity: 'error',
    pattern: /\b(?:var_dump|die|dd|dump)\s*\(/g,
    message: () => 'PHP debug statement (var_dump/die/dd). Remove before deploying.',
    tags: ['debug', 'php'],
  },
  {
    id: 'VIBE005',
    name: 'binding.pry / byebug — Ruby Debug',
    severity: 'error',
    pattern: /\b(?:binding\.pry|byebug|pry)\b/g,
    message: () => 'Ruby debugger statement. Remove before committing.',
    tags: ['debug', 'ruby'],
  },
  {
    id: 'VIBE006',
    name: 'Python pdb / breakpoint()',
    severity: 'error',
    pattern: /\b(?:pdb\.set_trace|breakpoint)\s*\(\)/g,
    message: () => 'Python debugger breakpoint detected. Remove before committing.',
    tags: ['debug', 'python'],
  },
  {
    id: 'VIBE007',
    name: 'Java System.out.println Debug',
    severity: 'warning',
    pattern: /System\.out\.println\s*\(/g,
    message: () => 'System.out.println detected. Use a proper logging framework (SLF4J, Log4j) in production code.',
    tags: ['debug', 'java'],
  },

  // ─── MAGIC NUMBERS ────────────────────────────────────────────────────────
  {
    id: 'VIBE010',
    name: 'Magic Number',
    severity: 'info',
    pattern: /(?<![A-Za-z_$.])(?!0\b|1\b|2\b|-1\b|100\b|1000\b)(\d{3,})\b(?!\s*(?:px|em|rem|%|vh|vw|ms|s|deg))/g,
    message: (match) => `Magic number: ${match}. Extract into a named constant to explain its meaning.`,
    tags: ['magic-numbers', 'readability'],
  },
  {
    id: 'VIBE011',
    name: 'Magic String Constant',
    severity: 'info',
    pattern: /(?:===?|!==?)\s*['\"`](?:[A-Z_]{3,}|[a-z_]{4,})['\"`]/g,
    message: () => 'Inline string comparison to a constant. Consider extracting to a named constant or enum.',
    tags: ['magic-strings', 'readability'],
  },
  {
    id: 'VIBE012',
    name: 'Unexplained Bitwise Hack',
    severity: 'info',
    pattern: /(?:\|0|~~\w|<<\s*0|>>>?\s*0)/g,
    message: (match) => `Unexplained bitwise operation "${match.trim()}" used as a type cast or optimization. Add a comment explaining why.`,
    tags: ['readability', 'magic-numbers'],
  },

  // ─── NESTING & COMPLEXITY ─────────────────────────────────────────────────
  {
    id: 'VIBE020',
    name: 'Deep Nesting (4+ levels)',
    severity: 'warning',
    customCheck: (lines) => {
      const issues = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const indent = line.match(/^(\s*)/)[1].length;
        const usesSpaces = !line.match(/^\t/);
        const indentUnit = usesSpaces ? 2 : 1;
        const nestLevel = Math.floor(indent / Math.max(indentUnit, 2));
        if (nestLevel >= 4 && line.trim().length > 0) {
          issues.push({
            line: i,
            message: `Deep nesting at ~${nestLevel} levels. Refactor using early returns, guard clauses, or extracted functions.`,
          });
        }
      }
      const deduped = [];
      let lastLine = -5;
      for (const issue of issues) {
        if (issue.line - lastLine > 3) { deduped.push(issue); lastLine = issue.line; }
      }
      return deduped;
    },
    tags: ['complexity', 'nesting'],
  },
  {
    id: 'VIBE021',
    name: 'God Function (60+ lines)',
    severity: 'warning',
    customCheck: (lines) => {
      const issues = [];
      let funcStart = -1;
      let braceDepth = 0;
      let inFunction = false;
      const funcPattern = /(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\(|(?:async\s+)?\w+\s*\()/;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!inFunction && funcPattern.test(line) && line.includes('{')) {
          funcStart = i;
          inFunction = true;
          braceDepth = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
        } else if (inFunction) {
          braceDepth += (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
          if (braceDepth <= 0) {
            const length = i - funcStart;
            if (length > 60) {
              issues.push({
                line: funcStart,
                message: `Function is ${length} lines long (lines ${funcStart + 1}–${i + 1}). Functions over 60 lines are hard to test. Break it up.`,
              });
            }
            inFunction = false;
            funcStart = -1;
            braceDepth = 0;
          }
        }
      }
      return issues;
    },
    tags: ['complexity', 'function-length'],
  },
  {
    id: 'VIBE022',
    name: 'Callback Hell',
    severity: 'warning',
    pattern: /function\s*\([^)]*\)\s*\{[^}]*function\s*\([^)]*\)\s*\{[^}]*function\s*\([^)]*\)\s*\{/g,
    message: () => 'Callback nesting 3+ deep (callback hell). Refactor with async/await or Promises.',
    tags: ['async', 'complexity'],
  },
  {
    id: 'VIBE023',
    name: 'Large File (500+ lines)',
    severity: 'info',
    customCheck: (lines) => {
      if (lines.length > 500) {
        return [{
          line: 0,
          message: `File has ${lines.length} lines. Files over 500 lines are hard to navigate and test. Consider splitting into modules.`,
        }];
      }
      return [];
    },
    tags: ['complexity', 'file-size'],
  },
  {
    id: 'VIBE024',
    name: 'Switch with Too Many Cases (10+)',
    severity: 'info',
    customCheck: (lines) => {
      const issues = [];
      let inSwitch = false;
      let switchStart = -1;
      let caseCount = 0;
      for (let i = 0; i < lines.length; i++) {
        const t = lines[i].trim();
        if (/\bswitch\s*\(/.test(t)) { inSwitch = true; switchStart = i; caseCount = 0; }
        if (inSwitch && /^\s*case\s+/.test(lines[i])) caseCount++;
        if (inSwitch && t === '}') {
          if (caseCount >= 10) {
            issues.push({ line: switchStart, message: `switch statement has ${caseCount} cases. Consider a lookup table or polymorphism instead.` });
          }
          inSwitch = false;
        }
      }
      return issues;
    },
    tags: ['complexity', 'design'],
  },

  // ─── ASYNC / ERROR HANDLING ───────────────────────────────────────────────
  {
    id: 'VIBE030',
    name: 'Unhandled Promise / Missing .catch()',
    severity: 'warning',
    pattern: /\b(?:fetch|axios\.get|axios\.post|\w+\.then\s*\([^)]+\))(?!\s*\.catch)/g,
    message: () => 'Promise chain without .catch() — unhandled rejections can crash Node.js and silently fail in browsers.',
    tags: ['async', 'error-handling'],
  },
  {
    id: 'VIBE031',
    name: 'async Function without try/catch',
    severity: 'warning',
    customCheck: (lines) => {
      const issues = [];
      const fullText = lines.join('\n');
      const asyncFuncPattern = /async\s+(?:function\s+\w+|\w+\s*=>\s*|\(\w*\)\s*=>)\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}/g;
      let match;
      while ((match = asyncFuncPattern.exec(fullText)) !== null) {
        const body = match[1];
        if (/\bawait\b/.test(body) && !/\btry\s*\{/.test(body)) {
          const lineNum = fullText.substring(0, match.index).split('\n').length - 1;
          issues.push({ line: lineNum, message: 'async function uses await without try/catch. Unhandled rejections will crash your application.' });
        }
      }
      return issues;
    },
    tags: ['async', 'error-handling'],
  },
  {
    id: 'VIBE032',
    name: 'Swallowed Error in catch',
    severity: 'warning',
    pattern: /catch\s*\([^)]+\)\s*\{\s*(?:\/\/[^\n]*\n\s*)?(?:return (?:null|false|undefined|""|'\s*'|\[\]|\{\});?\s*)\}/g,
    message: () => 'catch block swallows the error silently. Log it, handle it, or re-throw it.',
    tags: ['error-handling'],
  },
  {
    id: 'VIBE033',
    name: 'Promise.resolve/reject Anti-Pattern',
    severity: 'info',
    pattern: /return\s+new\s+Promise\s*\(\s*(?:resolve|reject)\s*=>\s*\{\s*(?:resolve|reject)\s*\(/g,
    message: () => 'Wrapping an already-resolved value in a new Promise is unnecessary. Return the value or a resolved promise directly.',
    tags: ['async', 'redundancy'],
  },

  // ─── POOR VARIABLE NAMING ─────────────────────────────────────────────────
  {
    id: 'VIBE040',
    name: 'Single-Letter Variable (outside loops)',
    severity: 'info',
    pattern: /\b(?:var|let|const)\s+([a-wyz])\s*=/g,
    message: (match) => {
      const varName = match.match(/\b(?:var|let|const)\s+([a-wyz])\b/)?.[1];
      return `Single-letter variable "${varName}" outside a loop. Use a descriptive name.`;
    },
    tags: ['naming', 'readability'],
  },
  {
    id: 'VIBE041',
    name: 'Double-Negative Variable Name',
    severity: 'info',
    pattern: /\b(?:isNot|notIs|noIs|notActive|notEnabled|notValid|notVisible|notFound|notLoaded|notReady)\b/g,
    message: (match) => `Double-negative variable name: "${match}". Rename to the positive and invert usage where needed.`,
    tags: ['naming', 'readability'],
  },
  {
    id: 'VIBE042',
    name: 'Hungarian Notation',
    severity: 'info',
    pattern: /\b(?:str[A-Z]|int[A-Z]|arr[A-Z]|obj[A-Z]|bln[A-Z]|num[A-Z]|fn[A-Z])\w+/g,
    message: (match) => `Hungarian notation: "${match}". Modern IDEs provide type info; descriptive names are more valuable.`,
    tags: ['naming', 'style'],
  },
  {
    id: 'VIBE043',
    name: 'Numbered Variable Siblings',
    severity: 'info',
    pattern: /\b(?:var|let|const)\s+\w+(\d)\s*=[\s\S]{0,200}(?:var|let|const)\s+\w+(?!\1)(\d)\s*=/g,
    message: () => 'Numbered variable siblings (e.g., data1, data2). Use an array or descriptive names instead.',
    tags: ['naming', 'design'],
  },

  // ─── STYLE ISSUES ─────────────────────────────────────────────────────────
  {
    id: 'VIBE050',
    name: 'Mixed Tabs and Spaces',
    severity: 'warning',
    customCheck: (lines) => {
      let hasTab = false, hasSpace = false, tabLine = -1, spaceLine = -1;
      for (let i = 0; i < Math.min(lines.length, 200); i++) {
        if (/^\t/.test(lines[i])) { hasTab = true; if (tabLine < 0) tabLine = i; }
        if (/^ {2,}/.test(lines[i])) { hasSpace = true; if (spaceLine < 0) spaceLine = i; }
      }
      if (hasTab && hasSpace) {
        return [{ line: Math.min(tabLine, spaceLine), message: 'Mixed tabs and spaces detected. Standardize on one indentation style and configure your editor.' }];
      }
      return [];
    },
    tags: ['style', 'formatting'],
  },
  {
    id: 'VIBE051',
    name: 'Trailing Whitespace',
    severity: 'info',
    pattern: /[ \t]+$/gm,
    message: () => 'Trailing whitespace. Configure your editor to strip trailing spaces on save.',
    tags: ['style', 'formatting'],
  },
  {
    id: 'VIBE052',
    name: 'Multiple Blank Lines',
    severity: 'info',
    pattern: /\n{4,}/g,
    message: () => '3+ consecutive blank lines. Max 2 blank lines between code sections.',
    tags: ['style', 'formatting'],
  },
  {
    id: 'VIBE053',
    name: 'Line Too Long (120+ chars)',
    severity: 'info',
    customCheck: (lines) => {
      const issues = [];
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].length > 120) {
          issues.push({ line: i, message: `Line is ${lines[i].length} chars (max recommended: 120). Break into multiple lines.` });
        }
      }
      return issues.slice(0, 10);
    },
    tags: ['style', 'readability'],
  },

  // ─── LOGIC SMELLS ─────────────────────────────────────────────────────────
  {
    id: 'VIBE060',
    name: 'Boolean Trap — Bare Boolean Param',
    severity: 'info',
    pattern: /\w+\s*\(\s*(?:[^,)]+,\s*){0,5}(?:true|false)\s*\)/g,
    message: () => 'Bare boolean argument in function call ("boolean trap"). Use named params or an options object for clarity.',
    tags: ['api-design', 'readability'],
  },
  {
    id: 'VIBE061',
    name: 'Nested Ternary Expression',
    severity: 'warning',
    pattern: /\?[^:?]+\?[^:?]+:[^;]+:[^;]+/g,
    message: () => 'Nested ternary expression. Unreadable and error-prone — extract to if/else or a named function.',
    tags: ['readability', 'complexity'],
  },
  {
    id: 'VIBE062',
    name: '== Instead of === (JavaScript)',
    severity: 'warning',
    pattern: /(?<![=!<>])={2}(?!=)(?![=])/g,
    message: () => 'Loose equality (==) can cause type coercion bugs. Use strict equality (===) in JavaScript.',
    tags: ['correctness', 'javascript'],
  },
  {
    id: 'VIBE063',
    name: 'Unnecessary else After Return',
    severity: 'info',
    pattern: /if\s*\([^)]+\)\s*\{[^}]*return[^}]*\}\s*else\s*\{/g,
    message: () => 'Unnecessary else after return. Remove the else block and reduce indentation.',
    tags: ['readability', 'style'],
  },
  {
    id: 'VIBE064',
    name: 'Object Mutation in Loop',
    severity: 'warning',
    pattern: /for\s*\([^)]+\)\s*\{[^}]*(?:push|splice|shift|unshift|sort|reverse)\s*\(/g,
    message: () => 'Array mutation inside a loop. Consider using map/filter/reduce for cleaner transformations.',
    tags: ['performance', 'functional'],
  },
  {
    id: 'VIBE065',
    name: 'Comparing to undefined Explicitly',
    severity: 'info',
    pattern: /(?:===?|!==?)\s*undefined/g,
    message: () => 'Explicit comparison to undefined is fragile. Use typeof x === "undefined" or x == null for safety.',
    tags: ['correctness', 'javascript'],
  },
  {
    id: 'VIBE066',
    name: 'typeof Compared to Non-String',
    severity: 'warning',
    pattern: /typeof\s+\w+\s*===?\s*(?!'(?:string|number|boolean|object|function|undefined|symbol|bigint)')['"`][^'\"`]+['"`]/g,
    message: () => 'typeof can only return specific string values. Check for typos in the comparison string.',
    tags: ['correctness', 'javascript'],
  },
  {
    id: 'VIBE067',
    name: 'Mutable Default Argument (Python)',
    severity: 'error',
    pattern: /def\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|list\(\)|dict\(\))/g,
    message: () => 'Mutable default argument in Python function. Use None as default and initialize inside the function to avoid shared state bugs.',
    tags: ['correctness', 'python'],
  },
  {
    id: 'VIBE068',
    name: 'Chained Assignment',
    severity: 'info',
    pattern: /\w+\s*=\s*\w+\s*=\s*\w+\s*=\s*/g,
    message: () => 'Chained assignment. Declare each variable separately for clarity and to avoid accidental global creation.',
    tags: ['readability', 'javascript'],
  },

  // ─── MISSING FUNDAMENTALS ─────────────────────────────────────────────────
  {
    id: 'VIBE070',
    name: 'No Input Validation on Request Param',
    severity: 'info',
    pattern: /(?:req\.body|req\.params|req\.query)\.\w+(?!\s*(?:&&|\?|trim|replace|validate|sanitize|parseInt|parseFloat|\[))/g,
    message: () => 'Request parameter used directly without visible validation. Always validate and sanitize external input.',
    tags: ['validation', 'robustness'],
  },
  {
    id: 'VIBE071',
    name: 'parseInt Without Radix',
    severity: 'warning',
    pattern: /\bparseInt\s*\([^,)]+\)/g,
    message: () => 'parseInt() called without a radix. Always specify parseInt(x, 10) to avoid octal/hex surprises.',
    tags: ['correctness', 'javascript'],
  },
  {
    id: 'VIBE072',
    name: 'Floating Point Equality',
    severity: 'warning',
    pattern: /[\d.]+\s*===?\s*[\d.]*\.\d+/g,
    message: () => 'Direct float equality comparison is unreliable. Use Math.abs(a - b) < Number.EPSILON instead.',
    tags: ['correctness', 'math'],
  },
  {
    id: 'VIBE073',
    name: 'Public Function Without JSDoc',
    severity: 'info',
    pattern: /(?:export\s+)?(?:async\s+)?function\s+[A-Z]\w+\s*\([^)]*\)\s*\{/g,
    message: () => 'Public/exported function without JSDoc or return annotation. Document public APIs.',
    tags: ['documentation', 'api'],
  },
  {
    id: 'VIBE074',
    name: 'Array Index Access Without Bounds Check',
    severity: 'info',
    pattern: /\w+\[(?:req\.|request\.|params\.|body\.)\w+\]/g,
    message: () => 'Array accessed with user-supplied index without bounds check. Validate the index before use.',
    tags: ['validation', 'robustness'],
  },
  {
    id: 'VIBE075',
    name: 'Missing null/undefined Check Before Access',
    severity: 'info',
    pattern: /(?:const|let|var)\s+\{\s*\w+(?:\s*,\s*\w+)*\s*\}\s*=\s*(?:req\.|request\.|params\.|body\.)/g,
    message: () => 'Destructuring request data without a null guard. If the body is missing or malformed, this will throw.',
    tags: ['validation', 'robustness'],
  },

  // ─── PERFORMANCE ANTIPATTERNS ────────────────────────────────────────────
  {
    id: 'VIBE080',
    name: 'Sync I/O in Async Context',
    severity: 'warning',
    pattern: /\breadFileSync\b|\bwriteFileSync\b|\bexecSync\b|\bexistsSync\b/g,
    message: (match) => `${match} blocks the event loop. Use the async version in async/server code.`,
    tags: ['performance', 'async', 'node'],
  },
  {
    id: 'VIBE081',
    name: 'await Inside a for Loop',
    severity: 'warning',
    pattern: /for\s*\([^)]+\)\s*\{[^}]*await\b/g,
    message: () => 'await inside a for loop runs requests sequentially. Use Promise.all() for parallel execution.',
    tags: ['performance', 'async'],
  },
  {
    id: 'VIBE082',
    name: 'DOM Query Inside Loop',
    severity: 'warning',
    pattern: /for\s*\([^)]+\)\s*\{[^}]*document\.querySelector/g,
    message: () => 'DOM query inside a loop causes repeated reflows. Cache the element reference outside the loop.',
    tags: ['performance', 'dom'],
  },
  {
    id: 'VIBE083',
    name: 'delete Operator on Object Property',
    severity: 'info',
    pattern: /\bdelete\s+\w+(?:\.\w+)+/g,
    message: () => "delete operator deoptimizes V8's hidden class structure. Set the property to undefined or reconstruct the object.",
    tags: ['performance', 'javascript'],
  },
  {
    id: 'VIBE084',
    name: 'JSON.parse(JSON.stringify()) for Deep Clone',
    severity: 'warning',
    pattern: /JSON\.parse\s*\(\s*JSON\.stringify\s*\(/g,
    message: () => 'JSON.parse(JSON.stringify(x)) is a lossy deep clone (drops undefined, Date, functions). Use structuredClone() or a library.',
    tags: ['performance', 'correctness'],
  },
  {
    id: 'VIBE085',
    name: 'String Concatenation in a Loop',
    severity: 'warning',
    pattern: /for\s*\([^)]+\)\s*\{[^}]*\+=\s*['\"`][^'\"`]*['\"`]/g,
    message: () => 'String concatenation inside a loop creates excessive garbage. Build an array and join() at the end.',
    tags: ['performance', 'strings'],
  },
  {
    id: 'VIBE086',
    name: 'Unnecessary Array Spread to Clone',
    severity: 'info',
    pattern: /\[\s*\.\.\.\w+\s*\](?!\s*\.(?:map|filter|reduce|forEach|find|some|every))/g,
    message: () => 'Array spread used purely to clone. Use [...arr] only when you need the clone — and document why.',
    tags: ['performance', 'clarity'],
  },
  {
    id: 'VIBE087',
    name: 'Object.keys().forEach() Instead of for...in',
    severity: 'info',
    pattern: /Object\.keys\s*\([^)]+\)\.forEach\s*\(/g,
    message: () => 'Object.keys().forEach() creates an intermediate array. Use for...of Object.keys() or for...in for better performance on large objects.',
    tags: ['performance', 'iteration'],
  },
  {
    id: 'VIBE088',
    name: 'Repeated Object Property Lookups',
    severity: 'info',
    pattern: /(?:\w+\.\w+\.\w+\b.{0,50}){4,}/g,
    message: () => 'Repeated deep property access. Destructure or cache the reference: const { x } = obj.deep.',
    tags: ['performance', 'readability'],
  },

  // ─── SECURITY HYGIENE (VIBE) ──────────────────────────────────────────────
  {
    id: 'VIBE090',
    name: 'alert() / prompt() / confirm() in Production',
    severity: 'warning',
    pattern: /\b(?:alert|prompt|confirm)\s*\(/g,
    message: () => 'Browser dialog (alert/prompt/confirm) detected. These block the UI and are not appropriate for production apps.',
    tags: ['ux', 'debug'],
  },
  {
    id: 'VIBE091',
    name: 'process.exit() Without Error Code',
    severity: 'info',
    pattern: /process\.exit\s*\(\s*\)/g,
    message: () => 'process.exit() with no argument (defaults to 0 = success). Use process.exit(1) to signal an error to the shell.',
    tags: ['node', 'correctness'],
  },
  {
    id: 'VIBE092',
    name: 'console.log(object) Without JSON.stringify',
    severity: 'info',
    pattern: /console\.log\s*\(\s*(?:req|res|request|response|err|error|data)\s*\)/g,
    message: () => 'Logging a complex object directly may show [Object object]. Use JSON.stringify(obj, null, 2) for readable output.',
    tags: ['debug', 'readability'],
  },
  {
    id: 'VIBE093',
    name: 'Hard-Coded Timeout Value',
    severity: 'info',
    pattern: /(?:setTimeout|setInterval)\s*\([^,]+,\s*(?:\d{4,})\s*\)/g,
    message: (match) => `Hard-coded timeout value detected. Extract to a named constant so the intent is clear.`,
    tags: ['magic-numbers', 'readability'],
  },
  {
    id: 'VIBE094',
    name: 'Unused catch Variable',
    severity: 'info',
    pattern: /catch\s*\(\s*(?:e|err|error|ex|exception)\s*\)\s*\{[^}]*(?!(?:e|err|error|ex|exception))[^}]*\}/g,
    message: () => 'Caught exception variable never used in catch block. Use catch { } (no variable) in modern JS, or log the error.',
    tags: ['cleanliness', 'error-handling'],
  },
  {
    id: 'VIBE095',
    name: 'require() Inside a Function',
    severity: 'warning',
    pattern: /(?<!\/\/.*)(?:const|let|var)\s+\w+\s*=\s*require\s*\([^)]+\)\s*;/g,
    message: () => 'require() call inside a function loads the module on every call. Move requires to the top of the file.',
    tags: ['performance', 'node'],
  },
  {
    id: 'VIBE096',
    name: 'Implicit Global Variable',
    severity: 'error',
    pattern: /^(?!(?:\s*\/\/|\s*\*|import|export|const|let|var|function|class|if|for|while|switch|try|return|throw|async|await|\/\*))(\s*)([a-z_$][a-zA-Z0-9_$]*)\s*=/gm,
    message: (match) => `Possible implicit global assignment: "${match.trim()}". Always declare variables with const, let, or var.`,
    tags: ['correctness', 'globals'],
  },
];

function analyzeVibeCodeIssues(text, filePath) {
  const issues = [];
  const lines = text.split('\n');

  for (const rule of VIBE_RULES) {
    if (rule.customCheck) {
      const customIssues = rule.customCheck(lines);
      for (const ci of customIssues) {
        issues.push({
          ruleId: rule.id,
          name: rule.name,
          category: 'vibe-code',
          severity: rule.severity,
          message: ci.message || rule.name,
          line: ci.line || 0,
          column: 0,
          endColumn: 80,
          lineText: (lines[ci.line] || '').trim(),
          tags: rule.tags,
          fix: null,
        });
      }
      continue;
    }

    const patternCopy = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match;
    while ((match = patternCopy.exec(text)) !== null) {
      const lineNumber = text.substring(0, match.index).split('\n').length - 1;
      const lineText = lines[lineNumber] || '';
      const colStart = match.index - text.substring(0, match.index).lastIndexOf('\n') - 1;

      const trimmed = lineText.trim();
      if (rule.id !== 'VIBE001' && (trimmed.startsWith('//') || trimmed.startsWith('#'))) {
        continue;
      }

      issues.push({
        ruleId: rule.id,
        name: rule.name,
        category: 'vibe-code',
        severity: rule.severity,
        message: rule.message(match[0]),
        line: lineNumber,
        column: Math.max(0, colStart),
        endColumn: Math.max(0, colStart) + match[0].length,
        lineText: lineText.trim(),
        tags: rule.tags,
        fix: null,
      });
    }
  }

  return issues;
}

module.exports = { analyzeVibeCodeIssues, VIBE_RULES };
