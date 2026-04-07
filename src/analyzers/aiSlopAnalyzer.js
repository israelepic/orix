/**
 * Orix - Code Quality & Security Scanner — AI Slop Analyzer
 * Detects lazy, AI-generated, placeholder, and low-effort code patterns.
 */

'use strict';

const AI_SLOP_RULES = [
  // ─── PLACEHOLDER COMMENTS ─────────────────────────────────────────────────
  {
    id: 'SLOP001',
    name: 'TODO: Implement This',
    severity: 'warning',
    pattern: /\/\/\s*TODO\s*:?\s*(?:implement|add|fix|complete|finish|handle|write|do|update)\s+(?:this|here|logic|functionality|feature|it)/gi,
    message: () => 'Unimplemented TODO. Often left by AI code generation — fill in the actual logic.',
    tags: ['placeholder', 'incomplete'],
  },
  {
    id: 'SLOP002',
    name: 'Empty Catch Block',
    severity: 'warning',
    pattern: /catch\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*\n\s*)?\}/g,
    message: () => 'Empty catch block. Either handle the error or at minimum log it with context.',
    tags: ['error-handling', 'placeholder'],
  },
  {
    id: 'SLOP003',
    name: 'Generic AI Comment — Obvious Restatement',
    severity: 'info',
    pattern: /\/\/\s*(?:This function|This method|This code|The following code|Here we|We (?:then|now|first|next)|This (?:will|is|creates?|returns?|handles?|checks?|gets?|sets?))\s/gi,
    message: () => 'Comment restates what the code obviously does — a hallmark of AI-generated filler. Replace with "why" context.',
    tags: ['comments', 'ai-generated'],
  },
  {
    id: 'SLOP004',
    name: 'Placeholder Variable Names',
    severity: 'warning',
    pattern: /\b(?:var|let|const)\s+(foo|bar|baz|qux|quux|temp|tmp|test|data2?|result2?|val2?|item2?|thing|stuff|obj2?|arr2?|str2?|num2?)\b/gi,
    message: (match) => `Placeholder variable name: "${match.split(/\s+/)[1]}". Use a descriptive name that explains what this holds.`,
    tags: ['naming', 'placeholder'],
  },
  {
    id: 'SLOP005',
    name: 'Boilerplate Function Names',
    severity: 'info',
    pattern: /(?:function|const|let)\s+(doSomething|handleThing|processData|getData|setData|doStuff|myFunction|testFunction|handleEvent|doAction|runProcess|executeTask|performAction)\s*[=(]/gi,
    message: () => 'Generic function name detected. Rename to reflect its specific purpose.',
    tags: ['naming', 'ai-generated'],
  },
  {
    id: 'SLOP006',
    name: 'Lorem Ipsum Text',
    severity: 'warning',
    pattern: /lorem\s+ipsum/gi,
    message: () => 'Lorem ipsum placeholder text in code. Replace with real content or proper i18n strings.',
    tags: ['placeholder', 'content'],
  },
  {
    id: 'SLOP007',
    name: 'Generic Error Messages',
    severity: 'info',
    pattern: /['\"`](?:Something went wrong|An error occurred|Error occurred|Oops[!,]? Something went wrong|Something happened|Unexpected error|An unexpected error|Request failed)['\"`\s;]/gi,
    message: () => 'Generic error message. Users deserve actionable, specific error messages.',
    tags: ['ux', 'error-messages'],
  },
  {
    id: 'SLOP008',
    name: 'AI Preamble in Comments/Strings',
    severity: 'error',
    pattern: /(?:as an ai|as a language model|i (?:cannot|can't|am not able to)|i'm just an ai|i don't have the ability)/gi,
    message: () => 'AI model preamble detected in code. This is raw LLM output that was not reviewed.',
    tags: ['ai-generated', 'unreviewed'],
  },
  {
    id: 'SLOP009',
    name: 'Unimplemented Method Stub',
    severity: 'warning',
    pattern: /(?:function|(?:async\s+)?(?:\w+\s+)?\w+\s*\([^)]*\)\s*\{)\s*(?:\/\/[^\n]*)?\s*(?:throw new Error\s*\(\s*['"`](?:Not implemented|TODO|not yet implemented))/gi,
    message: () => 'Unimplemented stub that throws "Not Implemented". Replace with actual logic before shipping.',
    tags: ['placeholder', 'incomplete'],
  },
  {
    id: 'SLOP010',
    name: 'Commented-Out Code Block',
    severity: 'info',
    pattern: /(?:\/\/[^\n]*\n){4,}/g,
    message: () => '4+ consecutive commented lines — likely commented-out code. Remove dead code; use version control instead.',
    tags: ['dead-code', 'maintenance'],
  },
  {
    id: 'SLOP011',
    name: 'Hardcoded Test Email',
    severity: 'warning',
    pattern: /['\"`](?:test@test\.com|test@example\.com|foo@bar\.com|john\.doe@|jane\.doe@|user@user\.com)['\"`]/gi,
    message: () => 'Hardcoded test email address. Use proper test fixtures.',
    tags: ['test-data', 'placeholder'],
  },
  {
    id: 'SLOP012',
    name: 'Hardcoded Test Phone/Name',
    severity: 'info',
    pattern: /['\"`](?:John Doe|Jane Doe|Test User|Sample User|Dummy User|Fake User|Example User|\+1234567890|555-1234)['\"`]/gi,
    message: () => 'Hardcoded test/placeholder personal data. Replace with proper test fixtures.',
    tags: ['test-data', 'placeholder'],
  },
  {
    id: 'SLOP013',
    name: 'Python Empty Stub (pass)',
    severity: 'info',
    pattern: /def\s+\w+\s*\([^)]*\)\s*:\s*\n\s*pass\b/g,
    message: () => 'Python function with only "pass" — unimplemented stub.',
    tags: ['placeholder', 'python'],
  },
  {
    id: 'SLOP014',
    name: 'Stub Return with TODO',
    severity: 'info',
    pattern: /^\s*(?:return false;|return null;|return None;|return "";|return \[\];|return \{\};)\s*\/\/\s*(?:TODO|FIXME|temp|placeholder|stub)/gim,
    message: () => 'Stub return with TODO marker. Implement the actual return logic.',
    tags: ['placeholder', 'incomplete'],
  },
  {
    id: 'SLOP015',
    name: 'Excessive Inline Comment Density',
    severity: 'info',
    customCheck: (lines) => {
      const issues = [];
      let commentCount = 0;
      let codeCount = 0;
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('#')) commentCount++;
        else if (trimmed.length > 0) codeCount++;
        if ((i + 1) % 20 === 0 && codeCount > 0) {
          const ratio = commentCount / (codeCount + commentCount);
          if (ratio > 0.6) {
            issues.push({
              line: i,
              message: `High comment density (${Math.round(ratio * 100)}% comments in last 20 lines) — may indicate over-explained AI output.`,
            });
          }
          commentCount = 0;
          codeCount = 0;
        }
      }
      return issues;
    },
    tags: ['ai-generated', 'comments'],
  },
  {
    id: 'SLOP016',
    name: 'Copy-Paste Duplication',
    severity: 'warning',
    customCheck: (lines) => {
      const issues = [];
      const blockSize = 5;
      const seen = new Map();
      for (let i = 0; i <= lines.length - blockSize; i++) {
        const block = lines.slice(i, i + blockSize)
          .map(l => l.trim())
          .filter(l => l.length > 3 && !l.startsWith('//'))
          .join('\n');
        if (block.length < 80) continue;
        if (seen.has(block)) {
          const firstLine = seen.get(block);
          if (i - firstLine > blockSize * 2) {
            issues.push({
              line: i,
              message: `Duplicate code block (first seen at line ${firstLine + 1}). Extract to a shared function.`,
            });
          }
        } else {
          seen.set(block, i);
        }
      }
      return issues.slice(0, 5);
    },
    tags: ['duplication', 'maintenance'],
  },
  {
    id: 'SLOP017',
    name: 'AI-Style Step Comment Chain',
    severity: 'info',
    pattern: /(?:\/\/\s*(?:Step\s*\d+|First[,:]|Next[,:]|Then[,:]|Finally[,:]|After that[,:]|Now[,:]).*\n){3,}/gm,
    message: () => 'Step-by-step narrative comments are a hallmark of AI-generated code. Replace with meaningful function decomposition.',
    tags: ['ai-generated', 'comments'],
  },
  {
    id: 'SLOP018',
    name: 'Overly Long Block Comment',
    severity: 'info',
    pattern: /\/\*{1,2}[\s\S]{300,}?\*\//gm,
    message: () => 'Very long block comment (300+ chars). Verify this was intentionally written and not AI-dumped documentation.',
    tags: ['ai-generated', 'comments'],
  },
  {
    id: 'SLOP019',
    name: 'FIXME / HACK / XXX Marker',
    severity: 'warning',
    pattern: /\/\/\s*(?:FIXME|HACK|XXX|BUG|BROKEN|KLUDGE)\b/gi,
    message: (match) => `${match.trim()} marker detected. Track this in a proper issue tracker, not a code comment.`,
    tags: ['placeholder', 'technical-debt'],
  },
  {
    id: 'SLOP020',
    name: 'Hardcoded localhost URL',
    severity: 'info',
    pattern: /['\"`]https?:\/\/localhost(?::\d+)?(?:\/[^'\"`]*)?['\"`]/gi,
    message: () => 'Hardcoded localhost URL. Move base URLs to environment config — this will break outside local.',
    tags: ['configuration', 'placeholder'],
  },
  {
    id: 'SLOP021',
    name: 'console.error with No Context',
    severity: 'info',
    pattern: /console\.error\s*\(\s*(?:e|err|error)\s*\)/g,
    message: () => 'Bare console.error(err) logs no context. Add a message: console.error("Failed to do X:", err).',
    tags: ['error-handling', 'debug'],
  },
  {
    id: 'SLOP022',
    name: 'Hardcoded Version String',
    severity: 'info',
    pattern: /['\"`]v?\d+\.\d+\.\d+['\"`]\s*(?:\/\/|;|,)/g,
    message: () => 'Hardcoded version string in code. Import from package.json or config instead.',
    tags: ['configuration', 'maintenance'],
  },
  {
    id: 'SLOP023',
    name: 'Overly Generic Class Name',
    severity: 'info',
    pattern: /\bclass\s+(?:Manager|Handler|Helper|Util|Utils|Base|Common|Misc|Generic|Abstract|Default|Main|Core)(?:\s*\{|\s+extends)/g,
    message: (match) => `Generic class name in "${match.trim()}". Use a name describing what this class specifically does.`,
    tags: ['naming', 'design'],
  },
  {
    id: 'SLOP024',
    name: 'Python Bare except + pass',
    severity: 'warning',
    pattern: /except\s+Exception\s*(?:as\s+\w+)?\s*:\s*\n\s*pass\b/g,
    message: () => 'Python "except Exception: pass" silently swallows all errors. Handle or re-raise with context.',
    tags: ['error-handling', 'python'],
  },
  {
    id: 'SLOP025',
    name: 'Unnecessary Boolean Literal in Return',
    severity: 'info',
    pattern: /if\s*\([^)]+\)\s*\{\s*return\s+true\s*;\s*\}\s*(?:else\s*\{\s*)?return\s+false\s*;/g,
    message: () => 'Returning true/false from an if/else restates the condition. Return the boolean expression directly.',
    tags: ['readability', 'simplification'],
  },
  {
    id: 'SLOP026',
    name: 'Repeated String Literal',
    severity: 'info',
    customCheck: (lines) => {
      const issues = [];
      const counts = new Map();
      const stringPattern = /['\"`]([A-Za-z][A-Za-z0-9_\- ]{4,})['\"`]/g;
      const fullText = lines.join('\n');
      let match;
      while ((match = stringPattern.exec(fullText)) !== null) {
        const s = match[1];
        counts.set(s, (counts.get(s) || 0) + 1);
      }
      const reported = new Set();
      for (const [str, count] of counts) {
        if (count >= 4 && !reported.has(str)) {
          reported.add(str);
          issues.push({ line: 0, message: `String "${str}" repeated ${count} times. Extract to a named constant.` });
        }
      }
      return issues.slice(0, 5);
    },
    tags: ['duplication', 'maintainability'],
  },
  {
    id: 'SLOP027',
    name: 'Useless Default Then Immediate Reassignment',
    severity: 'info',
    pattern: /(?:let|var)\s+(\w+)\s*=\s*(?:null|undefined|0|false|""|'');?\s*\n(?:\s*\/\/[^\n]*)?\s*\1\s*=/gm,
    message: () => 'Variable given a default then immediately reassigned before use. Declare with the final value directly.',
    tags: ['redundancy', 'cleanliness'],
  },
  {
    id: 'SLOP028',
    name: '"any" Type Annotation (TypeScript)',
    severity: 'warning',
    pattern: /:\s*any\b/g,
    message: () => 'TypeScript "any" type defeats type safety. Use a specific type, union, or "unknown" instead.',
    tags: ['typescript', 'type-safety'],
  },
  {
    id: 'SLOP029',
    name: '@ts-ignore / @ts-nocheck',
    severity: 'warning',
    pattern: /\/\/\s*@ts-(?:ignore|nocheck)\b/g,
    message: () => 'TypeScript error suppression. Fix the underlying type error instead of suppressing the check.',
    tags: ['typescript', 'type-safety'],
  },
  {
    id: 'SLOP030',
    name: 'eslint-disable Comment',
    severity: 'info',
    pattern: /\/\/\s*eslint-disable(?:-next-line|-line)?\b/g,
    message: () => 'ESLint rule suppressed. Fix the underlying issue rather than silencing the linter.',
    tags: ['linting', 'technical-debt'],
  },
  {
    id: 'SLOP031',
    name: 'Placeholder URL (example.com)',
    severity: 'warning',
    pattern: /['\"`]https?:\/\/(?:example\.com|your-domain\.com|yourdomain\.com|yoursite\.com|placeholder\.com|your-api\.com)[^\s'\"`]*/gi,
    message: () => 'Placeholder URL detected. Replace with the actual endpoint or make it configurable via environment.',
    tags: ['placeholder', 'configuration'],
  },
  {
    id: 'SLOP032',
    name: 'Hardcoded Magic Port',
    severity: 'info',
    pattern: /(?:port|PORT)\s*[:=]\s*(?!process\.env)\b(?:3000|8080|8000|4200|5000|4000|9000)\b/gi,
    message: (match) => `Hardcoded port in "${match.trim()}". Use process.env.PORT with a fallback.`,
    tags: ['configuration', 'deployment'],
  },
  {
    id: 'SLOP033',
    name: '"Works on My Machine" Comment',
    severity: 'info',
    pattern: /\/\/.*(?:works on my machine|works locally|only tested on|tested in chrome only|idk why this works)/gi,
    message: () => '"Works on my machine" comment. Investigate and write a proper fix or regression test.',
    tags: ['quality', 'ai-generated'],
  },
  {
    id: 'SLOP034',
    name: 'Excessive Function Arguments (5+)',
    severity: 'warning',
    pattern: /function\s+\w+\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+/g,
    message: () => 'Function has 5+ parameters. Group related params into a config/options object.',
    tags: ['api-design', 'complexity'],
  },
  {
    id: 'SLOP035',
    name: 'Hardcoded Database Name',
    severity: 'info',
    pattern: /(?:database|dbName|databaseName)\s*[:=]\s*['\"`](?!test|memory|:memory:)\w+['\"`]/gi,
    message: () => 'Hardcoded database name. Move to environment config to support multiple environments.',
    tags: ['configuration', 'database'],
  },
  {
    id: 'SLOP036',
    name: 'TODO Without Ticket Reference',
    severity: 'info',
    pattern: /\/\/\s*TODO(?!\s*[:\-]?\s*(?:#\d+|\[|\())/gi,
    message: () => 'TODO without a ticket/issue reference. Link to the tracking issue: // TODO #123: description.',
    tags: ['process', 'technical-debt'],
  },
  {
    id: 'SLOP037',
    name: 'Deeply Chained Optional Access (4+)',
    severity: 'info',
    pattern: /\?\.\w+\?\.\w+\?\.\w+\?\.\w+/g,
    message: () => 'Deep optional chaining (4+ levels) suggests missing data contracts. Define proper interfaces/types.',
    tags: ['type-safety', 'design'],
  },
  {
    id: 'SLOP038',
    name: 'Spread in Tight Loop',
    severity: 'warning',
    pattern: /for\s*\([^)]+\)\s*\{[^}]*\.\.\./g,
    message: () => 'Spread operator inside a loop creates a new array/object on every iteration. Preallocate outside the loop.',
    tags: ['performance', 'ai-generated'],
  },
];

function analyzeAISlopIssues(text, filePath) {
  const issues = [];
  const lines = text.split('\n');

  for (const rule of AI_SLOP_RULES) {
    if (rule.customCheck) {
      const customIssues = rule.customCheck(lines);
      for (const ci of customIssues) {
        issues.push({
          ruleId: rule.id,
          name: rule.name,
          category: 'ai-slop',
          severity: rule.severity,
          message: ci.message || `[${rule.id}] ${rule.name}`,
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

      issues.push({
        ruleId: rule.id,
        name: rule.name,
        category: 'ai-slop',
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

module.exports = { analyzeAISlopIssues, AI_SLOP_RULES };
