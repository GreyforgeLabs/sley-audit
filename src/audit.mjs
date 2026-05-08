#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const DEFAULT_EXTENSIONS = new Set(['.rs', '.sley', '.js', '.mjs', '.ts', '.json', '.toml', '.md', '.yml', '.yaml']);
const SKIP_DIRS = new Set(['.git', 'node_modules', 'target', '.cache', 'dist']);

function usage() {
  return `sley-audit [--path <dir>] [--json] [--sarif <file>] [--allowlist <file>] [--fail-on-error]\n\n` +
    `  --path        Workspace to scan (default: .)\n` +
    `  --json        Emit structured JSON report\n` +
    `  --sarif       Write SARIF v2.1.0 report file\n` +
    `  --allowlist   Newline-separated regex allowlist file (path/message scoped)\n` +
    `  --fail-on-error  Exit 1 when findings are present\n`;
}

const args = process.argv.slice(2);
if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
  process.stdout.write(usage());
  process.exit(0);
}

const options = {
  path: '.',
  json: false,
  sarif: null,
  allowlistPath: null,
  failOnError: false,
  includeExtOnly: DEFAULT_EXTENSIONS,
};

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  if (arg === '--json') {
    options.json = true;
  } else if (arg === '--fail-on-error') {
    options.failOnError = true;
  } else if (arg === '--path') {
    options.path = args[++i];
    if (!options.path) {
      console.error('--path requires a value');
      process.exit(2);
    }
  } else if (arg === '--sarif') {
    options.sarif = args[++i];
    if (!options.sarif) {
      console.error('--sarif requires a file path');
      process.exit(2);
    }
  } else if (arg === '--allowlist') {
    options.allowlistPath = args[++i];
    if (!options.allowlistPath) {
      console.error('--allowlist requires a file path');
      process.exit(2);
    }
  } else {
    console.error(`unknown option: ${arg}`);
    process.stderr.write(usage());
    process.exit(2);
  }
}

const root = path.resolve(options.path);
if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
  console.error(`scan root does not exist or is not a directory: ${options.path}`);
  process.exit(2);
}

const allowlist = loadAllowlist(options.allowlistPath);

const rules = [
  {
    id: 'SLEY-AUDIT-DEBUG-FORMAT',
    severity: 'high',
    message: 'Debug formatter in logging-like macro can leak sensitive value shapes/contents',
    matcher: line => {
      const hasLoggerLikeCall = /\b(?:println|eprintln|format|dbg|panic|assert|error|warn|info|trace|debug)\s*!(?:\s*\()/.test(line);
      const hasDebugPlaceholder = /\{\s*[^{}]*:\s*#?\?[^{}]*\}/.test(line);
      return hasLoggerLikeCall && hasDebugPlaceholder;
    },
  },
  {
    id: 'SLEY-AUDIT-EXPLICIT-DEBUG-RECORD',
    severity: 'high',
    message: 'Explicit debug-record interpolation may output cleartext error fields',
    matcher: line => /\{\s*\w+(?:\.\w+)*(?:\{)?\s*:\s*#\?\s*\}?/.test(line),
  },
  {
    id: 'SLEY-AUDIT-SUSPECT-PANIC-LITERAL',
    severity: 'medium',
    message: 'panic-like message interpolates full runtime objects with debug format',
    matcher: line => /\bpanic\s*!\s*\([^\)]*\{[^\}]*\#?\?[^\}]*\}/.test(line),
  },
];

const findings = [];

walk(root, (filePath, content) => {
  const lines = content.split(/\r?\n/);
  for (let lineNumber = 0; lineNumber < lines.length; lineNumber += 1) {
    const line = lines[lineNumber];
    for (const rule of rules) {
      if (rule.matcher(line)) {
        const finding = {
          ruleId: rule.id,
          severity: rule.severity,
          message: rule.message,
          path: normalizePath(filePath),
          line: lineNumber + 1,
          column: 1,
          snippet: line.trim(),
        };
        if (!isAllowlisted(finding, allowlist)) {
          findings.push(finding);
        }
      }
    }
  }
});

const sorted = findings.sort((a, b) => {
  if (a.path !== b.path) return a.path.localeCompare(b.path);
  return a.line - b.line;
});

const status = sorted.length === 0 ? 'pass' : 'fail';

if (options.json) {
  console.log(JSON.stringify({
    schema: 'sley.audit.report.v0',
    generatedAt: new Date().toISOString(),
    status,
    totalFindings: sorted.length,
    findings: sorted,
  }, null, 2));
}

if (options.sarif) {
  writeSarif(sorted, root, options.sarif);
}

if (!options.json) {
  if (sorted.length === 0) {
    console.log(`sley-audit: PASS (${root})`);
  } else {
    console.log(`sley-audit: FAIL (${sorted.length} finding(s))`);
    for (const finding of sorted) {
      const displayPath = path.relative(root, finding.path).replace(/\\/g, '/');
      console.log(`${displayPath}:${finding.line} ${finding.ruleId} ${finding.severity}: ${finding.message}`);
      if (finding.snippet) {
        console.log(`  ${finding.snippet}`);
      }
    }
  }
}

if (options.failOnError && sorted.length > 0) {
  process.exit(1);
}

process.exit(0);

function walk(current, callback) {
  for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
    const fullPath = path.join(current, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) {
        continue;
      }
      walk(fullPath, callback);
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    const ext = path.extname(entry.name);
    if (DEFAULT_EXTENSIONS.has(ext) || shouldScanUnknownText(fullPath)) {
      const content = safeReadFile(fullPath);
      if (content !== null) {
        callback(fullPath, content);
      }
    }
  }
}

function shouldScanUnknownText(file) {
  const base = path.basename(file).toLowerCase();
  if (base.startsWith('.') || base === 'Cargo.lock') {
    return true;
  }
  const ext = path.extname(file).toLowerCase();
  return ext.length === 0;
}

function safeReadFile(file) {
  try {
    const buffer = fs.readFileSync(file);
    if (buffer.indexOf(0) !== -1) {
      return null;
    }
    return buffer.toString('utf8');
  } catch {
    return null;
  }
}

function loadAllowlist(file) {
  if (!file) return [];
  const full = path.resolve(file);
  if (!fs.existsSync(full)) {
    console.error(`allowlist file not found: ${file}`);
    process.exit(2);
  }
  const content = fs.readFileSync(full, 'utf8');
  const entries = [];
  for (const line of content.split(/\r?\n/)) {
    const value = line.trim();
    if (!value || value.startsWith('#')) {
      continue;
    }
    try {
      entries.push(new RegExp(value));
    } catch {
      console.error(`invalid allowlist regex: ${value}`);
      process.exit(2);
    }
  }
  return entries;
}

function isAllowlisted(finding, entries) {
  if (entries.length === 0) {
    return false;
  }
  const haystack = `${finding.path}:${finding.line}:${finding.snippet}`;
  return entries.some((re) => re.test(finding.path) || re.test(haystack) || re.test(finding.message));
}

function normalizePath(file) {
  return file.replace(/\\/g, '/');
}

function writeSarif(items, rootDir, outFile) {
  const runTool = {
    driver: {
      name: 'sley-audit',
      semanticVersion: '0.1.0',
      informationUri: 'https://sley.greyforge.tech/tools/sley-audit',
      rules: deriveRules(items),
    },
  };
  const results = items.map((finding) => ({
    ruleId: finding.ruleId,
    level: finding.severity === 'high' ? 'error' : 'warning',
    message: { text: finding.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: path.relative(rootDir, finding.path).replace(/^\.\//, '').replace(/\\/g, '/') },
          region: {
            startLine: finding.line,
            startColumn: finding.column,
          },
        },
      },
    ],
    properties: {
      snippet: finding.snippet,
      sha: findingFingerprint(finding),
    },
  }));
  const sarif = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0-rtm.5.json',
    runs: [
      {
        tool: runTool,
        results,
      },
    ],
  };
  fs.writeFileSync(outFile, `${JSON.stringify(sarif, null, 2)}\n`, 'utf8');
}

function deriveRules(items) {
  const grouped = new Map();
  for (const finding of items) {
    if (!grouped.has(finding.ruleId)) {
      grouped.set(finding.ruleId, {
        id: finding.ruleId,
        shortDescription: { text: finding.message },
        fullDescription: { text: finding.message },
        helpUri: 'https://sley.greyforge.tech/tools/sley-audit',
      });
    }
  }
  return [...grouped.values()];
}

function findingFingerprint(finding) {
  const h = crypto.createHash('sha1');
  h.update(finding.ruleId);
  h.update('\0');
  h.update(finding.path);
  h.update('\0');
  h.update(String(finding.line));
  h.update('\0');
  h.update(finding.snippet);
  return h.digest('hex');
}
