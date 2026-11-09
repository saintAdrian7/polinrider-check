#!/usr/bin/env node
// Removes the PolinRider payload from a config file and keeps the real config.
//
//   node clean-config.js <file> [--dry-run]
//
// What it does, in order:
//   1. Finds the first line that carries the payload: a known marker, or a run
//      of 8+ spaces followed by code on a line over 500 characters. Everything
//      from the marker (or the padding) to the end of that line is removed.
//      Lines after it are dropped too: the payload is always the last thing in
//      the file.
//   2. Removes the ESM shim the malware adds at the top of .mjs configs
//      (`import { createRequire } from 'module'` + `const require = createRequire(...)`).
//   3. Writes the result, keeping a copy of the original as <file>.polinrider.bak.
//
// With --dry-run it prints what would change and writes nothing. Review the
// result: if the config did not end with `};` or `export default ...`, check
// that the last real line survived.

const fs = require("fs");
const path = require("path");

const file = process.argv[2];
const dryRun = process.argv.includes("--dry-run");
if (!file) {
  console.error("usage: node clean-config.js <file> [--dry-run]");
  process.exit(2);
}

const MARKERS = [
  /global\s*\.\s*i\s*=\s*["']A\d+/,
  /global\s*\[\s*["']!["']\s*\]\s*=/,
  /global\s*\[\s*["']_V["']\s*\]\s*=/,
  /\("Cot%3t=shtP",\d+\)/,
  /\("rmcej%otb%",\d+\)/,
  /global\s*\[\s*["']r["']\s*\]\s*=\s*require/,
  /var\s+_0x[0-9a-f]{4,}\s*=/,
];

const original = fs.readFileSync(file, "utf8");
const eol = original.includes("\r\n") ? "\r\n" : "\n";
const lines = original.split(/\r?\n/);

let cutLine = -1;
let cutAt = -1;
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  let idx = -1;
  for (const m of MARKERS) {
    const found = line.search(m);
    if (found >= 0 && (idx < 0 || found < idx)) idx = found;
  }
  if (idx < 0 && line.length > 500) {
    const pad = line.search(/ {8,}\S/);
    if (pad >= 0) idx = pad;
  }
  if (idx >= 0) {
    cutLine = i;
    cutAt = idx;
    break;
  }
}

let out = lines.slice();
let removedPayload = false;
if (cutLine >= 0) {
  // Keep what precedes the payload on that line, trimmed of the padding.
  out = lines.slice(0, cutLine + 1);
  out[cutLine] = lines[cutLine].slice(0, cutAt).replace(/\s+$/, "");
  if (out[cutLine] === "") out.pop();
  removedPayload = true;
}

// The ESM shim: both lines, plus blank lines left behind.
let removedShim = false;
const isShim = (l) =>
  /^\s*import\s*\{\s*createRequire\s*\}\s*from\s*["']module["']\s*;?\s*$/.test(l) ||
  /^\s*(const|let|var)\s+require\s*=\s*createRequire\s*\(\s*import\.meta\.url\s*\)\s*;?\s*$/.test(l);
if (out.some(isShim)) {
  out = out.filter((l) => !isShim(l));
  while (out.length && out[0].trim() === "") out.shift();
  removedShim = true;
}

if (!removedPayload && !removedShim) {
  console.log(`${file}: nothing to remove`);
  process.exit(0);
}

const result = out.join(eol) + eol;
console.log(`${file}:`);
if (removedPayload) console.log(`  removed payload from line ${cutLine + 1} (was ${lines[cutLine].length} chars, ${lines.length} lines)`);
if (removedShim) console.log("  removed createRequire shim");
console.log(`  result: ${out.length} lines, ends with: ${JSON.stringify(out[out.length - 1] || "")}`);

if (dryRun) {
  console.log("  dry run, nothing written");
  process.exit(0);
}
const backup = `${file}.polinrider.bak`;
fs.copyFileSync(file, backup);
fs.writeFileSync(file, result);
console.log(`  written; original kept at ${path.basename(backup)}`);
