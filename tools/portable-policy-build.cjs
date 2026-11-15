#!/usr/bin/env node
'use strict';
// Build/export coordinator. Source is compiled by Axial C, never interpreted here.
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const binary = path.join(root, 'build', 'portable-policy-export');
function coreDigest() {
  const files = [];
  function collect(directory) {
    for (const item of fs.readdirSync(path.join(root, directory), {withFileTypes: true})) {
      const relative = path.posix.join(directory, item.name);
      if (item.isDirectory()) collect(relative);
      else if (item.isFile() && /\.[ch]$/.test(item.name)) files.push(relative);
    }
  }
  for (const directory of ['src', 'include', 'vendor']) collect(directory);
  const hash = crypto.createHash('sha256').update('axial.portable-core.v1\n');
  for (const file of files.sort()) {
    const contentHash = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, file))).digest('hex');
    hash.update(file + '\0' + contentHash + '\n');
  }
  return hash.digest('hex');
}
function run(command, args, options = {}) {
  const r = cp.spawnSync(command, args, {cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...options});
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${command} failed (${r.status}): ${r.stderr || r.stdout}`);
  return r.stdout;
}
function build() {
  const digest = coreDigest();
  run('make', ['-j4', 'dev']);
  if (coreDigest() !== digest) throw new Error('compiler source changed during build');
  const objects = fs.readdirSync(path.join(root, 'src'))
    .filter(n => n.endsWith('.c') && n !== 'axi_main.c' && n !== 'axi_dossier_main.c')
    .sort().map(n => path.join('build', 'src', n.replace(/\.c$/, '.o')));
  run(process.env.HOSTCC || 'cc', ['-std=c99', '-O1', '-Wall', '-Wextra', '-Werror',
    '-D_POSIX_C_SOURCE=200809L', '-D_DARWIN_C_SOURCE', '-Isrc', '-Iinclude', '-Ivendor',
    '-DAXIAL_PORTABLE_CORE_DIGEST="' + digest + '"',
    'tools/portable-policy-export.c', ...objects, 'build/vendor/ed25519.o', '-lm', '-o', binary]);
  return binary;
}
function exportPolicy(source) {
  run(path.join(root, 'build', 'axi'), ['check', path.resolve(source)]);
  const text = run(binary, ['export', path.resolve(source)]);
  const program = JSON.parse(text);
  if (program.compilerSourceDigest !== coreDigest()) throw new Error('exporter compiler identity is stale; rebuild first');
  if (!require('../runtime/portable-pure-v1.js').validate(program)) throw new Error('portable export failed JS profile validation');
  return text;
}
module.exports = {root, binary, run, build, exportPolicy, coreDigest};
if (require.main === module) {
  try {
    build();
    const source = process.argv[2], output = process.argv[3];
    if (source) {
      const text = exportPolicy(source);
      if (output) {
        const target = path.resolve(output), temporary = target + '.tmp';
        fs.mkdirSync(path.dirname(target), {recursive: true});
        fs.writeFileSync(temporary, text, {flag: 'w'}); fs.renameSync(temporary, target);
        process.stdout.write(`Exported ${target}\n`);
      } else process.stdout.write(text);
    } else process.stdout.write(`${binary}\n`);
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
