'use strict';
const fs = require('node:fs');
const path = require('node:path');

function argValue(flag, fallback) {
  const index = process.argv.indexOf(flag);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}
const root = path.resolve(__dirname, '..');
const nodeModules = path.join(root, 'node_modules');
const output = path.resolve(root, argValue('--output', 'THIRD_PARTY_NODE_LICENSES.json'));
if (!fs.existsSync(nodeModules)) {
  console.error('node_modules not found; install the pinned npm dependencies first.');
  process.exit(1);
}
const packages = new Map();
function scanModules(modulesPath) {
  if (!fs.existsSync(modulesPath)) return;
  let entries;
  try { entries = fs.readdirSync(modulesPath, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    const packagePath = path.join(modulesPath, entry.name);
    if (entry.name.startsWith('@')) {
      scanModules(packagePath);
      continue;
    }
    const manifestPath = path.join(packagePath, 'package.json');
    try {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      if (manifest.name && manifest.version) {
        const key = `${manifest.name}@${manifest.version}`;
        packages.set(key, {
          name: manifest.name,
          version: manifest.version,
          license: manifest.license || 'UNKNOWN — review package metadata and LICENSE files',
          repository: typeof manifest.repository === 'string' ? manifest.repository : (manifest.repository && manifest.repository.url) || null,
          path: path.relative(root, packagePath),
        });
      }
    } catch { /* Ignore non-package directories. */ }
    scanModules(path.join(packagePath, 'node_modules'));
  }
}
scanModules(nodeModules);
const result = {
  generatedAt: new Date().toISOString(),
  notice: 'Inventory from installed npm package metadata; manually verify license expressions and bundled Electron/Chromium/Node notices before redistribution.',
  packages: [...packages.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)),
};
fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
console.log(`Wrote ${result.packages.length} package records to ${path.relative(root, output)}`);
