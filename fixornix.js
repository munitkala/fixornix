#!/usr/bin/env node
// fixornix: goes through a repo's open Dependabot alerts and tells you, for each one, whether to fix it now,
// what's blocking the fix, or whether it can be dismissed because the vulnerable code never ships.
//
// It reads the alerts from GitHub, then checks them against the lockfiles in your checkout:
//   npm, yarn, pnpm - is the package dev-only, and do the packages that pull it in allow a fixed version?
//   cargo           - via `cargo tree` / `cargo update --dry-run`: is it built for your targets, and can it update?
// Other ecosystems fall back to what GitHub reports (runtime or development scope, patched version).
"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

// ---------- versions and ranges ----------
// Just enough semver for npm ranges and GitHub's advisory ranges (">= 4.2.0, <= 4.3.1").

function parseVersion(v) {
  const m = /^\s*v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?/.exec(String(v));
  if (!m) return null;
  const num = (s) => (s === undefined || /[xX*]/.test(s) ? null : Number(s));
  return { major: Number(m[1]), minor: num(m[2]), patch: num(m[3]), pre: m[4] ? m[4].split(".") : [] };
}

function compareVersions(a, b) {
  a = typeof a === "string" ? parseVersion(a) : a;
  b = typeof b === "string" ? parseVersion(b) : b;
  for (const k of ["major", "minor", "patch"]) {
    const d = (a[k] ?? 0) - (b[k] ?? 0);
    if (d) return Math.sign(d);
  }
  // A release sorts after its prereleases: 1.0.0-beta < 1.0.0.
  if (!a.pre.length || !b.pre.length) return b.pre.length - a.pre.length ? Math.sign(b.pre.length - a.pre.length) : 0;
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    if (a.pre[i] === undefined) return -1;
    if (b.pre[i] === undefined) return 1;
    const x = /^\d+$/.test(a.pre[i]) ? Number(a.pre[i]) : a.pre[i];
    const y = /^\d+$/.test(b.pre[i]) ? Number(b.pre[i]) : b.pre[i];
    if (x !== y) return typeof x === typeof y ? (x < y ? -1 : 1) : typeof x === "number" ? -1 : 1;
  }
  return 0;
}

// Turn one range term ("^1.2.3", "~1.2", "1.x", ">=2", "1.2.3") into [operator, version] pairs.
function comparatorsFor(term) {
  if (term === "" || term === "*" || /^[xX]$/.test(term)) return [];
  const m = /^(\^|~|>=|<=|>|<|=)?(.*)$/.exec(term);
  const op = m[1] || "";
  const v = parseVersion(m[2]);
  if (!v) throw new Error(`can't read version range "${term}"`);
  const { major, minor, patch } = v;
  const lo = `${major}.${minor ?? 0}.${patch ?? 0}${v.pre.length ? "-" + v.pre.join(".") : ""}`;
  if (op === "^") {
    if (major > 0 || minor === null) return [[">=", lo], ["<", `${major + 1}.0.0-0`]];
    if (minor > 0 || patch === null) return [[">=", lo], ["<", `0.${minor + 1}.0-0`]];
    return [[">=", lo], ["<", `0.0.${patch + 1}-0`]];
  }
  if (op === "~") {
    if (minor === null) return [[">=", lo], ["<", `${major + 1}.0.0-0`]];
    return [[">=", lo], ["<", `${major}.${minor + 1}.0-0`]];
  }
  if (op === "" || op === "=") {
    // "1" and "1.2" mean "any 1.x" and "any 1.2.x".
    if (minor === null) return [[">=", lo], ["<", `${major + 1}.0.0-0`]];
    if (patch === null) return [[">=", lo], ["<", `${major}.${minor + 1}.0-0`]];
    return [["=", lo]];
  }
  if (op === ">" && (minor === null || patch === null)) {
    return [[">=", minor === null ? `${major + 1}.0.0` : `${major}.${minor + 1}.0`]];
  }
  if (op === "<=" && (minor === null || patch === null)) {
    return [["<", minor === null ? `${major + 1}.0.0-0` : `${major}.${minor + 1}.0-0`]];
  }
  return [[op, lo]];
}

function satisfies(version, range) {
  const v = parseVersion(version);
  if (!v) return false;
  return String(range)
    .split("||")
    .some((alt) => {
      let s = alt.trim().replace(/,/g, " ").replace(/(>=|<=|>|<|=|\^|~)\s+/g, "$1");
      const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(s);
      if (hyphen) s = `>=${hyphen[1]} <=${hyphen[2]}`;
      const comps = s.split(/\s+/).filter(Boolean).flatMap(comparatorsFor);
      return comps.every(([op, w]) => {
        const c = compareVersions(v, w);
        return { "=": c === 0, ">": c > 0, ">=": c >= 0, "<": c < 0, "<=": c <= 0 }[op];
      });
    });
}

// ---------- JavaScript lockfiles: npm, yarn and pnpm ----------
// Each lockfile is read into the same shape, a dependency graph:
//   nodes: installed packages, each with the dependencies it asked for (name, range if the lockfile records it,
//          and the installed package that satisfied it)
//   roots: the project's own direct dependencies, marked dev or not
// Everything after that (who pulls a package in, is it dev-only, can it update) works the same for all three.

// A small reader for the indentation-based formats in pnpm-lock.yaml and yarn.lock (both the classic format,
// `name "value"`, and the newer YAML one, `name: value`). Lists and multi-line strings aren't needed and are skipped.
function readTree(text) {
  const root = {};
  const stack = [{ indent: -1, obj: root }];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line === "---" || line.startsWith("#") || line.startsWith("- ")) continue;
    const indent = raw.length - raw.trimStart().length;
    while (stack[stack.length - 1].indent >= indent) stack.pop();
    const [key, value] = splitLine(line);
    const parent = stack[stack.length - 1].obj;
    if (value === null) {
      parent[key] = {};
      stack.push({ indent, obj: parent[key] });
    } else {
      parent[key] = unquote(value);
    }
  }
  return root;
}

function unquote(s) {
  if (/^".*"$/.test(s)) {
    try {
      return JSON.parse(s);
    } catch {
      return s.slice(1, -1);
    }
  }
  if (/^'.*'$/.test(s)) return s.slice(1, -1).replace(/''/g, "'");
  return s;
}

// Returns [key, value], with value null when the line opens a nested block.
function splitLine(line) {
  if (line[0] === '"' || line[0] === "'") {
    const q = line[0];
    let i = 1;
    while (i < line.length && line[i] !== q) i += line[i] === "\\" && q === '"' ? 2 : 1;
    const rest = line.slice(i + 1);
    // Classic yarn.lock headers list several quoted keys: "a@^1", "a@^1.2":
    if (/^,\s/.test(rest) && line.endsWith(":")) return [line.slice(0, -1), null];
    const value = rest.replace(/^:/, "").trim();
    return [unquote(line.slice(0, i + 1)), value === "" ? null : value];
  }
  if (line.endsWith(":")) return [line.slice(0, -1), null];
  const colon = line.indexOf(": ");
  const space = line.search(/\s/);
  if (colon !== -1 && (space === -1 || colon < space)) return [line.slice(0, colon), line.slice(colon + 2).trim()];
  return [line.slice(0, space), line.slice(space + 1).trim()];
}

// "@scope/name@npm:^1.2.3" -> { name: "@scope/name", range: "^1.2.3" }
function parseDescriptor(d) {
  d = unquote(d.trim());
  const at = d.startsWith("@") ? d.indexOf("@", 1) : d.indexOf("@");
  return { name: d.slice(0, at), range: d.slice(at + 1).replace(/^npm:/, "") };
}

const PROD_FIELDS = ["dependencies", "optionalDependencies", "peerDependencies"];

// Where Node would find `name` when required from the package at `fromKey` (a lockfile key like
// "node_modules/a/node_modules/b"): its own node_modules first, then each parent's, then the top level.
function resolveFrom(packages, fromKey, name) {
  let dir = fromKey;
  for (;;) {
    const key = dir ? `${dir}/node_modules/${name}` : `node_modules/${name}`;
    if (packages[key]) return key;
    if (!dir) return null;
    const cut = dir.lastIndexOf("/node_modules/");
    dir = cut === -1 ? "" : dir.slice(0, cut);
  }
}

function npmGraph(lock) {
  if (!lock.packages) throw new Error("package-lock.json is the old v1 format; run `npm install` with npm 7 or newer to update it");
  const nodes = new Map();
  const roots = [];
  for (const [key, e] of Object.entries(lock.packages)) {
    if (e.link) continue;
    // Keys without node_modules/ are the project itself ("") and its workspaces ("packages/x").
    const isProject = !key.includes("node_modules/");
    const deps = [];
    for (const field of isProject ? [...PROD_FIELDS, "devDependencies"] : PROD_FIELDS) {
      for (const [name, range] of Object.entries(e[field] || {})) {
        const to = resolveFrom(lock.packages, key, name);
        if (isProject) roots.push({ name, range, to, dev: field === "devDependencies" });
        else deps.push({ name, range, to });
      }
    }
    if (!isProject) nodes.set(key, { id: key, name: e.name || key.slice(key.lastIndexOf("node_modules/") + 13), version: e.version, deps });
  }
  return { manager: "npm", nodes, roots };
}

function yarnGraph(text, pkg) {
  const doc = readTree(text);
  const berry = "__metadata" in doc;
  const byDescriptor = new Map();
  const nodes = new Map();
  const roots = [];
  for (const [key, e] of Object.entries(doc)) {
    if (key === "__metadata" || typeof e !== "object") continue;
    const descriptors = key.split(/,\s*/).map((d) => unquote(d.trim()));
    for (const d of descriptors) byDescriptor.set(d, key);
    nodes.set(key, { id: key, name: parseDescriptor(descriptors[0]).name, version: e.version, entry: e });
  }
  const find = (name, range) => byDescriptor.get(`${name}@${range}`) ?? byDescriptor.get(`${name}@npm:${range}`) ?? null;
  for (const node of nodes.values()) {
    const e = node.entry;
    delete node.entry;
    const deps = [];
    for (const field of ["dependencies", "optionalDependencies"]) {
      for (const [name, range] of Object.entries(e[field] || {})) deps.push({ name, range: range.replace(/^npm:/, ""), to: find(name, range) });
    }
    // Workspaces are listed as entries in the newer format. Their dependencies count as shipped, which can only
    // make the answer more careful, never less.
    if (/@workspace:/.test(e.resolution || "")) {
      nodes.delete(node.id);
      if (e.resolution.endsWith("@workspace:.")) continue; // the root project comes from package.json below
      for (const d of deps) roots.push({ ...d, dev: false });
      continue;
    }
    node.deps = deps;
  }
  for (const [field, dev] of [["dependencies", false], ["optionalDependencies", false], ["devDependencies", true]]) {
    for (const [name, range] of Object.entries(pkg[field] || {})) roots.push({ name, range, to: find(name, range), dev });
  }
  return { manager: berry ? "yarn" : "yarn-classic", nodes, roots };
}

function pnpmGraph(text) {
  const doc = readTree(text);
  const version = parseFloat(doc.lockfileVersion);
  // From lockfile v9 the dependency graph lives under "snapshots"; before that, under "packages".
  const entries = version >= 9 ? doc.snapshots || {} : doc.packages || {};
  // Keys look like "a@1.0.0" (v9), "/a@1.0.0" (v6) or "/a/1.0.0" (v5), optionally followed by peer info.
  const keyFor = (name, v) => {
    if (v.startsWith("link:") || v.startsWith("file:")) return null;
    // Versions start with a digit; anything else is an alias pointing at another package ("other@1.0.0").
    if (!/^\d/.test(v)) return version >= 9 ? v : v.startsWith("/") ? v : `/${v}`;
    return version >= 9 ? `${name}@${v}` : version >= 6 ? `/${name}@${v}` : `/${name}/${v}`;
  };
  const nodes = new Map();
  for (const [key, e] of Object.entries(entries)) {
    const bare = key.replace(/^\//, "").replace(/[(_].*$/, "");
    const at = bare.lastIndexOf("@");
    const [name, v] = at > 0 ? [bare.slice(0, at), bare.slice(at + 1)] : [bare.slice(0, bare.lastIndexOf("/")), bare.slice(bare.lastIndexOf("/") + 1)];
    const deps = [];
    // pnpm records which version was installed but not the range asked for; the range is looked up later if needed.
    for (const field of ["dependencies", "optionalDependencies"]) {
      for (const [dn, dv] of Object.entries(e[field] || {})) deps.push({ name: dn, range: null, to: keyFor(dn, dv) });
    }
    nodes.set(key, { id: key, name, version: v, deps });
  }
  const roots = [];
  const importers = doc.importers || { ".": doc };
  for (const imp of Object.values(importers)) {
    for (const [field, dev] of [["dependencies", false], ["optionalDependencies", false], ["devDependencies", true]]) {
      for (const [name, val] of Object.entries(imp[field] || {})) {
        const resolved = typeof val === "object" ? val.version : val;
        const range = typeof val === "object" ? val.specifier : imp.specifiers?.[name] ?? null;
        roots.push({ name, range, to: keyFor(name, resolved), dev });
      }
    }
  }
  return { manager: "pnpm", nodes, roots };
}

// Packages reachable from the project's non-dev dependencies. Anything else is only installed for development.
function shippedIds(graph) {
  const seen = new Set();
  const todo = graph.roots.filter((r) => !r.dev && r.to).map((r) => r.to);
  while (todo.length) {
    const id = todo.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    for (const d of graph.nodes.get(id)?.deps || []) if (d.to && !seen.has(d.to)) todo.push(d.to);
  }
  return seen;
}

// Every installed copy of `name`, whether it's dev-only, and which packages (or the project) pull it in.
function jsInstances(graph, name) {
  const shipped = shippedIds(graph);
  const out = [];
  for (const node of graph.nodes.values()) {
    if (node.name !== name) continue;
    const parents = [];
    for (const r of graph.roots) if (r.to === node.id) parents.push({ project: true, name: "your project", range: r.range, dev: r.dev });
    for (const p of graph.nodes.values()) {
      for (const d of p.deps) if (d.to === node.id) parents.push({ project: false, name: p.name, version: p.version, range: d.range });
    }
    out.push({ id: node.id, version: node.version, devOnly: !shipped.has(node.id), parents });
  }
  return out;
}

// One lookup per package per run (kept per fetch function, so tests with fake registries don't mix).
const registryCaches = new WeakMap();
function registryInfo(name, fetchImpl) {
  if (!registryCaches.has(fetchImpl)) registryCaches.set(fetchImpl, new Map());
  const registryCache = registryCaches.get(fetchImpl);
  if (!registryCache.has(name)) {
    registryCache.set(
      name,
      fetchImpl(`https://registry.npmjs.org/${name.replace("/", "%2F")}`, { headers: { accept: "application/vnd.npm.install-v1+json" } }).then((res) => {
        if (!res.ok) throw new Error(`npm registry: ${name}: HTTP ${res.status}`);
        return res.json();
      }),
    );
  }
  return registryCache.get(name);
}

// The range a published package version asks for `name` (used when the lockfile doesn't record it, as in pnpm).
async function declaredRange(parent, name, fetchImpl) {
  const meta = (await registryInfo(parent.name, fetchImpl)).versions?.[parent.version] || {};
  return meta.dependencies?.[name] ?? meta.optionalDependencies?.[name] ?? meta.peerDependencies?.[name] ?? null;
}

function fixCommand(manager, name, version, direct, dev) {
  const D = dev ? "-D " : "";
  if (direct) {
    if (manager === "npm") return `npm install ${D}${name}@^${version}`;
    if (manager === "pnpm") return `pnpm add ${D}${name}@^${version}`;
    if (manager === "yarn") return `yarn up ${name}@^${version}`;
    return `yarn upgrade ${name}@^${version}`;
  }
  if (manager === "npm") return `npm update ${name}`;
  if (manager === "pnpm") return `pnpm update ${name}`;
  if (manager === "yarn") return `yarn up -R ${name}`;
  // Classic yarn can't update a package it didn't install directly; removing its entries makes it re-resolve.
  return `remove the ${name}@ entries from yarn.lock, then run yarn install`;
}

async function analyzeJs(alert, graph, fetchImpl) {
  const name = alert.dependency.package.name;
  const vulnerable = alert.security_vulnerability.vulnerable_version_range;
  const patched = alert.security_vulnerability.first_patched_version?.identifier ?? null;
  const hits = jsInstances(graph, name).filter((i) => i.version && satisfies(i.version, vulnerable));
  if (!hits.length) return { verdict: "fix", reason: `no installed copy of ${name} is in the vulnerable range any more`, action: "GitHub should close this alert on its next scan" };

  const devOnly = hits.every((h) => h.devOnly);
  const where = `${name} ${[...new Set(hits.map((h) => h.version))].join(", ")}`;
  if (!patched) {
    return devOnly
      ? devOnlyResult(`${where} is only used in development, and no fixed version exists yet`)
      : { verdict: "no-fix", reason: `${where} is shipped and no fixed version has been published`, action: "watch the advisory, or replace the package" };
  }

  const parents = hits.flatMap((h) => h.parents);
  for (const p of parents) if (p.range === null && !p.project) p.range = await declaredRange(p, name, fetchImpl).catch(() => null);

  // Find the lowest fixed version that every package pulling it in already accepts.
  const info = await registryInfo(name, fetchImpl);
  const fixed = Object.keys(info.versions || {})
    .filter((v) => compareVersions(v, patched) >= 0 && !parseVersion(v).pre.length && !satisfies(v, vulnerable))
    .sort(compareVersions);
  if (!fixed.length) {
    const why = `${where} is vulnerable, and the fixed version (${patched}) isn't on the npm registry yet`;
    return devOnly ? devOnlyResult(why) : { verdict: "no-fix", reason: why, action: "watch the advisory, or replace the package" };
  }
  const accepts = (p, v) => p.range !== null && satisfies(v, p.range.replace(/^npm:/, ""));
  const good = fixed.find((v) => parents.every((p) => accepts(p, v)));
  if (good) {
    const direct = parents.find((p) => p.project);
    return { verdict: "fix", reason: `${where} can move to ${good} without breaking anything that depends on it`, action: fixCommand(graph.manager, name, good, !!direct, direct?.dev) };
  }

  // Something pins it below the fix. Check whether a newer release of that package lifts the pin.
  const blockers = parents.filter((p) => !fixed.some((v) => accepts(p, v)));
  const steps = [];
  const stuck = [];
  for (const b of [...new Map(blockers.map((b) => [`${b.name}@${b.range}`, b])).values()]) {
    if (b.project) {
      steps.push(`change ${name} in your package.json from ${b.range} to ^${patched}`);
      continue;
    }
    try {
      const pinfo = await registryInfo(b.name, fetchImpl);
      const latest = pinfo["dist-tags"]?.latest;
      const wants = latest && (await declaredRange({ name: b.name, version: latest }, name, fetchImpl));
      if (latest && (!wants || fixed.some((v) => satisfies(v, wants)))) steps.push(`upgrade ${b.name} to ${latest}`);
      else stuck.push(`${b.name} (even ${latest ?? "its latest release"}) needs ${name}@${wants ?? b.range}`);
    } catch {
      stuck.push(`${b.name} needs ${name}@${b.range ?? "an older version"}`);
    }
  }
  // Every pin can be lifted: it's a fix, just a bigger one (usually a major-version upgrade).
  if (!stuck.length) return { verdict: "fix", reason: `${where} needs a bigger upgrade to reach ${patched}`, action: [...new Set(steps)].join(", then ") };
  if (devOnly) return devOnlyResult(`${where} is only used in development and can't be updated yet: ${stuck.join("; ")}`);
  return {
    verdict: "blocked",
    reason: `${where} is held back: ${stuck.join("; ")}`,
    action: `wait for ${[...new Set(stuck.map((s) => s.split(" ")[0]))].join(", ")} to release an update${steps.length ? `; meanwhile you can ${[...new Set(steps)].join(", ")}` : ""}`,
  };
}

// Picks the lockfile in a folder and reads it.
function jsGraph(dir) {
  const read = (f) => fs.readFileSync(path.join(dir, f), "utf8");
  if (fs.existsSync(path.join(dir, "package-lock.json"))) return npmGraph(JSON.parse(read("package-lock.json")));
  if (fs.existsSync(path.join(dir, "pnpm-lock.yaml"))) return pnpmGraph(read("pnpm-lock.yaml"));
  if (fs.existsSync(path.join(dir, "yarn.lock"))) {
    const pkg = fs.existsSync(path.join(dir, "package.json")) ? JSON.parse(read("package.json")) : {};
    return yarnGraph(read("yarn.lock"), pkg);
  }
  return null;
}

// ---------- cargo: Cargo.lock ----------

function lockedCrateVersions(cargoLock, name) {
  const out = [];
  for (const block of cargoLock.split(/\n\[\[package\]\]\n/).slice(1)) {
    const n = /^name = "([^"]+)"/m.exec(block);
    const v = /^version = "([^"]+)"/m.exec(block);
    if (n && v && n[1] === name) out.push(v[1]);
  }
  return out;
}

function hostTarget(run) {
  const out = run("rustc", ["-vV"]);
  return /^host: (\S+)/m.exec(out.stdout)?.[1];
}

function analyzeCargo(alert, dir, targets, run) {
  const name = alert.dependency.package.name;
  const vulnerable = alert.security_vulnerability.vulnerable_version_range;
  const patched = alert.security_vulnerability.first_patched_version?.identifier ?? null;
  const lockFile = path.join(dir, "Cargo.lock");
  const versions = lockedCrateVersions(fs.readFileSync(lockFile, "utf8"), name).filter((v) => satisfies(v, vulnerable));
  if (!versions.length) return { verdict: "fix", reason: `Cargo.lock no longer has a vulnerable ${name}`, action: "GitHub should close this alert on its next scan" };
  const where = `${name} ${versions.join(", ")}`;

  // `cargo tree -i` prints nothing when the crate isn't in the build for that target and edge kind.
  const inTree = (v, edges, target) => run("cargo", ["tree", "-q", "-i", `${name}@${v}`, "-e", edges, "--target", target], dir).stdout.trim() !== "";
  const shipped = versions.some((v) => targets.some((t) => inTree(v, "normal", t)));
  let notShippedWhy = null;
  if (!shipped) {
    const buildOnly = versions.some((v) => targets.some((t) => inTree(v, "build,dev", t)));
    notShippedWhy = buildOnly ? `${where} is only used by build scripts or tests, never in the shipped program` : `${where} isn't compiled for your targets (${targets.join(", ")})`;
  }

  if (patched) {
    // A dry run tells us whether everything that depends on it allows the fixed version.
    for (const v of versions) {
      const r = run("cargo", ["update", "-p", `${name}@${v}`, "--precise", patched, "--dry-run"], dir);
      if (r.status === 0) return { verdict: "fix", reason: `${where} can move to ${patched}`, action: `cargo update -p ${name}@${v} --precise ${patched}` };
      const why = /required by package `([^`]+)`/.exec(r.stderr)?.[1];
      const blocked = `${where} can't move to ${patched}${why ? `: ${why} requires an older version` : ""}`;
      if (notShippedWhy) return notShipped(`${notShippedWhy}; ${blocked}`, "not_used");
      return { verdict: "blocked", reason: blocked, action: why ? `upgrade ${why.split(" ")[0]} once a release allows ${name} ${patched}` : "see `cargo update` output" };
    }
  }
  if (notShippedWhy) return notShipped(`${notShippedWhy}, and no fixed version exists yet`, "not_used");
  return { verdict: "no-fix", reason: `${where} is built into your program and no fixed version has been published`, action: "watch the advisory, or replace the crate" };
}

// ---------- everything else ----------

function analyzeGeneric(alert) {
  const name = alert.dependency.package.name;
  const patched = alert.security_vulnerability.first_patched_version?.identifier ?? null;
  if (alert.dependency.scope === "development") {
    if (patched) return { verdict: "fix", reason: `${name} is a development dependency with a fix available`, action: `update ${name} to ${patched} or later` };
    return devOnlyResult(`${name} is a development dependency and no fixed version exists yet`);
  }
  if (patched) return { verdict: "fix", reason: `${name} has a fixed version`, action: `update ${name} to ${patched} or later` };
  return { verdict: "no-fix", reason: `no fixed version of ${name} has been published`, action: "watch the advisory" };
}

// Dev dependencies usually stay out of what you ship, but frontend bundlers (Vite, webpack, SvelteKit...) can pack
// them into the app. So these are flagged for a person to confirm rather than treated as certainly safe.
function devOnlyResult(reason) {
  return { verdict: "dev-only", reason, action: `dismiss as "tolerable risk" if it isn't bundled into what you ship`, dismissReason: "tolerable_risk" };
}

function notShipped(reason, dismissReason) {
  return { verdict: "not-shipped", reason, action: `dismiss as "${dismissReason.replace("_", " ")}"`, dismissReason };
}

// ---------- GitHub ----------

function githubToken(run) {
  if (process.env.GITHUB_TOKEN || process.env.GH_TOKEN) return process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const r = run("gh", ["auth", "token"]);
  if (r.status === 0 && r.stdout.trim()) return r.stdout.trim();
  throw new Error("no GitHub token: set GITHUB_TOKEN, or sign in with `gh auth login`");
}

async function github(fetchImpl, token, url, init = {}) {
  const res = await fetchImpl(url.startsWith("http") ? url : `https://api.github.com${url}`, {
    ...init,
    headers: { accept: "application/vnd.github+json", authorization: `Bearer ${token}`, "x-github-api-version": "2022-11-28", ...init.headers },
  });
  if (!res.ok) throw new Error(`GitHub ${res.status} for ${url}: ${(await res.text()).slice(0, 200)}`);
  return res;
}

async function openAlerts(fetchImpl, token, repo) {
  const alerts = [];
  let url = `/repos/${repo}/dependabot/alerts?state=open&per_page=100`;
  while (url) {
    const res = await github(fetchImpl, token, url);
    alerts.push(...(await res.json()));
    url = /<([^>]+)>;\s*rel="next"/.exec(res.headers.get("link") || "")?.[1] ?? null;
  }
  return alerts;
}

function repoFromGit(dir, run) {
  const url = run("git", ["remote", "get-url", "origin"], dir).stdout.trim();
  return /github\.com[:/]([^/]+\/[^/]+?)(?:\.git)?$/.exec(url)?.[1] ?? null;
}

// ---------- putting it together ----------

async function triage(alerts, { dir, targets, fetchImpl, run }) {
  const results = [];
  for (const alert of alerts) {
    const eco = alert.dependency.package.ecosystem;
    const manifestDir = path.join(dir, path.dirname(alert.dependency.manifest_path || "."));
    let result;
    try {
      const graph = eco === "npm" ? jsGraph(manifestDir) : null;
      if (graph) {
        result = await analyzeJs(alert, graph, fetchImpl);
      } else if (eco === "rust" && fs.existsSync(path.join(manifestDir, "Cargo.lock"))) {
        result = analyzeCargo(alert, manifestDir, targets(), run);
      } else {
        result = analyzeGeneric(alert);
      }
    } catch (e) {
      result = { ...analyzeGeneric(alert), reason: `couldn't check locally (${e.message}); based on GitHub's data only` };
    }
    results.push({ alert, ...result });
  }
  return results;
}

const ORDER = ["fix", "blocked", "no-fix", "dev-only", "not-shipped"];
const TITLES = {
  fix: "Fix now",
  blocked: "Blocked by another package",
  "no-fix": "No fix published yet",
  "dev-only": "Development only, no fix: check, then dismiss",
  "not-shipped": "Not in your build: safe to dismiss",
};

function report(results, markdown) {
  const lines = [];
  for (const verdict of ORDER) {
    const group = results.filter((r) => r.verdict === verdict);
    if (!group.length) continue;
    lines.push(markdown ? `### ${TITLES[verdict]} (${group.length})\n` : `\n${TITLES[verdict]} (${group.length})`);
    for (const r of group) {
      const a = r.alert;
      const head = `#${a.number} ${a.dependency.package.name} [${a.security_advisory.severity}] ${a.security_advisory.summary}`;
      if (markdown) lines.push(`- **${head}**  \n  ${r.reason}  \n  → ${r.action}`);
      else lines.push(`  ${head}\n    ${r.reason}\n    -> ${r.action}`);
    }
    if (markdown) lines.push("");
  }
  return lines.join("\n");
}

function parseArgs(argv) {
  const opts = { dir: process.cwd(), repo: null, targets: null, markdown: null, json: false, dismiss: false, includeDev: false, yes: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--repo") opts.repo = argv[++i];
    else if (a === "--dir") opts.dir = path.resolve(argv[++i]);
    else if (a === "--target") opts.targets = argv[++i].split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--markdown") opts.markdown = argv[++i];
    else if (a === "--json") opts.json = true;
    else if (a === "--dismiss") opts.dismiss = true;
    else if (a === "--include-dev") opts.includeDev = true;
    else if (a === "--yes") opts.yes = true;
    else if (a === "-h" || a === "--help") opts.help = true;
    else throw new Error(`unknown option ${a}`);
  }
  return opts;
}

const HELP = `fixornix: sort your open Dependabot alerts into fix now, blocked, no fix yet and safe to dismiss.

Usage: fixornix [options]   (run it in your repo's folder)

  --repo owner/name   repository to check (default: the git remote "origin")
  --dir path          checkout to inspect (default: current folder)
  --target t1,t2      Rust targets you ship, e.g. x86_64-pc-windows-msvc (default: this machine's)
  --markdown file     also write a Markdown report (use $GITHUB_STEP_SUMMARY in Actions)
  --json              print the results as JSON
  --dismiss           dismiss the "not in your build" alerts on GitHub, with the reason as a comment
  --include-dev       with --dismiss, also dismiss the "development only" ones (check they aren't bundled first)
  --yes               needed with --dismiss, so nothing is dismissed by accident

Needs a GitHub token that can read Dependabot alerts: GITHUB_TOKEN, GH_TOKEN, or \`gh auth login\`.`;

function runner(cmd, args, cwd) {
  // On Windows, cargo/gh/git are .exe files, so no shell is needed.
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", windowsHide: true });
  return { status: r.status ?? 1, stdout: r.stdout || "", stderr: r.stderr || (r.error ? r.error.message : "") };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) return console.log(HELP);
  const run = runner;
  const repo = opts.repo || repoFromGit(opts.dir, run);
  if (!repo) throw new Error("couldn't tell which GitHub repo this is; pass --repo owner/name");
  const token = githubToken(run);
  let cachedTargets = opts.targets;
  const targets = () => (cachedTargets ??= [hostTarget(run)].filter(Boolean));

  const alerts = await openAlerts(fetch, token, repo);
  const results = await triage(alerts, { dir: opts.dir, targets, fetchImpl: fetch, run });

  if (opts.json) console.log(JSON.stringify(results.map(({ alert, ...r }) => ({ number: alert.number, package: alert.dependency.package.name, ...r })), null, 2));
  else console.log(alerts.length ? `${repo}: ${alerts.length} open alert${alerts.length === 1 ? "" : "s"}\n${report(results, false)}` : `${repo}: no open Dependabot alerts`);
  if (opts.markdown) fs.appendFileSync(opts.markdown, `## fixornix: ${repo}\n\n${report(results, true) || "No open Dependabot alerts."}\n`);

  if (opts.dismiss) {
    const toDismiss = results.filter((r) => r.verdict === "not-shipped" || (opts.includeDev && r.verdict === "dev-only"));
    if (!opts.yes) return console.log(`\n${toDismiss.length} alert(s) would be dismissed. Add --yes to do it.`);
    for (const r of toDismiss) {
      await github(fetch, token, `/repos/${repo}/dependabot/alerts/${r.alert.number}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ state: "dismissed", dismissed_reason: r.dismissReason, dismissed_comment: `fixornix: ${r.reason}`.slice(0, 280) }),
      });
      console.log(`dismissed #${r.alert.number} (${r.alert.dependency.package.name})`);
    }
  }
}

module.exports = { parseVersion, compareVersions, satisfies, readTree, npmGraph, yarnGraph, pnpmGraph, jsGraph, jsInstances, analyzeJs, analyzeCargo, analyzeGeneric, lockedCrateVersions, triage, report, parseArgs };

if (require.main === module) {
  main().catch((e) => {
    console.error(`fixornix: ${e.message}`);
    process.exit(1);
  });
}
