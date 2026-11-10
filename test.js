// Run with: node --test
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const f = require("./fixornix.js");

test("version ranges", () => {
  const yes = [
    ["4.3.1", ">= 4.2.0, <= 4.3.1"],
    ["1.2.5", "^1.2.3"],
    ["0.2.9", "^0.2.3"],
    ["1.2.9", "~1.2.3"],
    ["1.9.0", "1.x"],
    ["2.0.0", "1.x || >=2"],
    ["1.5.0", "1.2.3 - 1.6"],
    ["3.0.0", "*"],
    ["1.0.0", "1.0.0"],
  ];
  const no = [
    ["4.3.2", ">= 4.2.0, <= 4.3.1"],
    ["2.0.0", "^1.2.3"],
    ["0.3.0", "^0.2.3"],
    ["0.0.4", "^0.0.3"],
    ["1.3.0", "~1.2.3"],
    ["2.0.0-beta.1", "^1.0.0"],
    ["1.7.0", "1.2.3 - 1.6"],
  ];
  for (const [v, r] of yes) assert.ok(f.satisfies(v, r), `${v} should satisfy ${r}`);
  for (const [v, r] of no) assert.ok(!f.satisfies(v, r), `${v} should not satisfy ${r}`);
  assert.strictEqual(f.compareVersions("1.0.0-beta", "1.0.0"), -1);
  assert.strictEqual(f.compareVersions("1.0.0-beta.2", "1.0.0-beta.10"), -1);
});

// A small lockfile: a build tool (dev) pulls in "merge" 4.3.1; "app-lib" (shipped) pulls in "parse" 1.0.0 at ^1.0.0,
// and "old-lib" pins "pinned" to 2.x.
const lock = {
  lockfileVersion: 3,
  packages: {
    "": { name: "demo", dependencies: { "app-lib": "^1.0.0", "old-lib": "^1.0.0" }, devDependencies: { "build-tool": "^7.0.0" } },
    "node_modules/build-tool": { version: "7.3.1", dev: true, dependencies: { merge: "^4.3.1" } },
    "node_modules/merge": { version: "4.3.1", dev: true },
    "node_modules/app-lib": { version: "1.0.0", dependencies: { parse: "^1.0.0" } },
    "node_modules/parse": { version: "1.0.0" },
    "node_modules/old-lib": { version: "1.0.0", dependencies: { pinned: "~2.0.0" } },
    "node_modules/pinned": { version: "2.0.1" },
  },
};

// Fake npm registry: parse 1.0.1 fixes the bug; pinned's fix is 3.0.0; old-lib 2.0.0 moves to pinned ^3.
const registry = {
  merge: { "dist-tags": { latest: "4.3.1" }, versions: { "4.3.1": {} } },
  parse: { "dist-tags": { latest: "1.0.1" }, versions: { "1.0.0": {}, "1.0.1": {} } },
  pinned: { "dist-tags": { latest: "3.0.0" }, versions: { "2.0.1": {}, "3.0.0": {} } },
  "old-lib": { "dist-tags": { latest: "2.0.0" }, versions: { "1.0.0": { dependencies: { pinned: "~2.0.0" } }, "2.0.0": { dependencies: { pinned: "^3.0.0" } } } },
};
const fakeFetch = async (url) => {
  const name = decodeURIComponent(url.split("/").pop());
  return { ok: !!registry[name], status: registry[name] ? 200 : 404, json: async () => registry[name] };
};

function alert(name, vulnerable, patched, eco = "npm", extra = {}) {
  return {
    number: 1,
    dependency: { package: { name, ecosystem: eco }, manifest_path: "package-lock.json", scope: "runtime", ...extra },
    security_vulnerability: { vulnerable_version_range: vulnerable, first_patched_version: patched ? { identifier: patched } : null },
    security_advisory: { severity: "high", summary: "test" },
  };
}

const npm = f.npmGraph(lock);

test("finds who pulls a package in", () => {
  const [m] = f.jsInstances(npm, "merge");
  assert.strictEqual(m.devOnly, true);
  assert.deepStrictEqual(m.parents.map((p) => p.name), ["build-tool"]);
  assert.strictEqual(f.jsInstances(npm, "parse")[0].devOnly, false);
});

test("npm: fixable, blocked, dev-only with no fix", async () => {
  const fix = await f.analyzeJs(alert("parse", "< 1.0.1", "1.0.1"), npm, fakeFetch);
  assert.strictEqual(fix.verdict, "fix");
  assert.strictEqual(fix.action, "npm update parse");

  // old-lib pins it, but old-lib 2.0.0 lifts the pin: still a fix, just a bigger one.
  const lifted = await f.analyzeJs(alert("pinned", "< 3.0.0", "3.0.0"), npm, fakeFetch);
  assert.strictEqual(lifted.verdict, "fix");
  assert.match(lifted.action, /upgrade old-lib to 2\.0\.0/);

  // If even old-lib's latest release pins it, it's blocked.
  const stuck = { ...registry, "old-lib": { "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { dependencies: { pinned: "~2.0.0" } } } } };
  const stuckFetch = async (url) => ({ ok: true, status: 200, json: async () => stuck[decodeURIComponent(url.split("/").pop())] });
  const blocked = await f.analyzeJs(alert("pinned", "< 3.0.0", "3.0.0"), npm, stuckFetch);
  assert.strictEqual(blocked.verdict, "blocked");
  assert.match(blocked.reason, /old-lib \(even 1\.0\.0\) needs pinned@~2\.0\.0/);

  // Dev-only with no fix is flagged for a person, never assumed safe (bundlers can ship devDependencies).
  const dev = await f.analyzeJs(alert("merge", ">= 4.2.0, <= 4.3.1", null), npm, fakeFetch);
  assert.strictEqual(dev.verdict, "dev-only");
  assert.strictEqual(dev.dismissReason, "tolerable_risk");

  const gone = await f.analyzeJs(alert("parse", "< 0.9.0", "0.9.0"), npm, fakeFetch);
  assert.match(gone.reason, /no installed copy/);
});

// The same project as above, written as each other lockfile format. Every format must give the same answers.
const pkgJson = { dependencies: { "app-lib": "^1.0.0", "old-lib": "^1.0.0" }, devDependencies: { "build-tool": "^7.0.0" } };
const yarnClassic = `# yarn lockfile v1


"app-lib@^1.0.0":
  version "1.0.0"
  dependencies:
    parse "^1.0.0"

build-tool@^7.0.0:
  version "7.3.1"
  dependencies:
    merge "^4.3.1"

merge@^4.3.1:
  version "4.3.1"

old-lib@^1.0.0:
  version "1.0.0"
  dependencies:
    pinned "~2.0.0"

parse@^1.0.0:
  version "1.0.0"

pinned@~2.0.0:
  version "2.0.1"
`;
const yarnBerry = `__metadata:
  version: 8

"app-lib@npm:^1.0.0":
  version: 1.0.0
  resolution: "app-lib@npm:1.0.0"
  dependencies:
    parse: "npm:^1.0.0"

"build-tool@npm:^7.0.0":
  version: 7.3.1
  resolution: "build-tool@npm:7.3.1"
  dependencies:
    merge: "npm:^4.3.1"

"demo@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo@workspace:."

"merge@npm:^4.3.1":
  version: 4.3.1
  resolution: "merge@npm:4.3.1"

"old-lib@npm:^1.0.0":
  version: 1.0.0
  resolution: "old-lib@npm:1.0.0"
  dependencies:
    pinned: "npm:~2.0.0"

"parse@npm:^1.0.0":
  version: 1.0.0
  resolution: "parse@npm:1.0.0"

"pinned@npm:~2.0.0":
  version: 2.0.1
  resolution: "pinned@npm:2.0.1"
`;
const pnpm9 = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      app-lib:
        specifier: ^1.0.0
        version: 1.0.0
      old-lib:
        specifier: ^1.0.0
        version: 1.0.0
    devDependencies:
      build-tool:
        specifier: ^7.0.0
        version: 7.3.1

packages:

  app-lib@1.0.0:
    resolution: {integrity: sha512-x}

snapshots:

  app-lib@1.0.0:
    dependencies:
      parse: 1.0.0

  build-tool@7.3.1:
    dependencies:
      merge: 4.3.1

  merge@4.3.1: {}

  old-lib@1.0.0:
    dependencies:
      pinned: 2.0.1

  parse@1.0.0: {}

  pinned@2.0.1: {}
`;
const pnpm6 = `lockfileVersion: '6.0'

dependencies:
  app-lib:
    specifier: ^1.0.0
    version: 1.0.0
  old-lib:
    specifier: ^1.0.0
    version: 1.0.0

devDependencies:
  build-tool:
    specifier: ^7.0.0
    version: 7.3.1

packages:

  /app-lib@1.0.0:
    resolution: {integrity: sha512-x}
    dependencies:
      parse: 1.0.0
    dev: false

  /build-tool@7.3.1:
    dependencies:
      merge: 4.3.1
    dev: true

  /merge@4.3.1:
    dev: true

  /old-lib@1.0.0:
    dependencies:
      pinned: 2.0.1
    dev: false

  /parse@1.0.0:
    dev: false

  /pinned@2.0.1:
    dev: false
`;
// pnpm doesn't record the ranges packages ask for, so they come from the (fake) registry.
registry["app-lib"] = { "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { dependencies: { parse: "^1.0.0" } } } };
registry["build-tool"] = { "dist-tags": { latest: "7.3.1" }, versions: { "7.3.1": { dependencies: { merge: "^4.3.1" } } } };

test("yarn (classic and berry) and pnpm (v6 and v9) give the same answers as npm", async () => {
  const graphs = {
    "yarn classic": f.yarnGraph(yarnClassic, pkgJson),
    "yarn berry": f.yarnGraph(yarnBerry, pkgJson),
    "pnpm v9": f.pnpmGraph(pnpm9),
    "pnpm v6": f.pnpmGraph(pnpm6),
  };
  for (const [label, g] of Object.entries(graphs)) {
    assert.strictEqual(f.jsInstances(g, "merge")[0].devOnly, true, `${label}: merge is dev-only`);
    assert.strictEqual(f.jsInstances(g, "parse")[0].devOnly, false, `${label}: parse is shipped`);
    assert.strictEqual((await f.analyzeJs(alert("parse", "< 1.0.1", "1.0.1"), g, fakeFetch)).verdict, "fix", label);
    const lifted = await f.analyzeJs(alert("pinned", "< 3.0.0", "3.0.0"), g, fakeFetch);
    assert.match(lifted.action, /upgrade old-lib to 2\.0\.0/, label);
    assert.strictEqual((await f.analyzeJs(alert("merge", "<= 4.3.1", null), g, fakeFetch)).verdict, "dev-only", label);
  }
  // The suggested command matches the package manager.
  assert.strictEqual((await f.analyzeJs(alert("parse", "< 1.0.1", "1.0.1"), graphs["pnpm v9"], fakeFetch)).action, "pnpm update parse");
  assert.strictEqual((await f.analyzeJs(alert("parse", "< 1.0.1", "1.0.1"), graphs["yarn berry"], fakeFetch)).action, "yarn up -R parse");
});

test("reads quoted keys, scoped names and classic multi-key headers", () => {
  const t = f.readTree('"@scope/a@^1.0.0", "@scope/a@^1.1.0":\n  version "1.2.0"\n  resolved "https://x/a.tgz#abc"\n');
  assert.deepStrictEqual(Object.values(t)[0], { version: "1.2.0", resolved: "https://x/a.tgz#abc" });
  const g = f.yarnGraph('"@scope/a@^1.0.0", "@scope/a@^1.1.0":\n  version "1.2.0"\n', { dependencies: { "@scope/a": "^1.1.0" } });
  assert.strictEqual(f.jsInstances(g, "@scope/a")[0].parents[0].name, "your project");
  const p = f.pnpmGraph("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      '@s/b':\n        specifier: ^2.0.0\n        version: 2.1.0(react@18.0.0)\nsnapshots:\n  '@s/b@2.1.0(react@18.0.0)': {}\n");
  const [b] = f.jsInstances(p, "@s/b");
  assert.strictEqual(b.version, "2.1.0");
  assert.strictEqual(b.devOnly, false);
});

test("cargo: platform-only crate with no fix, and an updatable one", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fixornix-"));
  fs.writeFileSync(path.join(dir, "Cargo.lock"), 'version = 4\n\n[[package]]\nname = "glib"\nversion = "0.18.5"\n\n[[package]]\nname = "time"\nversion = "0.3.1"\n');
  // Pretend cargo: glib only shows up for Linux; time updates fine.
  const run = (cmd, args) => {
    if (args[0] === "tree") return { status: 0, stdout: args.includes("glib@0.18.5") && args.includes("x86_64-unknown-linux-gnu") ? "glib v0.18.5\n" : "", stderr: "" };
    if (args[0] === "update") return args.includes("time@0.3.1") ? { status: 0, stdout: "", stderr: "" } : { status: 101, stdout: "", stderr: "required by package `gtk v0.18.2`" };
    return { status: 1, stdout: "", stderr: "" };
  };
  const glib = f.analyzeCargo(alert("glib", ">= 0.15.0, < 0.20.0", "0.20.0", "rust"), dir, ["x86_64-pc-windows-msvc"], run);
  assert.strictEqual(glib.verdict, "not-shipped");
  assert.strictEqual(glib.dismissReason, "not_used");
  assert.match(glib.reason, /isn't compiled for your targets/);
  assert.match(glib.reason, /gtk v0\.18\.2/);

  const onLinux = f.analyzeCargo(alert("glib", ">= 0.15.0, < 0.20.0", "0.20.0", "rust"), dir, ["x86_64-unknown-linux-gnu"], run);
  assert.strictEqual(onLinux.verdict, "blocked");

  const time = f.analyzeCargo(alert("time", "< 0.3.2", "0.3.2", "rust"), dir, ["x86_64-pc-windows-msvc"], run);
  assert.strictEqual(time.verdict, "fix");
  assert.strictEqual(time.action, "cargo update -p time@0.3.1 --precise 0.3.2");
  fs.rmSync(dir, { recursive: true });
});

test("other ecosystems use GitHub's scope", () => {
  assert.strictEqual(f.analyzeGeneric(alert("x", "<1", null, "pip", { scope: "development" })).verdict, "dev-only");
  assert.strictEqual(f.analyzeGeneric(alert("x", "<1", "1.0", "pip")).verdict, "fix");
  assert.strictEqual(f.analyzeGeneric(alert("x", "<1", null, "pip")).verdict, "no-fix");
});

test("report groups alerts, and options parse", () => {
  const out = f.report([{ alert: alert("glib", "<5", null), verdict: "not-shipped", reason: "linux only", action: "dismiss" }], false);
  assert.match(out, /Not in your build: safe to dismiss \(1\)/);
  assert.deepStrictEqual(f.parseArgs(["--target", "a, b", "--dismiss"]).targets, ["a", "b"]);
  assert.throws(() => f.parseArgs(["--nope"]));
});
