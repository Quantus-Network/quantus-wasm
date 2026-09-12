const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");

// wasm-pack writes pkg/.gitignore ("*"), and some npm versions honour nested
// ignore files even for paths listed in package.json#files; 0.2.0 and 0.3.0
// shipped without the wasm because of it. The build removes that file; this
// test fails if the tarball would still lack any runtime file.
test("npm pack includes the wasm and the loaders", () => {
  const [pack] = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
  const files = new Set(pack.files.map((f) => f.path));
  for (const required of ["dist/index.js", "dist/index.d.ts", "pkg/quantus_wasm_bg.wasm", "pkg/quantus_wasm.js", "pkg/quantus_wasm.d.ts"]) {
    assert.ok(files.has(required), `${required} missing from the package; have: ${[...files].join(", ")}`);
  }
});
