import { readFileSync, writeFileSync } from "node:fs";

const { version } = JSON.parse(readFileSync("package.json", "utf8"));

function sync(path, pattern) {
  const src = readFileSync(path, "utf8");
  if (!pattern.test(src)) {
    throw new Error(`No version field found in ${path}`);
  }
  writeFileSync(path, src.replace(pattern, (_, prefix) => `${prefix}"${version}"`));
}

sync("Cargo.toml", /^(version = )"[^"]*"/m);
sync("Cargo.lock", /(name = "quantus-wasm"\nversion = )"[^"]*"/);
