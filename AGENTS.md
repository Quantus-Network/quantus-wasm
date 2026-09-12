# quantus-wasm: rules for agents

## Releases and publishing are done by a human

Never run any of these; tell the user to run them and stop:

- `scripts/create-release.sh` or `npm version` (they commit, tag, push `main`, and create a GitHub Release)
- `gh release create` / `gh release edit` / `gh release delete`
- `npm publish`, `npm deprecate`, `npm unpublish`
- `gh workflow run` / `gh run rerun` / `gh run cancel` for `publish.yml` or `native.yml`

Publishing a GitHub Release triggers `publish.yml`, which publishes to npm. So creating a release *is* publishing.

## Git

- Never push to `main`. It is protected; changes go through a pull request.
- Never create, move or delete tags. Version tags are created by the release script, run by a human.
- Commit and push only when asked, and only to a feature branch. Open a PR for review.
- No AI attribution in commits, PR descriptions or comments.

## Verifying a package before release

`npm test` includes `test/package.test.js`, which checks that `npm pack` would ship the wasm. CI installs `npm@latest`; if the test passes locally but fails in CI, check the npm version first (`npm pack --json` output changed shape in npm 12). `publish.yml` runs the same check before `npm publish`.

## Layout

- Root crate + `js/`: the `@quantus-network/wasm` signing package (wasm-pack, stable Rust).
- `wormhole/`: the `@quantus-network/wormhole` native addon (napi-rs, stable Rust) and its core library. Its build script generates circuit artifacts and takes minutes.
