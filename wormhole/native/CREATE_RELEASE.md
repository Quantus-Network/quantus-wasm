# Cutting a release of @quantus-network/wormhole

Releases of this package are independent of `@quantus-network/wasm`: they use
`wormhole-vX.Y.Z` tags and the `Native addon` workflow (`native.yml`); the wasm
package uses `vX.Y.Z` tags and `publish.yml`.

## One-time setup on npmjs.com

Six package names are published: `@quantus-network/wormhole` and one
`@quantus-network/wormhole-<platform>` per target in `package.json#napi.targets`
(`darwin-arm64`, `darwin-x64`, `linux-x64-gnu`, `linux-arm64-gnu`,
`linux-x64-musl`). The workflow publishes with Trusted Publishing (OIDC), which
is configured per package under Package settings → Trusted publishing:
organization `Quantus-Network`, repository `quantus-wasm`, workflow filename
`native.yml`, no environment.

That settings page only exists once a package has been published, so the very
first version of each of the six packages has to be published with a token or
from a logged-in machine (see "First release" below). After that, releases are
fully automatic.

## Every release

Commit any pending work first (a clean tree is required), then, from the
repository root:

```bash
wormhole/native/scripts/create-release.sh patch   # or: minor | major | 0.2.0
```

This bumps `wormhole/native/package.json` and the platform packages, commits,
tags `wormhole-vX.Y.Z`, pushes, and opens a GitHub Release. The release triggers
`native.yml`: it builds every platform, verifies the tag against the package
version, publishes the platform packages (`napi prepublish`) and then the
package itself.

Bump the version whenever the pinned circuit crates change: the package must
match the circuit version the runtime verifies against.

## First release (manual, once per package name)

1. Run the release script as above so the tag and release exist; the workflow's
   publish job will fail on the first attempt because the packages are unknown
   to npm.
2. Download the five `bindings-*` artifacts from that workflow run and place the
   `.node` files: `cd wormhole/native && npx napi artifacts` (expects them under
   `artifacts/`), then `npx napi prepublish --no-gh-release -t npm` publishes
   the platform packages, and `npm run build:ts && npm publish --access public`
   publishes the package. This needs `npm login` (or an automation token with
   2FA bypass) for the `@quantus-network` scope.
3. On npmjs.com, add the trusted publisher to each of the six packages.
4. Re-run the failed publish job to confirm OIDC works, or wait for the next
   release.
