# Cutting a release

Commit any pending work first (a clean tree is required), then run one command
with the new version — `npm version` accepts `patch`/`minor`/`major` or an
explicit `x.y.z`:

```bash
scripts/create-release.sh patch     # or: minor | major | 0.2.0
```

This bumps the version in `package.json`, `Cargo.toml`, and `Cargo.lock`,
commits and tags `vX.Y.Z`, pushes, and opens a GitHub Release. The release
triggers the `Publish to npm` workflow, which publishes via Trusted Publishing
(OIDC) — no token required.
