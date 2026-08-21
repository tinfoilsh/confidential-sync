# Native cloud import fixture

`native-cloud-import-v1.zip` is the exact `tinfoil-native-cloud-import` ZIP emitted by the web restore packager. The Go contract test passes these bytes directly to the production archive parser and native backup validator.

- Source repository: `tinfoilsh/tinfoil-webapp`
- Source branch: `feat/native-backup-restore-format-v2`
- Source commit: `848d162883e2abc0b27322a187e53916b717ecba`
- Fixture SHA-256: `3a4b8c93a983f3dcfaa0df6b4a4de21a86f49eb1a8babe3824f10468861deb10`
- Tool versions: Node.js 22.22.2, npm 11.12.1, vite-node 6.0.0, `@zip.js/zip.js` 2.8.53

Generate the fixture deterministically from the sync repository root after checking out the source commit and running `npm ci` in the webapp checkout:

```bash
WEBAPP_DIR=/path/to/tinfoil-webapp
TZ=UTC WEBAPP_DIR="$WEBAPP_DIR" npx --prefix "$WEBAPP_DIR" --yes vite-node@6.0.0 --root "$WEBAPP_DIR" --config "$WEBAPP_DIR/vitest.config.ts" internal/server/testdata/generate-native-cloud-import.mts internal/server/testdata/native-cloud-import-v1.zip
```

When packaging changes, update the source branch and commit above, rerun the command with the documented tool versions, review the parsed semantic assertions, and replace the SHA-256 here and in `TestNativeCloudContractFixtureProvenance`.
