# Retired — the CLI ships in this package

This directory used to hold a separate npm package, `provenance-cli`, whose
source was a second copy of the commands already exposed by this package's
`provenance` binary. The two had drifted: the separate copy supported `validate`
and `help` while the shipped binary did not, so the documented `validate`
command did not exist in the CLI people actually installed.

That copy is now the shipped binary at [`../src/cli.js`](../src/cli.js). There is
one CLI, released by the same tag that releases the SDK.

```bash
npx provenance-protocol help          # without installing
npm install -g provenance-protocol    # then: provenance help
```

The `provenance-cli` package on npm (last at 0.1.1) is superseded and should be
deprecated:

```bash
npm deprecate provenance-cli "Superseded — use provenance-protocol, which ships the same CLI as its provenance binary."
```
