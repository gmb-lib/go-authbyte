# Contributing

Thank you for considering a contribution. Bug reports, fixes and improvements are welcome. For
anything that could be exploited, use the private route in [SECURITY.md](SECURITY.md) — never a
public issue.

For anything larger than a small fix, please open an issue first and describe what you want to
change and why. It protects your time: a change that fights the library's design is better
redirected before it is written than after.

## Building and testing

You need the Go toolchain at the version named in [go.mod](go.mod). The gate a change must pass is
the same one CI runs:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
```

Three more checks run in CI and are worth running before you push:

- **Lint** — `golangci-lint run`, at the version pinned in
  [.github/workflows/ci.yml](.github/workflows/ci.yml); the repo's [.golangci.yml](.golangci.yml)
  carries the configuration.
- **Vulnerabilities** — `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`.
- **Fuzz** — a short sweep runs every `Fuzz*` target for 30 seconds. This module has none today; if you add a parser for input that comes from outside, add one.

The committed tree must already be tidy: CI runs `go mod tidy -diff` and fails if it would change
anything, so run `go mod tidy` after touching dependencies. All Go code is `gofmt`-formatted, and
`.gitattributes` pins Go files to LF line endings — leave that alone, it keeps the tidy-diff gate
stable across platforms.

## What a change to this library needs

This library is a consuming service's access-control boundary, so the bar on changes to token
validation, DPoP proof verification, scope checking and the delegated-token cache is higher than
elsewhere. A change to any of them needs a test that **fails when the check is removed** — proving
the guard is what refuses, not something else further down.

Three rules worth knowing before you start:

- **Never widen a default.** If a change makes something acceptable that was previously refused,
  that is the change, and it needs to be stated plainly in the pull request.
- **Cache keys are security boundaries.** A delegated token is cached per audience, scope and
  subject; anything that changes what goes into a cache key needs a test that a different subject
  cannot be served another's entry.
- **Nothing secret is ever logged, wrapped into an error, or attached to a request that is not its
  audience** — tokens, proofs, client secrets and private keys included.

## Proposing a change

- Work on a branch and open a pull request against `develop`. `develop` is merged into `main` and
  tagged there when a release goes out, so `main` is never committed to directly.
- **Sign off every commit.** This project uses the
  [Developer Certificate of Origin](https://developercertificate.org/): by adding a
  `Signed-off-by: Your Name <you@example.org>` line you certify that you wrote the change or
  otherwise have the right to submit it under this project's licence. `git commit -s` adds the line
  for you; the name and address must match the commit author. A pull request whose commits lack it
  fails the DCO check and cannot be merged.
- Keep the change focused: one concern per pull request.
- A change in behaviour comes with a test that fails without it.
- Match the style around you — naming, error handling, comment density. Comments explain what and
  why in plain domain terms; a reference to a standard is cited in the bracket form already used in
  the code.
- Pull requests also run a dependency review. A new dependency needs a reason the standard library
  or the existing ones cannot cover.

## Releases

A release is a tag on `main`, and for a Go module the tag *is* the publication — the release
workflow re-runs the gate, then checks the tagged version is actually importable from the module
proxy before declaring success. If your change is a breaking one, say so in the pull request: the
version it lands in is decided from that.

## Licence

This project is licensed under the MIT License (see [LICENSE](LICENSE)). By submitting a
contribution you agree that it is provided under the same licence.
