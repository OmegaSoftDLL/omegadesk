# Contributing to OmegaDesk

Thank you for your interest in OmegaDesk! This guide explains how changes get into the project.

## Before you write code

- **Bugs:** search the [existing issues](https://github.com/OmegaSoftDLL/omegadesk/issues) first. If the bug is new, [open an issue](https://github.com/OmegaSoftDLL/omegadesk/issues/new/choose) with clear steps to reproduce.
- **New features or larger changes:** open an issue or a [discussion](https://github.com/OmegaSoftDLL/omegadesk/discussions) and agree on the design before spending time on code. Small fixes (typos, obvious bugs, documentation) can go straight to a pull request.
- **Security problems:** do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## How changes are merged

The `main` branch is protected. Every change, including the maintainer's own, goes through a pull request that must:

1. pass all CI checks: formatting, spelling (`typos`), Clippy, tests on Windows, Linux and macOS, the license and advisory policy, and CodeQL;
2. be **reviewed and approved by the maintainer** (see [CODEOWNERS](.github/CODEOWNERS));
3. have every review conversation resolved;
4. be up to date with `main`.

Pull requests are **squash-merged**, so the PR title becomes the commit message on `main`. Write it as a [Conventional Commit](https://www.conventionalcommits.org):

```
feat(codec): add NVENC encoder
fix(input): release modifier keys when the session drops
docs: explain the mesh relay design
```

Common types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`. The scope is the crate or area you changed.

## Sign your commits (DCO)

OmegaDesk uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO), the same model as Tailscale and the Linux kernel. Every commit must carry a `Signed-off-by` line. It certifies that you wrote the change, or otherwise have the right to submit it under the project's license (AGPL-3.0):

```sh
git commit -s -m "fix(input): release modifier keys when the session drops"
```

The `DCO` check blocks pull requests with unsigned commits. To fix a branch: `git rebase --signoff main` followed by `git push --force-with-lease`.

## Development setup

You need:

- [Rust](https://rustup.rs) 1.90 or newer. The repository's `rust-toolchain.toml` selects the right components.
- On Windows: the Visual Studio 2022 C++ Build Tools (the "Desktop development with C++" workload).

Run the same checks as CI before you push:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check            # cargo install cargo-deny
typos                       # cargo install typos-cli
```

To try the agent and the client locally, see the [quick start](README.md#quick-start).

## Code standards

- **Study the references first.** Before you design a module, read how the projects in [docs/references.md](docs/references.md) solve the same problem (a local clone of each one helps). Say in the code or in the PR where an idea came from and what you improved. Never copy code whose license is not compatible with AGPL-3.0.
- **Safety:** `unsafe` is denied workspace-wide. Platform modules may allow it locally with `#![allow(unsafe_code, reason = "...")]`, and every unsafe block must have a clear justification.
- **Errors:** no `unwrap`, `expect` or `panic!` outside tests. Use `thiserror` in libraries and `anyhow` in binaries.
- **Lints:** the workspace enables Clippy `pedantic` and treats warnings as errors in CI. Fix the warning instead of silencing it. If an `allow` is truly needed, keep it local and give a `reason`.
- **Tests:** new behavior needs tests. Tests that need hardware (GPU encoders, a display) must skip cleanly when the hardware is missing, because CI runners have no GPU.
- **Dependencies:** new dependencies must pass `cargo deny` (license policy in [`deny.toml`](deny.toml)). Prefer well-maintained crates from crates.io. Git dependencies are not allowed.
- **Latency is a feature:** if your change touches the capture → encode → network → decode → draw path, include before/after numbers in the PR description.

## Licensing

By contributing, you agree that your contribution is licensed under the [AGPL-3.0](LICENSE), the license of the project.
