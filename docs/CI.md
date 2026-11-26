# CI and fuzzing

## CI

`.github/workflows/ci.yml` runs on every push to `main`, on pull requests, nightly (fuzzing only) and by hand (`workflow_dispatch`, which also fuzzes; input `seconds` per target, default 300).

| Job | Runner | What it runs |
| --- | --- | --- |
| macOS | `macos-15` (aarch64) | `mise run check`, exactly what a laptop runs before a change is done (with `../dojo` checked out beside, for `dojo check`) |
| Linux | `ubuntu-24.04-arm` | `scripts/check-linux.sh` inside the check image of `tests/linux` (`bash tests/linux/run.sh bash scripts/check-linux.sh`, locally `mise run check-linux`) |
| Windows | `macos-15`, cross | `mise run check-windows`: the sandbox crates without Wasmtime (`rinse-sandbox`, `-none`, `-linux`, `-macos`, `rinse-process`, `rinse-build`, all targets) and the mail crates without Wasmtime (`rinse-mail`, `-engine`, `-direct`, `-process`, `-worker`, `rinse-doc-model`, `rinse-text`, libraries only, since their tests pull Wasmtime in through dev-dependencies) for `aarch64-pc-windows-msvc`; `rinse-wasm`, `rinse-host`, `rinse-mail-wasm` and `rinse-worker` need the Windows SDK headers for Wasmtime's fiber crate and are not checked |
| Dependencies | `ubuntu-24.04-arm` | `cargo deny check advisories bans licenses sources` with `deny.toml` from dojo's template |
| Fuzz | `ubuntu-24.04-arm` | `fuzz/run.sh all <seconds>` with the pinned nightly; nightly at a fixed minute and on `workflow_dispatch` only; failing inputs are uploaded as the `fuzz-crashes` artifact, and `fuzz/work` is cached between runs so the corpus keeps growing. `cargo-fuzz` is built from source with `cargo install cargo-fuzz --locked --version 0.13.2` (version in `CARGO_FUZZ_VERSION`) on the pinned nightly and kept in `~/.cargo/bin` by `Swatinem/rust-cache`: there is no prebuilt aarch64 Linux binary and `taiki-e/install-action` has no manifest for it, and the job stays on arm like the Linux job |

- **Pinned actions.** Every `uses:` names a full commit SHA with the release tag in a comment (`actions/checkout`, `jdx/mise-action`, `Swatinem/rust-cache`, `actions/cache`, `actions/upload-artifact`). Update by resolving the new tag's commit (`git ls-remote --tags https://github.com/<owner>/<repo> 'refs/tags/<tag>*'`; for an annotated tag take the `^{}` line) and changing SHA and comment together.
- **Least privilege.** The workflow grants nothing at the top level (`permissions: {}`); each job asks only for `contents: read`. No job writes to the repository, packages or pull requests.
- **No private siblings.** rinse has no path dependency on another repository; the only sibling checkout is the open `peleda-app/dojo`, for `dojo check` in the macOS job. No checkout token is needed.
- **Caches.** `Swatinem/rust-cache` for cargo (registry, git and target directories, keyed on the lock files) in the macOS, Windows, dependencies and fuzz jobs; the Linux job caches the container's registry and target directory through `LINUX_CACHE_DIR` (`tests/linux/run.sh` mounts host directories instead of named volumes when it is set) with `actions/cache/restore` on every run and `actions/cache/save` only on pushes to `main` when the key missed, after dropping `incremental/` directories; the key (lock file and Dockerfile, no commit SHA) keeps one entry per dependency set so the multi-GB container cache cannot crowd the other jobs' entries out of the 10 GB repository limit.
- **Concurrency.** A newer run of the same workflow, ref and event cancels an older one only on pull requests; every push to `main` runs to completion so each commit there gets a full result.
- **Toolchains.** `jdx/mise-action` installs what `mise.toml` pins; the jobs add the components and targets `rust-toolchain.toml` lists, because mise selects the toolchain by name and rustup then ignores that file.

## Fuzzing

The targets live in [`fuzz/`](../fuzz/README.md): their own workspace and lock file, built with the nightly pinned in `fuzz/rust-toolchain.toml` (`cargo fuzz` needs nightly; the repository itself stays on the stable toolchain of `rust-toolchain.toml`). One-time setup: `cargo install cargo-fuzz` and `rustup toolchain install <the pinned nightly>`.

```sh
mise run fuzz -- all 60          # build, then every target for 60 seconds
mise run fuzz -- <target> 300    # one target for 300 seconds (extra libFuzzer flags may follow)
mise run fuzz -- list            # target names
mise run fuzz -- replay <target> artifacts/<target>/crash-...   # paths relative to fuzz/
```

`fuzz/run.sh` builds without sanitizers (`-s none`: the code is safe Rust, so the useful signal is panics, assertion failures, timeouts over 10 s and memory over 2 GiB) into `fuzz/target`, not the machine's shared target directory, so targets with the same name in sibling repositories cannot overwrite each other. Inputs are capped at 64 KiB. Each target reads `fuzz/corpus/<target>` (checked in: a small curated corpus and every input that once found a bug) plus any read-only seed directory listed for it in `fuzz/seeds`, and writes what it learns to `fuzz/work/<target>` (ignored). `text_normalize` covers `rinse-text`, the display-text normalizer for sender names, subjects and file names; its corpus starts with the inputs that once broke idempotence (found through `../app`'s `snapshot_plain`). A failing input lands in `fuzz/artifacts/<target>/`; the fix starts with a regression test that feeds it to the crate's own tests, then the input is copied into `fuzz/corpus/<target>/` under a descriptive name.

`mise run check` compiles and formats the targets on stable, so they never rot, and the crates' unit tests feed the same entry points truncated, bit-flipped and length-lying inputs on every `cargo test`.
