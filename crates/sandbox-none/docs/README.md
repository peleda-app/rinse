# rinse-sandbox-none

> **Not a wall.** Workers started by this crate have every right of the user running the host application: files, network, processes. It exists for development, tests, and platforms whose sandbox is not written yet. Nothing in a release build may pick it.

An implementation of [`rinse-sandbox`](../../sandbox/docs/README.md) with no restriction:

- `NoneLauncher`: `Launcher::is_wall()` is `false`, `name()` is `"none"`; requires nothing in the report.
- `NoLockdown`: applies no restriction; like every lockdown its `prepare` closes the descriptors the worker inherited above stderr (`rinse_sandbox::close_inherited_descriptors`), so the report holds only `ClosedDescriptors` on Unix (`missing` on Windows).

What it keeps from the contract: the policy argument, an empty environment, `/` as the working directory (on Unix), discarded stderr, the announcement and framing protocol with its size caps, the wall-time kill, kill on drop and the `Exit` mapping. It does not enforce `memory_bytes` or `cpu_seconds`.

It is portable (Unix and Windows) and is the launcher the composition roots fall back to only where they explicitly allow it (for example tests, or a platform whose sandbox is not written yet).

## Tests

`cargo test -p rinse-sandbox-none` runs `rinse_sandbox::testing::run_mechanics` (not `run`: none of the denials hold) with the test binary as its own probe.

## Dependencies

`rinse-sandbox`, `async-trait`, `tokio` (`process`, `io-util`, `time`).
