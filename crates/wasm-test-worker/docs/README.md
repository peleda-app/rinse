# rinse-wasm-test-worker

A `wasi:cli/command` binary built for `wasm32-wasip2` by [`rinse-wasm-fixtures`](../../wasm-fixtures/docs/README.md) and used only by the sandbox layer's own tests; never shipped.

It reads all of stdin and answers by the whole input:

| Input | Behavior |
| --- | --- |
| `spin` | loops forever (time limit) |
| `hog` | allocates 1 MiB chunks forever (memory limit) |
| `huge` | writes 2 MiB (output limit) |
| `panic` | panics (a trap) |
| `exit3` | exits with code 3 |
| `probe` | writes `env=<n> args=<n> root=… cwd=… tmp=… tcp=… wall=<ns>`: how many environment variables and arguments it sees, whether it can list `/` or `.`, write to `/tmp`, connect to TCP on loopback, and what the wall clock reads |
| `count` | increments a static counter and writes it (`1` in every fresh instance) |
| anything else | echoes the input |

On a native target it builds as an ordinary binary (so `cargo clippy --workspace` covers it) and is never run.
