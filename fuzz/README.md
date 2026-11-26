# Fuzz targets

libFuzzer targets for the decoders of untrusted input of every layer, in one workspace of their own (own `[workspace]` and lock file, nightly pinned in `rust-toolchain.toml`). How to run them, the corpus layout and what CI does: [docs/CI.md](../docs/CI.md). Short form: `mise run fuzz -- all 60`. `seeds` adds the hostile corpus (`../crates/mail/fixtures/hostile`) as read-only seeds for the message targets.

## Sandbox layer

| Target | Entry point |
| --- | --- |
| `frame` | `rinse_sandbox::fuzz::frame`: `read_frame` with the announcement cap, then `decode_announcement`, as a launcher reads a worker's stdout |
| `announcement` | `rinse_sandbox::fuzz::announcement`: `decode_announcement` on a payload |
| `policy` | `rinse_sandbox::fuzz::policy`: `Policy::from_args` on arguments split at NUL bytes |
| `frames` | a stream of length-prefixed frames under a cap chosen by the first byte, read until it fails: every frame fits the cap and round-trips through `write_frame`; every frame that decodes as an announcement (a `LockdownReport`) re-encodes with `announce` and decodes to the same report |

The unit tests of `rinse-sandbox` feed the same entry points truncated, bit-flipped and length-lying variants on every `cargo test`.

## Mail layer

| Target | Entry point and invariant |
| --- | --- |
| `engine_render` | `rinse_mail_engine::render` on arbitrary message bytes; the first byte picks options (original HTML, 16-pixel images, a 64 KiB output cap). Every success passes `verify_rendered` and fits `max_output_bytes` |
| `render_raw` | the same message bytes through the worker protocol (`rinse_mail_worker::handle` with a well-formed render request); the decoded answer, value or error kind, equals `rinse_mail_engine::render` on the same request |
| `decode_part` | `rinse_mail_engine::decode_part` with a part id from the first two bytes (high bit: a 4 KiB output cap), then the same request through the worker, whose decoded answer must equal the direct one (value or error kind). A success has the requested id, fits the cap and a lowercase media type |
| `worker_request` | `rinse_mail_worker::handle` on arbitrary request bytes (op byte, postcard request) |
| `host_response` | what the host does with a worker's answer: postcard `Rendered` and `Result<Rendered, ContentError>`, then `verify_rendered` |
| `facts` | `MessageFacts` extraction: the input spliced into every place facts are read from (`rinse_mail::testing::facts_message`: list, authentication and thread headers, JSON-LD, iCalendar, HTML, `.pkpass`); every answer passes `verify_rendered` (which runs `verify_facts`) |
| `doc_model` | `rinse_doc_model::decode` with default limits |
| `text_normalize` | `rinse_text::normalize` on the lossy UTF-8 of everything after two cap bytes (graphemes, then bytes; 255 means no cap). The output is idempotent with no findings on a second pass, fits both caps, and holds no bidi control, invisible or control character and no zero-width joiner outside two emoji parts |

For `facts`, also seed inputs whose fifth NUL-separated piece is a real `.pkpass` zip with `pass.json`, stored and deflated (`pkpass` in `untrusted_inputs.rs` builds both), so the central-directory walk, the local header and inflating are reached; whole `.eml` files land in the header piece.

The same entry points run on every `cargo test` with the hostile corpus and truncated, bit-flipped and length-lying variants: `crates/mail-worker/tests/untrusted_inputs.rs`.
