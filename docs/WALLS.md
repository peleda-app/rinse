# Walls

rinse assumes every input was crafted to exploit the parser that reads it, and arranges things so that the exploit gets nothing: no files, no network, no other process, no other input, no time beyond its budget. Every byte crosses the walls in this order, and each wall assumes the previous one has already fallen:

1. **Memory-safe parsing in a WebAssembly sandbox** (sandbox layer, generic).
2. **An OS sandbox around the runtime** (sandbox layer, generic).
3. **The receiver trusts nothing the worker returns** (per format layer; today the mail layer).

The sandbox layer knows nothing about what the bytes are and never trusts the output it carries either; it only bounds it. A format layer brings the parser component and adds wall 3 on top. The application-wide picture for Peleda (Safe view, Original view, links, attachments, the UI) stays in `../app/docs/ISOLATION.md`.

## 1. Memory-safe parsing in a WebAssembly sandbox

[`rinse-wasm`](../crates/wasm/docs/README.md). The parser is a `wasm32-wasip2` component built from Rust (memory-safe code, then a WebAssembly sandbox around it in case it is not):

- **Fresh instance per call**: nothing survives from one input to the next.
- **Empty, frozen WASI context**: the Rust standard library links the `wasi:cli` import surface (environment, clocks, random, stdio, filesystem, sockets); the host satisfies it with no arguments, no environment, no preopened directories, TCP, UDP and name lookup off, clocks frozen at zero, stderr discarded. Input is stdin, output is stdout.
- **Limits per call**: memory across all linear memories (for example 256 MiB), an epoch deadline (for example 2 s), output size. Exceeding one ends the call with a typed error; the next call starts clean.
- **Backends**: Cranelift native code (needs executable memory while compiling) or the Pulley interpreter (no executable memory at all, for iOS and for workers signed without JIT rights).

A minimal import surface without WASI (a custom WIT world exporting one bytes-in/bytes-out function) is a later hardening step; see [DECISIONS.md](DECISIONS.md) ("From washer", 3).

In the mail layer, the mail worker ([`rinse-mail-worker`](../crates/mail-worker/docs/README.md)) is a `wasm32-wasip2` component built from [`rinse-mail-engine`](../crates/mail-engine/docs/README.md); [`rinse-mail-wasm`](../crates/mail-wasm/docs/README.md) runs it with `rinse-wasm`.

## 2. An OS sandbox around the runtime

[`rinse-sandbox`](../crates/sandbox/docs/README.md) (contract and conformance suite), [`rinse-process`](../crates/process/docs/README.md) (parent side) and [`rinse-host`](../crates/host/docs/README.md) (child side). The WebAssembly runtime runs in a separate process with no rights, one process per request, so one input cannot poison the next and a runtime escape lands in a process that cannot open a file or a socket, start a process, signal another process (on macOS with one exception: it can still have the kernel send `SIGIO` to a process it names, see the macOS row below), or outlive its time budget, and can only use its stdin, stdout and stderr: every other descriptor it inherited is closed before it loads anything.

The worker locks itself down before it reads anything: it compiles the component and runs a warm-up request (trusted bytes), applies the platform lockdown to every thread, announces what it applied, and only then receives the one request. The parent refuses a worker whose report lacks a required restriction, caps the response size, and kills the worker when its time budget runs out. Because compilation happens before the lockdown, the locked-down process needs no executable memory, so the native backend runs without JIT rights after lockdown.

| Platform | Mechanism | Status |
| --- | --- | --- |
| Linux | user, network, IPC and mount namespaces where unprivileged user namespaces are allowed; inherited descriptors closed; `RLIMIT_CPU`, `RLIMIT_DATA`, zero `RLIMIT_FSIZE` and `RLIMIT_CORE`; `no_new_privs`; Landlock handling every right with no rule, on all threads; a seccomp filter on all threads that kills on any system call outside a small allowlist (no `open`, `socket`, `exec`, `clone`, `kill`, no `PROT_EXEC`, no `MAP_SHARED`, `fcntl` without `F_SETOWN`/`F_SETSIG`) | implemented ([`rinse-sandbox-linux`](../crates/sandbox-linux/docs/README.md)) |
| macOS | a deny-default Seatbelt profile applied by the worker with `sandbox_init`, inherited descriptors closed, `RLIMIT_CPU`, zero file and core size, a memory watchdog in the parent that refuses a worker whose footprint it cannot read. Not denied: `fcntl(F_SETOWN, <other pid>)` plus `O_ASYNC` on the worker's own pipe, so the worker can make the kernel send `SIGIO` (macOS has no `F_SETSIG`, so no other signal) to any process it may signal; a target without a `SIGIO` handler ignores it. The conformance suite asserts this outcome on macOS so a change in either direction is noticed | implemented ([`rinse-sandbox-macos`](../crates/sandbox-macos/docs/README.md)); signing inside the App Sandbox not set up or verified |
| Windows | Less Privileged AppContainer with no capabilities, a Job object for memory, CPU and process count, child process creation blocked | planned ([`rinse-sandbox`](../crates/sandbox/docs/README.md#windows-planned-not-implemented)); until then only wall 1, in the caller's process |
| Android | `isolatedProcess` service | planned |
| iOS | no helper processes allowed | wall 1 only, in-process, on Pulley |

[`rinse-sandbox-none`](../crates/sandbox-none/docs/README.md) starts workers without any restriction for tests and is never a wall.

In the mail layer, [`rinse-mail-process`](../crates/mail-process/docs/README.md) runs every message in a fresh locked-down process with `rinse-process`; the worker executable is [`apps/rinse-worker`](../apps/rinse-worker/docs/README.md) (`rinse-host` plus the embedded mail worker), shipped by the Peleda app as the `rinse-worker` sidecar. [`rinse-mail-direct`](../crates/mail-direct/docs/README.md) runs the engine in-process and is no wall: tests, development and the server node in its own container.

## What the mail worker parses

All parsing of untrusted message content happens in the worker:

- MIME and headers, charset decoding, `text/html` and `text/plain`, calendar and contact attachments;
- the facts beyond the display (`rinse_mail::facts`): list, authentication and thread header grammars, `application/ld+json` scripts (read from the DOM before the walk drops every script), `text/calendar` parts and `pass.json` inside `.pkpass` zip attachments;
- HTML to the safe document model, CSS reduced to an allowlist of inline properties;
- every image decoded and re-encoded to PNG at a capped size; SVG dropped for now; animated images flattened to the first frame (planned to move to the files layer, see [PLAN.md](PLAN.md));
- later: text extraction from attachments for search and PDF pages rasterized for preview, both in Rust, inside a worker.

Limits per call come from `ContentLimits` (memory, time budget, input and output size, document limits). A worker that exceeds them fails with a typed `ContentError`, and the message is shown as unreadable, with a plain-text fallback only if extracting it in a fresh worker succeeds.

### Fonts and PDF never reach system engines

No font that came with a message is ever handed to CoreText, DirectWrite, FreeType, PDFKit or a webview: HTML loses every web font (`@font-face`, font links); PDF previews will be rasterized inside a worker by a Rust renderer, only re-encoded PNG pages leave it, and they carry no links. A memory-disclosure bug in that renderer can read only the worker's own linear memory, which holds nothing but the one attachment, in a process with no network.

## 3. The receiver trusts nothing the worker returns

The document model is a closed, versioned schema ([`rinse-doc-model`](../crates/doc-model/docs/README.md)): blocks (paragraph, heading, quote, list, table, preformatted, image, divider), inline runs (text, emphasis, link, code), a small set of styles (color from a palette mapped to tokens, alignment; headings carry size). Every implementation and every receiver checks the postcard size of a response before decoding it, then runs `rinse_mail::verify_rendered` (or `verify_decoded_part`) on it, whatever produced it:

- the document passes `rinse_doc_model::validate`: depth and count limits, links only `https:`, `http:`, `mailto:`, `tel:`, images only as references to returned blobs, no bidi or invisible characters;
- image ids are the BLAKE3 of the PNG bytes, within the size caps;
- display strings are normalized one-liners within their caps ([`rinse-text`](../crates/text/docs/README.md));
- remote image URLs are well-formed;
- the original HTML passes `check_sanitized_html`;
- the facts pass `verify_facts`: known signal bits only, every string a display string, identifiers and domains without whitespace, every list capped, every URL a `SafeUrl` with a public host (unsubscribe URLs `https` only), mailto targets one address, prices and times in range, layout indices inside the body and one placement per link.

Anything else is dropped as `Crashed`. Hostile serialized input cannot exhaust the receiver's stack: the document travels as a flat node list with bounded depth. The contract is [`rinse-mail`](../crates/mail/docs/README.md#validation-by-the-receiver).

## The hostile corpus

[`crates/mail/fixtures/hostile`](../crates/mail/fixtures/hostile/README.md) holds invented messages built to attack the mail pipeline; the [`rinse-mail`](../crates/mail/docs/README.md#conformance-suite) conformance suite (`testing::run`) embeds them and every implementation runs it (`direct`, `wasm` on both backends, `process` on macOS and Linux). Rules:

- **Invented only.** Addresses on `example.com` and `example.org`, IP addresses from `192.0.2.0/24`; never a real message, even redacted.
- **One attack per file**, named for it, with a row in the corpus README saying what must happen.
- **A bug found in the pipeline adds a fixture** (or a targeted test) that fails on the old code before the fix.
- **Every wall must pass the whole corpus** before a release; a new implementation is not done until it does.
- Large and binary fixtures are kept as plain files; the script that produced them is not kept.
- Other repositories use the corpus through `rinse_mail::testing::fixture` (feature `testing`), never by relative path.

## What is verified where

Recorded on 2026-11-25, before the merge, in the two source repositories (`washer` for walls 1 and 2, `peleda-content` for the mail layer). Cells marked "(merge baseline)" come from the `mise run check-linux` runs of both source repositories made on the same day as the baseline for the merge, not from the original records. After the merge the same suites run from this workspace in `mise run check` and `mise run check-linux` (results in [DECISIONS.md](DECISIONS.md), "Merge into rinse").

| Check | macOS 27.3, Apple silicon, real Seatbelt | Linux 7.2 aarch64 in Docker (OrbStack), default seccomp profile | same with `--security-opt seccomp=unconfined` |
| --- | --- | --- | --- |
| `rinse-sandbox` conformance (`rinse-sandbox-macos` / `-linux` tests) | passes | passes; report without the four namespaces | passes; all twelve restrictions |
| conformance with a `rinse_host::run` executable as the probe (`rinse-host --features probe`, `rinse-worker --features probe`) | passes | passes | not run |
| `rinse-process` runner (one worker per request, faults, limits) | passes | passes (4 GiB under 256 MiB: `Crashed`, an abort under `RLIMIT_DATA`) | not run |
| `rinse-host` serve (both backends under the real lockdown, the component's own limits) | passes | passes (native backend under seccomp without `PROT_EXEC`) | passes |
| `rinse-wasm` (both backends, debug and release) | passes | passes (debug); release passes (merge baseline) | not run |
| `rinse-sandbox-none` mechanics | passes | n/a | n/a |
| `cargo test --workspace` of the mail layer (contract, engine, doc model, text, direct, worker, wasm, handler, worker serve) | passes | passes (run during the extract review, together with the worker probe test); not re-run after the review fixes because the Docker daemon stopped when the disk filled up; passes (merge baseline) | not run |
| full mail conformance suite through `rinse-mail-process` (`--release`, two warm workers) | passes, about 26 s | passes, about 36 s; the 4 GiB fault is `Crashed` (abort under `RLIMIT_DATA`) | not run |
| `rinse-worker` serve, both backends | passes | passes | not run |
| mail conformance on Pulley (`cargo test --release -p rinse-mail-wasm`) | passes | not run in the original pass; passes (merge baseline) | not run |
| Windows (`aarch64-pc-windows-msvc`) compile check | `rinse-sandbox`, `-none`, `-linux`, `-macos`, `rinse-process`, `rinse-build` (all targets), `rinse-mail`, `-engine`, `-direct`, `-process`, `-worker`, `rinse-doc-model`, `rinse-text` (libraries; blake3 is `pure` on Windows) compile; `rinse-wasm`, `rinse-host`, `rinse-mail-wasm` and `rinse-worker` do not build here because Wasmtime's fiber crate compiles C against `windows.h` and this Mac has no Windows SDK | | |

Not verified anywhere: x86_64, Linux kernels older than 7.0 (Landlock then reports missing), distributions that restrict user namespaces with AppArmor, a signed worker under the macOS hardened runtime or App Sandbox, Windows and Android walls (not written).
