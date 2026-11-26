# Plan

## What exists (2026-11-25)

- **Sandbox layer**, walls 1 and 2: the `rinse-sandbox` contract with Linux, macOS and none implementations and its conformance suite; the WebAssembly runner (`rinse-wasm`, Native and Pulley); the process runner (`rinse-process`) and the worker-side host (`rinse-host`); `rinse-build` for nested component builds. Verified on macOS and in the Linux image ([WALLS.md](WALLS.md#what-is-verified-where)).
- **Mail layer**, wall 3: the `rinse-mail` contract with `direct`, `wasm` and `process` implementations, the engine (MIME, HTML to the safe document model, image re-encoding, link and attachment checks, `MessageFacts`), the document model and the text normalizer, the hostile corpus, and the worker executable `apps/rinse-worker` that the app ships as its sidecar.
- One workspace, one `Cargo.lock`, one fuzz workspace with all twelve targets, CI for macOS, Linux, Windows (cross compile check) and nightly fuzzing.

## Next

1. **Files layer.** A new layer between the sandbox and mail: a contract for washing one file into a rebuilt file plus findings, run in the same walls.
   - Move image decoding and re-encoding out of `rinse-mail-engine` into the files layer; the mail engine calls it for inline images and attachments.
   - PDF, office documents and archives, each with limits against bombs: compression ratio, nesting depth, member count, total and per-member size, pixel count. Refused, never passed through, when a limit is hit.
   - A hostile corpus per format with the same rules as the mail corpus, and a fuzz target per decoder.
2. **Remote-resource proxy.** Fetching remote images and other resources for a message on behalf of a viewer: SSRF protection (public addresses only, after resolution, no redirects into private ranges), size and time limits, type checked by content and not by header, the response re-encoded through the files layer before anyone sees it.
3. **Remote runner.** Washing on a dirty server in one disposable microVM per job, for formats that need large native tools and for iOS: [REMOTE.md](REMOTE.md).
4. **More walls.** Windows (Less Privileged AppContainer and a Job object), Android (`isolatedProcess`).
5. **Smaller items carried over:** a minimal import surface without WASI for components ("From washer", 3); microdata in structured facts ("From peleda-content", 18).
