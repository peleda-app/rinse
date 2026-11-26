# Remote runner (planned)

Content disarm and reconstruction as a service: a message or an attachment goes to a dedicated "dirty" server and only things rebuilt from scratch come back, never the original bytes. Moved here from `../app/docs/RINSE.md` on 2026-11-25; nothing of it exists yet. The app reaches it through the same `rinse-mail` contract as the embedded worker, so washing on the device and washing on a separate server are two implementations of one interface.

## What it returns

- the safe document model of a message, the same output `rinse-mail-wasm` produces;
- safe copies of attachments:
  - PDF rebuilt from rasterized pages (optionally with an OCR text layer), with no fonts, scripts, forms, links or embedded files from the original;
  - images decoded and re-encoded to PNG;
  - office documents, RTF and legacy formats converted to rasterized PDF and plain text;
  - archives listed, and their members washed one by one within limits;
- text for search, and findings (what was removed, what could not be washed).

Anything it cannot wash is refused, not passed through.

## Two places washing runs

| Implementation | Where | Washes | When |
| --- | --- | --- | --- |
| `rinse-mail-wasm` / `rinse-mail-process` | inside the app, WebAssembly in a sandboxed process | messages, images, PDF previews in Rust | always available, offline, standalone mode |
| `rinse-mail-remote` (planned) | a dedicated dirty server reached over `baton-link` | everything, including formats that need large C and C++ tools (LibreOffice, pdfium, Ghostscript) | connected mode, heavy formats, iOS |

The core decides per item: light work stays on the device, heavy formats go to the dirty server, and without a connection it falls back to the embedded worker or shows the item as not washed. In connected mode the person's node sends every incoming message to the dirty server on arrival, so devices receive washed results and never touch raw heavy formats.

`rinse-mail-remote` will be an ordinary implementation crate in this repository; it runs the `rinse-mail` conformance suite against a server instance in tests. Since rinse is open and Baton is not, the client side reaches `baton-link` only through a contract the composition root fills in (rinse never depends on Baton).

## Inside the dirty server

```
 node / app ──link (pinned keys)──▶ dispatcher ──vsock──▶ microVM per job
                                     no parsing             no network, no disk
                                     validates output       destroyed after the job
```

- **Dispatcher.** Accepts jobs only from roster members, never parses content, enforces size and rate limits, starts a fresh microVM per job, and validates every result with the same `rinse-doc-model` validation the core uses before sending it back.
- **One disposable microVM per job.** Firecracker or Cloud Hypervisor on KVM, restored from a snapshot in tens of milliseconds, with a read-only root image holding the washing tools, no network device, input and output only over vsock, CPU, memory and time caps. Destroyed after the job whatever happens.
- **The host keeps nothing.** No secrets beyond its own link identity, no access to the node's storage, no outbound internet, no content in logs. A compromised VM sees one item and cannot reach anything; a compromised dispatcher sees content in transit but holds no keys to anything else.
- Runs on a separate machine (or at least a separate VM) from the node, so an escape from a washing VM does not land next to the person's credentials.

## Trust

The dirty server sees plaintext of what it washes. It must be the person's own (or run next to their own node) and stateless. It does not fit the blind node mode: there only the embedded worker washes.

## Not in the app

Running microVMs inside the app itself (Virtualization.framework on macOS, Hyper-V on Windows, KVM on Linux) is possible but costs hundreds of megabytes and conflicts with store rules. It may become an optional paranoid mode on desktops later; it is not planned.

## Order of work

1. This document and the `rinse-mail-remote` design.
2. Dispatcher, job protocol, microVM runner, image and PDF rebuilding first.
3. Office and legacy formats, archives.
4. The node routes incoming mail through the dirty server; the app routes heavy attachments.
