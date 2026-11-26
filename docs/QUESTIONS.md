# Questions

What only the maintainer can decide.

1. **The `peleda-image:`, `peleda-remote:` and `peleda-link:` schemes.** The mail layer still rewrites sanitized original HTML to these schemes, and the app's webview and CSP resolve them. They name the application in a repository that is meant to be generic. Rename them (for example to `rinse-image:`) in one change across rinse and the app, or keep them as part of the wire contract? Kept for now (DECISIONS, "Merge into rinse").
2. **Publishing.** rinse is open (MIT OR Apache-2.0) but every crate still has `publish = false`. Publish the sandbox layer to crates.io once a release process with trusted publishing exists, or keep consuming it by path?
3. **GitHub.** Create `peleda-app/rinse` (public) and retire `peleda-app/washer` and `peleda-app/peleda-content` there; CI's checkout and the app's workflow already name `peleda-app/rinse`.
4. **Remote runner and Baton.** The dirty server's link is `baton-link`, which is noncommercial, while rinse is open and may depend only on open repositories. Keep the client behind a contract the app fills in (current plan, [REMOTE.md](REMOTE.md)), or put the remote client in the app or the node?
