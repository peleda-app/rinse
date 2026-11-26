use std::sync::{Arc, LazyLock};
use std::time::Instant;

use bytes::Bytes;

use rinse_mail::testing::{self, fixture};
use rinse_mail::{ContentLimits, RenderOptions};

use super::*;

const TEST_WORKER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rinse-mail-worker-test.wasm"));

static NATIVE: LazyLock<WasmContent> =
    LazyLock::new(|| WasmContent::from_component(EMBEDDED_WORKER, Backend::Native).unwrap());
static PULLEY: LazyLock<WasmContent> =
    LazyLock::new(|| WasmContent::from_component(EMBEDDED_WORKER, Backend::Pulley).unwrap());
static HOOKS: LazyLock<WasmContent> =
    LazyLock::new(|| WasmContent::from_component(TEST_WORKER, Backend::Native).unwrap());
static HOOKS_PULLEY: LazyLock<WasmContent> =
    LazyLock::new(|| WasmContent::from_component(TEST_WORKER, Backend::Pulley).unwrap());

fn request(raw: &'static [u8], limits: ContentLimits) -> RenderRequest {
    RenderRequest {
        raw: Bytes::from_static(raw),
        options: RenderOptions::default(),
        limits,
    }
}

async fn renders_a_message(content: &WasmContent) {
    let out = content
        .render(request(fixture("cid-image.eml"), ContentLimits::default()))
        .await
        .unwrap();
    assert_eq!(out.images.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_native() {
    testing::run(Arc::new(NATIVE.clone())).await;
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(
    debug_assertions,
    ignore = "Pulley is about 100x slower in unoptimized builds; run with --release"
)]
async fn conformance_pulley() {
    assert_eq!(PULLEY.backend(), Backend::Pulley);
    testing::run(Arc::new(PULLEY.clone())).await;
}

#[test]
fn default_backend_follows_the_feature() {
    let expected = if cfg!(feature = "pulley") {
        Backend::Pulley
    } else {
        Backend::Native
    };
    assert_eq!(Backend::default(), expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn embedded_constructor_works() {
    let content = WasmContent::embedded().unwrap();
    assert_eq!(content.backend(), Backend::default());
    renders_a_message(&content).await;
}

#[test]
fn from_runner_wraps_a_compiled_worker() {
    let runner = WasmRunner::new(EMBEDDED_WORKER, Backend::Native).unwrap();
    let content = WasmContent::from_runner(runner);
    assert_eq!(content.backend(), Backend::Native);
    let out = content
        .render_blocking(request(fixture("cid-image.eml"), ContentLimits::default()))
        .unwrap();
    assert_eq!(out.images.len(), 1);
}

#[test]
fn rejects_bytes_that_are_not_a_worker() {
    assert_eq!(
        WasmContent::from_component(b"not wasm", Backend::Native).unwrap_err(),
        ContentError::Unavailable
    );
}

async fn spinning_worker_times_out(content: &WasmContent) {
    let limits = ContentLimits {
        time_budget_ms: 100,
        ..ContentLimits::default()
    };
    let started = Instant::now();
    let result = content.render(request(b"RINSE-TEST-SPIN", limits)).await;
    assert_eq!(result, Err(ContentError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(5));
    renders_a_message(content).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn spinning_worker_times_out_native() {
    spinning_worker_times_out(&HOOKS).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn spinning_worker_times_out_pulley() {
    spinning_worker_times_out(&HOOKS_PULLEY).await;
}

async fn hungry_worker_hits_memory_limit(content: &WasmContent) {
    let limits = ContentLimits {
        memory_bytes: 64 << 20,
        ..ContentLimits::default()
    };
    let result = content.render(request(b"RINSE-TEST-HOG", limits)).await;
    assert_eq!(result, Err(ContentError::LimitExceeded(LimitKind::Memory)));
    renders_a_message(content).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hungry_worker_hits_memory_limit_native() {
    hungry_worker_hits_memory_limit(&HOOKS).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hungry_worker_hits_memory_limit_pulley() {
    hungry_worker_hits_memory_limit(&HOOKS_PULLEY).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_output_is_refused() {
    let limits = ContentLimits {
        max_output_bytes: 1 << 20,
        ..ContentLimits::default()
    };
    let result = HOOKS.render(request(b"RINSE-TEST-HUGE", limits)).await;
    assert_eq!(result, Err(ContentError::LimitExceeded(LimitKind::Output)));
    renders_a_message(&HOOKS).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn garbage_output_is_crashed() {
    let result = HOOKS
        .render(request(b"RINSE-TEST-GARBAGE", ContentLimits::default()))
        .await;
    assert_eq!(result, Err(ContentError::Crashed));
}

#[tokio::test(flavor = "multi_thread")]
async fn panicking_worker_is_crashed() {
    let result = HOOKS
        .render(request(b"RINSE-TEST-PANIC", ContentLimits::default()))
        .await;
    assert_eq!(result, Err(ContentError::Crashed));
    renders_a_message(&HOOKS).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn renders_concurrently() {
    let mut tasks = Vec::new();
    for _ in 0..8 {
        tasks.push(tokio::spawn(async {
            NATIVE
                .render(request(fixture("cid-image.eml"), ContentLimits::default()))
                .await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap().images.len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn shipped_worker_has_no_test_hooks() {
    assert_ne!(EMBEDDED_WORKER, TEST_WORKER);
    let spin = ContentLimits {
        time_budget_ms: 2_000,
        ..ContentLimits::default()
    };
    let small = ContentLimits {
        memory_bytes: 64 << 20,
        max_output_bytes: 1 << 20,
        ..ContentLimits::default()
    };
    for (raw, limits, hook) in [
        (&b"RINSE-TEST-SPIN"[..], spin, ContentError::Timeout),
        (
            b"RINSE-TEST-HOG",
            small,
            ContentError::LimitExceeded(LimitKind::Memory),
        ),
        (
            b"RINSE-TEST-HUGE",
            small,
            ContentError::LimitExceeded(LimitKind::Output),
        ),
        (
            b"RINSE-TEST-GARBAGE",
            ContentLimits::default(),
            ContentError::Crashed,
        ),
        (
            b"RINSE-TEST-PANIC",
            ContentLimits::default(),
            ContentError::Crashed,
        ),
    ] {
        let result = NATIVE.render(request(raw, limits)).await;
        assert_ne!(result.err(), Some(hook), "{}", String::from_utf8_lossy(raw));
    }
}
