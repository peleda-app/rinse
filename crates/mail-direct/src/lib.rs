//! [`DirectContent`] runs the content engine in the calling process, on Tokio's blocking pool.
//!
//! **This is not a security wall.** A parser bug exploited by a message runs with every right
//! of the process that hosts it. Use it for tests, development, and the server node, which runs
//! inside its own container; devices use the sandboxed worker described in `docs/WALLS.md`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use rinse_mail::{
    Content, ContentError, DecodedPart, PartRequest, RenderRequest, Rendered, verify_decoded_part,
    verify_rendered,
};

/// The content pipeline in-process.
///
/// Every call runs on `tokio::task::spawn_blocking` behind `catch_unwind`, so a panic becomes
/// [`ContentError::Crashed`], and under `tokio::time::timeout` with the request's time budget, so
/// a slow call returns [`ContentError::Timeout`]. A timed-out render is told to stop and gives
/// its blocking thread back within a small step of work; a timed-out `decode_part` (one linear
/// transfer decode) runs to its end. Memory is bounded by the engine's own limits (parser node
/// and depth budgets, image allocation limits derived from `memory_bytes`), not by the process:
/// nothing here caps the process as a whole.
///
/// Every output is checked with [`verify_rendered`] or [`verify_decoded_part`], like the core
/// checks a worker's.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectContent;

impl DirectContent {
    /// A pipeline that needs no configuration.
    pub fn new() -> Self {
        Self
    }
}

async fn run<T: Send + 'static>(
    budget_ms: u64,
    work: impl FnOnce(Arc<AtomicBool>) -> Result<T, ContentError> + Send + 'static,
) -> Result<T, ContentError> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let task = tokio::task::spawn_blocking(move || catch_unwind(AssertUnwindSafe(|| work(flag))));
    match tokio::time::timeout(Duration::from_millis(budget_ms.max(1)), task).await {
        Err(_) => {
            stop.store(true, Ordering::Relaxed);
            Err(ContentError::Timeout)
        }
        Ok(Err(_)) | Ok(Ok(Err(_))) => Err(ContentError::Crashed),
        Ok(Ok(Ok(result))) => result,
    }
}

#[async_trait]
impl Content for DirectContent {
    async fn render(&self, request: RenderRequest) -> Result<Rendered, ContentError> {
        if request.raw.len() as u64 > request.limits.max_input_bytes {
            return Err(ContentError::InputTooLarge);
        }
        let request = Arc::new(request);
        let shared = Arc::clone(&request);
        let out = run(request.limits.time_budget_ms, move |stop| {
            rinse_mail_engine::render_until(&shared, &|| stop.load(Ordering::Relaxed))
        })
        .await?;
        verify_rendered(&request, &out)?;
        Ok(out)
    }

    async fn decode_part(&self, request: PartRequest) -> Result<DecodedPart, ContentError> {
        if request.raw.len() as u64 > request.limits.max_input_bytes {
            return Err(ContentError::InputTooLarge);
        }
        let request = Arc::new(request);
        let shared = Arc::clone(&request);
        let out = run(request.limits.time_budget_ms, move |_| {
            rinse_mail_engine::decode_part(&shared)
        })
        .await?;
        verify_decoded_part(&request, &out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use rinse_mail::testing::{self, fixture};
    use rinse_mail::{ContentLimits, RenderOptions};

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn conformance() {
        testing::run(Arc::new(DirectContent::new())).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn panics_become_crashed() {
        assert_eq!(
            run::<()>(1_000, |_| panic!("engine bug")).await,
            Err(ContentError::Crashed)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn slow_work_times_out() {
        let slow = |_| {
            std::thread::sleep(Duration::from_millis(300));
            Ok(())
        };
        assert_eq!(run(10, slow).await, Err(ContentError::Timeout));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timeout_tells_the_work_to_stop() {
        let (tx, rx) = std::sync::mpsc::channel();
        let work = move |stop: Arc<AtomicBool>| {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(1));
            }
            tx.send(()).unwrap();
            Ok(())
        };
        assert_eq!(run(10, work).await, Err(ContentError::Timeout));
        rx.recv_timeout(Duration::from_secs(5))
            .expect("the work saw the stop signal");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn renders_concurrently() {
        let content = Arc::new(DirectContent::new());
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let content = Arc::clone(&content);
            tasks.push(tokio::spawn(async move {
                content
                    .render(RenderRequest {
                        raw: Bytes::from_static(fixture("cid-image.eml")),
                        options: RenderOptions::default(),
                        limits: ContentLimits::default(),
                    })
                    .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap().images.len(), 1);
        }
    }
}
