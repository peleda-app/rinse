use std::sync::LazyLock;
use std::time::Instant;

use rinse_wasm_fixtures::TEST_WORKER;

use super::*;

static NATIVE: LazyLock<WasmRunner> =
    LazyLock::new(|| WasmRunner::new(TEST_WORKER, Backend::Native).unwrap());
static PULLEY: LazyLock<WasmRunner> =
    LazyLock::new(|| WasmRunner::new(TEST_WORKER, Backend::Pulley).unwrap());

fn both() -> [&'static WasmRunner; 2] {
    [&NATIVE, &PULLEY]
}

fn echoes(runner: &WasmRunner) {
    let out = runner
        .run_blocking(b"hello".to_vec(), &Limits::default())
        .unwrap();
    assert_eq!(&out[..], b"hello");
}

#[test]
fn echoes_on_both_backends() {
    assert_eq!(NATIVE.backend(), Backend::Native);
    assert_eq!(PULLEY.backend(), Backend::Pulley);
    for runner in both() {
        echoes(runner);
        let empty = runner.run_blocking(Vec::new(), &Limits::default()).unwrap();
        assert!(empty.is_empty());
    }
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

#[test]
fn rejects_bytes_that_are_not_a_component() {
    for bytes in [&b"not wasm"[..], &[], b"\0asm\x01\0\0\0"] {
        assert_eq!(
            WasmRunner::new(bytes, Backend::Native).unwrap_err(),
            WasmError::Unavailable
        );
    }
}

#[test]
fn spinning_component_times_out() {
    let limits = Limits {
        time_budget: Duration::from_millis(100),
        ..Limits::default()
    };
    for runner in both() {
        let started = Instant::now();
        assert_eq!(
            runner.run_blocking(b"spin".to_vec(), &limits),
            Err(WasmError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        echoes(runner);
    }
}

#[test]
fn hungry_component_hits_the_memory_limit() {
    let limits = Limits {
        memory_bytes: 64 << 20,
        ..Limits::default()
    };
    for runner in both() {
        assert_eq!(
            runner.run_blocking(b"hog".to_vec(), &limits),
            Err(WasmError::MemoryExceeded)
        );
        echoes(runner);
    }
}

#[test]
fn oversized_output_is_refused() {
    let limits = Limits {
        max_output_bytes: 1 << 20,
        ..Limits::default()
    };
    assert_eq!(
        NATIVE.run_blocking(b"huge".to_vec(), &limits),
        Err(WasmError::OutputTooLarge)
    );
    let exact = Limits {
        max_output_bytes: 5,
        ..Limits::default()
    };
    assert_eq!(
        &NATIVE.run_blocking(b"12345".to_vec(), &exact).unwrap()[..],
        b"12345"
    );
    assert_eq!(
        NATIVE.run_blocking(b"123456".to_vec(), &exact),
        Err(WasmError::OutputTooLarge)
    );
    let generous = Limits {
        max_output_bytes: 4 << 20,
        ..Limits::default()
    };
    assert_eq!(
        NATIVE
            .run_blocking(b"huge".to_vec(), &generous)
            .unwrap()
            .len(),
        2 << 20
    );
}

#[test]
fn panics_and_failed_exits_are_crashes() {
    for runner in both() {
        for input in [&b"panic"[..], b"exit3"] {
            assert_eq!(
                runner.run_blocking(input.to_vec(), &Limits::default()),
                Err(WasmError::Crashed)
            );
            echoes(runner);
        }
    }
}

#[test]
fn the_context_is_empty_and_frozen() {
    let out = NATIVE
        .run_blocking(b"probe".to_vec(), &Limits::default())
        .unwrap();
    assert_eq!(
        std::str::from_utf8(&out).unwrap(),
        "env=0 args=0 root=denied cwd=denied tmp=denied tcp=denied wall=0"
    );
}

#[test]
fn nothing_survives_from_one_call_to_the_next() {
    for _ in 0..3 {
        let out = NATIVE
            .run_blocking(b"count".to_vec(), &Limits::default())
            .unwrap();
        assert_eq!(&out[..], b"1");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_concurrently_on_the_blocking_pool() {
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        tasks.push(tokio::spawn(async move {
            NATIVE.run(vec![b'a' + i; 1000], Limits::default()).await
        }));
    }
    for (i, task) in tasks.into_iter().enumerate() {
        let out = task.await.unwrap().unwrap();
        assert_eq!(out.len(), 1000);
        assert!(out.iter().all(|&b| b == b'a' + i as u8));
    }
}

#[test]
fn clones_share_the_component() {
    let clone = NATIVE.clone();
    echoes(&clone);
    assert!(format!("{clone:?}").contains("Native"));
}
