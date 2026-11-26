//! The real executable, started through this platform's launcher by `ProcessContent`, renders a
//! message and decodes a part, on both backends.

use std::path::PathBuf;
use std::process::ExitCode;

use bytes::Bytes;
use rinse_mail::testing::fixture;
use rinse_mail::{Content, ContentLimits, PartRequest, RenderOptions, RenderRequest};
use rinse_mail_process::{ProcessConfig, ProcessContent};
use rinse_sandbox::WorkerCommand;

mod common;

fn content(args: &[&str]) -> ProcessContent {
    let mut config = ProcessConfig::new(WorkerCommand {
        program: PathBuf::from(env!("CARGO_BIN_EXE_rinse-worker-host")),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
    });
    config.warm_workers = 0;
    ProcessContent::new(common::launcher(), config)
}

fn main() -> ExitCode {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let limits = ContentLimits {
            time_budget_ms: 60_000,
            ..ContentLimits::default()
        };
        for args in [&[][..], &["--backend=pulley"][..]] {
            let content = content(args);
            let out = content
                .render(RenderRequest {
                    raw: Bytes::from_static(fixture("cid-image.eml")),
                    options: RenderOptions::default(),
                    limits,
                })
                .await
                .unwrap_or_else(|e| panic!("render with {args:?}: {e}"));
            assert_eq!(out.images.len(), 1);
            let raw = Bytes::from_static(fixture("calendar-attachment.eml"));
            let out = content
                .render(RenderRequest {
                    raw: raw.clone(),
                    options: RenderOptions::default(),
                    limits,
                })
                .await
                .unwrap_or_else(|e| panic!("render with {args:?}: {e}"));
            let attachment = out
                .attachments
                .first()
                .expect("the fixture has an attachment");
            let part = content
                .decode_part(PartRequest {
                    raw,
                    part: attachment.part,
                    limits,
                })
                .await
                .unwrap_or_else(|e| panic!("decode with {args:?}: {e}"));
            assert_eq!(part.part, attachment.part);
            println!("worker host {args:?}: ok ({})", content.launcher_name());
        }
    });
    ExitCode::SUCCESS
}
