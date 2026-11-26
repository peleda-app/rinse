//! A helper for build scripts that embed a WebAssembly component built from the same workspace.
//!
//! [`Component::build`] runs a nested `cargo build --target wasm32-wasip2 --release` for one
//! binary, in its own target directory next to the outer build's (so it never waits on the outer
//! build's lock), with the outer build's wrapper and flag variables cleared, and returns the path
//! of the `.wasm` file. When the compiler running the build has no `wasm32-wasip2` standard
//! library, it asks rustup for the toolchain named in the workspace's `rust-toolchain.toml`.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The target every component is built for.
pub const TARGET: &str = "wasm32-wasip2";

/// One binary of a workspace to build as a component.
#[derive(Debug, Clone)]
pub struct Component<'a> {
    /// Root of the workspace: holds `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml`.
    pub workspace: &'a Path,
    /// The package.
    pub package: &'a str,
    /// The binary of the package; its file is `<bin>.wasm`.
    pub bin: &'a str,
    /// Features of the package to turn on.
    pub features: &'a [&'a str],
    /// The nested build's target directory.
    pub target_dir: &'a Path,
}

impl Component<'_> {
    /// Builds the component and returns the path of the `.wasm` file. Panics with an explanation
    /// when cargo cannot start or the build fails, which fails the calling build script.
    pub fn build(&self) -> PathBuf {
        let mut cmd = cargo(self.workspace);
        cmd.arg("build")
            .arg("--manifest-path")
            .arg(self.workspace.join("Cargo.toml"))
            .args([
                "-p",
                self.package,
                "--bin",
                self.bin,
                "--target",
                TARGET,
                "--release",
            ]);
        if !self.features.is_empty() {
            cmd.arg("--features").arg(self.features.join(","));
        }
        for var in [
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTFLAGS",
            "CARGO_BUILD_TARGET",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_TARGET_DIR",
            "CARGO_PRIMARY_PACKAGE",
            "CLIPPY_ARGS",
        ] {
            cmd.env_remove(var);
        }
        cmd.env("CARGO_TARGET_DIR", self.target_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let status = cmd.status().unwrap_or_else(|e| {
            panic!(
                "could not start cargo to build {} for {TARGET}: {e}",
                self.bin
            )
        });
        assert!(
            status.success(),
            "building {} for {TARGET} failed; the toolchain needs the {TARGET} standard library \
             (rustup target add {TARGET})",
            self.bin
        );
        self.target_dir
            .join(TARGET)
            .join("release")
            .join(format!("{}.wasm", self.bin))
    }

    /// Prints `cargo:rerun-if-changed` for the workspace manifest, lock file and toolchain file
    /// and for each of `inputs` (paths relative to the workspace root).
    pub fn rerun_if_changed(&self, inputs: &[&str]) {
        for input in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
            .iter()
            .chain(inputs)
        {
            println!(
                "cargo:rerun-if-changed={}",
                self.workspace.join(input).display()
            );
        }
    }
}

/// A target directory for nested builds named `name`, next to the outer build's: four levels
/// above `OUT_DIR` (`<target>/<profile>/build/<crate>-<hash>/out`).
pub fn nested_target_dir(name: &str) -> PathBuf {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    out.ancestors().nth(4).unwrap_or(&out).join(name)
}

/// Copies a built file, panicking with both paths on failure.
pub fn copy(from: &Path, to: &Path) {
    std::fs::copy(from, to)
        .unwrap_or_else(|e| panic!("copying {} to {}: {e}", from.display(), to.display()));
}

fn has_wasip2(rustc: &OsString) -> bool {
    Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            let sysroot = String::from_utf8_lossy(&o.stdout).trim().to_owned();
            Path::new(&sysroot)
                .join("lib/rustlib")
                .join(TARGET)
                .is_dir()
        })
        .unwrap_or(false)
}

fn toolchain_channel(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join("rust-toolchain.toml")).ok()?;
    text.lines()
        .find_map(|l| l.trim().strip_prefix("channel"))
        .and_then(|rest| rest.split('"').nth(1))
        .map(str::to_owned)
}

fn cargo(root: &Path) -> Command {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    if has_wasip2(&rustc) {
        return Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    }
    let channel = toolchain_channel(root).unwrap_or_else(|| {
        panic!(
            "{} has no {TARGET} standard library and no rust-toolchain.toml names one",
            rustc.display()
        )
    });
    let which = |tool: &str| -> PathBuf {
        let out = Command::new("rustup")
            .args(["which", "--toolchain", &channel, tool])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .unwrap_or_else(|| {
                panic!(
                    "{} has no {TARGET} standard library and rustup cannot provide toolchain \
                     {channel}; install it with `rustup target add {TARGET} --toolchain {channel}`",
                    rustc.display()
                )
            });
        PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())
    };
    let mut cmd = Command::new(which("cargo"));
    cmd.env("RUSTC", which("rustc"));
    for var in ["RUSTDOC", "CARGO", "RUSTUP_TOOLCHAIN"] {
        cmd.env_remove(var);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_toolchain_channel() {
        let dir = std::env::temp_dir().join(format!("rinse-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.99\"\ntargets = [\"wasm32-wasip2\"]\n",
        )
        .unwrap();
        assert_eq!(toolchain_channel(&dir).as_deref(), Some("1.99"));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(toolchain_channel(&dir), None);
    }
}
