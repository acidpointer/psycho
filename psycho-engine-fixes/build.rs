use shadow_rs::{COMMIT_HASH, ShadowBuilder, default_deny};
use std::env;
use std::io::Write;
use std::path::PathBuf;

/// Commit supplied by builds whose source tree has no `.git` (the Nix
/// sandbox). shadow-rs only reads git, so without this override the logged
/// commit would be empty.
const GIT_COMMIT_OVERRIDE: &str = "PSYCHO_GIT_COMMIT";

fn main() {
    let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR") else {
        println!(
            "cargo:warning=CARGO_MANIFEST_DIR is not set for psycho-engine-fixes build script"
        );
        std::process::exit(1);
    };
    let manifest_dir = PathBuf::from(manifest_dir);
    let def_file = manifest_dir.join("psycho_engine_fixes.def");

    println!("cargo:rustc-cdylib-link-arg=-Wl,--exclude-all-symbols");
    println!("cargo:rustc-cdylib-link-arg={}", def_file.display());
    // rustc's generated export list names the `extern "system"` exports
    // undecorated, while i686 stdcall symbols carry `@N`. ld's stdcall fixup
    // resolves them to the intended exports; enabling it explicitly keeps that
    // result and silences the per-symbol notice.
    println!("cargo:rustc-cdylib-link-arg=-Wl,--enable-stdcall-fixup");
    println!("cargo:rerun-if-env-changed={GIT_COMMIT_OVERRIDE}");

    let mut builder = ShadowBuilder::builder();
    let commit_override = env::var(GIT_COMMIT_OVERRIDE)
        .ok()
        .filter(|commit| is_commit_hash(commit));
    if let Some(commit) = commit_override {
        // Replace shadow-rs's git-derived constant with the supplied one so
        // `build_info::COMMIT_HASH` keeps its name and type.
        let mut deny = default_deny();
        deny.insert(COMMIT_HASH);
        builder = builder.deny_const(deny).hook(move |file: &std::fs::File| {
            let mut file = file;
            writeln!(file, "#[allow(dead_code)]")?;
            writeln!(file, "pub const COMMIT_HASH: &str = \"{commit}\";")?;
            Ok(())
        });
    } else if env::var_os(GIT_COMMIT_OVERRIDE).is_some() {
        println!("cargo:warning={GIT_COMMIT_OVERRIDE} is not a hexadecimal commit hash; ignored");
    }

    if let Err(err) = builder.build() {
        println!("cargo:warning=shadow-rs build failed: {err}");
        std::process::exit(1);
    }
}

/// Accept only a full hexadecimal object name, which is also safe to embed
/// in a Rust string literal without escaping.
fn is_commit_hash(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
