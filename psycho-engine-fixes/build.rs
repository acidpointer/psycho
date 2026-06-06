use shadow_rs::ShadowBuilder;
use std::env;
use std::path::PathBuf;

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

    if let Err(err) = ShadowBuilder::builder().build() {
        println!("cargo:warning=shadow-rs build failed: {err}");
        std::process::exit(1);
    }
}
