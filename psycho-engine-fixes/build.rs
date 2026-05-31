use shadow_rs::ShadowBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let def_file = manifest_dir.join("psycho_engine_fixes.def");

    println!("cargo:rustc-cdylib-link-arg=-Wl,--exclude-all-symbols");
    println!("cargo:rustc-cdylib-link-arg={}", def_file.display());

    ShadowBuilder::builder().build().unwrap();
}
