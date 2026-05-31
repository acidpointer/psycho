use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let def_file = manifest_dir.join("dinput8.def");

    println!("cargo:rustc-cdylib-link-arg=-Wl,--exclude-all-symbols");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--exclude-symbols=_rust_eh_personality");
    println!("cargo:rustc-cdylib-link-arg={}", def_file.display());
}
