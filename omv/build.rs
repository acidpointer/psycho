use std::env;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR") else {
        println!("cargo:warning=CARGO_MANIFEST_DIR is not set for omv build script");
        std::process::exit(1);
    };
    let manifest_dir = PathBuf::from(manifest_dir);
    let def_file = manifest_dir.join("omv.def");

    println!("cargo:rustc-cdylib-link-arg=-static-libstdc++");
    println!("cargo:rustc-cdylib-link-arg=-static-libgcc");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--exclude-all-symbols");
    println!("cargo:rustc-cdylib-link-arg={}", def_file.display());

    let build_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned());

    println!("cargo:rustc-env=OMV_BUILD_UNIX={build_unix}");
    println!("cargo:rustc-env=OMV_BUILD_TARGET={target}");
    println!("cargo:rustc-env=OMV_BUILD_PROFILE={profile}");
}
