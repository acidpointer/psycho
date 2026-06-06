use std::{env, path::PathBuf, process::Command};

fn main() {
    let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR") else {
        println!("cargo:warning=CARGO_MANIFEST_DIR is not set for psycho-imgui build script");
        std::process::exit(1);
    };
    let manifest_dir = PathBuf::from(manifest_dir);
    let imgui_dir = manifest_dir.join("vendor").join("imgui");
    let backends_dir = imgui_dir.join("backends");

    println!("cargo:rerun-if-changed=src/bridge.cpp");
    println!("cargo:rerun-if-changed=vendor/imgui/imgui.cpp");
    println!("cargo:rerun-if-changed=vendor/imgui/imgui_draw.cpp");
    println!("cargo:rerun-if-changed=vendor/imgui/imgui_tables.cpp");
    println!("cargo:rerun-if-changed=vendor/imgui/imgui_widgets.cpp");
    println!("cargo:rerun-if-changed=vendor/imgui/backends/imgui_impl_dx9.cpp");
    println!("cargo:rerun-if-changed=vendor/imgui/backends/imgui_impl_win32.cpp");

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .include(&imgui_dir)
        .include(&backends_dir)
        .define("WIN32_LEAN_AND_MEAN", None)
        .define("NOMINMAX", None)
        .define("IMGUI_USE_BGRA_PACKED_COLOR", None)
        .cpp_link_stdlib_static(true)
        .file("src/bridge.cpp")
        .file(imgui_dir.join("imgui.cpp"))
        .file(imgui_dir.join("imgui_draw.cpp"))
        .file(imgui_dir.join("imgui_tables.cpp"))
        .file(imgui_dir.join("imgui_widgets.cpp"))
        .file(backends_dir.join("imgui_impl_dx9.cpp"))
        .file(backends_dir.join("imgui_impl_win32.cpp"));

    if env::var("TARGET").is_ok_and(|target| target.contains("windows-gnu")) {
        add_mingw_static_lib_search_path("i686-w64-mingw32-g++", "libstdc++.a");
        build.flag_if_supported("-std=c++11");
        build.flag_if_supported("-fno-exceptions");
        build.flag_if_supported("-fno-rtti");
    }

    build.compile("psycho_imgui");

    println!("cargo:rustc-link-lib=shell32");
    println!("cargo:rustc-link-lib=gdi32");
    println!("cargo:rustc-link-lib=dwmapi");
}

fn add_mingw_static_lib_search_path(compiler: &str, library: &str) {
    let Ok(output) = Command::new(compiler)
        .arg(format!("-print-file-name={library}"))
        .output()
    else {
        return;
    };

    if !output.status.success() {
        return;
    }

    let path_text = String::from_utf8_lossy(&output.stdout);
    let archive = PathBuf::from(path_text.trim());
    if archive.file_name().is_none_or(|name| name != library) {
        return;
    }

    if let Some(parent) = archive.parent() {
        println!("cargo:rustc-link-search=native={}", parent.display());
    }
}
