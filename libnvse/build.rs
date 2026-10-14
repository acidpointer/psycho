use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

fn main() {
    let target = match env::var("TARGET") {
        Ok(target) => target,
        Err(err) => fail(format!("TARGET not set: {err}")),
    };

    // xNVSE is 32-bit only
    if !target.contains("i686") && !target.contains("i586") {
        fail(
            "libnvse only supports i686 (32-bit) targets. \
             xNVSE is designed for 32-bit Fallout New Vegas.",
        );
    }

    let is_msvc = target.contains("msvc");

    // Use xNVSE from git submodule
    let nvse_dir = PathBuf::from("xnvse");

    if !nvse_dir.exists() || !nvse_dir.join("nvse/nvse/PluginAPI.h").exists() {
        fail(
            "xNVSE submodule not found or not initialized.\n\
             Please run: git submodule update --init --recursive",
        );
    }

    let out_dir = match env::var_os("OUT_DIR") {
        Some(out_dir) => PathBuf::from(out_dir),
        None => fail("OUT_DIR not set"),
    };

    let patched_include_dir = patch_xnvse_headers(&nvse_dir, &out_dir);

    // Clang target must match the ABI of the game binary (MSVC).
    // Even when compiling with MinGW, we target MSVC ABI because
    // xNVSE and Fallout NV are MSVC-compiled binaries.
    let clang_target = "i686-pc-windows-msvc";

    eprintln!(
        "Generating bindings for xNVSE 6.4.4 (rust_target={}, clang_target={})",
        target, clang_target
    );

    let mut builder = bindgen::Builder::default()
        .header("wrapper/nvse_wrapper.h")
        // Include paths: the patched header copy shadows its original, then
        // xNVSE source. The patched copy no longer sits next to its siblings,
        // so the original directory resolves its quoted relative includes.
        .clang_arg(format!("-I{}", patched_include_dir.display()))
        .clang_arg(format!("-I{}", nvse_dir.display()))
        .clang_arg(format!("-I{}", nvse_dir.join("nvse").display()))
        .clang_arg(format!("-I{}", nvse_dir.join("nvse/nvse").display()))
        // Target and defines
        .clang_arg("-target")
        .clang_arg(clang_target)
        .clang_arg("-DRUNTIME=1")
        .clang_arg("-D_WIN32")
        // C++ configuration
        .clang_arg("-x")
        .clang_arg("c++")
        .clang_arg("-std=c++17")
        .clang_arg("-fms-compatibility")
        .clang_arg("-fms-extensions")
        // Suppress warnings
        .clang_arg("-Wno-unknown-attributes")
        .clang_arg("-Wno-ignored-attributes")
        .clang_arg("-Wno-error")
        .clang_arg("-Wno-c++17-attribute-extensions")
        // Prevent problematic intrinsic headers
        .clang_arg("-D_MM_MALLOC_H_INCLUDED")
        .clang_arg("-D_INTRIN_H_")
        .clang_arg("-D__INTRIN_H")
        .clang_arg("-D_INC_MALLOC");

    // Use our stub headers for both MSVC and MinGW targets.
    // This guarantees identical bindings regardless of host OS
    // and removes the Windows SDK dependency for bindgen.
    let _ = is_msvc; // acknowledged; both paths use stubs
    builder = builder
        .clang_arg("-nostdinc++")
        .clang_arg(format!("-I{}", "wrapper/include"));

    let bindings = match builder
        // Bindgen configuration
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Block C++ stdlib types (we don't cross the FFI boundary with them)
        .blocklist_type("std::vector.*")
        .blocklist_type("std::map.*")
        .blocklist_type("std::unordered_map.*")
        .blocklist_type("std::list.*")
        .blocklist_type("std::function.*")
        .blocklist_type("std::shared_ptr.*")
        .blocklist_type("std::unique_ptr.*")
        .blocklist_type("__gnu_cxx::.*")
        .opaque_type("std::string")
        .opaque_type("std::string_view")
        .opaque_type("std::vector")
        .opaque_type("std::map")
        .opaque_type("std::unordered_map")
        .opaque_type("std::unique_ptr")
        .opaque_type("std::shared_ptr")
        .blocklist_type("game_unique_ptr")
        .blocklist_function("IsFormParam")
        .blocklist_function("IsPtrParam")
        .blocklist_function("GetNonPtrParamType")
        .blocklist_function("MakeUnique")
        .blocklist_function("EnterCriticalSection")
        .blocklist_function("LeaveCriticalSection")
        .blocklist_function("GetCurrentThreadId")
        .blocklist_function("Sleep")
        .allowlist_function(".*")
        .allowlist_type(".*")
        .allowlist_var(".*")
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .use_core()
        .derive_default(true)
        .derive_debug(true)
        .derive_copy(true)
        .enable_cxx_namespaces()
        .layout_tests(false)
        .raw_line("#![allow(unsafe_op_in_unsafe_fn)]")
        .generate()
    {
        Ok(bindings) => bindings,
        Err(err) => fail(format!("Unable to generate bindings: {err}")),
    };

    let bindings_path = PathBuf::from("src/bindings/nvse.rs");
    if let Err(err) = bindings.write_to_file(&bindings_path) {
        fail(format!(
            "Couldn't write bindings to {}: {err}",
            bindings_path.display()
        ));
    }

    eprintln!(
        "[OK] Generated xNVSE bindings at {}",
        bindings_path.display()
    );

    // Rerun triggers
    println!("cargo:rerun-if-changed=wrapper/nvse_wrapper.h");
    println!("cargo:rerun-if-changed=wrapper/include");
    println!("cargo:rerun-if-changed=xnvse/nvse/nvse/PluginAPI.h");
    println!("cargo:rerun-if-changed=xnvse/nvse/nvse/GameAPI.h");
    println!("cargo:rerun-if-changed=build.rs");
}

fn fail(message: impl AsRef<str>) -> ! {
    let message = message.as_ref();
    println!("cargo:warning={message}");
    eprintln!("{message}");
    process::exit(1);
}

/// Writes a bindgen-compatible copy of xNVSE's `PluginAPI.h` into `OUT_DIR`.
///
/// The submodule header declares helpers as `static [[nodiscard]] bool ...`.
/// MSVC accepts an attribute list after `static`, but clang rejects that
/// position with "an attribute list cannot appear here". The copy moves each
/// attribute to the start of its declaration (`[[nodiscard]] static bool ...`),
/// where standard C++ places it, so the declarations keep their meaning.
/// Neither a bindgen parse callback nor `-Dnodiscard=` can avoid this:
/// callbacks run after clang parses, and an empty `[[]]` in the same position
/// is still rejected.
///
/// The copy is written to `<out_dir>/xnvse_patched/nvse/PluginAPI.h` and the
/// submodule is never modified, so `git submodule` state stays clean and the
/// patch is redone on every build script run.
///
/// # Arguments
///
/// * `nvse_dir` - Root of the xNVSE checkout (the `xnvse` submodule).
/// * `out_dir` - Cargo's `OUT_DIR` for this build script.
///
/// # Returns
///
/// The `xnvse_patched` include root. It must be passed to clang with `-I`
/// before the xNVSE include paths so `#include "nvse/PluginAPI.h"` in the
/// wrapper resolves to the patched copy. Headers that include the bare
/// `"PluginAPI.h"` from `nvse/nvse/` still find the original first, because
/// quoted includes search the including file's directory before `-I` paths.
///
/// # Failure
///
/// Exits the build script through [`fail`] if the source header cannot be
/// read or the patched copy cannot be written.
fn patch_xnvse_headers(nvse_dir: &Path, out_dir: &Path) -> PathBuf {
    let plugin_api = nvse_dir.join("nvse/nvse/PluginAPI.h");

    let content = match fs::read_to_string(&plugin_api) {
        Ok(content) => content,
        Err(err) => fail(format!("Couldn't read {}: {err}", plugin_api.display())),
    };

    let include_dir = out_dir.join("xnvse_patched");
    let patched_dir = include_dir.join("nvse");
    let patched_path = patched_dir.join("PluginAPI.h");

    if let Err(err) = fs::create_dir_all(&patched_dir) {
        fail(format!("Couldn't create {}: {err}", patched_dir.display()));
    }

    let patched = content.replace("static [[nodiscard]]", "[[nodiscard]] static");

    if let Err(err) = fs::write(&patched_path, patched) {
        fail(format!("Couldn't write {}: {err}", patched_path.display()));
    }

    include_dir
}
