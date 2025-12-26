use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").expect("TARGET not set");

    // xNVSE is 32-bit only - enforce i686 architecture
    if !target.contains("i686") && !target.contains("i586") {
        panic!("libnvse only supports i686 (32-bit) targets. xNVSE is designed for 32-bit Fallout New Vegas.");
    }

    // Use xNVSE from git submodule
    let nvse_dir = PathBuf::from("xnvse");

    // Verify submodule exists
    if !nvse_dir.exists() || !nvse_dir.join("nvse/nvse/PluginAPI.h").exists() {
        panic!(
            "xNVSE submodule not found or not initialized.\n\
             Please run: git submodule update --init --recursive"
        );
    }

    // Patch headers if needed (done in-place in submodule)
    patch_xnvse_headers(&nvse_dir);

    // Determine clang target
    let clang_target = "i686-pc-windows-msvc";
    eprintln!("Generating bindings for xNVSE 6.4.4 (target: {})", clang_target);

    // Generate bindings
    let bindings = bindgen::Builder::default()
        .header("wrapper/nvse_wrapper.h")
        // Include paths
        .clang_arg(format!("-I{}", "wrapper/include"))
        .clang_arg(format!("-I{}", nvse_dir.display()))
        .clang_arg(format!("-I{}", nvse_dir.join("nvse").display()))
        // Target and defines
        .clang_arg("-target").clang_arg(clang_target)
        .clang_arg("-DRUNTIME=1")
        .clang_arg("-D_WIN32")
        // C++ configuration
        .clang_arg("-x").clang_arg("c++")
        .clang_arg("-std=c++17")
        .clang_arg("-fms-compatibility")
        .clang_arg("-fms-extensions")
        .clang_arg("-nostdinc++")
        // Suppress warnings and allow C++17 attributes
        .clang_arg("-Wno-unknown-attributes")
        .clang_arg("-Wno-ignored-attributes")
        .clang_arg("-Wno-error")
        .clang_arg("-Wno-c++17-attribute-extensions")
        // Prevent problematic intrinsic headers
        .clang_arg("-D_MM_MALLOC_H_INCLUDED")
        .clang_arg("-D_INTRIN_H_")
        .clang_arg("-D__INTRIN_H")
        .clang_arg("-D_INC_MALLOC")
        // Bindgen configuration
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Block most std types but allow string and string_view which are used by NVSE API
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
        .allowlist_function(".*")
        .allowlist_type(".*")
        .allowlist_var(".*")
        .default_enum_style(bindgen::EnumVariation::Rust { non_exhaustive: false })
        .use_core()
        .derive_default(true)
        .derive_debug(true)
        .derive_copy(true)
        .enable_cxx_namespaces()
        .layout_tests(false)
        // Suppress unsafe_op_in_unsafe_fn warnings in generated code
        .raw_line("// Suppress unsafe_op_in_unsafe_fn warnings in generated code")
        .raw_line("// We can consider ALL bindings code unsafe, so warn specific lines makes no sense.")
        .raw_line("#![allow(unsafe_op_in_unsafe_fn)]")
        .generate()
        .expect("Unable to generate bindings");

    // Write bindings to a fixed location for rust-analyzer
    let bindings_path = PathBuf::from("src/bindings/nvse.rs");
    bindings
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings");

    eprintln!("✓ Generated xNVSE bindings at {}", bindings_path.display());

    // Rerun triggers
    println!("cargo:rerun-if-changed=wrapper/nvse_wrapper.h");
    println!("cargo:rerun-if-changed=wrapper/include");
    println!("cargo:rerun-if-changed=xnvse/nvse/nvse/PluginAPI.h");
    println!("cargo:rerun-if-changed=build.rs");
}

fn patch_xnvse_headers(nvse_dir: &PathBuf) {
    // Remove [[nodiscard]] attributes that cause clang parsing errors.
    // This is necessary because the clang version used by bindgen doesn't fully support
    // C++17 attribute syntax in all positions. Since [[nodiscard]] is just a compiler hint
    // and doesn't affect the ABI, removing it is safe and doesn't break the bindings.
    let plugin_api = nvse_dir.join("nvse/nvse/PluginAPI.h");
    if plugin_api.exists()
        && let Ok(content) = fs::read_to_string(&plugin_api) {
            // Only patch if [[nodiscard]] is present
            if content.contains("[[nodiscard]]") {
                let patched = content.replace("[[nodiscard]]", "");
                fs::write(&plugin_api, patched).ok();
                eprintln!("✓ Patched PluginAPI.h (removed [[nodiscard]] attributes)");
            }
        }
}
