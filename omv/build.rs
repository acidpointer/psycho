use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn git_value(repository: &PathBuf, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()
        && !value
            .chars()
            .any(|character| matches!(character, '\r' | '\n')))
    .then(|| value.to_owned())
}

fn main() {
    let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR") else {
        println!("cargo:warning=CARGO_MANIFEST_DIR is not set for omv build script");
        std::process::exit(1);
    };
    let manifest_dir = PathBuf::from(manifest_dir);
    let repository = manifest_dir
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.clone());
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
    let git_commit =
        git_value(&repository, &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_owned());
    let git_tag =
        git_value(&repository, &["describe", "--tags", "--exact-match"]).unwrap_or_default();
    let git_branch = git_value(&repository, &["symbolic-ref", "--short", "-q", "HEAD"])
        .or_else(|| {
            env::var("GITHUB_HEAD_REF")
                .ok()
                .filter(|value| !value.is_empty())
        })
        .or_else(|| {
            (env::var("GITHUB_REF_TYPE").as_deref() == Ok("branch"))
                .then(|| env::var("GITHUB_REF_NAME").ok())
                .flatten()
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| {
            if git_commit == "unknown" {
                "unknown".to_owned()
            } else {
                "detached".to_owned()
            }
        });
    let git_dirty = Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map_or("unknown", |output| {
            if output.stdout.is_empty() {
                "false"
            } else {
                "true"
            }
        });

    println!("cargo:rustc-env=OMV_BUILD_UNIX={build_unix}");
    println!("cargo:rustc-env=OMV_BUILD_TARGET={target}");
    println!("cargo:rustc-env=OMV_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=OMV_GIT_COMMIT={git_commit}");
    println!("cargo:rustc-env=OMV_GIT_TAG={git_tag}");
    println!("cargo:rustc-env=OMV_GIT_BRANCH={git_branch}");
    println!("cargo:rustc-env=OMV_GIT_DIRTY={git_dirty}");

    let git_directory = repository.join(".git");
    println!(
        "cargo:rerun-if-changed={}",
        git_directory.join("HEAD").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        git_directory.join("packed-refs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        git_directory.join("refs/heads").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        git_directory.join("refs/tags").display()
    );
    for path in [
        repository.join("Cargo.toml"),
        repository.join("Cargo.lock"),
        manifest_dir,
        repository.join("libpsycho"),
        repository.join("libnvse"),
        repository.join("psycho-imgui"),
    ] {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-env-changed=GITHUB_HEAD_REF");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_TYPE");
}
