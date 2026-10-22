//! Isolated filesystem execution for production worker behavioral tests.

use std::{fs, path::PathBuf, process::Command};

pub(crate) struct Workspace;

pub(crate) fn isolated(name: &str) -> Option<Workspace> {
    if std::env::var("OMV_PROFILE_TEST_CHILD").as_deref() == Ok(name) {
        std::env::set_current_dir(
            std::env::var_os("OMV_PROFILE_TEST_ROOT").expect("isolated test root"),
        )
        .unwrap();
        return Some(Workspace);
    }
    let root: PathBuf = std::env::temp_dir().join(format!(
        "omv-profile-{}-{:x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    fs::create_dir_all(&root).unwrap();
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("OMV_PROFILE_TEST_CHILD", name)
        .env("OMV_PROFILE_TEST_ROOT", &root)
        .output()
        .unwrap();
    // All worker threads have exited with the child before its relative paths
    // are removed. The parent never changes its own current directory.
    let _ = fs::remove_dir_all(&root);
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    None
}
