//! Durable, atomic publication for OMV-owned text files.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use libpsycho::os::windows::winapi::{
    move_file_replace_write_through_wide, move_file_write_through_wide,
};

pub(crate) fn atomic_write_text(path: &Path, text: &str) -> Result<()> {
    atomic_publish_text(path, text, true)
}

pub(crate) fn atomic_create_text(path: &Path, text: &str) -> Result<()> {
    atomic_publish_text(path, text, false)
}

fn atomic_publish_text(path: &Path, text: &str, replace_existing: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;

    let temporary = temporary_path(path);
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(text.as_bytes())
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to flush {}", temporary.display()))?;
        drop(file);

        if replace_existing {
            move_file_replace_write_through_wide(temporary.as_os_str(), path.as_os_str())
        } else {
            move_file_write_through_wide(temporary.as_os_str(), path.as_os_str())
        }
        .with_context(|| format!("failed to publish {}", path.display()))
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn temporary_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("omv.toml");
    path.with_file_name(format!(
        ".{file_name}.tmp-{}-{:032x}",
        std::process::id(),
        rand::random::<u128>()
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{atomic_create_text, atomic_write_text};

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn atomic_write_creates_and_replaces_complete_text() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("omv-atomic-text-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).expect("create test directory");
        let _cleanup = TestDirectory(directory.clone());
        let path = directory.join("settings-\u{043f}\u{0440}\u{0435}\u{0441}\u{0435}\u{0442}.toml");

        atomic_write_text(&path, "old = true\n").expect("create text");
        atomic_write_text(&path, "new = true\n").expect("replace text");

        assert_eq!(fs::read_to_string(path).unwrap(), "new = true\n");
        assert!(fs::read_dir(directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        }));
    }

    #[test]
    fn atomic_create_never_replaces_an_existing_destination() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("omv-create-text-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).expect("create test directory");
        let _cleanup = TestDirectory(directory.clone());
        let path = directory.join("preset.omvpreset.toml");

        atomic_create_text(&path, "version = \"1.0.0\"\n").expect("create preset");
        atomic_create_text(&path, "version = \"2.0.0\"\n").expect_err("create must not replace");

        assert_eq!(fs::read_to_string(path).unwrap(), "version = \"1.0.0\"\n");
    }
}
