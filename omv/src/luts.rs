//! Disk-backed color lookup table catalog.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use anyhow::{Context, Result, anyhow, bail};

pub(crate) const LUT_DIRECTORY: &str = "Data/NVSE/plugins/omv/luts";
pub(crate) const MIN_LUT_SIZE: u32 = 2;
pub(crate) const MAX_LUT_SIZE: u32 = 64;
const MAX_LUT_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

#[derive(Clone, Debug)]
pub(crate) struct LutAsset {
    pub(crate) id: u32,
    pub(crate) revision: u64,
    pub(crate) display_name: String,
    pub(crate) file_name: String,
    pub(crate) path: PathBuf,
    pub(crate) size: u32,
    pub(crate) domain_min: [f32; 3],
    pub(crate) domain_max: [f32; 3],
    pub(crate) pixels: Vec<u32>,
    stamp: FileStamp,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LutCatalog {
    pub(crate) assets: Vec<Arc<LutAsset>>,
}

impl LutCatalog {
    pub(crate) fn selected(&self, index: i32) -> Option<&LutAsset> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.assets.get(index))
            .map(Arc::as_ref)
    }

    pub(crate) fn choices(&self) -> (Vec<String>, Vec<u32>) {
        (
            self.assets
                .iter()
                .map(|asset| asset.display_name.clone())
                .collect(),
            self.assets.iter().map(|asset| asset.id).collect(),
        )
    }
}

#[derive(Debug)]
pub(crate) struct LutScanResult {
    pub(crate) catalog: LutCatalog,
    pub(crate) resources_changed: bool,
    pub(crate) warnings: Vec<String>,
}

pub(crate) fn scan_luts(previous: &LutCatalog) -> Result<LutScanResult> {
    scan_luts_in(Path::new(LUT_DIRECTORY), previous)
}

fn scan_luts_in(directory: &Path, previous: &LutCatalog) -> Result<LutScanResult> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(LutScanResult {
                catalog: LutCatalog::default(),
                resources_changed: !previous.assets.is_empty(),
                warnings: vec![format!("LUT directory is missing: {}", directory.display())],
            });
        }
        Err(err) => return Err(err).with_context(|| format!("read {}", directory.display())),
    };

    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("enumerate {}", directory.display()))?;
        let path = entry.path();
        if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("cube"))
        {
            files.push(path);
        }
    }
    files.sort_by_key(|path| path.file_name().map(|name| name.to_ascii_lowercase()));

    let previous_by_path: HashMap<&Path, &Arc<LutAsset>> = previous
        .assets
        .iter()
        .map(|asset| (asset.path.as_path(), asset))
        .collect();
    let mut assets = Vec::with_capacity(files.len());
    let mut warnings = Vec::new();
    let mut ids = HashSet::new();

    for path in files {
        let stamp = file_stamp(&path)?;
        let previous_asset = previous_by_path.get(path.as_path()).copied();
        let asset = if previous_asset.is_some_and(|asset| asset.stamp == stamp) {
            previous_asset.cloned()
        } else {
            match load_cube(&path, stamp) {
                Ok(asset) => Some(Arc::new(asset)),
                Err(err) => {
                    warnings.push(format!("{}: {err:#}", path.display()));
                    previous_asset.cloned()
                }
            }
        };

        let Some(asset) = asset else {
            continue;
        };
        if !ids.insert(asset.id) {
            warnings.push(format!(
                "{}: filename ID collides with another LUT; file ignored",
                path.display()
            ));
            continue;
        }
        assets.push(asset);
    }

    let resources_changed = assets.len() != previous.assets.len()
        || assets.iter().zip(&previous.assets).any(|(left, right)| {
            left.id != right.id || left.revision != right.revision || left.path != right.path
        });
    Ok(LutScanResult {
        catalog: LutCatalog { assets },
        resources_changed,
        warnings,
    })
}

fn file_stamp(path: &Path) -> Result<FileStamp> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("not a regular file");
    }
    if metadata.len() > MAX_LUT_FILE_BYTES {
        bail!(
            "file exceeds the {} MiB safety limit",
            MAX_LUT_FILE_BYTES / 1024 / 1024
        );
    }
    Ok(FileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn load_cube(path: &Path, stamp: FileStamp) -> Result<LutAsset> {
    let text = fs::read_to_string(path).with_context(|| "read UTF-8 .cube data")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("filename is not valid UTF-8"))?
        .to_owned();
    parse_cube(path, file_name, stamp, &text)
}

fn parse_cube(path: &Path, file_name: String, stamp: FileStamp, text: &str) -> Result<LutAsset> {
    let mut title = None;
    let mut size = None;
    let mut domain_min = [0.0; 3];
    let mut domain_max = [1.0; 3];
    let mut values = Vec::new();

    for (line_index, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let first = fields.next().unwrap_or_default();
        match first.to_ascii_uppercase().as_str() {
            "TITLE" => {
                let value = line[first.len()..].trim().trim_matches('"').trim();
                if !value.is_empty() {
                    title = Some(value.to_owned());
                }
            }
            "LUT_3D_SIZE" => {
                if size.is_some() {
                    bail!("line {} repeats LUT_3D_SIZE", line_index + 1);
                }
                let parsed = parse_single_u32(fields, line_index, "LUT_3D_SIZE")?;
                if !(MIN_LUT_SIZE..=MAX_LUT_SIZE).contains(&parsed) {
                    bail!(
                        "line {} LUT size {} is outside {}..={}",
                        line_index + 1,
                        parsed,
                        MIN_LUT_SIZE,
                        MAX_LUT_SIZE
                    );
                }
                size = Some(parsed);
            }
            "DOMAIN_MIN" => domain_min = parse_triplet(fields, line_index, "DOMAIN_MIN")?,
            "DOMAIN_MAX" => domain_max = parse_triplet(fields, line_index, "DOMAIN_MAX")?,
            "LUT_1D_SIZE" => bail!(
                "line {} is a 1D LUT; OMV requires LUT_3D_SIZE",
                line_index + 1
            ),
            _ => {
                if size.is_none() {
                    bail!("line {} has color data before LUT_3D_SIZE", line_index + 1);
                }
                let mut color_fields = line.split_whitespace();
                values.push(parse_triplet(&mut color_fields, line_index, "color")?);
            }
        }
    }

    let size = size.ok_or_else(|| anyhow!("missing LUT_3D_SIZE"))?;
    for channel in 0..3 {
        if !domain_min[channel].is_finite()
            || !domain_max[channel].is_finite()
            || domain_max[channel] <= domain_min[channel]
        {
            bail!("invalid DOMAIN range in channel {channel}");
        }
    }
    let expected = (size as usize)
        .checked_pow(3)
        .ok_or_else(|| anyhow!("LUT dimensions overflow"))?;
    if values.len() != expected {
        bail!(
            "expected {expected} colors for size {size}, found {}",
            values.len()
        );
    }

    // .cube data is red-major, then green, then blue. The flattened D3D9
    // texture stores red across X, blue slices across X, and green across Y.
    let side = size as usize;
    let mut pixels = Vec::with_capacity(expected);
    for green in 0..side {
        for blue in 0..side {
            for red in 0..side {
                let source_index = blue * side * side + green * side + red;
                pixels.push(pack_argb(values[source_index]));
            }
        }
    }

    Ok(LutAsset {
        id: stable_file_id(&file_name),
        revision: fnv1a64(text.as_bytes()),
        display_name: title.unwrap_or_else(|| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("Unnamed LUT")
                .to_owned()
        }),
        file_name,
        path: path.to_owned(),
        size,
        domain_min,
        domain_max,
        pixels,
        stamp,
    })
}

fn parse_single_u32<'a>(
    mut fields: impl Iterator<Item = &'a str>,
    line_index: usize,
    field: &str,
) -> Result<u32> {
    let value = fields
        .next()
        .ok_or_else(|| anyhow!("line {} has no {field} value", line_index + 1))?
        .parse::<u32>()
        .with_context(|| format!("line {} has invalid {field}", line_index + 1))?;
    if fields.next().is_some() {
        bail!("line {} has extra {field} values", line_index + 1);
    }
    Ok(value)
}

fn parse_triplet<'a>(
    mut fields: impl Iterator<Item = &'a str>,
    line_index: usize,
    field: &str,
) -> Result<[f32; 3]> {
    let mut output = [0.0; 3];
    for value in &mut output {
        *value = fields
            .next()
            .ok_or_else(|| anyhow!("line {} has too few {field} values", line_index + 1))?
            .parse::<f32>()
            .with_context(|| format!("line {} has invalid {field} value", line_index + 1))?;
        if !value.is_finite() {
            bail!("line {} has non-finite {field} value", line_index + 1);
        }
    }
    if fields.next().is_some() {
        bail!("line {} has too many {field} values", line_index + 1);
    }
    Ok(output)
}

fn pack_argb(color: [f32; 3]) -> u32 {
    let channel = |value: f32| (value.clamp(0.0, 1.0) * 255.0).round() as u32;
    0xff00_0000 | (channel(color[0]) << 16) | (channel(color[1]) << 8) | channel(color[2])
}

pub(crate) fn stable_file_id(file_name: &str) -> u32 {
    let lower = file_name.to_ascii_lowercase();
    fnv1a32(lower.as_bytes())
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
pub(crate) fn shipped_luts_for_test() -> Vec<LutAsset> {
    [
        ("00_neutral.cube", include_str!("../luts/00_neutral.cube")),
        (
            "01_mojave_natural.cube",
            include_str!("../luts/01_mojave_natural.cube"),
        ),
        (
            "02_dusty_western.cube",
            include_str!("../luts/02_dusty_western.cube"),
        ),
        (
            "03_bleached_wasteland.cube",
            include_str!("../luts/03_bleached_wasteland.cube"),
        ),
        (
            "04_neon_nights.cube",
            include_str!("../luts/04_neon_nights.cube"),
        ),
        (
            "05_high_desert_clarity.cube",
            include_str!("../luts/05_high_desert_clarity.cube"),
        ),
        (
            "06_atomic_amber.cube",
            include_str!("../luts/06_atomic_amber.cube"),
        ),
        (
            "07_frontier_cinema.cube",
            include_str!("../luts/07_frontier_cinema.cube"),
        ),
        (
            "08_old_world_film.cube",
            include_str!("../luts/08_old_world_film.cube"),
        ),
        (
            "09_vault_fluorescent.cube",
            include_str!("../luts/09_vault_fluorescent.cube"),
        ),
        (
            "10_sierra_sunset.cube",
            include_str!("../luts/10_sierra_sunset.cube"),
        ),
        (
            "11_zion_canyon.cube",
            include_str!("../luts/11_zion_canyon.cube"),
        ),
        (
            "12_divide_duststorm.cube",
            include_str!("../luts/12_divide_duststorm.cube"),
        ),
        (
            "13_wasteland_noir.cube",
            include_str!("../luts/13_wasteland_noir.cube"),
        ),
    ]
    .into_iter()
    .map(|(file_name, text)| {
        parse_cube(
            Path::new(file_name),
            file_name.to_owned(),
            FileStamp::default(),
            text,
        )
        .expect("parse shipped LUT")
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        FileStamp, LutCatalog, parse_cube, scan_luts_in, shipped_luts_for_test, stable_file_id,
    };
    use std::{fs, path::PathBuf};

    fn cube(size: u32, title: &str, transform: impl Fn([f32; 3]) -> [f32; 3]) -> String {
        let mut text =
            format!("TITLE \"{title}\"\nLUT_3D_SIZE {size}\nDOMAIN_MIN 0 0 0\nDOMAIN_MAX 1 1 1\n");
        let denominator = (size - 1) as f32;
        for blue in 0..size {
            for green in 0..size {
                for red in 0..size {
                    let output = transform([
                        red as f32 / denominator,
                        green as f32 / denominator,
                        blue as f32 / denominator,
                    ]);
                    text.push_str(&format!(
                        "{:.6} {:.6} {:.6}\n",
                        output[0], output[1], output[2]
                    ));
                }
            }
        }
        text
    }

    #[test]
    fn parser_reorders_cube_data_for_flattened_d3d_texture() {
        let text = cube(2, "Axis", |value| value);
        let asset = parse_cube(
            PathBuf::from("axis.cube").as_path(),
            "axis.cube".to_owned(),
            FileStamp::default(),
            &text,
        )
        .expect("parse cube");
        assert_eq!(asset.size, 2);
        assert_eq!(asset.display_name, "Axis");
        assert_eq!(asset.pixels.len(), 8);
        assert_eq!(asset.pixels[1], 0xffff_0000);
        assert_eq!(asset.pixels[2], 0xff00_00ff);
        assert_eq!(asset.pixels[4], 0xff00_ff00);
        assert_eq!(asset.id, stable_file_id("axis.cube"));
    }

    #[test]
    fn parser_rejects_incomplete_1d_and_non_finite_luts() {
        for text in [
            "LUT_3D_SIZE 2\n0 0 0\n",
            "LUT_1D_SIZE 2\n0 0 0\n1 1 1\n",
            "LUT_3D_SIZE 2\nNaN 0 0\n",
            "LUT_3D_SIZE 65\n",
            "LUT_3D_SIZE 2\nDOMAIN_MIN 1 0 0\nDOMAIN_MAX 0 1 1\n",
        ] {
            assert!(
                parse_cube(
                    PathBuf::from("bad.cube").as_path(),
                    "bad.cube".to_owned(),
                    FileStamp::default(),
                    text,
                )
                .is_err(),
                "accepted invalid LUT: {text}"
            );
        }
    }

    #[test]
    fn scan_reuses_unchanged_assets_and_retains_last_good_reload() {
        let directory = std::env::temp_dir().join(format!(
            "omv-lut-test-{}-{}",
            std::process::id(),
            stable_file_id(module_path!())
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create test LUT directory");
        let path = directory.join("look.cube");
        fs::write(&path, cube(2, "Look", |value| value)).expect("write LUT");

        let first = scan_luts_in(&directory, &LutCatalog::default()).expect("first scan");
        assert!(first.resources_changed);
        assert_eq!(first.catalog.assets.len(), 1);
        let second = scan_luts_in(&directory, &first.catalog).expect("second scan");
        assert!(!second.resources_changed);
        assert!(std::sync::Arc::ptr_eq(
            &first.catalog.assets[0],
            &second.catalog.assets[0]
        ));

        fs::write(&path, "LUT_3D_SIZE 2\n0 0 0\n").expect("break LUT");
        let broken = scan_luts_in(&directory, &second.catalog).expect("broken scan");
        assert!(!broken.resources_changed);
        assert_eq!(broken.catalog.assets.len(), 1);
        assert_eq!(broken.warnings.len(), 1);
        assert!(std::sync::Arc::ptr_eq(
            &second.catalog.assets[0],
            &broken.catalog.assets[0]
        ));
        fs::remove_dir_all(&directory).expect("remove test LUT directory");
    }

    #[test]
    fn scanner_accepts_an_unbounded_dynamic_file_count_and_tracks_add_remove() {
        let directory = std::env::temp_dir().join(format!(
            "omv-lut-count-test-{}-{}",
            std::process::id(),
            stable_file_id("dynamic-count")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create test LUT directory");
        for index in 0..17 {
            fs::write(
                directory.join(format!("user_{index:02}.cube")),
                cube(2, &format!("User {index}"), |value| value),
            )
            .expect("write user LUT");
        }

        let first = scan_luts_in(&directory, &LutCatalog::default()).expect("initial scan");
        assert_eq!(first.catalog.assets.len(), 17);
        assert!(first.resources_changed);
        let (names, ids) = first.catalog.choices();
        assert_eq!(names.len(), 17);
        assert_eq!(ids.len(), 17);
        assert_eq!(
            ids.iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            17
        );

        fs::remove_file(directory.join("user_08.cube")).expect("remove one LUT");
        let second = scan_luts_in(&directory, &first.catalog).expect("removal scan");
        assert_eq!(second.catalog.assets.len(), 16);
        assert!(second.resources_changed);
        fs::remove_dir_all(&directory).expect("remove test LUT directory");
    }

    #[test]
    fn shipped_library_is_original_external_cube_data_with_professional_invariants() {
        let assets = shipped_luts_for_test();
        assert_eq!(assets.len(), 14);
        assert_eq!(assets[1].id, 97_154_384);
        assert_eq!(assets[1].file_name, "01_mojave_natural.cube");
        let names: std::collections::HashSet<&str> = assets
            .iter()
            .map(|asset| asset.display_name.as_str())
            .collect();
        assert_eq!(names.len(), assets.len());

        let unpack = |pixel: u32| {
            [
                ((pixel >> 16) & 0xff) as f32 / 255.0,
                ((pixel >> 8) & 0xff) as f32 / 255.0,
                (pixel & 0xff) as f32 / 255.0,
            ]
        };
        for asset in &assets {
            assert_eq!(asset.size, 32);
            assert_eq!(asset.pixels.len(), 32usize.pow(3));
            assert_eq!(asset.domain_min, [0.0; 3]);
            assert_eq!(asset.domain_max, [1.0; 3]);
            assert!(asset.pixels.iter().all(|pixel| pixel >> 24 == 0xff));
        }

        let neutral = &assets[0];
        assert_eq!(unpack(neutral.pixels[0]), [0.0; 3]);
        assert_eq!(
            unpack(*neutral.pixels.last().expect("last neutral texel")),
            [1.0; 3]
        );
        for asset in &assets[1..] {
            assert_ne!(asset.revision, neutral.revision);
            let mut previous_luma = -1.0f32;
            for step in 0..32usize {
                let pixel = unpack(asset.pixels[step * 32 * 32 + step * 32 + step]);
                let luma = pixel[0] * 0.2126 + pixel[1] * 0.7152 + pixel[2] * 0.0722;
                assert!(luma + 1.0 / 255.0 >= previous_luma);
                previous_luma = luma;
            }
        }
        for left in 0..assets.len() {
            for right in left + 1..assets.len() {
                let mean_channel_distance = assets[left]
                    .pixels
                    .iter()
                    .zip(&assets[right].pixels)
                    .map(|(left, right)| {
                        let left = unpack(*left);
                        let right = unpack(*right);
                        (0..3)
                            .map(|channel| (left[channel] - right[channel]).abs())
                            .sum::<f32>()
                    })
                    .sum::<f32>()
                    / (assets[left].pixels.len() * 3) as f32;
                assert!(
                    mean_channel_distance >= 0.008,
                    "{} and {} are visually redundant ({mean_channel_distance:.4})",
                    assets[left].file_name,
                    assets[right].file_name
                );
            }
        }

        for text in [
            include_str!("../luts/00_neutral.cube"),
            include_str!("../luts/01_mojave_natural.cube"),
            include_str!("../luts/02_dusty_western.cube"),
            include_str!("../luts/03_bleached_wasteland.cube"),
            include_str!("../luts/04_neon_nights.cube"),
            include_str!("../luts/05_high_desert_clarity.cube"),
            include_str!("../luts/06_atomic_amber.cube"),
            include_str!("../luts/07_frontier_cinema.cube"),
            include_str!("../luts/08_old_world_film.cube"),
            include_str!("../luts/09_vault_fluorescent.cube"),
            include_str!("../luts/10_sierra_sunset.cube"),
            include_str!("../luts/11_zion_canyon.cube"),
            include_str!("../luts/12_divide_duststorm.cube"),
            include_str!("../luts/13_wasteland_noir.cube"),
        ] {
            assert!(text.starts_with("# Original OMV LUT; redistribution permitted with OMV."));
        }
    }

    #[test]
    fn installer_and_release_contract_ship_the_external_lut_directory() {
        let installer = include_str!("../../build_fnv.sh");
        assert!(installer.contains("OMV_LUT_SRC_DIR=\"$DIR/omv/luts\""));
        assert!(installer.contains("-exec cp '{}' \"$OMV_LUT_DIR/\""));

        let packager = include_str!("../../.github/scripts/package_release.sh");
        assert!(packager.contains("OMV_LUT_SOURCE_DIR=\"$WORKSPACE_DIR/omv/luts\""));
        assert!(packager.contains("Data/NVSE/plugins/omv/luts"));
        assert!(packager.contains("-iname '*.cube'"));

        let workflow = include_str!("../../.github/workflows/release.yml");
        for file_name in [
            "00_neutral.cube",
            "01_mojave_natural.cube",
            "02_dusty_western.cube",
            "03_bleached_wasteland.cube",
            "04_neon_nights.cube",
            "05_high_desert_clarity.cube",
            "06_atomic_amber.cube",
            "07_frontier_cinema.cube",
            "08_old_world_film.cube",
            "09_vault_fluorescent.cube",
            "10_sierra_sunset.cube",
            "11_zion_canyon.cube",
            "12_divide_duststorm.cube",
            "13_wasteland_noir.cube",
        ] {
            assert!(workflow.contains(file_name), "release omits {file_name}");
        }
    }

    #[test]
    fn runtime_commits_lut_choices_in_the_shader_scan_transaction() {
        let runtime = include_str!("runtime.rs");
        let start = runtime
            .find("fn scan_shaders_if_due(&mut self)")
            .expect("scan transaction");
        let end = runtime[start..]
            .find("fn ensure_imgui")
            .map(|offset| start + offset)
            .expect("scan transaction end");
        let scan = &runtime[start..end];
        let sync = scan.find("sync_embedded_effect_config").expect("menu sync");
        let lut_scan = scan.find("luts::scan_luts").expect("LUT scan");
        let shader_scan = scan
            .find("shaders::scan_screen_shaders")
            .expect("shader scan");
        let choices = scan.find("self.color_luts.choices()").expect("LUT choices");
        let merge = scan
            .find("merge_embedded_sources_with_luts")
            .expect("joint source merge");
        assert!(
            sync < lut_scan && lut_scan < shader_scan && shader_scan < choices && choices < merge
        );
        assert!(scan.contains("self.blooming_hdr = None"));
    }
}
