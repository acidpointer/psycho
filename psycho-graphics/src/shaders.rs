//! Live screen-space shader loading and sidecar configuration.

use std::{
    collections::HashMap,
    ffi::CString,
    fs,
    mem::{size_of, transmute},
    path::{Path, PathBuf},
    ptr::null_mut,
    slice,
    sync::OnceLock,
    time::SystemTime,
};

use anyhow::{Context, Result};
use libpsycho::os::windows::winapi::{get_proc_address, load_library_a};
use serde::{Deserialize, Serialize};
use windows::{
    Win32::Graphics::Direct3D::ID3DBlob,
    core::{HRESULT, Interface, PCSTR},
};

pub(crate) const SHADER_DIR: &str = "./mods/psycho_shaders";
const FIRST_OPTION_REGISTER: u32 = 3;
const ENVIRONMENT_REGISTER: u32 = 6;
const SUN_REGISTER: u32 = 8;
const MAX_OPTION_REGISTER: u32 = 31;
const MIN_SHADER_PASSES: u32 = 1;
const MAX_SHADER_PASSES: u32 = 8;
const D3DCOMPILE_ENABLE_BACKWARDS_COMPATIBILITY: u32 = 1 << 12;
const D3DCOMPILE_OPTIMIZATION_LEVEL3: u32 = 1 << 15;
const D3D_COMPILER_DLLS: &[&str] = &[
    "d3dcompiler_47.dll",
    "d3dcompiler_46.dll",
    "d3dcompiler_43.dll",
    "d3dcompiler_42.dll",
    "d3dcompiler_41.dll",
];
static D3D_COMPILE_FN: OnceLock<std::result::Result<D3DCompileFn, String>> = OnceLock::new();

type D3DCompileFn = unsafe extern "system" fn(
    src_data: *const std::ffi::c_void,
    src_data_size: usize,
    source_name: PCSTR,
    defines: *const std::ffi::c_void,
    include: *mut std::ffi::c_void,
    entry_point: PCSTR,
    target: PCSTR,
    flags1: u32,
    flags2: u32,
    code: *mut *mut std::ffi::c_void,
    error_messages: *mut *mut std::ffi::c_void,
) -> HRESULT;

#[derive(Clone, Debug)]
pub(crate) struct ScreenShaderSource {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) config_path: PathBuf,
    pub(crate) bytecode: Option<Vec<u32>>,
    pub(crate) enabled: bool,
    pub(crate) phase: ShaderPhase,
    pub(crate) pass_count: u32,
    pub(crate) options: Vec<ShaderOption>,
    pub(crate) option_constants: Vec<[f32; 4]>,
    pub(crate) shader_error: Option<String>,
    pub(crate) config_error: Option<String>,
    shader_stamp: FileStamp,
    config_stamp: FileStamp,
}

impl ScreenShaderSource {
    pub(crate) fn bytecode(&self) -> Option<&[u32]> {
        self.bytecode.as_deref()
    }

    pub(crate) fn set_enabled(&mut self, enabled: bool) -> Result<()> {
        if self.enabled == enabled {
            return Ok(());
        }

        self.enabled = enabled;
        self.save_config()
    }

    pub(crate) fn set_pass_count(&mut self, pass_count: u32) -> Result<()> {
        let pass_count = sanitize_pass_count(pass_count);
        if self.pass_count == pass_count {
            return Ok(());
        }

        self.pass_count = pass_count;
        self.save_config()
    }

    pub(crate) fn phase(&self) -> ShaderPhase {
        self.phase
    }

    pub(crate) fn set_option_float(&mut self, index: usize, value: f32) -> Result<()> {
        let Some(option) = self.options.get_mut(index) else {
            return Ok(());
        };
        let ShaderOptionValue::Float(float) = &mut option.value else {
            return Ok(());
        };

        let value = value.clamp(option.min, option.max);
        if (*float - value).abs() <= f32::EPSILON {
            return Ok(());
        }

        *float = value;
        self.rebuild_option_constants();
        self.save_config()
    }

    pub(crate) fn set_option_bool(&mut self, index: usize, value: bool) -> Result<()> {
        let Some(option) = self.options.get_mut(index) else {
            return Ok(());
        };
        let ShaderOptionValue::Bool(flag) = &mut option.value else {
            return Ok(());
        };

        if *flag == value {
            return Ok(());
        }

        *flag = value;
        self.rebuild_option_constants();
        self.save_config()
    }

    fn save_config(&mut self) -> Result<()> {
        let config = ShaderConfigFile::from_source(self);
        let text = toml::to_string_pretty(&config).context("failed to serialize shader config")?;
        fs::write(&self.config_path, text)
            .with_context(|| format!("failed to write {}", self.config_path.display()))?;
        self.config_stamp = file_stamp(&self.config_path).unwrap_or_default();
        self.config_error = None;
        Ok(())
    }

    fn rebuild_option_constants(&mut self) {
        self.option_constants.clear();

        for option in &self.options {
            let Some(binding) = option.binding else {
                continue;
            };
            let index = (binding.register - FIRST_OPTION_REGISTER) as usize;
            if self.option_constants.len() <= index {
                self.option_constants.resize(index + 1, [0.0; 4]);
            }

            self.option_constants[index][binding.component] = option.value.as_constant();
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ShaderOption {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) value: ShaderOptionValue,
    pub(crate) min: f32,
    pub(crate) max: f32,
    binding: Option<ConstantBinding>,
    constant: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum ShaderOptionValue {
    Float(f32),
    Bool(bool),
}

impl ShaderOptionValue {
    fn as_constant(&self) -> f32 {
        match self {
            Self::Float(value) => *value,
            Self::Bool(value) => {
                if *value {
                    1.0
                } else {
                    0.0
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ShaderScanResult {
    pub(crate) sources: Vec<ScreenShaderSource>,
    pub(crate) shader_resources_changed: bool,
}

pub(crate) fn scan_screen_shaders(previous: &[ScreenShaderSource]) -> Result<ShaderScanResult> {
    let mut files = shader_files()?;
    files.sort();

    let previous_by_path: HashMap<&Path, &ScreenShaderSource> = previous
        .iter()
        .map(|source| (source.path.as_path(), source))
        .collect();

    let mut shader_resources_changed = previous.len() != files.len();
    let mut sources = Vec::with_capacity(files.len());

    for path in files {
        let previous = previous_by_path.get(path.as_path()).copied();
        let shader_stamp = file_stamp(&path)?;
        let config_path = shader_config_path(&path);
        let config_stamp = ensure_shader_config(&config_path)?;

        let shader_changed = previous
            .is_none_or(|source| source.shader_stamp != shader_stamp || source.path != path);
        let config_changed = previous.is_none_or(|source| source.config_stamp != config_stamp);

        let mut source = if shader_changed {
            shader_resources_changed = true;
            let mut loaded = load_shader_file(&path, previous)
                .unwrap_or_else(|err| failed_shader_source(&path, previous, err));
            loaded.shader_stamp = shader_stamp;
            loaded
        } else {
            match previous {
                Some(source) => source.clone(),
                None => {
                    shader_resources_changed = true;
                    let mut loaded = load_shader_file(&path, None)
                        .unwrap_or_else(|err| failed_shader_source(&path, None, err));
                    loaded.shader_stamp = shader_stamp;
                    loaded
                }
            }
        };

        if config_changed || source.config_path != config_path {
            apply_config(&mut source, &config_path, config_stamp);
        }

        sources.push(source);
    }

    Ok(ShaderScanResult {
        sources,
        shader_resources_changed,
    })
}

fn shader_files() -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    let path = Path::new(SHADER_DIR);
    if !path.exists() {
        return Ok(files);
    }

    let entries = fs::read_dir(path)
        .with_context(|| format!("failed to read shader directory {}", path.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read entry in {}", path.display()))?;
        let path = entry.path();
        if path.is_file() && is_shader_file(&path) {
            files.push(path);
        }
    }

    Ok(files)
}

fn is_shader_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            ext.eq_ignore_ascii_case("pso")
                || ext.eq_ignore_ascii_case("cso")
                || ext.eq_ignore_ascii_case("hlsl")
        })
}

fn shader_config_path(path: &Path) -> PathBuf {
    path.with_extension("toml")
}

fn ensure_shader_config(path: &Path) -> Result<FileStamp> {
    if path.exists() {
        return file_stamp(path);
    }

    let config = ShaderConfigFile::default();
    let text =
        toml::to_string_pretty(&config).context("failed to serialize default shader config")?;
    fs::write(path, text).with_context(|| format!("failed to create {}", path.display()))?;
    log::info!(
        "[SHADERS] Created default shader config '{}'",
        path.display()
    );
    file_stamp(path)
}

fn load_shader_file(
    path: &Path,
    previous: Option<&ScreenShaderSource>,
) -> Result<ScreenShaderSource> {
    let bytecode = if path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("hlsl"))
    {
        compile_hlsl_shader(path)?
    } else {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read shader file {}", path.display()))?;
        dword_aligned_bytecode(&bytes)?
    };

    log::info!("[SHADERS] Loaded shader '{}'", path.display());

    Ok(ScreenShaderSource {
        name: shader_name(path),
        path: path.to_owned(),
        config_path: shader_config_path(path),
        bytecode: Some(bytecode),
        enabled: previous.map_or(true, |source| source.enabled),
        phase: previous.map_or(ShaderPhase::default(), |source| source.phase),
        pass_count: previous.map_or(MIN_SHADER_PASSES, |source| source.pass_count),
        options: previous.map_or_else(Vec::new, |source| source.options.clone()),
        option_constants: previous.map_or_else(Vec::new, |source| source.option_constants.clone()),
        shader_error: None,
        config_error: previous.and_then(|source| source.config_error.clone()),
        shader_stamp: FileStamp::default(),
        config_stamp: previous.map_or_else(FileStamp::default, |source| source.config_stamp),
    })
}

fn failed_shader_source(
    path: &Path,
    previous: Option<&ScreenShaderSource>,
    err: anyhow::Error,
) -> ScreenShaderSource {
    let message = format!("{err:#}");
    log::warn!("[SHADERS] Failed to load {}: {message}", path.display());

    if let Some(previous) = previous {
        let mut source = previous.clone();
        source.shader_error = Some(message);
        return source;
    }

    ScreenShaderSource {
        name: shader_name(path),
        path: path.to_owned(),
        config_path: shader_config_path(path),
        bytecode: None,
        enabled: true,
        phase: previous.map_or(ShaderPhase::default(), |source| source.phase),
        pass_count: MIN_SHADER_PASSES,
        options: Vec::new(),
        option_constants: Vec::new(),
        shader_error: Some(message),
        config_error: None,
        shader_stamp: FileStamp::default(),
        config_stamp: FileStamp::default(),
    }
}

fn apply_config(source: &mut ScreenShaderSource, config_path: &Path, config_stamp: FileStamp) {
    source.config_path = config_path.to_owned();
    source.config_stamp = config_stamp;

    match load_shader_config(config_path) {
        Ok(config) => {
            source.enabled = config.shader.enabled;
            source.phase = config.shader.phase;
            source.pass_count = sanitize_pass_count(config.shader.passes);
            source.options = config.options.into_iter().map(ShaderOption::from).collect();
            assign_missing_bindings(&mut source.options);
            source.rebuild_option_constants();
            source.config_error = None;
            log::debug!("[SHADERS] Loaded shader config '{}'", config_path.display());
        }
        Err(err) => {
            let message = format!("{err:#}");
            source.config_error = Some(message.clone());
            log::warn!(
                "[SHADERS] Failed to load shader config {}: {message}",
                config_path.display()
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ShaderPhase {
    ScenePreImageSpace,
    ScenePostImageSpace,
    #[default]
    FinalImageSpace,
}

impl ShaderPhase {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ScenePreImageSpace => "scene_pre_image_space",
            Self::ScenePostImageSpace => "scene_post_image_space",
            Self::FinalImageSpace => "final_image_space",
        }
    }
}

fn sanitize_pass_count(pass_count: u32) -> u32 {
    pass_count.clamp(MIN_SHADER_PASSES, MAX_SHADER_PASSES)
}

fn load_shader_config(path: &Path) -> Result<ShaderConfigFile> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read shader config {}", path.display()))?;
    toml::from_str(&text)
        .with_context(|| format!("failed to parse shader config {}", path.display()))
}

fn assign_missing_bindings(options: &mut [ShaderOption]) {
    let mut next_register = FIRST_OPTION_REGISTER;
    let mut next_component = 0usize;

    for option in options {
        if option.binding.is_none() {
            option.binding = Some(ConstantBinding {
                register: next_register,
                component: next_component,
            });
            option.constant = Some(format!(
                "c{}.{}",
                next_register,
                component_name(next_component)
            ));
        }

        next_component += 1;
        if next_component == 4 {
            next_component = 0;
            next_register = next_option_register(next_register);
        }
    }
}

fn next_option_register(register: u32) -> u32 {
    let mut next = register + 1;
    while is_reserved_register(next) {
        next += 1;
    }
    next
}

fn is_reserved_register(register: u32) -> bool {
    register == ENVIRONMENT_REGISTER || register == SUN_REGISTER
}

fn compile_hlsl_shader(path: &Path) -> Result<Vec<u32>> {
    let source = fs::read(path)
        .with_context(|| format!("failed to read shader source {}", path.display()))?;
    let source_name = path.to_string_lossy();
    let bytecode = compile_hlsl_bytes(&source_name, &source)?;
    log::info!("[SHADERS] Compiled HLSL shader '{}'", path.display());
    Ok(bytecode)
}

fn compile_hlsl_bytes(source_name: &str, source: &[u8]) -> Result<Vec<u32>> {
    let compiler = d3d_compile_fn()?;
    let source_name = CString::new(source_name.as_bytes())?;
    let entry = CString::new("Main")?;
    let target = CString::new("ps_3_0")?;
    let flags = D3DCOMPILE_ENABLE_BACKWARDS_COMPATIBILITY | D3DCOMPILE_OPTIMIZATION_LEVEL3;

    let mut code = null_mut();
    let mut errors = null_mut();
    let result = unsafe {
        compiler(
            source.as_ptr().cast(),
            source.len(),
            PCSTR::from_raw(source_name.as_ptr().cast()),
            std::ptr::null(),
            null_mut(),
            PCSTR::from_raw(entry.as_ptr().cast()),
            PCSTR::from_raw(target.as_ptr().cast()),
            flags,
            0,
            &mut code,
            &mut errors,
        )
    };

    let error_text = unsafe { take_blob(errors) }.and_then(|blob| blob_text(&blob));
    if result.is_err() {
        let message = error_text.unwrap_or_else(|| format!("D3DCompile failed: {result:?}"));
        anyhow::bail!("{message}");
    }

    if let Some(message) = error_text {
        log::debug!("[SHADERS] Compiler diagnostics for {source_name:?}: {message}");
    }

    let Some(code) = (unsafe { take_blob(code) }) else {
        anyhow::bail!("D3DCompile returned no shader bytecode");
    };

    let bytes = unsafe { blob_bytes(&code) };
    dword_aligned_bytecode(bytes)
}

fn dword_aligned_bytecode(bytes: &[u8]) -> Result<Vec<u32>> {
    if bytes.is_empty() {
        anyhow::bail!("shader bytecode is empty");
    }

    if bytes.len() % size_of::<u32>() != 0 {
        anyhow::bail!("shader bytecode length is not DWORD aligned");
    }

    Ok(bytes
        .chunks_exact(size_of::<u32>())
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}

fn d3d_compile_fn() -> Result<D3DCompileFn> {
    match D3D_COMPILE_FN.get_or_init(resolve_d3d_compile_fn) {
        Ok(function) => Ok(*function),
        Err(err) => anyhow::bail!("{err}"),
    }
}

fn resolve_d3d_compile_fn() -> std::result::Result<D3DCompileFn, String> {
    for dll in D3D_COMPILER_DLLS {
        if let Ok(module) = load_library_a(dll)
            && let Ok(proc) = get_proc_address(module, "D3DCompile")
        {
            return Ok(unsafe { transmute::<*mut std::ffi::c_void, D3DCompileFn>(proc) });
        }
    }

    Err(format!(
        "D3DCompile not found; tried {}",
        D3D_COMPILER_DLLS.join(", ")
    ))
}

unsafe fn take_blob(ptr: *mut std::ffi::c_void) -> Option<ID3DBlob> {
    if ptr.is_null() {
        return None;
    }

    Some(unsafe { ID3DBlob::from_raw(ptr) })
}

unsafe fn blob_bytes(blob: &ID3DBlob) -> &[u8] {
    let ptr = unsafe { blob.GetBufferPointer() };
    let len = unsafe { blob.GetBufferSize() };
    unsafe { slice::from_raw_parts(ptr.cast::<u8>(), len) }
}

fn blob_text(blob: &ID3DBlob) -> Option<String> {
    let bytes = unsafe { blob_bytes(blob) };
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }

    Some(String::from_utf8_lossy(&bytes[..end]).trim().to_owned())
}

fn shader_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("unnamed")
        .to_owned()
}

fn file_stamp(path: &Path) -> Result<FileStamp> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    Ok(FileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

#[derive(Clone, Copy, Debug)]
struct ConstantBinding {
    register: u32,
    component: usize,
}

impl ConstantBinding {
    fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let rest = text.strip_prefix('c')?;
        let (register, component) = rest.split_once('.')?;
        let register = register.parse::<u32>().ok()?;
        if !(FIRST_OPTION_REGISTER..=MAX_OPTION_REGISTER).contains(&register)
            || is_reserved_register(register)
        {
            return None;
        }

        let component = match component {
            "x" | "X" => 0,
            "y" | "Y" => 1,
            "z" | "Z" => 2,
            "w" | "W" => 3,
            _ => return None,
        };

        Some(Self {
            register,
            component,
        })
    }
}

fn component_name(component: usize) -> &'static str {
    match component {
        0 => "x",
        1 => "y",
        2 => "z",
        3 => "w",
        _ => "x",
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
struct ShaderConfigFile {
    shader: ShaderConfigHeader,
    options: Vec<ShaderOptionConfig>,
}

impl Default for ShaderConfigFile {
    fn default() -> Self {
        Self {
            shader: ShaderConfigHeader::default(),
            options: Vec::new(),
        }
    }
}

impl ShaderConfigFile {
    fn from_source(source: &ScreenShaderSource) -> Self {
        Self {
            shader: ShaderConfigHeader {
                enabled: source.enabled,
                phase: source.phase,
                passes: source.pass_count,
            },
            options: source
                .options
                .iter()
                .map(ShaderOptionConfig::from_option)
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
struct ShaderConfigHeader {
    enabled: bool,
    phase: ShaderPhase,
    passes: u32,
}

impl Default for ShaderConfigHeader {
    fn default() -> Self {
        Self {
            enabled: true,
            phase: ShaderPhase::default(),
            passes: MIN_SHADER_PASSES,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
struct ShaderOptionConfig {
    key: String,
    label: String,
    kind: ShaderOptionKind,
    value: ShaderOptionConfigValue,
    min: f32,
    max: f32,
    constant: Option<String>,
}

impl Default for ShaderOptionConfig {
    fn default() -> Self {
        Self {
            key: String::new(),
            label: String::new(),
            kind: ShaderOptionKind::Float,
            value: ShaderOptionConfigValue::Float(0.0),
            min: 0.0,
            max: 1.0,
            constant: None,
        }
    }
}

impl ShaderOptionConfig {
    fn from_option(option: &ShaderOption) -> Self {
        let (kind, value) = match option.value {
            ShaderOptionValue::Float(value) => (
                ShaderOptionKind::Float,
                ShaderOptionConfigValue::Float(value),
            ),
            ShaderOptionValue::Bool(value) => {
                (ShaderOptionKind::Bool, ShaderOptionConfigValue::Bool(value))
            }
        };

        Self {
            key: option.key.clone(),
            label: option.label.clone(),
            kind,
            value,
            min: option.min,
            max: option.max,
            constant: option.constant.clone(),
        }
    }
}

impl From<ShaderOptionConfig> for ShaderOption {
    fn from(config: ShaderOptionConfig) -> Self {
        let key = if config.key.is_empty() {
            "option".to_owned()
        } else {
            config.key
        };
        let label = if config.label.is_empty() {
            key.clone()
        } else {
            config.label
        };

        let (min, max) = sanitize_float_bounds(config.min, config.max);
        let value = match config.kind {
            ShaderOptionKind::Float => {
                ShaderOptionValue::Float(sanitize_float_value(config.value.as_float(), min, max))
            }
            ShaderOptionKind::Bool => ShaderOptionValue::Bool(config.value.as_bool()),
        };
        let binding = config.constant.as_deref().and_then(ConstantBinding::parse);

        Self {
            key,
            label,
            value,
            min,
            max,
            binding,
            constant: config.constant,
        }
    }
}

fn sanitize_float_bounds(min: f32, max: f32) -> (f32, f32) {
    let min = if min.is_finite() { min } else { 0.0 };
    let max = if max.is_finite() { max } else { min.max(1.0) };
    if min <= max { (min, max) } else { (max, min) }
}

fn sanitize_float_value(value: f32, min: f32, max: f32) -> f32 {
    if value.is_finite() {
        value.clamp(min, max)
    } else {
        min
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ShaderOptionKind {
    Float,
    Bool,
}

impl Default for ShaderOptionKind {
    fn default() -> Self {
        Self::Float
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum ShaderOptionConfigValue {
    Float(f32),
    Bool(bool),
    Integer(i64),
}

impl Default for ShaderOptionConfigValue {
    fn default() -> Self {
        Self::Float(0.0)
    }
}

impl ShaderOptionConfigValue {
    fn as_float(self) -> f32 {
        match self {
            Self::Float(value) => value,
            Self::Bool(value) => {
                if value {
                    1.0
                } else {
                    0.0
                }
            }
            Self::Integer(value) => value as f32,
        }
    }

    fn as_bool(self) -> bool {
        match self {
            Self::Float(value) => value != 0.0,
            Self::Bool(value) => value,
            Self::Integer(value) => value != 0,
        }
    }
}
