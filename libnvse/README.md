# libnvse

Safe Rust bindings for xNVSE 6.4.4 -- write full-featured Fallout: New Vegas
plugins entirely in Rust.

## What you can do

| Interface | Module | Purpose |
|-----------|--------|---------|
| **Messaging** | `api::messaging` | Listen for game events, communicate between plugins |
| **Console** | `api::console` | Execute console commands from code |
| **Commands** | `api::command` | Register new script commands callable from GECK/console |
| **CommandTable** | `api::command_table` | Look up existing commands and plugins |
| **StringVars** | `api::string_var` | Create and manipulate NVSE string variables |
| **ArrayVars** | `api::array_var` | Create arrays, maps, string maps for scripts |
| **Scripts** | `api::script` | Compile scripts, call user-defined functions |
| **Serialization** | `api::serialization` | Persist plugin data with game saves (co-save) |
| **EventManager** | `api::event_manager` | Register custom events, dispatch to scripts |
| **PlayerControls** | `api::player_controls` | Toggle player input (movement, VATS, etc.) |
| **Data** | `api::data` | Access NVSE internals (singletons, functions) |
| **Logging** | `api::logging` | Get the plugin log directory path |
| **MessageBox** | `api::message_box` | Show in-game message box dialogs |

## Quick start

### 1. Create your plugin crate

```toml
# Cargo.toml
[lib]
crate-type = ["cdylib"]

[dependencies]
libnvse = { path = "../libnvse" }
log = "0.4"
```

### 2. Write plugin entry points

```rust
use libnvse::{NVSEInterfaceFFI, PluginInfoFFI};
use libnvse::api::interface::NVSEInterface;
use libnvse::api::messaging::NVSEMessageType;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Query(
    _nvse: *const NVSEInterfaceFFI,
    info: *mut PluginInfoFFI,
) -> bool {
    let info = unsafe { &mut *info };
    info.name = c"my-plugin".as_ptr();
    info.version = 1;
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Load(
    nvse: *const NVSEInterfaceFFI,
) -> bool {
    let mut nvse = match NVSEInterface::from_raw(nvse) {
        Ok(n) => n,
        Err(e) => { log::error!("{}", e); return false; }
    };

    // Listen for NVSE messages
    nvse.messaging_interface_mut()
        .register_listener("NVSE", |msg| {
            if msg.get_type() == NVSEMessageType::DeferredInit {
                log::info!("Game ready!");
            }
        })
        .ok();

    true
}
```

### 3. Build and install

```bash
cargo build --target i686-pc-windows-gnu --release
# Copy target/i686-pc-windows-gnu/release/my_plugin.dll
#   to Data/NVSE/Plugins/
```

## Cookbook

### Register a console command

```rust
use libnvse::api::command::{CommandBuilder, Param, ParamType, ReturnType};

fn register_commands(nvse: &NVSEInterface) -> anyhow::Result<()> {
    let mut cmds = nvse.command_builder()?;
    cmds.set_opcode_base(0x3000)?;

    // Simple command: MyHeal <amount:int>
    cmds.register(
        "MyHeal", "mh", "Heal the player by amount", false,
        &[Param::required(ParamType::Integer)],
        Some(cmd_my_heal),
    )?;

    Ok(())
}

unsafe extern "C" fn cmd_my_heal(
    param_info: *mut libnvse::ParamInfoFFI,
    script_data: *mut core::ffi::c_void,
    this_obj: *mut libnvse::TESObjectREFR,
    // ...remaining COMMAND_ARGS...
) -> bool {
    // Your implementation here
    true
}
```

### Save and load plugin data

```rust
use libnvse::api::serialization::Serialization;

fn setup_cosave(nvse: &NVSEInterface) -> anyhow::Result<()> {
    let handle = nvse.get_plugin_handle().get_handle();
    let mut ser = nvse.query_serialization()?;

    ser.set_save_callback(handle, || {
        // Write your data
        // ser.write_record(b"DATA", 1, &my_bytes)?;
    })?;

    ser.set_load_callback(handle, || {
        // Read your data
        // while let Some(rec) = ser.next_record()? { ... }
    })?;

    Ok(())
}
```

### Custom events

```rust
use libnvse::api::event_manager::{EventParamType, EventFlags};

static MY_PARAMS: &[EventParamType] = &[
    EventParamType::AnyForm,
    EventParamType::Float,
];

fn setup_events(nvse: &NVSEInterface) -> anyhow::Result<()> {
    let events = nvse.query_event_manager()?;
    events.register_event(
        "MyPlugin:OnDamage",
        MY_PARAMS,
        EventFlags::NONE,
    )?;
    Ok(())
}
```

### Toggle player controls

```rust
use libnvse::api::player_controls::ControlFlags;

fn freeze_player(nvse: &NVSEInterface) -> anyhow::Result<()> {
    let controls = nvse.query_player_controls(c"my-plugin")?;
    controls.disable(ControlFlags::MOVEMENT | ControlFlags::JUMPING)?;
    // Later: controls.enable(ControlFlags::MOVEMENT | ControlFlags::JUMPING)?;
    Ok(())
}
```

## Building

### Prerequisites

1. Initialize the xNVSE submodule (first time only):
   ```bash
   git submodule update --init --recursive
   ```

2. Install i686 Windows target:
   ```bash
   rustup target add i686-pc-windows-gnu
   ```

3. Install required tools:
   - `mingw-w64` (for cross-compilation from Linux)
   - `bindgen` dependencies (clang/libclang)

### Build

```bash
cargo build --target i686-pc-windows-gnu
```

The build process will:
1. Verify the xNVSE submodule is present
2. Patch xNVSE headers for bindgen compatibility
3. Generate Rust bindings to `src/bindings/nvse.rs`
4. Compile the crate

## Project structure

```
libnvse/
+-- xnvse/                   Git submodule (xNVSE 6.4.4 source)
+-- wrapper/
|   +-- nvse_wrapper.h        Main wrapper header for bindgen
|   +-- include/               Minimal C++ stdlib stubs
+-- src/
|   +-- lib.rs                 Crate root
|   +-- bindings/nvse.rs       Auto-generated (gitignored)
|   +-- api/
|       +-- interface.rs       NVSEInterface (main entry point)
|       +-- messaging.rs       Plugin messaging + listeners
|       +-- console.rs         Console command execution
|       +-- logging.rs         Plugin log path
|       +-- command.rs         Command registration builders
|       +-- command_table.rs   Command table queries
|       +-- string_var.rs      NVSE string variables
|       +-- array_var.rs       NVSE arrays, maps, string maps
|       +-- script.rs          Script compilation + function calls
|       +-- serialization.rs   Co-save read/write
|       +-- event_manager.rs   Custom event registration + dispatch
|       +-- player_controls.rs Player input toggling
|       +-- data.rs            NVSE internal data access
|       +-- message_box.rs     In-game message box
+-- build.rs                   Bindgen build script
```

## Design principles

- **Safe by default**: All interfaces validate NULL pointers and return Results
- **No .unwrap()/.expect()**: Errors propagate via Result types
- **Idiomatic Rust**: Enums, builders, iterators instead of raw C patterns
- **Zero overhead**: Wrappers are thin -- one pointer dereference per call
- **Closure-friendly**: Message listeners and callbacks accept Rust closures
- **Leak-safe**: Closures stored in HashMaps to preserve lifetime across FFI

## Updating xNVSE version

```bash
cd libnvse/xnvse
git fetch --tags
git checkout <new-version>
cd ../..
git add libnvse/xnvse
git commit -m "Update xNVSE to version X.Y.Z"
```

## Notes

- Bindings are generated at build time to `src/bindings/nvse.rs` (gitignored)
- xNVSE source is vendored via git submodule (version controlled)
- Target must be `i686-pc-windows-gnu` -- Fallout NV is 32-bit only
- No network access required during build
