# libnvse

Safe Rust bindings for xNVSE 6.4.4 -- write full-featured Fallout: New Vegas
plugins entirely in Rust.

## Features

libnvse provides two API layers:

- **`plugin` API** (recommended) -- High-level, zero-unsafe interface with `PluginContext`.
  Uses standard Rust types (`String`, `FormId`, `Value`). Best for most plugins.
- **`api` API** -- Low-level 1:1 wrappers over each xNVSE interface.
  Useful when you need direct control or access to interfaces not yet exposed by `PluginContext`.

### Available interfaces

| Interface | Low-level (`api::`) | High-level (`PluginContext`) | Purpose |
|-----------|---------------------|------------------------------|---------|
| **Messaging** | `messaging` | `on_message()`, `dispatch_message()` | Game events, inter-plugin comms |
| **Console** | `console` | `console()` | Execute console commands |
| **Commands** | `command` | `set_opcode_base()`, `register_command()` | Register script commands (GECK/console) |
| **CommandTable** | `command_table` | `low_level()` | Look up existing commands/plugins |
| **StringVars** | `string_var` | `string_vars()` | NVSE string variables |
| **ArrayVars** | `array_var` | `low_level()` | Arrays, maps, string maps for scripts |
| **Scripts** | `script` | `low_level()` | Compile scripts, call UDFs |
| **Serialization** | `serialization` | `on_save()`, `on_load()`, `on_new_game()` | Persist data with game saves (co-save) |
| **EventManager** | `event_manager` | `low_level()` | Custom events, dispatch to scripts |
| **PlayerControls** | `player_controls` | `player_controls()` | Toggle player input |
| **Data** | `data` | `low_level()` | Access NVSE singletons/internals |
| **Logging** | `logging` | `low_level()` | Plugin log directory path |
| **MessageBox** | `message_box` | `message_box()`, `message_box_with_callback()` | In-game dialog popups |
| **HUD** | `hud` | `hud_message()`, `hud_message_with()` | Vault Boy corner notifications |

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

### 2. Write plugin entry points (high-level API)

```rust
use libnvse::plugin::prelude::*;

// NVSE calls this first -- report plugin name and version.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Query(
    _nvse: *const libnvse::NVSEInterfaceFFI,
    info: *mut libnvse::PluginInfoFFI,
) -> bool {
    let info = unsafe { &mut *info };
    info.name = c"my-plugin".as_ptr();
    info.version = 1;
    true
}

// NVSE calls this after Query succeeds -- set up everything here.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NVSEPlugin_Load(
    nvse: *const libnvse::NVSEInterfaceFFI,
) -> bool {
    match plugin_main(nvse) {
        Ok(()) => true,
        Err(e) => { log::error!("Plugin load failed: {e}"); false }
    }
}

// All your plugin logic lives here -- fully safe Rust.
fn plugin_main(nvse: *const libnvse::NVSEInterfaceFFI) -> Result<(), PluginError> {
    let mut ctx = PluginContext::new(nvse, c"my-plugin")?;

    ctx.on_message(|msg| {
        if msg.get_type() == MessageType::DeferredInit {
            log::info!("Game ready!");
        }
    })?;

    Ok(())
}
```

### 3. Build and install

```bash
cargo build --target i686-pc-windows-gnu --release
# Copy target/i686-pc-windows-gnu/release/my_plugin.dll
#   to <game>/Data/NVSE/Plugins/
```

> Fallout: New Vegas is 32-bit only. The target **must** be `i686-pc-windows-gnu`.

## Cookbook

All examples below use the high-level `PluginContext` API and assume you have
`use libnvse::plugin::prelude::*;` at the top.

### Run console commands

```rust
fn do_stuff(ctx: &PluginContext) -> Result<(), PluginError> {
    let con = ctx.console()?;

    con.run("player.additem F 100")?;           // give 100 caps
    con.run("player.restoreav health 999")?;     // heal player
    con.run("set MyGlobalVar to 42")?;           // set a global

    con.run_silent("set SomeInternalVar to 1")?; // no console echo

    // Target a specific form by ID
    con.run_on(FormId::new(0x123ABC), "disable")?;

    Ok(())
}
```

### React to game events

```rust
fn setup_messages(ctx: &mut PluginContext) -> Result<(), PluginError> {
    ctx.on_message(|msg| {
        match msg.get_type() {
            MessageType::PostLoad => {
                log::info!("All plugins loaded");
            }
            MessageType::DeferredInit => {
                log::info!("Game engine ready -- safe to call console");
            }
            MessageType::LoadGame => {
                if let Some(path) = msg.data_as_path() {
                    log::info!("Loading save: {path}");
                }
            }
            MessageType::SaveGame => {
                if let Some(path) = msg.data_as_path() {
                    log::info!("Saving: {path}");
                }
            }
            MessageType::MainGameLoop => {
                // Called every frame -- use sparingly!
            }
            _ => {}
        }
    })?;
    Ok(())
}
```

### Register console commands

```rust
use libnvse::nvse_command;

// Define the command handler with the nvse_command! macro.
// The macro generates a Cmd_Execute function pointer named MY_HEAL_EXECUTE.
nvse_command!(MyHeal, ctx, {
    ctx.print("Healed!");
    ctx.set_result(1.0);
    true
});

fn register_commands(ctx: &mut PluginContext) -> Result<(), PluginError> {
    ctx.set_opcode_base(0x3000)?;
    ctx.register_command(
        "MyHeal",                         // name (used in console/GECK)
        "mh",                             // short alias
        "Heals the player",               // help text
        false,                            // needs reference object?
        &[],                              // parameters (see Param/ParamType)
        MY_HEAL_EXECUTE,                  // generated by nvse_command!
    )?;
    Ok(())
}
```

Commands with parameters:

```rust
use libnvse::api::command::{Param, ParamType};

nvse_command!(MyGive, ctx, {
    // Parameters are extracted from the script engine via NVSE.
    // Use ctx.set_result() to return a value to the calling script.
    ctx.set_result(1.0);
    true
});

fn register(ctx: &mut PluginContext) -> Result<(), PluginError> {
    ctx.set_opcode_base(0x3001)?;
    ctx.register_command(
        "MyGive", "mg", "Give items to player", false,
        &[
            Param::required(ParamType::Integer),   // amount
            Param::optional(ParamType::String),     // item name
        ],
        MY_GIVE_EXECUTE,
    )?;
    Ok(())
}
```

### Save and load plugin data (co-save)

```rust
use std::sync::Mutex;

static STATE: Mutex<MyState> = Mutex::new(MyState::new());

struct MyState {
    kill_count: u32,
    player_name: String,
    hardcore: bool,
}

impl MyState {
    const fn new() -> Self {
        Self { kill_count: 0, player_name: String::new(), hardcore: false }
    }
}

fn setup_cosave(ctx: &mut PluginContext) -> Result<(), PluginError> {
    // Called when the player saves
    ctx.on_save(|writer| {
        let state = STATE.lock().unwrap();
        writer.write(b"STAT", 1, |w| {
            w.write_u32(state.kill_count)?;
            w.write_string(&state.player_name)?;
            w.write_bool(state.hardcore)?;
            Ok(())
        })
    })?;

    // Called when the player loads a save
    ctx.on_load(|reader| {
        let mut state = STATE.lock().unwrap();
        while let Some(rec) = reader.next_record()? {
            if rec.tag == *b"STAT" {
                state.kill_count = reader.read_u32()?;
                state.player_name = reader.read_string()?;
                state.hardcore = reader.read_bool()?;
            } else {
                reader.skip(rec.length)?;
            }
        }
        Ok(())
    })?;

    // Called when the player starts a new game
    ctx.on_new_game(|| {
        let mut state = STATE.lock().unwrap();
        *state = MyState::new();
    })?;

    Ok(())
}
```

`SaveWriter` supports: `write_u8`, `write_u16`, `write_u32`, `write_u64`,
`write_i32`, `write_f32`, `write_f64`, `write_bool`, `write_string`,
`write_form_id`, `write_raw`.

`LoadReader` supports the matching `read_*` methods plus `read_form_id`
(with load-order resolution), `read_form_id_raw`, and `skip`.

### Show HUD notifications

```rust
fn notify(ctx: &PluginContext) -> Result<(), PluginError> {
    // Default: Neutral Vault Boy, 2 seconds
    ctx.hud_message("Hello from Rust!")?;

    // Custom emotion and duration
    use libnvse::api::hud::Emotion;
    ctx.hud_message_with("Ouch!", Emotion::Pain, 3.0)?;

    Ok(())
}
```

Available emotions: `Happy`, `Sad`, `Neutral`, `Pain`.

### Show message box dialogs

```rust
fn dialogs(ctx: &PluginContext) -> Result<(), PluginError> {
    // Simple (fire-and-forget)
    ctx.message_box("Hello!", "OK")?;

    // With callback -- keep the return value alive until the player clicks!
    let _dialog = ctx.message_box_with_callback("Save?", "Yes", || {
        log::info!("Player said yes");
    })?;

    Ok(())
}
```

### Toggle player controls

```rust
fn freeze_player(ctx: &PluginContext) -> Result<(), PluginError> {
    let ctrl = ctx.player_controls()?;
    ctrl.disable(Controls::MOVEMENT | Controls::JUMPING)?;

    // ... later ...
    ctrl.enable(Controls::MOVEMENT | Controls::JUMPING)?;

    // Check state
    if ctrl.is_disabled(Controls::MOVEMENT) {
        log::info!("Movement still locked");
    }

    Ok(())
}
```

Available flags: `MOVEMENT`, `LOOKING`, `PIPBOY`, `FIGHTING`, `POV`,
`ROLLING_TEXT`, `SNEAKING`, and more (see `ControlFlags` bitflags).

### Work with NVSE string variables

```rust
fn string_demo(ctx: &PluginContext) -> Result<(), PluginError> {
    let strings = ctx.string_vars()?;

    let id = strings.create("Hello from Rust!")?;
    let value = strings.get(id)?;
    assert_eq!(value, "Hello from Rust!");

    strings.set(id, "Updated!")?;
    Ok(())
}
```

### Send messages between plugins

```rust
fn ipc(ctx: &PluginContext) -> Result<(), PluginError> {
    // Broadcast to all plugins
    ctx.dispatch_message(1000, b"hello", None)?;

    // Send to a specific plugin
    ctx.dispatch_message(1000, b"hello", Some("OtherPlugin"))?;
    Ok(())
}

fn listen(ctx: &mut PluginContext) -> Result<(), PluginError> {
    // Listen for messages from a specific plugin
    ctx.on_plugin_message("OtherPlugin", |msg| {
        log::info!("Got message type {}", msg.get_type_raw());
    })?;
    Ok(())
}
```

### Custom events (low-level API)

```rust
use libnvse::api::event_manager::{EventParamType, EventFlags};

static MY_PARAMS: &[EventParamType] = &[
    EventParamType::AnyForm,
    EventParamType::Float,
];

fn setup_events(ctx: &PluginContext) -> Result<(), PluginError> {
    let events = ctx.low_level().query_event_manager()?;
    events.register_event("MyPlugin:OnDamage", MY_PARAMS, EventFlags::NONE)?;
    Ok(())
}
```

### Escape hatch to low-level API

When `PluginContext` doesn't expose what you need, drop down to the
underlying `NVSEInterface`:

```rust
fn advanced(ctx: &PluginContext) -> Result<(), PluginError> {
    let nvse = ctx.low_level();

    // Access array vars directly
    let arrays = nvse.query_array_vars()?;

    // Access scripts
    let scripts = nvse.query_scripts()?;

    // Access NVSE data singletons
    let data = nvse.query_data()?;

    Ok(())
}
```

## Safe types

The `plugin::types` module provides safe wrappers for common game concepts:

### FormId

Every game object has a unique 32-bit form ID. Upper 8 bits = plugin load
order index, lower 24 bits = local ID.

```rust
let player = FormId::PLAYER_REF;     // 0x00000007
let caps   = FormId::CAPS;           // 0x0000000F
let npc    = FormId::new(0x001234AB);

assert_eq!(npc.plugin_index(), 0x00);
assert_eq!(npc.local_id(), 0x1234AB);
assert_eq!(npc.to_hex(), "001234AB");

// Build from components
let form = FormId::from_parts(0x01, 0x000ABC);
```

### Value

A safe, owned variant type for NVSE arrays and events:

```rust
let greeting = Value::text("Hello, Courier!");
let damage   = Value::number(42.0);
let target   = Value::form(FormId::PLAYER_REF);
let flag     = Value::from(true);  // stored as 1.0

assert_eq!(greeting.as_str(), Some("Hello, Courier!"));
assert_eq!(damage.as_f64(), Some(42.0));
```

## Building

### Prerequisites

1. **Rust i686 target** (first time only):
   ```bash
   rustup target add i686-pc-windows-gnu
   ```

2. **Cross-compilation toolchain**:
   - `mingw-w64` -- GCC cross-compiler for Windows
   - `clang` / `libclang` -- required by bindgen

3. **xNVSE submodule** (first time only):
   ```bash
   git submodule update --init --recursive
   ```

### Build

```bash
cargo build --target i686-pc-windows-gnu          # debug
cargo build --target i686-pc-windows-gnu --release # release
```

The build script (`build.rs`) will:
1. Verify the xNVSE submodule is present
2. Patch xNVSE headers for bindgen compatibility (removes `[[nodiscard]]`)
3. Generate Rust FFI bindings to `src/bindings/nvse.rs`
4. Compile the crate against the generated bindings

Bindings are gitignored and regenerated on each build. No network access required.


## Dependencies

| Crate | Purpose |
|-------|---------|
| `libc` | FFI types for C interop |
| `log` | Logging facade (bring your own backend) |
| `thiserror` | Error type derivation |
| `anyhow` | Flexible error handling |
| `parking_lot` | Efficient synchronization primitives |
| `closure-ffi` | Safe closure marshaling across FFI boundary |
| `ahash` | Fast hashing (for callback storage maps) |
| `bitflags` | Bitfield abstractions (`ControlFlags`, etc.) |
| `paste` | Token pasting (powers `nvse_command!` macro) |
| `libpsycho` | Windows/x86 utilities (WinAPI string conversion) |
| `bindgen` | Build-time C/C++ binding generation |

## Design principles

- **Safe by default** -- All interfaces validate NULL pointers and return `Result`
- **No `.unwrap()` / `.expect()`** -- Errors propagate via `Result`; match and log at boundaries
- **Two API layers** -- High-level `PluginContext` for most work, low-level `api::` for everything else
- **Zero overhead** -- Thin wrappers; one pointer dereference per call, no runtime allocation in hot paths
- **Closure-friendly** -- Message listeners and callbacks accept Rust closures via `closure-ffi::BareFn`
- **Leak-safe** -- Closures stored in `AHashMap` to preserve lifetime across FFI
- **Idiomatic Rust** -- Enums, builders, bitflags, and iterators instead of raw C patterns

## Thread safety

xNVSE is **single-threaded**. All callbacks run on the main game thread. You can
use `Mutex` / `RwLock` for your own state if you spawn threads, but all NVSE
interface calls must happen on the main thread.

## Updating xNVSE version

```bash
cd libnvse/xnvse
git fetch --tags
git checkout <new-version>
cd ../..
git add libnvse/xnvse
git commit -m "Update xNVSE to version X.Y.Z"
```
