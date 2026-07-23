# OMV load-transition ownership

## Purpose and user-visible behavior

OMV must not retain workbench input or diagnostics ownership while Fallout New
Vegas replaces the active game state. When xNVSE publishes `PreLoadGame`, OMV
now closes the workbench before native loading begins. The game immediately
regains keyboard and mouse input, and the workbench stays closed after the
load.

This transition does not claim to complete or repair native ModelLoader work.
It removes OMV-owned state from the load boundary so an open diagnostics menu
cannot suppress game input or keep optional capture active during a load.

## Architecture and ordering

`omv/src/nvse_plugin.rs` handles `NVSEMessageType::PreLoadGame` and calls
`runtime::prepare_for_game_load` synchronously on the xNVSE message thread.
The runtime transition:

1. clears workbench visibility;
2. cancels pending keybind capture;
3. clears the pending replacement key;
4. deactivates menu-only diagnostic producers;
5. restores game DirectInput capture.

The input unblock path in `omv/src/input.rs` is deliberately write-only. Device
refresh and hook installation occur only when input becomes blocked. Releasing
input during `PreLoadGame` therefore performs no engine pointer read, hook
installation, allocation, file I/O, or blocking lock.

## Invariants and failure behavior

- Native loading never inherits an open OMV workbench.
- Keybind capture cannot consume a load-screen or post-load key.
- Diagnostics do not record the load transition as ordinary frame history.
- OMV never reopens the workbench automatically after a load.
- DirectInput hooks remain installed but dormant when capture is restored.
- This boundary does not bypass, time out, or alter native save-load work.

## Validation and runtime acceptance

Unit tests prove that `PreLoadGame` is wired to the transition and that menu
visibility, key capture, pending key state, diagnostics, and DirectInput
suppression are all cleared. Validation on 2026-07-23 passed all 296 OMV tests
and the complete supported i686 release build.

Runtime acceptance requires opening the workbench in the main menu, loading a
save, and confirming that the workbench closes immediately, game input is
restored, and reopening the workbench starts a fresh diagnostic session.
