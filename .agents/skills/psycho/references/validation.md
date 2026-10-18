# Validation

## Preflight

```bash
git status --short
git diff --stat
rustup target list --installed
i686-w64-mingw32-gcc --version
wine --version
```

The only supported target is `i686-pc-windows-gnu`. Always pass it explicitly.
`.cargo/config.toml` also selects it and runs test binaries through Wine, but
the explicit flag is the repository contract.

## Focused test while iterating

Use the narrowest filter that proves the change.

```bash
# One test by exact path
cargo test --target i686-pc-windows-gnu -p atom \
  input::buffered::tests::test_name -- --exact

# One module or family
cargo test --target i686-pc-windows-gnu -p omv effects::shadows:: -- --nocapture

# List tests without running them
cargo test --target i686-pc-windows-gnu -p <crate> -- --list
```

For an executable defect, run the unchanged path first and preserve the
failure. Then change code. Then run the same command again.

## Affected crate suite

```bash
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes
cargo test --target i686-pc-windows-gnu -p psycho-engine-fixes-helper
cargo test --target i686-pc-windows-gnu -p omv
cargo test --target i686-pc-windows-gnu -p atom
cargo test --target i686-pc-windows-gnu -p libpsycho --lib
cargo test --target i686-pc-windows-gnu -p psycho-imgui
```

`syringe` has `test = false` because it is `no_std` with its own panic handler.
Do not add a libtest harness to it.

## Ignored benchmarks

Explicit benchmarks use `#[ignore = "..."]`. Run them only when the task needs
the measurement, and run them one at a time because they share production
counters or device state.

```bash
cargo test --target i686-pc-windows-gnu -p omv \
  full_test_name -- --ignored --nocapture --test-threads=1
```

Report the measured workload, settings, rounds, and variance. Do not convert a
work-budget or CPU/GPU count into an FPS claim.

## GPU and Wine

- D3D9 tests create a real windowed device with
  `create_windowed_device(get_desktop_window(), ...)`.
- `DISPLAY` must be available. The configured Wine runner starts the Windows
  test executable.
- Some tests serialize through a process-wide mutex because they share
  production phase counters or render state. Do not parallelize those.
- A headless machine without a working D3D9 device cannot run the graphics
  suite. Report that as not run; do not replace it with a mock.
- Shader tests use the production compiler path. Compilation proves syntax and
  ABI, never image correctness.

## Formatting and diff

```bash
cargo fmt -p <crate> -- --check
cargo fmt -p <crate-a> -p <crate-b> -- --check
git diff --check
```

Prefer scoped formatting for touched crates. Workspace-wide formatting can
include unrelated legacy code. Formatting never replaces tests or building.

## Local release build (no deployment)

This produces local build artifacts only. Never install, copy, package, or
release them.

Build the complete supported set:

```bash
cargo build --release --target i686-pc-windows-gnu \
  -p syringe \
  -p psycho-engine-fixes \
  -p psycho-engine-fixes-helper \
  -p omv \
  -p atom
```

A single affected crate is acceptable while iterating:

```bash
cargo build --release --target i686-pc-windows-gnu -p <crate>
```

## Installation, packaging, and release are user-only

Agents must not run `build_fnv.sh`, `build.sh`, `release.sh`,
`.github/scripts/package_release.sh`, or any install, package, or deploy
command. Do not copy artifacts into a game or mod-manager directory.

Provide the validated local build and test results. The user performs every
deployment step outside the agent session.

## Documentation-only changes

- Check relative links and index coverage:
  `python3 .agents/skills/psycho/scripts/docs_index.py`
- Check the documentation index includes new files.
- Run `git diff --check`.
- Do not run a Rust build for documentation-only changes.

## Final report

State:

- outcome and files changed;
- behavioral evidence and exact commands;
- focused test, affected suite, release build, formatting, diff check;
- what was not run and why;
- whether changes are uncommitted;
- any unresolved contract or attribution.
