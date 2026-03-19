//! In-game message box display.
//!
//! # Ownership
//!
//! The game engine calls the callback asynchronously when the player clicks
//! a button. The [`MessageBox`] struct owns the callback closure and MUST
//! be kept alive until the player dismisses the dialog.
//!
//! ```no_run
//! // The returned MessageBox owns the callback. Store it somewhere that
//! // outlives the dialog (e.g. a struct field, a static, a Vec).
//! let _active = MessageBox::show("Hello!", "OK", || {
//!     log::info!("Player clicked OK");
//! })?;
//!
//! // When _active is dropped the callback becomes invalid.
//! // Only drop it AFTER the player has clicked the button.
//! ```

use closure_ffi::BareFn;
use libpsycho::os::windows::winapi::{WinString, WinapiError};
use thiserror::Error;

/// ShowMessageBox function type.
type ShowMessageBoxFn = unsafe extern "C" fn(
    message: *const i8,
    unk1: u32,
    unk2: u32,
    callback: Option<unsafe extern "C" fn()>,
    unk4: u32,
    unk5: u32,
    unk6: f32,
    unk7: f32,
    button1: *const i8,
    button2: *const i8,
    button3: *const i8,
    button4: *const i8,
    button5: *const i8,
    button6: *const i8,
    button7: *const i8,
    button8: *const i8,
    button9: *const i8,
    button10: *const i8,
    terminator: *const i8,
) -> bool;

/// ShowMessageBox callback function type.
pub type ShowMessageBoxCallbackFn = unsafe extern "C" fn();

/// ShowErrorMessageBox function type.
pub type ShowErrorMessageBoxFn = unsafe extern "C" fn(message: *const i8);

/// Get ShowMessageBox from game memory at 0x00703E80.
#[inline]
fn nvse_show_message_box() -> ShowMessageBoxFn {
    unsafe { std::mem::transmute(0x00703E80usize) }
}

/// Get ShowMessageBox_Callback from game memory at 0x005B4A70.
#[inline]
fn nvse_show_message_box_callback() -> ShowMessageBoxCallbackFn {
    unsafe { std::mem::transmute(0x005B4A70usize) }
}

#[derive(Debug, Error)]
pub enum MessageBoxError {
    #[error("WinAPI error: {0}")]
    WinApiError(#[from] WinapiError),
}

pub type MessageBoxResult<T> = std::result::Result<T, MessageBoxError>;

/// An active in-game message box.
///
/// Owns the callback closure that the game engine will invoke when the
/// player clicks a button. **You must keep this value alive** until the
/// dialog is dismissed -- dropping it invalidates the callback pointer.
///
/// # Typical patterns
///
/// Store it in a field:
/// ```no_run
/// struct MyPlugin {
///     active_dialog: Option<MessageBox<'static>>,
/// }
///
/// impl MyPlugin {
///     fn greet(&mut self) -> MessageBoxResult<()> {
///         self.active_dialog = Some(MessageBox::show("Hi!", "OK", || {
///             log::info!("Clicked!");
///         })?);
///         Ok(())
///     }
/// }
/// ```
///
/// Or use a long-lived container:
/// ```no_run
/// static DIALOGS: Mutex<Vec<MessageBox<'static>>> = Mutex::new(Vec::new());
///
/// fn show_greeting() -> MessageBoxResult<()> {
///     let mb = MessageBox::show("Hello!", "OK", || {
///         log::info!("Clicked!");
///     })?;
///     DIALOGS.lock().push(mb);
///     Ok(())
/// }
/// ```
pub struct MessageBox<'a> {
    /// Prevent the callback closure from being freed.
    _callback: BareFn<'a, ShowMessageBoxCallbackFn>,
}

impl<'a> MessageBox<'a> {
    /// Show an in-game message box with one button and a callback.
    ///
    /// Returns a [`MessageBox`] that owns the callback. Keep the returned
    /// value alive until the player clicks the button.
    pub fn show<F: Fn() + 'a>(
        message: &str,
        button_text: &str,
        on_click: F,
    ) -> MessageBoxResult<Self> {
        let win_message = WinString::new(message)?;
        let win_button = WinString::new(button_text)?;
        let show_fn = nvse_show_message_box();

        let callback: BareFn<'a, ShowMessageBoxCallbackFn> = BareFn::new(on_click);
        let bare_ptr = callback.bare();

        win_message.with_ansi(|msg| {
            win_button.with_ansi(|btn| {
                unsafe {
                    show_fn(
                        msg,
                        0,
                        0,
                        Some(bare_ptr),
                        0,
                        0x17,
                        0.0,
                        0.0,
                        btn,
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null::<i8>(),
                    );
                }
            });
        });

        Ok(Self {
            _callback: callback,
        })
    }

    /// Show an in-game message box with up to 10 custom buttons.
    ///
    /// `buttons` contains the label for each button (max 10).
    /// The callback fires regardless of which button is pressed.
    pub fn show_multi<F: Fn() + 'a>(
        message: &str,
        buttons: &[&str],
        on_click: F,
    ) -> MessageBoxResult<Self> {
        let win_message = WinString::new(message)?;
        let show_fn = nvse_show_message_box();

        let callback: BareFn<'a, ShowMessageBoxCallbackFn> = BareFn::new(on_click);
        let bare_ptr = callback.bare();

        // Convert up to 10 button labels to WinStrings
        let mut win_buttons: Vec<WinString> = Vec::with_capacity(buttons.len().min(10));
        for btn in buttons.iter().take(10) {
            win_buttons.push(WinString::new(btn)?);
        }

        win_message.with_ansi(|msg| {
            // Collect ANSI pointers -- each with_ansi borrows the WinString
            // so we build the pointer array manually.
            let mut ptrs: [*const i8; 10] = [std::ptr::null(); 10];
            for (i, wb) in win_buttons.iter().enumerate() {
                wb.with_ansi(|p| ptrs[i] = p);
            }

            unsafe {
                show_fn(
                    msg,
                    0,
                    0,
                    Some(bare_ptr),
                    0,
                    0x17,
                    0.0,
                    0.0,
                    ptrs[0], ptrs[1], ptrs[2], ptrs[3], ptrs[4],
                    ptrs[5], ptrs[6], ptrs[7], ptrs[8], ptrs[9],
                    std::ptr::null::<i8>(),
                );
            }
        });

        Ok(Self {
            _callback: callback,
        })
    }

    /// Show a simple message box with no callback (fire-and-forget).
    ///
    /// Uses the game's default callback. No ownership concerns.
    pub fn show_simple(message: &str, button_text: &str) -> MessageBoxResult<()> {
        let win_message = WinString::new(message)?;
        let win_button = WinString::new(button_text)?;
        let show_fn = nvse_show_message_box();
        let default_cb = nvse_show_message_box_callback();

        win_message.with_ansi(|msg| {
            win_button.with_ansi(|btn| {
                unsafe {
                    show_fn(
                        msg,
                        0,
                        0,
                        Some(default_cb),
                        0,
                        0x17,
                        0.0,
                        0.0,
                        btn,
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null::<i8>(),
                    );
                }
            });
        });

        Ok(())
    }
}
