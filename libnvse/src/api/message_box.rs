use closure_ffi::BareFn;
use libpsycho::os::windows::winapi::{WinString, WinapiError};
use thiserror::Error;

/// ShowMessageBox function type.
///
/// Displays an in-game message box with custom buttons.
/// The variadic parameters are button labels (const char*) terminated with NULL.
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
///
/// Displays a Windows MessageBox with error icon.
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

pub fn show_message_box<F: Fn()>(message: &str, ok_text: &str, cb: F) -> MessageBoxResult<()> {
    let win_ok_text = WinString::new(ok_text)?;

    let show_message_box_fn = nvse_show_message_box();

    let win_message = WinString::new(message)?;

    let closure: BareFn<ShowMessageBoxCallbackFn> = BareFn::new(cb);

    win_message.with_ansi(|msg: *const i8| {
        win_ok_text.with_ansi(|ok_text| {
            let buttons: [*const i8; 10] = [
                ok_text,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            ];

            unsafe {
                // Call the game's ShowMessageBox function
                // Parameters based on GameAPI.h documentation:
                // - message: the message text
                // - unk1 = 0
                // - unk2 = 0
                // - callback = ShowMessageBox_Callback (may be NULL)
                // - unk4 = 0
                // - unk5 = 0x17 (unknown constant from game internals)
                // - unk6 = 0.0
                // - unk7 = 0.0
                // - ...buttons (variadic, terminated with NULL)
                show_message_box_fn(
                    msg,
                    0,
                    0,
                    Some(closure.bare()),
                    0,
                    0x17,
                    0.0,
                    0.0,
                    buttons[0],
                    buttons[1],
                    buttons[2],
                    buttons[3],
                    buttons[4],
                    buttons[5],
                    buttons[6],
                    buttons[7],
                    buttons[8],
                    buttons[9],
                    std::ptr::null::<i8>(), // NULL terminator
                );
            }
        });
    });

    Ok(())
}
