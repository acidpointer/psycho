use libpsycho::os::windows::winapi::{WinString, WinapiError};
use thiserror::Error;

use super::statics;

#[derive(Debug, Error)]
pub enum MessageBoxError {
    #[error("WinAPI error: {0}")]
    WinApiError(#[from] WinapiError),
}

pub type MessageBoxResult<T> = std::result::Result<T, MessageBoxError>;

pub fn show_message_box(message: &str, ok_text: &str) -> MessageBoxResult<()> {
    let win_ok_text = WinString::new(ok_text)?;

    let show_message_box_fn = statics::show_message_box();

    let win_message = WinString::new(message)?;

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
                    None,
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
