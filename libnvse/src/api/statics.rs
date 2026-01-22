//! Static function pointers from game memory.
//!
//! These are not linked symbols but hardcoded memory addresses where the game's
//! functions exist at runtime. Addresses are from xNVSE GameAPI.cpp and Utilities.cpp.

/// ShowMessageBox function type.
///
/// Displays an in-game message box with custom buttons.
/// The variadic parameters are button labels (const char*) terminated with NULL.
pub type ShowMessageBoxFn = unsafe extern "C" fn(
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
pub fn show_message_box() -> ShowMessageBoxFn {
    unsafe { std::mem::transmute(0x00703E80usize) }
}

/// Get ShowMessageBox_Callback from game memory at 0x005B4A70.
#[inline]
pub fn show_message_box_callback() -> ShowMessageBoxCallbackFn {
    unsafe { std::mem::transmute(0x005B4A70usize) }
}

