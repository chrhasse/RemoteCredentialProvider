use std::{mem, ptr};

use windows::{
    w,
    Win32::{
        Foundation::BOOL,
        Security::Credentials::{
            CredUIPromptForWindowsCredentialsW, CREDUIWIN_CHECKBOX, CREDUI_INFOW,
        },
    },
};

fn main() {
    let ui_info = CREDUI_INFOW {
        cbSize: mem::size_of::<CREDUI_INFOW>() as _,
        pszMessageText: w!("Enter credentials"),
        pszCaptionText: w!("Testing custom credential provider"),
        ..Default::default()
    };
    let mut auth_package = 0;
    let mut auth_buffer = ptr::null_mut();
    let mut auth_buffer_size = 0;
    let mut save = BOOL::default();
    let _ = unsafe {
        CredUIPromptForWindowsCredentialsW(
            Some(&ui_info),
            0,
            &mut auth_package,
            None,
            0,
            &mut auth_buffer,
            &mut auth_buffer_size,
            Some(&mut save),
            CREDUIWIN_CHECKBOX,
        )
    };
}