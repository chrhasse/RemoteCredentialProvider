use std::{
    ffi::c_void,
};

use windows::{
    Win32::{
        UI::Shell::{
            SHStrDupW
        },
        Foundation::{
            UNICODE_STRING,
        },
        System::Com::{
            CoTaskMemAlloc,
            CoTaskMemFree
        },
    },
    core::{
        PWSTR,
        Result,
        PCWSTR, wcslen,
    },
    imp::E_OUTOFMEMORY
    };
pub struct Rswstr {
    ptr: *mut u16
}

impl Rswstr {
    pub fn with_length(len: usize) -> Result<Self> {
        unsafe {
            // When passing objects across COM boundaries, memory must be 
            // allocated through the OLE Allocator
            let buffer = CoTaskMemAlloc(len * std::mem::size_of::<u16>()) as *mut u16;
            if buffer.is_null() {
                Err(E_OUTOFMEMORY.into())
            } else {
                Ok(Rswstr {
                    ptr: buffer,
                })
            }
        }
    }
    
    pub fn as_mut(&self) -> *mut u16 {
        self.ptr
    }

    pub fn as_const(&self) -> *const u16 {
        self.ptr.cast_const()
    }
    
    pub fn str_len(&self) -> usize {
        unsafe {
            wcslen(self.into())
        }
    }
    
    pub fn to_pcwstr(self) -> PCWSTR {
        let value = std::mem::ManuallyDrop::new(self);
        PCWSTR(value.ptr.cast_const())
    }

    pub fn to_pwstr(self) -> PWSTR {
        let value = std::mem::ManuallyDrop::new(self);
        PWSTR(value.ptr)
    }

    pub fn to_unicode_string(self) -> UNICODE_STRING {
        let value = std::mem::ManuallyDrop::new(self);
        let size = (value.str_len() * std::mem::size_of::<u16>()) as u16;
        UNICODE_STRING { Length: size, MaximumLength: size + 1, Buffer: PWSTR(value.ptr) }
    }
    
    pub fn as_wide(&self) -> &[u16] {
        unsafe {
            std::slice::from_raw_parts(self.ptr, self.str_len())
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::mem::transmute::<&[u16], &[u8]>(self.as_wide())
        }
    }
    
    pub fn as_wide_with_terminator(&self) -> &[u16] {
        unsafe {
            std::slice::from_raw_parts(self.ptr, self.str_len() + 1)
        }
    }

    pub fn as_bytes_with_terminator(&self) -> &[u8] {
        unsafe {
            std::mem::transmute::<&[u16], &[u8]>(self.as_wide_with_terminator())
        }
    }

}

impl Drop for Rswstr {
    fn drop(&mut self) {
        unsafe {
            CoTaskMemFree(Some(self.ptr as *const c_void));
        }
    }
}

impl From<PWSTR> for Rswstr {
    fn from(value: PWSTR) -> Self {
        Self {
            ptr: value.0,
        }
    }
}

impl From<PCWSTR> for Rswstr {
    fn from(value: PCWSTR) -> Self {
        unsafe {
            // 
            if let Ok(copy) = SHStrDupW(value) {
                Self {
                    ptr: copy.0
                }
            } else {
                std::process::abort()
            }
        }
    }
}

impl From<&Rswstr> for PCWSTR {
    fn from(value: &Rswstr) -> Self {
        PCWSTR(value.ptr.cast_const())
    }
}

impl From<&Rswstr> for PWSTR {
    fn from(value: &Rswstr) -> Self {
        PWSTR(value.ptr)
    }
}

impl From<&Rswstr> for UNICODE_STRING {
    fn from(value: &Rswstr) -> Self {
        let size = (value.str_len() * std::mem::size_of::<u16>()) as u16;
        UNICODE_STRING { Length: size, MaximumLength: size, Buffer: PWSTR(value.ptr) }
    }
}
