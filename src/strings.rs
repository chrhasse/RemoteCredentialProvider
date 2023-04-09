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
            CoTaskMemFree, CoGetMalloc
        },
    },
    core::{
        PWSTR,
        Result,
        PCWSTR, wcslen,
    },
    imp::E_OUTOFMEMORY
    };

union RswstrUnion {
    as_mut: *mut u16,
    as_const: *const u16,
    as_pwstr: PWSTR,
    as_pcwstr: PCWSTR
}

pub struct Rswstr {
    ptr: RswstrUnion,
    should_drop: bool,
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
                    ptr: RswstrUnion{ as_mut: buffer },
                    should_drop: true
                })
            }
        }
    }
    
    pub unsafe fn as_mut(&self) -> *mut u16 {
        self.ptr.as_mut
    }

    pub unsafe fn as_const(&self) -> *const u16 {
        self.ptr.as_const
    }
    
    pub unsafe fn as_pwstr(&self) -> PWSTR {
        self.ptr.as_pwstr
    }

    pub unsafe fn as_pcwstr(&self) -> PCWSTR {
        self.ptr.as_pcwstr
    }

    pub unsafe fn as_wide(&self) -> &[u16] {
        std::slice::from_raw_parts(self.ptr.as_const, self.str_len())
    }

    pub unsafe fn as_bytes(&self) -> &[u8] {
        std::mem::transmute::<&[u16], &[u8]>(self.as_wide())
    }
    
    pub unsafe fn as_wide_with_terminator(&self) -> &[u16] {
        std::slice::from_raw_parts(self.ptr.as_const, self.str_len() + 1)
    }

    pub unsafe fn as_bytes_with_terminator(&self) -> &[u8] {
        std::mem::transmute::<&[u16], &[u8]>(self.as_wide_with_terminator())
    }
    
    pub fn allocation_size(&self) -> Result<usize> {
        unsafe {
            let malloc = CoGetMalloc(1)?;
            Ok(malloc.GetSize(Some(self.as_const() as *const c_void)))
        }
    }
    
    pub fn str_len(&self) -> usize {
        unsafe {
            wcslen(self.as_pcwstr())
        }
    }
    
    pub unsafe fn to_pcwstr(mut self) -> PCWSTR {
        self.should_drop = false;
        self.ptr.as_pcwstr
    }

    pub unsafe fn to_pwstr(mut self) -> PWSTR {
        self.should_drop = false;
        self.ptr.as_pwstr
    }

    pub unsafe fn to_unicode_string(mut self) -> UNICODE_STRING {
        self.should_drop = false;
        let size = (self.str_len() * std::mem::size_of::<u16>()) as u16;
        UNICODE_STRING { Length: size, MaximumLength: size, Buffer: self.ptr.as_pwstr }
    }
    
    pub unsafe fn clone_from_pcwstr(value: PCWSTR) -> Result<Self> {
            let copy = SHStrDupW(value)?;
            Ok(Self {
                ptr: RswstrUnion { as_pwstr: copy },
                should_drop: true
            })
    }
}

impl Clone for Rswstr {
    fn clone(&self) -> Self {
        unsafe {
            if let Ok(copy) = SHStrDupW(self.as_pcwstr()) {
                copy.into()
            } else {
                std::process::abort()
            }
        }
    }
}

impl Drop for Rswstr {
    fn drop(&mut self) {
        unsafe {
            if self.should_drop {
                CoTaskMemFree(Some(*self.as_const() as *const c_void));
            }
        }
    }
}

impl From<PWSTR> for Rswstr {
    fn from(value: PWSTR) -> Self {
        Self {
            ptr: RswstrUnion { as_pwstr: value },
            should_drop: true
        }
    }
}