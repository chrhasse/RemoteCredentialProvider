use std::{
    ptr::{self, addr_of_mut},
    ffi::c_void, ops::{Deref, DerefMut},
};

use windows::{
    Win32::{
        UI::Shell::{
            CREDENTIAL_PROVIDER_FIELD_STATE,
            CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
            CPFT_SUBMIT_BUTTON,
            CPFT_PASSWORD_TEXT,
            CPFT_LARGE_TEXT,
            CPFG_CREDENTIAL_PROVIDER_LABEL,
            CPFT_SMALL_TEXT,
            CPFG_CREDENTIAL_PROVIDER_LOGO,
            CPFT_TILE_IMAGE,
            CPFIS_NONE,
            CPFS_DISPLAY_IN_BOTH,
            CPFS_HIDDEN,
            CPFS_DISPLAY_IN_SELECTED_TILE,
            CPFIS_FOCUSED,
            CREDENTIAL_PROVIDER_USAGE_SCENARIO,
            CPUS_UNLOCK_WORKSTATION,
            CPUS_LOGON,
            CPUS_CREDUI,
            CREDENTIAL_PROVIDER_FIELD_TYPE,
        },
        Graphics::Gdi::{
            HBITMAP,
            DIB_RGB_COLORS,
            SetDIBits,
            RGBQUAD,
            BITMAPINFO,
            BITMAPINFOHEADER,
            CreateDIBSection,
            BITMAPFILEHEADER
        },
        Foundation::{
            E_INVALIDARG,
            E_FAIL,
            HANDLE,
            TRUE,
            FALSE,
            GetLastError,
            ERROR_INSUFFICIENT_BUFFER, E_OUTOFMEMORY,
        },
        Security::{Authentication::Identity::{
            KERB_INTERACTIVE_UNLOCK_LOGON,
            KERB_INTERACTIVE_LOGON,
            KerbWorkstationUnlockLogon,
            KerbInteractiveLogon,
            KERB_LOGON_SUBMIT_TYPE,
            LsaConnectUntrusted,
            NEGOSSP_NAME_A,
            LsaLookupAuthenticationPackage,
            LsaDeregisterLogonProcess
        },
        Credentials::{
            CredProtectW,
            CredIsProtectedW,
            CRED_PROTECTION_TYPE,
            CredUnprotected
        }},
        System::Com::{
            CoTaskMemAlloc,
            CoTaskMemFree
        },
    },
    core::{
        PWSTR,
        GUID,
        Result,
        PSTR
    },
    };

mod strings;
pub use crate::strings::Rswstr;

use log::LevelFilter;
pub use log::{warn, info, error};

fn logger_file_setup(folder: &str) -> std::io::Result<()> {
    let contents = std::fs::read_dir(folder)?;
    let file = format!("{folder}\\{:04}.log", contents.count());
    simple_logging::log_to_file(file, LevelFilter::Info)
}

pub fn logger_setup(folder: &str) {
    if let Err(e) = logger_file_setup(folder) {
        simple_logging::log_to_stderr(LevelFilter::Info);
        warn!("File failed: {e}");
    }
}
pub enum RemoteFieldID {
    TileImage = 0,
    Label = 1,
    LargeText = 2,
    Password = 3,
    SubmitButton = 4,
    NumFields = 5
}

pub struct FieldStatePair {
    pub cpfs: CREDENTIAL_PROVIDER_FIELD_STATE,
    pub cpfis: CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE
}

pub const FIELD_STATE_PAIRS: [FieldStatePair; RemoteFieldID::NumFields as usize] = [
    FieldStatePair { cpfs: CPFS_DISPLAY_IN_BOTH, cpfis: CPFIS_NONE}, // TileImage
    FieldStatePair { cpfs: CPFS_HIDDEN, cpfis: CPFIS_NONE}, // Label
    FieldStatePair { cpfs: CPFS_DISPLAY_IN_BOTH, cpfis: CPFIS_NONE}, // LargeText
    FieldStatePair { cpfs: CPFS_DISPLAY_IN_SELECTED_TILE, cpfis: CPFIS_FOCUSED}, // Password
    FieldStatePair { cpfs: CPFS_DISPLAY_IN_SELECTED_TILE, cpfis: CPFIS_NONE}, //SubmitButton
];

pub static CP_FIELD_DESCRIPTORS: [CPFieldDescriptor; RemoteFieldID::NumFields as usize] =
    [
        CPFieldDescriptor {
            field_id: RemoteFieldID::TileImage as u32,
            cpft: CPFT_TILE_IMAGE,
            label: "Image",
            guid_field_type: CPFG_CREDENTIAL_PROVIDER_LOGO
        },
        CPFieldDescriptor {
            field_id: RemoteFieldID::Label as u32,
            cpft: CPFT_SMALL_TEXT,
            label: "Tooltip",
            guid_field_type: CPFG_CREDENTIAL_PROVIDER_LABEL
        },
        CPFieldDescriptor {
            field_id: RemoteFieldID::LargeText as u32,
            cpft: CPFT_LARGE_TEXT,
            label: "LargeText",
            guid_field_type: GUID::from_u128(0)
        },
        CPFieldDescriptor {
            field_id: RemoteFieldID::Password as u32,
            cpft: CPFT_PASSWORD_TEXT,
            label: "Password text",
            guid_field_type: GUID::from_u128(0)
        },
        CPFieldDescriptor {
            field_id: RemoteFieldID::SubmitButton as u32,
            cpft: CPFT_SUBMIT_BUTTON,
            label: "Submit",
            guid_field_type: GUID::from_u128(0)
        }
    ];

pub struct CPFieldDescriptor {
    pub field_id: u32,
    pub cpft: CREDENTIAL_PROVIDER_FIELD_TYPE,
    pub label: &'static str,
    pub guid_field_type: GUID
}

impl CPFieldDescriptor {
    pub unsafe fn to_cpfd(&self) -> Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        let s = Rswstr::clone_from_str(self.label)?;
        let ptr = CoTaskMemAlloc(std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>()).cast::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>();
        if ptr.is_null(){
            return Err(E_OUTOFMEMORY.into())
        }
        addr_of_mut!((*ptr).dwFieldID).write(self.field_id);
        addr_of_mut!((*ptr).cpft).write(self.cpft);
        addr_of_mut!((*ptr).guidFieldType).write(self.guid_field_type);
        addr_of_mut!((*ptr).pszLabel).write(s.to_pwstr());
        Ok(ptr)
    }
}

const BMPFHSZ: usize = std::mem::size_of::<BITMAPFILEHEADER>();
const BMPIHSZ: usize = std::mem::size_of::<BITMAPINFOHEADER>();
const RGBQSZ: usize = std::mem::size_of::<RGBQUAD>();
const TILE_IMAGE: &[u8; 49206] = include_bytes!("./tileimage.bmp");

// Siginificant help from
// https://github.com/rust-windowing/winit-blit/blob/master/src/platform_impl/windows/mod.rs
// https://stackoverflow.com/questions/2886831/win32-c-c-load-image-from-memory-buffer
// https://stackoverflow.com/questions/67765151/my-windows-rs-script-doesnt-render-bitmap-or-doesnt-create-one-but-doesnt-c
pub fn get_tile_image() -> Result<HBITMAP> {
    unsafe {
        let bmpfh = std::mem::transmute_copy::<[u8; BMPFHSZ], BITMAPFILEHEADER>(TILE_IMAGE[0..BMPFHSZ].try_into().map_err(|_| E_INVALIDARG)?);
        let bmpih = std::mem::transmute_copy::<[u8; BMPIHSZ], BITMAPINFOHEADER>(TILE_IMAGE[BMPFHSZ..BMPFHSZ+BMPIHSZ].try_into().map_err(|_| E_INVALIDARG)?);
        let rgb = std::mem::transmute_copy::<[u8;RGBQSZ], RGBQUAD>(TILE_IMAGE[BMPFHSZ+BMPIHSZ..BMPFHSZ+BMPIHSZ+RGBQSZ].try_into().map_err(|_| E_INVALIDARG)?);
        let bmpi = BITMAPINFO {
            bmiColors: [rgb],
            bmiHeader: bmpih
        };
        let tile = &TILE_IMAGE[bmpfh.bfOffBits as usize..] as *const _ as *const c_void;
        let dib_section = CreateDIBSection(None, &bmpi, DIB_RGB_COLORS, ptr::null_mut(), None, 0)?;
        SetDIBits(None, dib_section, 0, bmpih.biHeight as u32, tile, &bmpi, DIB_RGB_COLORS);
        Ok(dib_section)
    }
}

//
// Initialize the members of a KERB_INTERACTIVE_UNLOCK_LOGON with weak references to the
// passed-in strings.  This is useful if you will later use KerbInteractiveUnlockLogonPack
// to serialize the structure.
//
// The password is stored in encrypted form for CPUS_LOGON and CPUS_UNLOCK_WORKSTATION
// because the system can accept encrypted credentials.  It is not encrypted in CPUS_CREDUI
// because we cannot know whether our caller can accept encrypted credentials.
//
pub fn kerb_interactive_unlock_logon_init(
    domain: Rswstr,
    username: Rswstr,
    password: Rswstr,
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO
) -> Result<KERB_INTERACTIVE_UNLOCK_LOGON> {
    let message_type = match cpus {
        CPUS_UNLOCK_WORKSTATION => KerbWorkstationUnlockLogon,
        CPUS_LOGON => KerbInteractiveLogon,
        // CREDUI has no message type
        CPUS_CREDUI => KERB_LOGON_SUBMIT_TYPE(0),
        _ => {return Err(E_FAIL.into())}
    };
    unsafe {
        Ok(KERB_INTERACTIVE_UNLOCK_LOGON {
            Logon: KERB_INTERACTIVE_LOGON {
                LogonDomainName: domain.to_unicode_string(),
                UserName: username.to_unicode_string(),
                Password: password.to_unicode_string(),
                MessageType: message_type
            },
            LogonId: windows::Win32::Foundation::LUID { LowPart: 0, HighPart: 0 }
        })
    }
}

//
// WinLogon and LSA consume "packed" KERB_INTERACTIVE_UNLOCK_LOGONs.  In these, the PWSTR members of each
// UNICODE_STRING are not actually pointers but byte offsets into the overall buffer represented
// by the packed KERB_INTERACTIVE_UNLOCK_LOGON.  For example:
//
// rkiulIn.Logon.LogonDomainName.Length = 14                                    -> Length is in bytes, not characters
// rkiulIn.Logon.LogonDomainName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) -> LogonDomainName begins immediately
//                                                                              after the KERB_... struct in the buffer
// rkiulIn.Logon.UserName.Length = 10
// rkiulIn.Logon.UserName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14   -> UNICODE_STRINGS are NOT null-terminated
//
// rkiulIn.Logon.Password.Length = 16
// rkiulIn.Logon.Password.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14 + 10
//
// THere's more information on this at:
// http://msdn.microsoft.com/msdnmag/issues/05/06/SecurityBriefs/#void
//
pub unsafe fn kerb_interactive_unlock_logon_pack(
    mut kiul: KERB_INTERACTIVE_UNLOCK_LOGON
) -> Result<CoAllocSlice<u8>> {
    // Allocate a buffer large enough to hold a
    // KERB_INTERACTIVE_UNLOCK_LOGON plus all strings
    const KIUL_SIZE: usize = std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>();
    let size = KIUL_SIZE +
                     kiul.Logon.LogonDomainName.Length as usize + 
                     kiul.Logon.UserName.Length as usize + 
                     kiul.Logon.Password.Length as usize;
    let mut buffer = CoAllocSlice::new(size)?;

    // Copy each string into the buffer leaving space at the start for KIUL
    let mut start;
    let mut end = KIUL_SIZE;
    for string in [kiul.Logon.LogonDomainName, kiul.Logon.UserName, kiul.Logon.Password] {
        info!("packing string: {}", string.Buffer.display());
        let len = string.Length as usize;
        (start, end) = (end, end + len);
        let bytes = std::slice::from_raw_parts(string.Buffer.0 as *mut u8, len);
        buffer[start..end].copy_from_slice(bytes);
        kiul.Logon.LogonDomainName.Buffer = PWSTR(start as *mut u16);
    }
    // Copy KIUL into the buffer
    buffer[..KIUL_SIZE].copy_from_slice(&std::mem::transmute::<KERB_INTERACTIVE_UNLOCK_LOGON, [u8; KIUL_SIZE]>(kiul));
    info!("copied kiul");
    Ok(buffer)
}

pub unsafe fn kerb_interactive_unlock_logon_unpack_in_place(mut packed: &[u8]) -> Result<()> {
    const KIUL_SIZE: usize = std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>();
    let mut kiul = std::mem::transmute::<&mut [u8; KIUL_SIZE], &mut KERB_INTERACTIVE_UNLOCK_LOGON>
        (&mut packed[..KIUL_SIZE].try_into().map_err(|_| E_INVALIDARG)?);
    let packed_ptr = std::ptr::addr_of_mut!(packed) as *mut u16;
    if (kiul.Logon.LogonDomainName.Buffer.0 as usize + kiul.Logon.LogonDomainName.MaximumLength as usize) <= packed.len() &&
       (kiul.Logon.UserName.Buffer.0 as usize + kiul.Logon.UserName.MaximumLength as usize) <= packed.len() &&
       (kiul.Logon.Password.Buffer.0 as usize + kiul.Logon.Password.MaximumLength as usize) <= packed.len() {
        kiul.Logon.LogonDomainName.Buffer = PWSTR(packed_ptr.offset(kiul.Logon.LogonDomainName.Buffer.0 as isize));
        kiul.Logon.UserName.Buffer = PWSTR(packed_ptr.offset(kiul.Logon.UserName.Buffer.0 as isize));
        kiul.Logon.Password.Buffer = PWSTR(packed_ptr.offset(kiul.Logon.Password.Buffer.0 as isize));
        Ok(())
    } else {
        Err(E_INVALIDARG.into())
    }
}

pub fn get_negotiate_auth_package() -> Result<u32> {
    let mut hlsa = HANDLE::default();
    let mut auth_package = 0u32;
    unsafe {
        let lsa_name = NEGOSSP_NAME_A;
        let lsa_name_len = lsa_name.as_bytes().len() as u16;
        let lsa_string = windows::Win32::System::Kernel::STRING {
            Length: lsa_name_len,
            MaximumLength: lsa_name_len + 1,
            Buffer: PSTR(lsa_name.as_ptr() as *mut u8)
        };
        LsaConnectUntrusted(std::ptr::addr_of_mut!(hlsa))?;
        LsaLookupAuthenticationPackage(
            hlsa,
            std::ptr::addr_of!(lsa_string),
            std::ptr::addr_of_mut!(auth_package)
        )?;
        LsaDeregisterLogonProcess(hlsa)?;
        Ok(auth_package)
    }
}

pub fn protect_string(to_protect: &Rswstr) -> Result<Rswstr> {
    unsafe {
        // Call CredProtect to determine the lenght of the encrypted string
        // CredProtect might require the null terminator which as_wide leaves out but
        // that might just be an artifact of C++ code that &[u16] doesn't need
        let mut protected_len = 0u32;
        CredProtectW(
            FALSE,
            &to_protect.as_wide_with_terminator(),
            PWSTR(std::ptr::null_mut()),
            std::ptr::addr_of_mut!(protected_len),
            None
        );
        
        let res;
        let last_err = GetLastError();
        if last_err != ERROR_INSUFFICIENT_BUFFER || protected_len <= 0 {
            res = Err(last_err.to_hresult().into())
        } else {
            let buffer = Rswstr::with_length(protected_len as usize)?;
            if TRUE == CredProtectW(
                FALSE,
                &to_protect.as_wide_with_terminator(),
                buffer.as_pwstr(),
                std::ptr::addr_of_mut!(protected_len),
                None
            ) {
                res = Ok(buffer);
            } else {
                res = Err(GetLastError().to_hresult().into());
            }
        }
        res
    }
}

pub fn protect_password_if_necessary(
    password: &Rswstr,
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO
) -> Result<Rswstr> {
    unsafe {
        if password.str_len() == 0 {
            return Ok(password.clone());
        }
        let mut already_protected = false;
        let mut protection_type = CRED_PROTECTION_TYPE(0);
        if CredIsProtectedW(
            password.as_pcwstr(),
            std::ptr::addr_of_mut!(protection_type)
        ) == TRUE {
            if CredUnprotected != protection_type {
                already_protected = true;
            }
        }
        
        if CPUS_CREDUI == cpus || already_protected {
            return Ok(password.clone())
        }

        protect_string(password)
    }
}
pub struct DomainUsername {
    pub domain: Rswstr,
    pub username: Rswstr
}

pub unsafe fn split_domain_and_username(qualified_user_name: &Rswstr) -> Result<DomainUsername> {
    if let Some((domain, username)) = qualified_user_name.copy_as_string()?.split_once("\\") {
        Ok(DomainUsername{
            domain: Rswstr::clone_from_str(domain)?,
            username: Rswstr::clone_from_str(username)?
        })
    } else {
        Ok(DomainUsername {
            domain: Rswstr::clone_from_str("")?,
            username: qualified_user_name.clone()
        })
    }
}

pub struct CoAllocSlice<T> {
    ptr: *mut T,
    size: usize,
}

impl<T> CoAllocSlice<T> {
    pub fn new(size: usize) -> Result<Self> {
        let alloc = unsafe { CoTaskMemAlloc(size) as *mut T };
        if alloc.is_null() {
            Err(E_OUTOFMEMORY.into())
        } else {
            Ok(Self {
                ptr: alloc,
                size,
            })
        }
    }
    
    pub unsafe fn get_ptr(&self) -> *mut T {
        self.ptr
    }
    
    pub fn get_size(&self) -> usize {
        self.size
    }
}

impl<T> Deref for CoAllocSlice<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size)}
    }
}

impl<T> DerefMut for CoAllocSlice<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size)}
    }
}

impl<T> Drop for CoAllocSlice<T> {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(Some(self.ptr as *mut c_void)) }
    }
}