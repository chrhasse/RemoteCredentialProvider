use std::{ptr, ffi::c_void, time::SystemTime};

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
            CPFIS_FOCUSED, CREDENTIAL_PROVIDER_USAGE_SCENARIO, CPUS_UNLOCK_WORKSTATION, CPUS_LOGON, CPUS_CREDUI
        },
        Graphics::Gdi::{
            HBITMAP,
            DIB_RGB_COLORS,
            SetDIBits,
            ReleaseDC,
            RGBQUAD,
            BITMAPINFO,
            BITMAPINFOHEADER,
            CreateDIBSection,
            GetDC,
            BI_RGB,
            CreateCompatibleDC,
            SelectObject,
            DeleteDC,
            DeleteObject,
            BitBlt,
            SRCCOPY, BITMAPFILEHEADER
        }, Foundation::{E_INVALIDARG, E_NOTIMPL, UNICODE_STRING, E_FAIL, HANDLE}, Security::Authentication::Identity::{KERB_INTERACTIVE_UNLOCK_LOGON, KERB_INTERACTIVE_LOGON, KerbWorkstationUnlockLogon, KerbInteractiveLogon, KERB_LOGON_SUBMIT_TYPE, LsaConnectUntrusted, NEGOSSP_NAME_A, LsaLookupAuthenticationPackage, LsaDeregisterLogonProcess}},
        core::{PWSTR, GUID, Result, PCWSTR, PSTR},
        w
    };

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

pub const FieldStatePairs: [FieldStatePair; RemoteFieldID::NumFields as usize] = [
    FieldStatePair { cpfs: CPFS_DISPLAY_IN_BOTH, cpfis: CPFIS_NONE}, // TileImage
    FieldStatePair { cpfs: CPFS_HIDDEN, cpfis: CPFIS_NONE}, // Label
    FieldStatePair { cpfs: CPFS_DISPLAY_IN_BOTH, cpfis: CPFIS_NONE}, // LargeText
    FieldStatePair { cpfs: CPFS_DISPLAY_IN_SELECTED_TILE, cpfis: CPFIS_FOCUSED}, // Password
    FieldStatePair { cpfs: CPFS_DISPLAY_IN_SELECTED_TILE, cpfis: CPFIS_NONE}, //SubmitButton
];

pub fn get_credential_provider_field_descriptors() ->
[CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR; RemoteFieldID::NumFields as usize] {
    [
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
            dwFieldID: RemoteFieldID::TileImage as u32,
            cpft: CPFT_TILE_IMAGE,
            pszLabel: PWSTR(w!("Image").as_ptr() as *mut u16),
            guidFieldType: CPFG_CREDENTIAL_PROVIDER_LOGO
        },
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
            dwFieldID: RemoteFieldID::Label as u32,
            cpft: CPFT_SMALL_TEXT,
            pszLabel: PWSTR(w!("Tooltip").as_ptr() as *mut u16),
            guidFieldType: CPFG_CREDENTIAL_PROVIDER_LABEL
        },
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
            dwFieldID: RemoteFieldID::LargeText as u32,
            cpft: CPFT_LARGE_TEXT,
            pszLabel: PWSTR(w!("LargeText").as_ptr() as *mut u16),
            guidFieldType: GUID::from_u128(0)
        },
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
            dwFieldID: RemoteFieldID::Password as u32,
            cpft: CPFT_PASSWORD_TEXT,
            pszLabel: PWSTR(w!("Password text").as_ptr() as *mut u16),
            guidFieldType: GUID::from_u128(0)
        },
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
            dwFieldID: RemoteFieldID::SubmitButton as u32,
            cpft: CPFT_SUBMIT_BUTTON,
            pszLabel: PWSTR(w!("Submit").as_ptr() as *mut u16),
            guidFieldType: GUID::from_u128(0)
        }
    ]
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

trait PwstrHelpers {
    fn to_unicode_string(self) -> UNICODE_STRING;
    fn len(&self) -> usize;
    fn to_pcwstr(self) -> PCWSTR;
    fn as_bytes(&self) -> &[u8];
}

impl PwstrHelpers for PWSTR {
    fn to_unicode_string(self) -> UNICODE_STRING {
        let size = (self.len() * std::mem::size_of::<u16>()) as u16;
        UNICODE_STRING { Length: size, MaximumLength: size, Buffer: self }
    }
    
    fn len(&self) -> usize {
        unsafe {
            (0..).take_while(|&i| *(self.0).offset(i) != 0).count()
        }
    }
    
    fn to_pcwstr(self) -> PCWSTR {
        PCWSTR(self.as_ptr() as *const u16)
    }
    
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::mem::transmute::<&[u16], &[u8]>(self.as_wide())
        }
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
    domain: PWSTR,
    username: PWSTR,
    password: PWSTR,
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO
) -> Result<KERB_INTERACTIVE_UNLOCK_LOGON> {
    let message_type = match cpus {
        CPUS_UNLOCK_WORKSTATION => KerbWorkstationUnlockLogon,
        CPUS_LOGON => KerbInteractiveLogon,
        // CREDUI has no message type
        CPUS_CREDUI => KERB_LOGON_SUBMIT_TYPE(0),
        _ => {return Err(E_FAIL.into())}
    };
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
    unpacked: KERB_INTERACTIVE_UNLOCK_LOGON
) -> Result<Vec<u8>> {
    // Allocate a buffer large enough to hold a
    // KERB_INTERACTIVE_UNLOCK_LOGON plus all strings
    let size = std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>() +
                     unpacked.Logon.LogonDomainName.Length as usize + 
                     unpacked.Logon.UserName.Length as usize + 
                     unpacked.Logon.Password.Length as usize;
    let mut buffer = vec![0_u8; size];

    let mut kiul = unpacked.clone();
    const KIUL_SIZE: usize = std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>();


    // Copy each string into the buffer leaving space at the start for KIUL
    let (mut start, mut end) = (KIUL_SIZE, KIUL_SIZE + kiul.Logon.LogonDomainName.Length as usize);
    kiul.Logon.LogonDomainName.Buffer = PWSTR(start as *mut u16);
    buffer[start..end].copy_from_slice(kiul.Logon.LogonDomainName.Buffer.as_bytes());

    (start, end) = (end, end + kiul.Logon.UserName.Length as usize);
    kiul.Logon.UserName.Buffer = PWSTR(start as *mut u16);
    buffer[start..end].copy_from_slice(kiul.Logon.UserName.Buffer.as_bytes());

    (start, end) = (end, end + kiul.Logon.Password.Length as usize);
    kiul.Logon.Password.Buffer = PWSTR(start as *mut u16);
    buffer[start..end].copy_from_slice(kiul.Logon.Password.Buffer.as_bytes());

    // Copy KIUL into the buffer
    buffer[..KIUL_SIZE].copy_from_slice(&std::mem::transmute::<KERB_INTERACTIVE_UNLOCK_LOGON, [u8; KIUL_SIZE]>(kiul));
    Ok(buffer)
}

pub fn get_negotiate_auth_package() -> Result<u32> {
    let mut hlsa = HANDLE::default();
    let mut auth_package = 0u32;
    unsafe {
        let lsa_name = NEGOSSP_NAME_A;
        let lsa_name_len = (0..).take_while(|&i| *(lsa_name.as_ptr().offset(i)) != 0).count();
        let lsa_string = windows::Win32::System::Kernel::STRING {
            Length: lsa_name_len as u16,
            MaximumLength: lsa_name_len as u16,
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