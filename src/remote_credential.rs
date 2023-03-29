use std::{cell::RefCell, ffi::c_void};
use core::option::Option;

use crate::helpers::*;

use windows::{
    core::{
        GUID,
        HRESULT,
        implement,
        Result,
        Interface,
        IUnknown,
        PWSTR,
        PCWSTR
    },
    Win32::{
        UI::Shell::{
            ICredentialProviderCredential,
            ICredentialProviderCredential_Impl,
            ICredentialProviderCredential2,
            ICredentialProviderCredential2_Impl,
            ICredentialProviderCredentialEvents2,
            ICredentialProviderCredentialWithFieldOptions,
            ICredentialProviderCredentialWithFieldOptions_Impl,
            CREDENTIAL_PROVIDER_USAGE_SCENARIO,
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
            CPUS_LOGON,
            CPUS_UNLOCK_WORKSTATION,
            CPFT_TILE_IMAGE,
            CPFG_CREDENTIAL_PROVIDER_LOGO,
            CPFT_SMALL_TEXT,
            CPFG_CREDENTIAL_PROVIDER_LABEL,
            CPFT_LARGE_TEXT,
            CPFT_PASSWORD_TEXT,
            CPFT_SUBMIT_BUTTON,
            ICredentialProviderCredentialEvents,
            CREDENTIAL_PROVIDER_FIELD_STATE,
            CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
            CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
            CREDENTIAL_PROVIDER_STATUS_ICON,
            CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS, ICredentialProviderUser, Identity_LocalUserProvider, SHStrDupW, CPFT_EDIT_TEXT, CPCFO_ENABLE_PASSWORD_REVEAL, CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE, CPCFO_NONE,
        },
        Foundation::{
            CLASS_E_CLASSNOTAVAILABLE,
            E_POINTER,
            S_OK,
            E_NOTIMPL,
            BOOL,
            E_INVALIDARG,
            CLASS_E_NOAGGREGATION,
            E_NOINTERFACE,
            S_FALSE,
            NTSTATUS, FALSE},
        Graphics::Gdi::{HBITMAP, CreateBitmap}, Storage::EnhancedStorage::PKEY_Identity_QualifiedUserName, System::Com::CoTaskMemFree
    },
    w
};

#[implement(ICredentialProviderCredential, ICredentialProviderCredential2, ICredentialProviderCredentialWithFieldOptions)]
pub struct RemoteCredential {
    _cpus: RefCell<CREDENTIAL_PROVIDER_USAGE_SCENARIO>,
    _ref: RefCell<i64>,
    _cred_prov_cred_events: RefCell<Option<ICredentialProviderCredentialEvents>>,
    _user_sid: RefCell<PWSTR>,
    _qualified_user_name: RefCell<PWSTR>,
    _is_local_user: RefCell<bool>,
    _field_strings: RefCell<[PCWSTR; RemoteFieldID::NumFields as usize]>,
}

impl RemoteCredential {
    pub fn new(
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        user: ICredentialProviderUser,
        password: PCWSTR
    ) -> Result<Self> {
        let guid_provider = unsafe { user.GetProviderID()? };
        Ok(RemoteCredential {
            _cpus: RefCell::new(cpus),
            _ref: RefCell::new(1),
            _cred_prov_cred_events: RefCell::new(None),
            _user_sid: RefCell::new(unsafe { user.GetSid()? }),
            _qualified_user_name: RefCell::new(
                unsafe { user.GetStringValue(&PKEY_Identity_QualifiedUserName)? }
            ),
            _is_local_user: RefCell::new(guid_provider == Identity_LocalUserProvider),
            _field_strings: RefCell::new([
                w!(""), // TileImage
                w!("Auto Login"), // Label
                w!("Auto Login"), // LargeText
                password, // Password
                w!("Submit"), // SubmitButton
            ]),
            
        })
    }
}

impl ICredentialProviderCredential_Impl for RemoteCredential {
    fn Advise(
        &self,
        pcpce: Option<&ICredentialProviderCredentialEvents>
    ) ->  Result<()> {
        *self._cred_prov_cred_events.borrow_mut() = pcpce.map(|x| x.clone());
        Ok(())
    }

    fn UnAdvise(&self) ->  Result<()> {
        *self._cred_prov_cred_events.borrow_mut() = None;
        Ok(())
    }

    fn SetSelected(&self) ->  Result<BOOL> {
        Ok(FALSE)
    }

    fn SetDeselected(&self) ->  Result<()> {
        (*self._field_strings.borrow_mut())[RemoteFieldID::Password as usize] = w!("");
        if let Some(cred_prov_events) = self._cred_prov_cred_events.take() {
            unsafe {
                cred_prov_events.SetFieldString(
                    &self.cast::<ICredentialProviderCredential>()?,
                    RemoteFieldID::Password as u32,
                    w!(""))?;
            }
            *self._cred_prov_cred_events.borrow_mut() = Some(cred_prov_events);
        }
        Ok(())
    }

    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE
    ) ->  Result<()> {
        if dwfieldid < RemoteFieldID::NumFields as u32 &&
        !pcpfs.is_null() &&
        !pcpfis.is_null() {
            unsafe {
                *pcpfs = FieldStatePairs[dwfieldid as usize].cpfs;
                *pcpfis = FieldStatePairs[dwfieldid as usize].cpfis;
            }
            Ok(())
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn GetStringValue(&self, dwfieldid: u32) ->  Result<PWSTR> {
        if dwfieldid < RemoteFieldID::NumFields as u32 {
            unsafe {
                SHStrDupW((*self._field_strings.borrow())[dwfieldid as usize])
            }
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn GetBitmapValue(&self, dwfieldid: u32) ->  Result<HBITMAP> {
        if dwfieldid == RemoteFieldID::TileImage as u32 {
            get_tile_image()
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn GetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _pbchecked: *mut BOOL,
        _ppszlabel: *mut PWSTR
    ) ->  Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetSubmitButtonValue(&self, dwfieldid: u32) ->  Result<u32> {
        if dwfieldid == RemoteFieldID::SubmitButton as u32 {
            Ok(RemoteFieldID::Password as u32)
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn GetComboBoxValueCount(
        &self,
        _dwfieldid: u32,
        _pcitems: *mut u32,
        _pdwselecteditem: *mut u32
    ) ->  Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetComboBoxValueAt(
        &self,
        _dwfieldid: u32,
        _dwitem:u32
    ) ->  Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn SetStringValue(
        &self,
        dwfieldid: u32,
        psz: &PCWSTR
    ) ->  Result<()> {
        if dwfieldid < RemoteFieldID::NumFields as u32 &&
            (get_credential_provider_field_descriptors()[dwfieldid as usize].cpft == CPFT_PASSWORD_TEXT ||
             get_credential_provider_field_descriptors()[dwfieldid as usize].cpft == CPFT_EDIT_TEXT) {
                (*self._field_strings.borrow_mut())[dwfieldid as usize] = psz.clone();
                Ok(())
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn SetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _bchecked: BOOL) ->  Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn SetComboBoxSelectedValue(
        &self,
        _dwfieldid: u32,
        _dwselecteditem: u32
    ) ->  Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn CommandLinkClicked(
        &self,
        _dwfieldid: u32
    ) ->  Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        ppszoptionalstatustext: *mut PWSTR,
        pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON
    ) ->  Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn ReportResult(
        &self,
        ntsstatus:NTSTATUS,
        ntssubstatus:NTSTATUS,
        ppszoptionalstatustext: *mut PWSTR,
        pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON
    ) ->  Result<()> {
        Err(E_NOTIMPL.into())
    }
}

impl ICredentialProviderCredential2_Impl for RemoteCredential {
    fn GetUserSid(&self) ->  Result<PWSTR> {
        Ok(self._user_sid.borrow().clone())
    }
}

impl ICredentialProviderCredentialWithFieldOptions_Impl for RemoteCredential {
    fn GetFieldOptions(&self, fieldid: u32) ->  Result<CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS> {
        let mut cpcfo = CPCFO_NONE;
        if fieldid == RemoteFieldID::Password as u32 {
            cpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
        } else if fieldid == RemoteFieldID::TileImage as u32 {
            cpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
        }
        Ok(cpcfo)
    }
}


