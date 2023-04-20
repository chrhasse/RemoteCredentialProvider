use std::{cell::RefCell, mem::ManuallyDrop, ptr::addr_of_mut};
use core::option::Option;

use helpers::*;

use windows::{
    core::{
        implement,
        Result,
        PWSTR,
        PCWSTR,
        ComInterface
    },
    Win32::{
        UI::Shell::{
            ICredentialProviderCredential,
            ICredentialProviderCredential_Impl,
            ICredentialProviderCredential2,
            ICredentialProviderCredential2_Impl,
            ICredentialProviderCredentialWithFieldOptions,
            ICredentialProviderCredentialWithFieldOptions_Impl,
            CREDENTIAL_PROVIDER_USAGE_SCENARIO,
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
            CPFT_PASSWORD_TEXT,
            ICredentialProviderCredentialEvents,
            ICredentialProviderCredentialEvents2,
            CREDENTIAL_PROVIDER_FIELD_STATE,
            CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
            CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
            CREDENTIAL_PROVIDER_STATUS_ICON,
            CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS,
            ICredentialProviderUser,
            Identity_LocalUserProvider,
            CPFT_EDIT_TEXT,
            CPCFO_ENABLE_PASSWORD_REVEAL,
            CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE,
            CPCFO_NONE,
            CPGSR_NO_CREDENTIAL_NOT_FINISHED,
            CPSI_NONE,
            CPGSR_RETURN_CREDENTIAL_FINISHED,
            CPSI_WARNING,
            CPSI_ERROR,
        },
        Foundation::{
            E_NOTIMPL,
            E_FAIL,
            BOOL,
            E_INVALIDARG,
            NTSTATUS,
            FALSE,
            GetLastError,
            ERROR_INSUFFICIENT_BUFFER,
            STATUS_SUCCESS,
            STATUS_INVALID_PARAMETER
        },
        Graphics::Gdi::{
            HBITMAP,
        },
        Storage::EnhancedStorage::PKEY_Identity_QualifiedUserName,
        Security::Credentials::{CRED_PACK_PROTECTED_CREDENTIALS,
        CRED_PACK_ID_PROVIDER_CREDENTIALS,
        CredPackAuthenticationBufferW,
        STATUS_LOGON_FAILURE,
        STATUS_ACCOUNT_RESTRICTION,
        STATUS_ACCOUNT_DISABLED},
    },
    w
};

#[implement(ICredentialProviderCredential, ICredentialProviderCredential2, ICredentialProviderCredentialWithFieldOptions)]
pub struct RemoteCredential {
    _cpus: RefCell<CREDENTIAL_PROVIDER_USAGE_SCENARIO>,
    _cred_prov_cred_events: RefCell<Option<ICredentialProviderCredentialEvents2>>,
    _user_sid: RefCell<Rswstr>,
    _qualified_user_name: RefCell<Rswstr>,
    _is_local_user: RefCell<bool>,
    _field_strings: RefCell<[Rswstr; RemoteFieldID::NumFields as usize]>,
}

impl RemoteCredential {
    pub fn new(
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        user: ICredentialProviderUser,
        password: PCWSTR
    ) -> Result<ICredentialProviderCredential2> {
        info!("RemoteCredential::new");
        crate::dll_add_ref();
        unsafe {
            let is_local = user.GetProviderID()? == Identity_LocalUserProvider;
            info!("got local");
            let user_sid = Rswstr::from(user.GetSid()?);
            info!("got sid");
            let qualified_user_name = Rswstr::from(user.GetStringValue(&PKEY_Identity_QualifiedUserName)?);
            info!("got username");
            let field_strings = [
                    Rswstr::clone_from_str("")?, // TileImage
                    Rswstr::clone_from_str("Auto Login")?, // Label
                    Rswstr::clone_from_str("Auto Login")?, // LargeText
                    Rswstr::clone_from_pcwstr(password)?, // Password
                    Rswstr::clone_from_str("Submit")?, // SubmitButton
                ];
            info!("got field_strings");
            let cred = RemoteCredential {
                _cpus: RefCell::new(cpus),
                _cred_prov_cred_events: RefCell::new(None),
                _user_sid: RefCell::new(user_sid),
                _qualified_user_name: RefCell::new(qualified_user_name),
                _is_local_user: RefCell::new(is_local),
                _field_strings: RefCell::new(field_strings),
                
            };
            info!("got cred");
            Ok(cred.into())
        }
    }
}

impl ICredentialProviderCredential_Impl for RemoteCredential {
    fn Advise(
        &self,
        pcpce: Option<&ICredentialProviderCredentialEvents>
    ) ->  Result<()> {
        info!("RemoteCredential::Advise");
        if let Some(events) = pcpce {
            *self._cred_prov_cred_events.borrow_mut() = Some(events.cast()?);
        } else {
            *self._cred_prov_cred_events.borrow_mut() = None;
        }
        Ok(())
    }

    fn UnAdvise(&self) ->  Result<()> {
        info!("RemoteCredential::UnAdvise");
        *self._cred_prov_cred_events.borrow_mut() = None;
        Ok(())
    }

    fn SetSelected(&self) ->  Result<BOOL> {
        info!("RemoteCredential::SetSelected");
        Ok(FALSE)
    }

    fn SetDeselected(&self) ->  Result<()> {
        info!("RemoteCredential::SetDeselected");
        (*self._field_strings.borrow_mut())[RemoteFieldID::Password as usize] = Rswstr::clone_from_str("")?;
        if let Some(ref cred_prov_events) = *self._cred_prov_cred_events.borrow() {
            unsafe {
                cred_prov_events.SetFieldString(
                    &self.cast::<ICredentialProviderCredential>()?,
                    RemoteFieldID::Password as u32,
                    w!(""))?;
            }
        }
        Ok(())
    }

    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE
    ) ->  Result<()> {
        info!("RemoteCredential::GetFieldState");
        if dwfieldid < RemoteFieldID::NumFields as u32 &&
        !pcpfs.is_null() &&
        !pcpfis.is_null() {
            unsafe {
                *pcpfs = FIELD_STATE_PAIRS[dwfieldid as usize].cpfs;
                *pcpfis = FIELD_STATE_PAIRS[dwfieldid as usize].cpfis;
            }
            Ok(())
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn GetStringValue(&self, dwfieldid: u32) ->  Result<PWSTR> {
        info!("RemoteCredential::GetStringValue");
        if dwfieldid < RemoteFieldID::NumFields as u32 {
            unsafe {
                let string = (*self._field_strings.borrow())[dwfieldid as usize].clone();
                info!("Value: {string}");
                Ok(string.to_pwstr())
            }
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn GetBitmapValue(&self, dwfieldid: u32) ->  Result<HBITMAP> {
        info!("RemoteCredential::GetBitmapValue");
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
        info!("RemoteCredential::GetCheckboxValue");
        Err(E_NOTIMPL.into())
    }

    fn GetSubmitButtonValue(&self, dwfieldid: u32) ->  Result<u32> {
        info!("RemoteCredential::GetSubmitButtonValue");
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
        info!("RemoteCredential::GetComboBoxValueCount");
        Err(E_NOTIMPL.into())
    }

    fn GetComboBoxValueAt(
        &self,
        _dwfieldid: u32,
        _dwitem:u32
    ) ->  Result<PWSTR> {
        info!("RemoteCredential::GetComboBoxValueAt");
        Err(E_NOTIMPL.into())
    }

    fn SetStringValue(
        &self,
        dwfieldid: u32,
        psz: &PCWSTR
    ) ->  Result<()> {
        info!("RemoteCredential::SetStringValue");
        if dwfieldid < RemoteFieldID::NumFields as u32 &&
            (CP_FIELD_DESCRIPTORS[dwfieldid as usize].cpft == CPFT_PASSWORD_TEXT ||
             CP_FIELD_DESCRIPTORS[dwfieldid as usize].cpft == CPFT_EDIT_TEXT) {
                unsafe {
                    let owned_str = Rswstr::clone_from_pcwstr(*psz)?;
                    (*self._field_strings.borrow_mut())[dwfieldid as usize] = owned_str;
                }
                Ok(())
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn SetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _bchecked: BOOL) ->  Result<()> {
        info!("RemoteCredential::SetCheckboxValue");
        Err(E_NOTIMPL.into())
    }

    fn SetComboBoxSelectedValue(
        &self,
        _dwfieldid: u32,
        _dwselecteditem: u32
    ) ->  Result<()> {
        info!("RemoteCredential::SetComboBoxSelectedValue");
        Err(E_NOTIMPL.into())
    }

    fn CommandLinkClicked(
        &self,
        _dwfieldid: u32
    ) ->  Result<()> {
        info!("RemoteCredential::CommandLinkClicked");
        Err(E_NOTIMPL.into())
    }

    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        ppszoptionalstatustext: *mut PWSTR,
        pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON
    ) ->  Result<()> {
        info!("RemoteCredential::GetSerialization");
        unsafe {
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            *ppszoptionalstatustext = PWSTR(std::ptr::null_mut());
            *pcpsioptionalstatusicon = CPSI_NONE;
            pcpcs.write_bytes(0_u8, 1);
            if *self._is_local_user.borrow() {
                info!("is local");
                let encrypted_password = protect_password_if_necessary(
                    &self._field_strings.borrow()[RemoteFieldID::Password as usize],
                    *self._cpus.borrow()
                )?;
                info!("got encrypted password");
                let user_domain = split_domain_and_username(&self._qualified_user_name.borrow())?;
                let kiul = kerb_interactive_unlock_logon_init(
                    user_domain.domain,
                    user_domain.username,
                    encrypted_password,
                    *self._cpus.borrow()
                )?;
                info!("created kiul");
                let packed = ManuallyDrop::new(kerb_interactive_unlock_logon_pack(kiul)?);
                info!("packed kiul");
                (*pcpcs).rgbSerialization = packed.get_ptr();
                (*pcpcs).cbSerialization = packed.get_size() as u32;
                (*pcpcs).ulAuthenticationPackage = get_negotiate_auth_package()?;
                (*pcpcs).clsidCredentialProvider = crate::CLSID_CP_DEMO;
                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                info!("serialized");
                Ok(())
            } else {
                info!("remote");
                let auth_flags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;
                if !CredPackAuthenticationBufferW(
                    auth_flags,
                    self._qualified_user_name.borrow().as_pcwstr(),
                    self._field_strings.borrow()[RemoteFieldID::Password as usize].as_pcwstr(),
                    None,
                    addr_of_mut!((*pcpcs).cbSerialization)
                ).as_bool() && GetLastError() == ERROR_INSUFFICIENT_BUFFER {
                    info!("got cred pack size");
                    let serialization = CoAllocSlice::new((*pcpcs).cbSerialization as usize)?;
                    if CredPackAuthenticationBufferW(
                        auth_flags,
                        self._qualified_user_name.borrow().as_pcwstr(),
                        self._field_strings.borrow()[RemoteFieldID::Password as usize].as_pcwstr(),
                        Some(serialization.get_ptr()),
                        addr_of_mut!((*pcpcs).cbSerialization)
                    ).as_bool() {
                        info!("got cred pack");
                        (*pcpcs).ulAuthenticationPackage = get_negotiate_auth_package()?;
                        (*pcpcs).clsidCredentialProvider = crate::CLSID_CP_DEMO;
                        (*pcpcs).rgbSerialization = ManuallyDrop::new(serialization).get_ptr();
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        info!("got serialization");
                        return Ok(())
                    }
                }
                Err(E_FAIL.into())
            }
        }

    }

    fn ReportResult(
        &self,
        ntsstatus:NTSTATUS,
        ntssubstatus:NTSTATUS,
        ppszoptionalstatustext: *mut PWSTR,
        pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON
    ) ->  Result<()> {
        info!("RemoteCredential::ReportResult");
        unsafe {
            *ppszoptionalstatustext = PWSTR(std::ptr::null_mut());
            *pcpsioptionalstatusicon = CPSI_NONE;
            let (status_info, status_icon) = match (ntsstatus, ntssubstatus) {
                (STATUS_LOGON_FAILURE, STATUS_SUCCESS) => ("Incorrect password or username.", CPSI_ERROR),
                (STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED) => ("The account is disabled.", CPSI_WARNING),
                (STATUS_INVALID_PARAMETER, STATUS_SUCCESS) => ("Must log in with password at least once after reboot", CPSI_ERROR),
                _ => ("Unknown Error", CPSI_ERROR)
            };
            *ppszoptionalstatustext = Rswstr::clone_from_str(status_info)?.to_pwstr();
            *pcpsioptionalstatusicon = status_icon;
            if ntsstatus.is_err() {
                (*self._cred_prov_cred_events.borrow()).as_ref().and_then(|e| {
                    e.SetFieldString(&self.cast::<ICredentialProviderCredential>().unwrap(), RemoteFieldID::Password as u32, w!("")).ok()
                });
            }
        }
        Ok(())
    }
}

impl ICredentialProviderCredential2_Impl for RemoteCredential {
    fn GetUserSid(&self) ->  Result<PWSTR> {
        info!("RemoteCredential::GetUserSid");
        unsafe {Ok(self._user_sid.borrow().clone().to_pwstr())}
    }
}

impl ICredentialProviderCredentialWithFieldOptions_Impl for RemoteCredential {
    fn GetFieldOptions(&self, fieldid: u32) ->  Result<CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS> {
        info!("RemoteCredential::GetFieldOptions");
        let mut cpcfo = CPCFO_NONE;
        if fieldid == RemoteFieldID::Password as u32 {
            cpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
        } else if fieldid == RemoteFieldID::TileImage as u32 {
            cpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
        }
        Ok(cpcfo)
    }
}

impl Drop for RemoteCredential {
    fn drop(&mut self) {
        info!("RemoteCredential::drop");
        crate::dll_release();
    }
}

