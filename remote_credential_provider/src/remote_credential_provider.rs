use std::cell::RefCell;
use core::option::Option;

use helpers::*;

use windows::{
    core::{
        implement,
        Result, ComInterface,
    },
    Win32::{
        UI::Shell::{
            ICredentialProvider,
            ICredentialProviderSetUserArray,
            ICredentialProvider_Impl,
            ICredentialProviderSetUserArray_Impl,
            ICredentialProviderEvents,
            ICredentialProviderCredential,
            CREDENTIAL_PROVIDER_USAGE_SCENARIO,
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
            CPUS_LOGON,
            CPUS_UNLOCK_WORKSTATION,
            CPUS_CREDUI,
            CPUS_CHANGE_PASSWORD,
            ICredentialProviderUserArray,
        },
        Foundation::{
            E_NOTIMPL,
            BOOL,
            E_INVALIDARG, E_UNEXPECTED,
        },
    },
};


#[implement(ICredentialProvider, ICredentialProviderSetUserArray)]
pub struct Provider {
    _up_advise_context: RefCell<usize>,
    _cred_prov_events: RefCell<Option<ICredentialProviderEvents>>,
    _recreate_enumerated_credentials: RefCell<bool>,
    _cpus: RefCell<CREDENTIAL_PROVIDER_USAGE_SCENARIO>,
}

impl Provider {
    pub fn new() -> Self {
        crate::dll_add_ref();
        Self {
            _up_advise_context: RefCell::new(0),
            _cred_prov_events: RefCell::new(None),
            _recreate_enumerated_credentials: RefCell::new(false),
            _cpus: RefCell::new(CREDENTIAL_PROVIDER_USAGE_SCENARIO::default())
        }
    }
    
    pub fn notify_changed(&self) -> Result<()> {
        let res = Err(E_UNEXPECTED.into());
        if let Some(ref events) = *self._cred_prov_events.borrow() {
            unsafe {
                events.CredentialsChanged(*self._up_advise_context.borrow())?;
            }
        }
        res
    }
}

impl ICredentialProviderSetUserArray_Impl for Provider {
    fn SetUserArray(
        &self,
        _users: Option<&ICredentialProviderUserArray>
    ) ->  Result<()> {
        Err(E_NOTIMPL.into())
    }
}

impl ICredentialProvider_Impl for Provider {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> Result<()> {
        match cpus {
            CPUS_LOGON | CPUS_UNLOCK_WORKSTATION | CPUS_CREDUI => {
                *self._recreate_enumerated_credentials.borrow_mut() = true;
                *self._cpus.borrow_mut() = cpus;
                Ok(())
            },
            CPUS_CHANGE_PASSWORD => Err(E_NOTIMPL.into()),
            _ => Err(E_INVALIDARG.into())
        }
    }
    
    fn SetSerialization(
        &self,
        _pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }
    
    fn Advise(
        &self,
        pcpe: Option<&ICredentialProviderEvents>,
        upadvisecontext: usize,
    ) -> Result<()> {
        if let Some(p) = pcpe {
            *self._cred_prov_events.borrow_mut() = Some(p.cast()?);
        }
        *self._up_advise_context.borrow_mut() = upadvisecontext;
        Ok(())
    }

    fn UnAdvise(&self) -> Result<()> {
        self._cred_prov_events.borrow_mut().take();
        Ok(())
    }

    fn GetFieldDescriptorCount(&self) -> Result<u32> {
        Ok(RemoteFieldID::NumFields as u32)
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        if dwindex >= RemoteFieldID::NumFields as u32{
            Err(E_INVALIDARG.into())
        } else {
            unsafe {CP_FIELD_DESCRIPTORS[dwindex as usize].to_cpfd()}
        }
    }

    fn GetCredentialCount(
        &self,
        _pdwcount: *mut u32,
        _pdwdefault: *mut u32,
        _pbautologonwithdefault: *mut BOOL,
    ) -> Result<()> {
        if *self._recreate_enumerated_credentials.borrow() {
            *self._recreate_enumerated_credentials.borrow_mut() = false;
        }
        Err(E_NOTIMPL.into())
    }

    fn GetCredentialAt(
        &self,
        _dwindex: u32,
    ) -> Result<ICredentialProviderCredential>
    {
        Err(E_NOTIMPL.into())
    }
        
}

impl Drop for Provider {
    fn drop(&mut self) {
        crate::dll_release();
    }
}