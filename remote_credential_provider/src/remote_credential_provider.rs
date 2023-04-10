use std::cell;
use core::option::Option;

use helpers::*;

use windows::{
    core::{
        implement,
        Result,
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
            ICredentialProviderUserArray,
        },
        Foundation::{
            E_NOTIMPL,
            BOOL,
            E_INVALIDARG,
        },
    },
};


#[implement(ICredentialProvider, ICredentialProviderSetUserArray)]
pub struct Provider {
    _up_advise_context: cell::RefCell<usize>,
    _cred_prov_events: cell::RefCell<Option<ICredentialProviderEvents>>,
    _recreate_enumerated_credentials: cell::RefCell<bool>,
}

impl Provider {
    pub fn new() -> Self {
        Self {
            _up_advise_context: cell::RefCell::new(0),
            _cred_prov_events: cell::RefCell::new(None),
            _recreate_enumerated_credentials: cell::RefCell::new(false),
        }
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
            CPUS_LOGON | CPUS_UNLOCK_WORKSTATION => {
                *self._recreate_enumerated_credentials.borrow_mut() = true;
                Ok(())
            }
            _ => Err(E_NOTIMPL.into())
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
            *self._cred_prov_events.borrow_mut() = Some(p.clone());
        }
        *self._up_advise_context.borrow_mut() = upadvisecontext;
        Ok(())
    }

    fn UnAdvise(&self) -> Result<()> {
        *self._cred_prov_events.borrow_mut() = None;
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
            Ok(&mut get_credential_provider_field_descriptors()[dwindex as usize].clone())
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