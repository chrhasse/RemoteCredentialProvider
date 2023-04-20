use std::cell::RefCell;
use core::option::Option;

use helpers::*;

use windows::{
    core::{
        implement,
        Result,
        ComInterface,
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
            ICredentialProviderCredential2,
            CREDENTIAL_PROVIDER_NO_DEFAULT,
        },
        Foundation::{
            E_NOTIMPL,
            BOOL,
            E_INVALIDARG,
            E_UNEXPECTED,
        },
    }, w,
};

use crate::remote_credential::RemoteCredential;


#[implement(ICredentialProvider, ICredentialProviderSetUserArray)]
pub struct Provider {
    _up_advise_context: RefCell<usize>,
    _cred_prov_events: RefCell<Option<ICredentialProviderEvents>>,
    _recreate_enumerated_credentials: RefCell<bool>,
    _cpus: RefCell<CREDENTIAL_PROVIDER_USAGE_SCENARIO>,
    _auto_logon: RefCell<bool>,
    _credential: RefCell<Option<ICredentialProviderCredential2>>,
    _user_array: RefCell<Option<ICredentialProviderUserArray>>,
}

impl Provider {
    pub fn new() -> Self {
        info!("Provider::new");
        crate::dll_add_ref();
        Self {
            _up_advise_context: RefCell::new(0),
            _cred_prov_events: RefCell::new(None),
            _recreate_enumerated_credentials: RefCell::new(false),
            _cpus: RefCell::new(CREDENTIAL_PROVIDER_USAGE_SCENARIO::default()),
            _auto_logon: RefCell::new(false),
            _credential: RefCell::new(None),
            _user_array: RefCell::new(None),

        }
    }
    
    pub fn notify_changed(&self) -> Result<()> {
        info!("Provider::notify_changed");
        let res = Err(E_UNEXPECTED.into());
        if let Some(ref events) = *self._cred_prov_events.borrow() {
            unsafe {
                events.CredentialsChanged(*self._up_advise_context.borrow())?;
            }
        }
        res
    }
    
    fn enumerate_credentials(&self) -> Result<()> {
        info!("Provider::enumerate_credentials");
        if let Some(ref user_array) = *self._user_array.borrow() {
            unsafe {
                let count = user_array.GetCount()?;
                if count > 0 {
                    let user = user_array.GetAt(0)?;
                    let cred = RemoteCredential::new(
                        *self._cpus.borrow(),
                        user,
                        w!("")
                    )?;
                    *self._credential.borrow_mut() = Some(cred);
                    return Ok(())
                }
            }
        }
        Err(E_UNEXPECTED.into())
    }
    
    fn release_credentials(&self) {
        info!("Provider::release_credentials");
        *self._credential.borrow_mut() = None;
    }
    
    fn create_enumerated_credentials(&self) -> Result<()>{
        info!("Provider::create_enumerated_credentials");
        match *self._cpus.borrow() {
            CPUS_UNLOCK_WORKSTATION | CPUS_LOGON | CPUS_CREDUI => self.enumerate_credentials()?,
            _ => ()
        };
        Ok(())
    }
}

impl ICredentialProviderSetUserArray_Impl for Provider {
    fn SetUserArray(
        &self,
        users: Option<&ICredentialProviderUserArray>
    ) ->  Result<()> {
        info!("Provider::SetUserArray");
        *self._user_array.borrow_mut() = users.and_then(|user| Some(user.clone()));
        Ok(())
    }
}

impl ICredentialProvider_Impl for Provider {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> Result<()> {
        info!("Provider::SetUsageScenario");
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
        info!("Provider::SetSerialization");
        Err(E_NOTIMPL.into())
    }
    
    fn Advise(
        &self,
        pcpe: Option<&ICredentialProviderEvents>,
        upadvisecontext: usize,
    ) -> Result<()> {
        info!("Provider::Advise");
        *self._cred_prov_events.borrow_mut() = pcpe.and_then(|p| Some(p.clone()));
        *self._up_advise_context.borrow_mut() = upadvisecontext;
        Ok(())
    }

    fn UnAdvise(&self) -> Result<()> {
        info!("Provider::UnAdvise");
        self._cred_prov_events.borrow_mut().take();
        Ok(())
    }

    fn GetFieldDescriptorCount(&self) -> Result<u32> {
        info!("Provider::GetFieldDescriptorCount");
        Ok(RemoteFieldID::NumFields as u32)
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        info!("Provider::GetFieldDescriptorAt");
        if dwindex >= RemoteFieldID::NumFields as u32{
            Err(E_INVALIDARG.into())
        } else {
            unsafe {CP_FIELD_DESCRIPTORS[dwindex as usize].to_cpfd()}
        }
    }

    fn GetCredentialCount(
        &self,
        pdwcount: *mut u32,
        pdwdefault: *mut u32,
        pbautologonwithdefault: *mut BOOL,
    ) -> Result<()> {
        info!("Provider::GetCredentialCount");
        if *self._recreate_enumerated_credentials.borrow() {
            *self._recreate_enumerated_credentials.borrow_mut() = false;
            self.release_credentials();
            self.create_enumerated_credentials()?;
        }
        if self._credential.borrow().is_some() && *self._auto_logon.borrow() {
            *self._auto_logon.borrow_mut() = false;
            unsafe {
                *pbautologonwithdefault = true.into();
                *pdwdefault = 0;
            }
        } else {
            unsafe {
                *pdwdefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
                *pbautologonwithdefault = false.into();
            }
        }
        unsafe { *pdwcount = 1 };
        Ok(())
    }

    fn GetCredentialAt(
        &self,
        dwindex: u32,
    ) -> Result<ICredentialProviderCredential> {
        info!("Provider::GetCredentialAt");
        if dwindex == 0 {
            if let Some(ref cred) = *self._credential.borrow() {
                return cred.cast();
            }
        }
        return Err(E_INVALIDARG.into());
    }
        
}

impl Drop for Provider {
    fn drop(&mut self) {
        info!("Provider::drop");
        crate::dll_release();
    }
}