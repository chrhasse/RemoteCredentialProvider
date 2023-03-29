// Significant example code taken from
// https://stackoverflow.com/questions/75279682/implementing-a-windows-credential-provider
mod remote_credential_provider;
mod remote_credential;
pub mod helpers;

pub use remote_credential_provider::*;
use std::{ffi, ptr, mem};
use core::option::Option;

use windows::{
    core::{GUID, HRESULT, implement, Result, Interface, IUnknown, ComInterface},
    Win32::{
        UI::Shell::ICredentialProvider,
        Foundation::{CLASS_E_CLASSNOTAVAILABLE, E_POINTER, S_OK, E_NOTIMPL, BOOL, E_INVALIDARG, CLASS_E_NOAGGREGATION, E_NOINTERFACE, S_FALSE},
        System::Com::{
            IClassFactory,
            IClassFactory_Impl,
        }
    },
};


#[no_mangle]
extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut ffi::c_void,
) -> HRESULT {
    // The "class ID" this credential provider is identified by. This value needs to
    // match the value used when registering the credential provider (see the .reg
    // script above)
    const CLSID_CP_DEMO: GUID = GUID::from_u128(0xDED30376_B312_4168_B2D3_2D0B3EADE513);

    // Validate arguments
    if ppv.is_null() {
        return E_POINTER;
    }
    unsafe { *ppv = ptr::null_mut() };
    if rclsid.is_null() || riid.is_null() {
        return E_INVALIDARG;
    }

    let rclsid = unsafe { *rclsid };
    let riid = unsafe { *riid };
    // The following isn't strictly correct; a client *could* request an interface other
    // than `IClassFactory::IID`, which this implementation is simply failing.
    // This is safe, even if overly restrictive
    if rclsid != CLSID_CP_DEMO || riid != IClassFactory::IID {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    // Construct the factory object and return its `IClassFactory` interface
    let factory: IClassFactory = ProviderFactory.into();
    unsafe { *ppv = mem::transmute(factory) };
    S_OK
}

#[no_mangle]
extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_FALSE
}

#[implement(IClassFactory)]
struct ProviderFactory;

impl IClassFactory_Impl for ProviderFactory {
    fn CreateInstance(
        &self,
        punkouter: Option<&IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut ffi::c_void,
    ) -> Result<()> {
        // Validate arguments
        if ppvobject.is_null() {
            return Err(E_POINTER.into());
        }
        unsafe { *ppvobject = ptr::null_mut() };
        if riid.is_null() {
            return Err(E_INVALIDARG.into());
        }
        let riid = unsafe { *riid };
        if punkouter.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        // We're only handling requests for `IID_ICredentialProvider`
        if riid != ICredentialProvider::IID {
            return Err(E_NOINTERFACE.into());
        }

        // Construct credential provider and return it as an `ICredentialProvider`
        // interface
        let provider: ICredentialProvider = Provider::new().into();
        unsafe { *ppvobject = mem::transmute(provider) };
        Ok(())
    }

    fn LockServer(&self, _flock: BOOL) -> Result<()> {
        Err(E_NOTIMPL.into())
    }
}