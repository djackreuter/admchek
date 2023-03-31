use std::{io::Error};
use std::ffi::c_void;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Security::{GetTokenInformation, TokenElevation};
use windows::Win32::{Foundation::{HANDLE}, System::Threading::{OpenProcessToken, GetCurrentProcess}, Security::{TOKEN_QUERY, TOKEN_ELEVATION}};

pub fn is_elevated() -> bool {
    return _is_elevated().unwrap_or(false);
}

fn _is_elevated() -> Result<bool, Error> {
    let token: QueryAccessToken = QueryAccessToken::from_current_process()?;
    token.is_elevated()
}

pub struct QueryAccessToken(HANDLE);
impl QueryAccessToken {

    pub fn from_current_process() -> Result<Self, Error> {
        unsafe {
            let mut handle: HANDLE = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle).as_bool() {
                Ok(Self(handle))
            } else {
                Err(Error::last_os_error())
            }
        }
    }

    pub fn is_elevated(&self) -> Result<bool, Error> {
        unsafe {
            let elevation: TOKEN_ELEVATION = TOKEN_ELEVATION::default();
            let mut ret_size: u32 = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

            let c_elev: *mut c_void = std::mem::transmute::<&TOKEN_ELEVATION, *mut c_void>(&elevation);

            if GetTokenInformation(self.0, TokenElevation, Some(c_elev), ret_size, &mut ret_size).as_bool() {
                Ok(elevation.TokenIsElevated != 0)
            } else {
                Err(Error::last_os_error())
            }
        }
    }
}

impl Drop for QueryAccessToken {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { CloseHandle(self.0) }; 
        }
    }
}