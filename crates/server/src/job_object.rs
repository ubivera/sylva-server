#![allow(unsafe_code)]

use std::io;

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub struct JobObject {
    handle: HANDLE,
}

impl JobObject {
    /// Create a job object with `KILL_ON_JOB_CLOSE`, assign the current
    /// process to it, and return the handle. Subsequent child processes
    /// inherit the job by default, so they're killed when this handle
    /// closes (i.e., when server dies).
    pub fn assign_current_process_for_kill_on_close() -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error()).context("CreateJobObjectW");
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let set_ok = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set_ok == 0 {
            let err = io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(err).context("SetInformationJobObject");
        }

        let assign_ok = unsafe { AssignProcessToJobObject(handle, GetCurrentProcess()) };
        if assign_ok == 0 {
            let err = io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(err).context("AssignProcessToJobObject(current process)");
        }

        Ok(Self { handle })
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

unsafe impl Send for JobObject {}
unsafe impl Sync for JobObject {}
