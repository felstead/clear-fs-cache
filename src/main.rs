fn main() {
    #[cfg(windows)]
    {  
        println!("Clearing disk cache...");
        let result = windows::clear_cache();
        if result == 0 {
            println!("Success!");
        } else {
            println!("Failed with error code: 0x{:08x} - ensure you are running as administrator", result);
        }
    }

    #[cfg(not(windows))]
    unimplemented!("This function is only implemented for Windows");
}

#[cfg(windows)]
pub mod windows {

    use std::ptr::*;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{AdjustTokenPrivileges, LookupPrivilegeValueW, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, SE_PRIVILEGE_ENABLED, SE_PROF_SINGLE_PROCESS_NAME, TOKEN_ADJUST_PRIVILEGES};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // This function is not exposed by the windows-rs wrapper as it is semi-undocumented
    #[link(name = "ntdll", kind = "dylib")]
    extern {
        fn NtSetSystemInformation(SystemInformationClass: u32, SystemInformation: *mut u8, SystemInformationLength: u32) -> u32;
    }

    pub fn clear_cache() -> u32 {
        let mut privileges = TOKEN_PRIVILEGES::default();
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Attributes = TOKEN_PRIVILEGES_ATTRIBUTES(SE_PRIVILEGE_ENABLED.0);
    
        unsafe { LookupPrivilegeValueW(None, SE_PROF_SINGLE_PROCESS_NAME, &mut privileges.Privileges[0].Luid) }.unwrap();
    
        let mut pt = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut pt) }.unwrap();
        unsafe { AdjustTokenPrivileges(pt, false, Some(addr_of!(privileges)), 0, None, None) }.unwrap();
    
    
        // References:
        // - https://stackoverflow.com/questions/12841845/clear-the-windows-7-standby-memory-programmatically
        // - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_information_class.htm
        const SYSTEM_MEMORY_LIST_INFORMATION : u32 = 0x50;
        const PURGE_STANDBY_LIST_COMMAND : u32 = 0x04;
    
        let mut command_list = [PURGE_STANDBY_LIST_COMMAND];
        let command_list_ptr = command_list.as_mut_ptr() as *mut u8;
        let command_list_len = std::mem::size_of::<[u32; 1]>() as u32;
    
        unsafe { NtSetSystemInformation(SYSTEM_MEMORY_LIST_INFORMATION, command_list_ptr, command_list_len) }
    }

}