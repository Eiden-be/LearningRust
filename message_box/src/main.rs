use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Threading::*;
use std::mem::{size_of, MaybeUninit};

//https://www.youtube.com/watch?v=i3MY0uw9HYE&list=PLq3cxyqYkAqlpeW6ngUmFDNIprxYRr3fx
//https://learn.microsoft.com/en-us/windows/dev-environment/rust/rss-reader-rust-for-windows
fn main() {
    let mut pids = [0u32; 1024];
    let mut bytes_returned = 0u32;

    let result = unsafe {
        K32EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * size_of::<u32>()) as u32,
            &mut bytes_returned,
        )
    };

    if result == false {
        panic!("EnumProcesses failed");
    }
    let count = bytes_returned as usize / std::mem::size_of::<u32>();
    
    let valid_pids = &mut pids[..count];
    valid_pids.sort();

    for pid in valid_pids {
        // println!("PID: {}", pid);
        let h_process = match unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, *pid)
        } {
            Ok(handle) => handle,
            Err(e) => {
                println!("Impossible d’ouvrir le PID {} : {:?}", pid, e);
                continue;
            }
        };
    
        let mut h_mod = MaybeUninit::<HMODULE>::uninit();
        
        let mut needed = 0u32;
        if unsafe {
            K32EnumProcessModules(
                h_process,
                h_mod.as_mut_ptr(),
                size_of::<HINSTANCE>() as u32,
                &mut needed,
                )
        }.as_bool() {
             println!("Échec EnumProcessModules pour PID {}", pid);
            unsafe { CloseHandle(h_process); }
            continue;
        }
        let h_mod = unsafe { h_mod.assume_init() };
        let mut name = [0u8; 260];

        let len = unsafe {
            K32GetModuleBaseNameA(h_process, Some(h_mod), & mut name)
        };

        if len > 0 {
            let name_str = String::from_utf8_lossy(&name[..len as usize]);
            println!("PID {} → {}", pid, name_str);
        }
        println!("→ PID {} : len = {}", pid, len);
        unsafe { CloseHandle(h_process); }
    }
    
}