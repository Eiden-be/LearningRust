    //https://research.checkpoint.com/2025/waiting-thread-hijacking/
    /*
    Steps : 
        Exécution: 
            - usage : ./waiting_thread_hijacking.exe [PID]
        Lire NtQuerySystemInformation 
            - Trouver le PID dans SystemProcessInformation de NtQuerySystemInformation 
            - Si on le trouve :
                - Trouver un thread avec ThreadState qui a la valeur WrQueue  
            - Injecter notre shellcode 
            - S'assurer du Happy Ending ;) 
    */

use std::{env, slice};
use std::ptr::null_mut;
use std::fmt::{self, Display};
use winapi::shared::ntdef::*;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntstatus::*;
use ntapi::ntexapi::*;

impl std::error::Error for Error {}

#[derive(Debug)]
pub enum Error {
    /// Code NTSTATUS retourné par un appel Nt* (< 0 signifie échec).
    Nt(NTSTATUS),
    NotFound(u32), // on conserve le PID pour le contexte si besoin
}

impl From<NTSTATUS> for Error {
    fn from(status: NTSTATUS) -> Self {
        Self::Nt(status)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Nt(code) => write!(f, "[!] Échec NTSTATUS = 0x{:X}", *code as u32),
            Error::NotFound(pid) => write!(f, "[!] Processus PID={} non trouvé", pid),
        }
    }
}

fn get_process_thread(pid:DWORD)-> Result<(),Error >{ //Ou Error ?
    unsafe {
        let mut buffer_size:ULONG = 0;
        let status_first = NtQuerySystemInformation(
            SystemProcessInformation, 
            null_mut(), 
            0, 
            &mut buffer_size);
        
        if status_first != STATUS_INFO_LENGTH_MISMATCH as NTSTATUS {
            return Err(status_first.into());
        }
        let mut buffer:Vec<u8> = Vec::with_capacity(buffer_size as usize); 
        
        let sys_info = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as PVOID,
            buffer_size, 
            &mut buffer_size);
        if !NT_SUCCESS(sys_info){
            return Err(sys_info.into());
        }
        let mut sys_procces_info = buffer.as_mut_ptr() as *const SYSTEM_PROCESS_INFORMATION;
        let mut found = false;
        while !sys_procces_info.is_null(){
            if (*sys_procces_info).UniqueProcessId as u32 == pid {
                found = true;
                break;
            }
            if (*sys_procces_info).NextEntryOffset == 0 {
                break;
            }
            sys_procces_info = (sys_procces_info as usize + (*sys_procces_info).NextEntryOffset as usize) as *const SYSTEM_PROCESS_INFORMATION;  
        }
        if !found{
            return Err(Error::NotFound(pid))
        }
        let thread_count = (*sys_procces_info).NumberOfThreads as usize;
         // &(*ptr).Threads pointe sur le premier SYSTEM_THREAD_INFORMATION
        let threads_ptr = &(*sys_procces_info).Threads as *const SYSTEM_THREAD_INFORMATION;
        let threads_slice: &[SYSTEM_THREAD_INFORMATION] = slice::from_raw_parts(threads_ptr, thread_count);
        for ti in threads_slice {
            let tid = ti.ClientId.UniqueThread as usize;
            let state = ti.ThreadState;
            let raison = ti.WaitReason;
            //https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-thread
            // Etat 5 = WrQueue, donc ce qu'on veut
            println!("[*] Thread TID={tid}  Etat={state} Raison={raison}");
        }
    }       
    Ok(())
}


fn run_proccess_injection(pid:DWORD)-> Result<(),Error>{
    get_process_thread(pid)?;

    Ok(())
}


fn main(){
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("[*] Usage: ./waiting_thread_hijacking.exe [PID]");
        return;
    }
    let pid: DWORD = match args[1].parse() {
        Ok(n) if n != 0 => n,
        _ => {
            println!("[*] T'es sérieux ?");
            return;
        }
    };
    match run_proccess_injection(pid){
        Ok(())=>println!("[!] Process Injecté avec succès !"),
        Err(err) => println!("Error : {}",err),
    };
}   
