//Référence : https://whokilleddb.github.io/blogs/posts/process-ghosting/

use std::{
    env,
    fs,
    io,
    mem::{self, size_of, zeroed},
    path::Path,
    ptr::null_mut,
    ffi::CString,
};

use winapi::{
    shared::{
        minwindef::{FALSE, LPCVOID, LPVOID, MAX_PATH, TRUE},
        ntdef::{
            InitializeObjectAttributes, HANDLE, NTSTATUS, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES,
            PUNICODE_STRING, PVOID, UNICODE_STRING,
        },
        ntstatus::{
            STATUS_INVALID_PARAMETER, STATUS_OBJECTID_NOT_FOUND, STATUS_OBJECT_NAME_NOT_FOUND,
            STATUS_SUCCESS,
        },
    },
    um::{
        errhandlingapi::GetLastError,
        fileapi::{self, CreateFileA, OPEN_ALWAYS,FILE_DISPOSITION_INFO},
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        winnt::{
            DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
        },
    },
};

use ntapi::ntioapi::{NtSetInformationFile, FileDispositionInformation, IO_STATUS_BLOCK};


#[derive(Debug)]
struct Error {
    status: NTSTATUS,
}

impl From<NTSTATUS> for Error {
    fn from(status: NTSTATUS) -> Self {
        Self { status }
    }
}

unsafe fn prepare_target(cible:&str) -> Option<(PVOID,u32)>{
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
    // Supposons qu'ici tu retournes un mapping plus tard
    Some((h_file as PVOID, 0))

}

unsafe fn process_ghosting(cible:&str,fake:&str) -> Result<(), Error>{
       
    println!("[+] Le fichier que l'on prend est : {cible}");
    println!("[+] Le fichier temporaire est : {fake}");
    
   if let Err(e) = fs::metadata(cible) {
        println!("[!] Erreur d'accès au fichier cible : {}", e);
        return Err(Error::from(STATUS_OBJECT_NAME_NOT_FOUND)); 
    }

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
    let cible = &args[1];
    let fake = &args[2];

    unsafe {
        match process_ghosting(cible, fake) {
            Ok(()) => println!("[+] Le process ghosting a fonctionné !"),
            Err(err) => println!("[!] Error: 0x{:x}", err.status),
        }
    }
}

