use std::{
    fs::OpenOptions,
    io::Write,
};
use windows::Win32::System::Threading::GetCurrentProcessId;

fn main() -> std::io::Result<()> {
    // Récupère le PID
    let pid = unsafe { GetCurrentProcessId() };

    // Ouvre (ou crée) temp.txt en écriture, tronque-le s’il existe
    let path = r"C:\Dev\Rust\temp.txt";
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    // Écrit le PID dans le fichier
    writeln!(file, "The current process pid is {}", pid)?;

    // Garde le programme vivant pour inspection (facultatif)
    println!("PID écrit dans temp.txt, appuyez sur Entrée pour quitter.");
    let mut dummy = String::new();
    std::io::stdin().read_line(&mut dummy).ok();

    Ok(())
}
