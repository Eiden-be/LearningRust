use windows::Win32::System::Threading::GetCurrentProcessId;

fn main() -> std::io::Result<()> {
    // Récupère le PID
    let pid = unsafe { GetCurrentProcessId() };

    // Écrit le PID dans le fichier
    println!("The current process pid is {}", pid);

    // Garde le programme vivant pour inspection (facultatif)
    let mut dummy = String::new();
    std::io::stdin().read_line(&mut dummy).ok();

    Ok(())
}
