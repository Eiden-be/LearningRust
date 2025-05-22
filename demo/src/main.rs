fn main() {
    println!("The current process pid is {}", unsafe{GetCurrentProcessId()});

    let mut buffer = String::new();
    std::io::stdin()
        .read_line(&mut buffer)
        .expect("Failed to read line");
}
