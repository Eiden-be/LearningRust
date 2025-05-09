use std::io;
use rand::Rng;
use std::cmp::Ordering;

fn main() {
    println!("Guess the number !");
    let secret = rand::thread_rng().gen_range(1..=100);
    println!("The secret number is: {secret}");
    loop {
        println!("Input guess");
        let mut guess = String::new();
        io::stdin()
            .read_line(&mut guess) 
            .expect("Failed to read line");
        
        let guess:u32 = match guess.trim().parse() {
            Ok(num) => num,
            Err(_) => continue,
        };
        println!("You guessed :{}", guess);

        match guess.cmp(&secret){
            Ordering::Less => println!("Too small"),
            Ordering::Equal => {
                println!("You win !");
                break;
            },
            Ordering::Greater => println!("Too big"),
        }
    }
}
