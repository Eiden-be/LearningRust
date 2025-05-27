use std::{io, thread, time::Duration};

fn main(){
    let mut alphabet: Vec<char> = ('A'..='Z').collect();
    let to_remove = ['Z', 'K', 'X', 'W', 'Y'];

    alphabet.retain(|c| !to_remove.contains(c));

    println!("Appuie sur Entrée pour commencer !");
    wait_for_enter();

    while !alphabet.is_empty() {
        // Retirer une lettre au hasard
        let letter = remove_random_letter(&mut alphabet);

        println!("\nLettre tirée : {}\n", letter);

        start_timer(180);

        // Émettre un "son" (alerte console)
        print!("\x07"); // Caractère ASCII pour un bip sonore
        println!("Temps écoulé ! Appuie sur Entrée pour continuer...");

        wait_for_enter();
    }

    println!("Toutes les lettres ont été utilisées. Fin du programme !");
}

fn remove_random_letter(vec: &mut Vec<char>) -> char {
    let mut rng = rand::rng();
    let index = rand::seq::index::sample(&mut rng, vec.len(), 1).index(0);
    vec.remove(index)
}

fn wait_for_enter() {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

fn start_timer(seconds: u64) {
    for remaining in (1..=seconds).rev() {
        print!("\rTemps restant : {:02}:{:02}", remaining / 60, remaining % 60);
        io::Write::flush(&mut io::stdout()).unwrap();
        thread::sleep(Duration::from_secs(1));
    }
    println!("\rTemps restant : 00:00");
}
