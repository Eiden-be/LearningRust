

fn main() {
   // let s = String::from("test test test");
    let s2 = "test test test";
    //first_word(s);
    println!("{}",first_word_adrien(s2));

    let mut s = String::from("hello world");
    let word = first_word(&s);
    s.clear();
}

fn first_word(s: &String) -> usize {
    let bytes = s.as_bytes();

    for (i, &item) in bytes.iter().enumerate() {
        if (item == b' '){
            return  i;
        }
    }
    s.len()
}

fn first_word2(s: &String) -> &str {
    let bytes = s.as_bytes();

    for (i, &item) in bytes.iter().enumerate() {
        if (item == b' '){
            return  &s[0..i];
        }
    }
    &s[..]
}

fn first_word_adrien(s: &str) -> &str {
    match s.find(' '){
        Some(index) => &s[..index],
        None => s,
    }
}