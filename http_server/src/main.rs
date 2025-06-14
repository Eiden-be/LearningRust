
use std::{io::{BufRead, BufReader, Write}, net::*};

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8181").unwrap();

    for stream in listener.incoming(){
        let stream = stream.unwrap();

        handle_connection(stream);
    } 
}

fn handle_connection(mut stream: TcpStream){
    let buf = BufReader::new(&stream);
    let vector : Vec<_> = buf
        .lines()
        .map(|result| result.unwrap())
        .take_while(|line| !line.is_empty())
        .collect();
    let response = "HTTP/1.1 200 OK\r\n\r\n";
    println!("{vector:#?}");
    stream.write_all(response.as_bytes()).unwrap();
}