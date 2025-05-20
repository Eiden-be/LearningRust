use windows::{
    core::*,
    Win32::UI::WindowsAndMessaging::*
};
//https://www.youtube.com/watch?v=i3MY0uw9HYE&list=PLq3cxyqYkAqlpeW6ngUmFDNIprxYRr3fx
//https://learn.microsoft.com/en-us/windows/dev-environment/rust/rss-reader-rust-for-windows
fn main() {
    println!("Hello, world!");
    unsafe {
        MessageBoxA(None, s!("Text"), s!("Caption"),MB_OK );
    }
}
