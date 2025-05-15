#[derive(Debug)]
struct Rectangle {
    width: u32,
    height: u32,
}

impl Rectangle {
    fn area(&self)->u32{
        self.width * self.height
    }
    fn can_hold(&self, other:&Rectangle)->bool{
        self.width>other.width && self.width > other.width
    }
}

fn main() {
    let rect = Rectangle{
        width: 20,
        height: 30,
    };
    println!(
        "The area is {}",
        rect.area()
    );
    println!(
        "Debugging Rectangle {rect:?}"
    );
    let rect2 = Rectangle{
        width: 15,
        height: 23,
    };
    println!("Can rect hold rect2 ? {}",rect.can_hold(&rect2));

    let mut v = vec![1,2,3,4,5];
    v.push(3);

    let first = &v[0];
    println!("The first element is {first}");

}


fn area(rectangle: &Rectangle) -> u32 {
    rectangle.width * rectangle.height
}