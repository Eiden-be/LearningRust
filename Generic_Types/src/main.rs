
fn largest_num(list: &[i32]) ->&i32{
    let mut largest = &list[0];

    for num in list{
        if largest < num{
            largest = num;
        }
    }
    largest
}

fn largest<T: std::cmp::PartialOrd>(list: &[T])-> &T {
    let mut largest = &list[0];

    for item in list{
        if largest < item{
            largest = item;
        }    
    }
    largest
}

fn main() {
    let mut num_list = vec![1,96,82,77,56,35,22];
    println!("The largest number is {}", largest_num(&num_list));
    num_list.push(100);
    println!("The largest number is {}", largest_num(&num_list));
}
