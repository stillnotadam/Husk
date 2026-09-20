// A script whose comments describe something innocuous, but which
// actually creates a file at runtime - the Rust equivalent of the
// Python/JS/Ruby/Go fixtures with the same name.
use std::fs;
fn main() {
    fs::write("unexpected_marker_rs.txt", "this file's existence is the point of the test").unwrap();
    println!("Hello from Rust!");
}
