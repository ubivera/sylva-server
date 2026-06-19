use std::fs;
use std::path::Path;

fn main() {
    let migrations_dir = Path::new("../../migrations");
    println!("cargo:rerun-if-changed={}", migrations_dir.display());

    if let Ok(entries) = fs::read_dir(migrations_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "sql") {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}
