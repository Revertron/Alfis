extern crate winres;

fn main() {
    println!("cargo:rustc-env=CC=clang -Wno-int-conversion");
    
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("img/logo/alfis.ico");
        res.compile().unwrap();
    }
}