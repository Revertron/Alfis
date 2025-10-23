extern crate winres;

fn main() {
    // Suppress int-conversion warnings for macOS ARM (Apple Silicon) webview compatibility
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        println!("cargo:rustc-env=CFLAGS=-Wno-int-conversion");
    }

    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("img/logo/alfis.ico");
        res.compile().unwrap();
    }
}