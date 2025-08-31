use std::env;
use std::process::Command;

fn main() {
    let arch = env::var("AX_ARCH").unwrap();
    let log_level = env::var("AX_LOG").unwrap();
    let root_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let cwd = root_dir + "/kernel_modules";
    let output = Command::new("make")
        .current_dir(&cwd)
        .env("ARCH", arch)
        .env("LOG", log_level)
        .output()
        .expect("Make error.");
    if !output.status.success() {
        let err = String::from_utf8(output.stderr).unwrap();
        panic!("{}", err);
    }

    println!("cargo::rustc-link-search=native={}", cwd);
    println!("cargo::rustc-link-lib=static=clinux");
    //println!("cargo::rustc-link-arg=--no-gc-sections");
    println!("cargo::rerun-if-changed=kernel_modules");
}
