use std::env;
use std::process::Command;

fn main() {
    let root_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let cwd = root_dir + "/kernel_modules";
    Command::new("make").current_dir(&cwd).status().unwrap();

    println!("cargo::rustc-link-search=native={}", cwd);
    println!("cargo::rustc-link-lib=static=clinux");
    println!("cargo::rerun-if-changed=kernel_modules");
}
