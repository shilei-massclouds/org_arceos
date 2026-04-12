use std::env;
use std::fs;
use std::process::Command;

fn run_cmd(mut cmd: Command, what: &str) {
    let output = cmd.output().expect("failed to spawn command");
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let out = String::from_utf8_lossy(&output.stdout);
        panic!("{what} failed\nstdout:\n{out}\nstderr:\n{err}");
    }
}

fn prepare_riscv_vdso(kernel_dir: &str, arch: &str, log_level: &str) {
    let vdso_dir = format!("{kernel_dir}/arch/riscv/kernel/vdso");
    let generated_dir = format!("{kernel_dir}/include/generated");

    run_cmd(
        {
            let mut cmd = Command::new("make");
            cmd.current_dir(kernel_dir)
                .env("ARCH", arch)
                .env("LOG", log_level)
                .args([
                    "-f",
                    "./scripts/Makefile.build",
                    "obj=arch/riscv/kernel/vdso/obj_list.txt",
                    "_build",
                ]);
            cmd
        },
        "materialize riscv vdso",
    );

    run_cmd(
        {
            let mut cmd = Command::new("sh");
            cmd.current_dir(kernel_dir).args([
                "-c",
                "nm arch/riscv/kernel/vdso/vdso.so.dbg | sh arch/riscv/kernel/vdso/gen_vdso_offsets.sh | LC_ALL=C sort > include/generated/vdso-offsets.h",
            ]);
            cmd
        },
        "generate vdso-offsets.h",
    );

    for rel in [
        "arch/riscv/kernel/signal.o",
        "arch/riscv/kernel/alternative.o",
        "arch/riscv/kernel/vdso.o",
    ] {
        fs::remove_file(format!("{kernel_dir}/{rel}")).ok();
    }

    println!("cargo::rerun-if-changed={vdso_dir}/vdso.lds.S");
    println!("cargo::rerun-if-changed={vdso_dir}/Makefile");
    println!("cargo::rerun-if-changed={vdso_dir}/gen_vdso_offsets.sh");
    println!("cargo::rerun-if-changed={generated_dir}/vdso-offsets.h");
}

fn main() {
    let arch = env::var("AX_ARCH").unwrap();
    let log_level = env::var("AX_LOG").unwrap();
    let root_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let cwd = root_dir + "/kernel_modules";

    if arch == "riscv64" {
        prepare_riscv_vdso(&cwd, &arch, &log_level);
    }

    run_cmd(
        {
            let mut cmd = Command::new("make");
            cmd.current_dir(&cwd)
                .env("ARCH", arch)
                .env("LOG", log_level)
                .arg("-j4");
            cmd
        },
        "kernel_modules make",
    );

    println!("cargo::rustc-link-search=native={}", cwd);
    println!("cargo::rustc-link-lib=static:+whole-archive=clinux");
    println!("cargo::rerun-if-changed=kernel_modules");
}
