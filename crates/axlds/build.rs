use std::io::Result;
use std::path::{Path, PathBuf};

fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let platform = axconfig::PLATFORM;
    if platform == "dummy" {
        return;
    }

    let fname = format!("linker_{platform}.lds");
    // target/<target_triple>/<mode>/build/axhal-xxxx/out
    let out_dir = std::env::var("OUT_DIR").unwrap();
    // target/<target_triple>/<mode>/linker_xxxx.lds
    let out_path = Path::new(&out_dir).join("../../..").join(fname);

    let lds = std::env::var("PLAT_LDS").unwrap();
    if !lds.is_empty() {
        /* FixMe: Now only support 'riscv64-dp1000'. */
        assert!(platform == "riscv64-dp1000");
        std::fs::copy(lds, &out_path).unwrap();
        return;
    }

    gen_linker_script(&arch, &out_path).unwrap();
}

fn gen_linker_script(arch: &str, out_path: &PathBuf) -> Result<()> {
    let output_arch = if arch == "x86_64" {
        "i386:x86-64"
    } else if arch.contains("riscv") {
        "riscv" // OUTPUT_ARCH of both riscv32/riscv64 is "riscv"
    } else {
        arch
    };
    let ld_content = std::fs::read_to_string("linker.lds.S")?;
    let ld_content = ld_content.replace("%ARCH%", output_arch);
    let ld_content = ld_content.replace(
        "%KERNEL_BASE%",
        &format!("{:#x}", axconfig::plat::KERNEL_BASE_VADDR),
    );
    let ld_content = ld_content.replace("%CPU_NUM%", &format!("{}", axconfig::plat::MAX_CPU_NUM));

    std::fs::write(out_path, ld_content)?;
    Ok(())
}
