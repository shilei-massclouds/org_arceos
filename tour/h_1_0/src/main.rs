#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]
#![feature(asm_const)]
#![feature(riscv_ext_intrinsics)]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;
extern crate alloc;

mod task;
mod vcpu;
mod regs;
mod csrs;

use std::io::{self, Read};
use std::fs::File;
use axhal::paging::MappingFlags;
use axhal::mem::{PAGE_SIZE_4K, phys_to_virt};
use vcpu::VmCpuRegisters;
use riscv::register::{htinst, htval, scause, sstatus, stval};
use csrs::defs::hstatus;
use tock_registers::LocalRegisterCopy;
use csrs::{traps, RiscvCsrTrait, CSR};
use vcpu::_run_guest;

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    println!("Hypervisor ...");
    let mut buf = [0u8; 64];
    if let Err(e) = load_user_app("/sbin/origin.bin", &mut buf) {
        panic!("Cannot load app! {:?}", e);
    }

    let entry = 0x8020_0000;
    let mut uspace = axmm::new_user_aspace().unwrap();
    uspace.map_alloc(entry.into(), PAGE_SIZE_4K, MappingFlags::READ|MappingFlags::WRITE|MappingFlags::EXECUTE|MappingFlags::USER, true).unwrap();

    let (paddr, _, _) = uspace
        .page_table()
        .query(entry.into())
        .unwrap_or_else(|_| panic!("Mapping failed for segment: {:#x}", entry));

    println!("paddr: {:#x}", paddr);

    unsafe {
        core::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            phys_to_virt(paddr).as_mut_ptr(),
            PAGE_SIZE_4K,
        );
    }

    println!("New user address space: {:#x?}", uspace);

    let ept_root = uspace.page_table_root();
    let mut ctx = VmCpuRegisters::default();
    // Set hstatus
    let mut hstatus = LocalRegisterCopy::<usize, hstatus::Register>::new(
        riscv::register::hstatus::read().bits(),
    );
    hstatus.modify(hstatus::spv::Guest);
    // Set SPVP bit in order to accessing VS-mode memory from HS-mode.
    hstatus.modify(hstatus::spvp::Supervisor);
    CSR.hstatus.write_value(hstatus.get());
    ctx.guest_regs.hstatus = hstatus.get();

    // Set sstatus
    let mut sstatus = sstatus::read();
    sstatus.set_spp(sstatus::SPP::Supervisor);
    ctx.guest_regs.sstatus = sstatus.bits();

    ctx.guest_regs.sepc = entry;
    let hgatp = 8usize << 60 | usize::from(ept_root) >> 12;
    unsafe {
        core::arch::asm!(
            "csrw hgatp, {hgatp}",
            hgatp = in(reg) hgatp,
        );
        core::arch::riscv64::hfence_gvma_all();
    }

    unsafe {
        _run_guest(&mut ctx);
    }
    /*
    let user_task = task::spawn_user_task(
        Arc::new(Mutex::new(uspace)),
        UspaceContext::new(entry.into(), ustack_top, 2333),
    );
    let exit_code = user_task.join();

    println!("monolithic kernel exit [{:?}] normally!", exit_code);
    */

    panic!("Hypervisor ok!");
}

/*
extern crate alloc;

mod task;
mod syscall;

use axhal::arch::UspaceContext;
use axsync::Mutex;
use alloc::sync::Arc;

const USER_STACK_SIZE: usize = 0x10000;
const KERNEL_STACK_SIZE: usize = 0x40000; // 256 KiB

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    let mut buf = [0u8; 64];
    if let Err(e) = load_user_app("/sbin/origin.bin", &mut buf) {
        panic!("Cannot load app! {:?}", e);
    }

    let entry = 0x1000;
    let mut uspace = axmm::new_user_aspace().unwrap();
    uspace.map_alloc(entry.into(), PAGE_SIZE_4K, MappingFlags::READ|MappingFlags::WRITE|MappingFlags::EXECUTE|MappingFlags::USER, true).unwrap();

    let (paddr, _, _) = uspace
        .page_table()
        .query(entry.into())
        .unwrap_or_else(|_| panic!("Mapping failed for segment: {:#x}", entry));

    println!("paddr: {:#x}", paddr);

    unsafe {
        core::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            phys_to_virt(paddr).as_mut_ptr(),
            PAGE_SIZE_4K,
        );
    }

    let ustack_top = uspace.end();
    let ustack_vaddr = ustack_top - crate::USER_STACK_SIZE;
    println!(
        "Mapping user stack: {:#x?} -> {:#x?}",
        ustack_vaddr, ustack_top
    );
    uspace.map_alloc(
        ustack_vaddr,
        crate::USER_STACK_SIZE,
        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
        true,
    ).unwrap();
    println!("New user address space: {:#x?}", uspace);

    let user_task = task::spawn_user_task(
        Arc::new(Mutex::new(uspace)),
        UspaceContext::new(entry.into(), ustack_top, 2333),
    );
    let exit_code = user_task.join();

    println!("monolithic kernel exit [{:?}] normally!", exit_code);
}
*/

fn load_user_app(fname: &str, buf: &mut [u8]) -> io::Result<usize> {
    println!("app: {}", fname);
    let mut file = File::open(fname)?;
    let n = file.read(buf)?;
    Ok(n)
}
