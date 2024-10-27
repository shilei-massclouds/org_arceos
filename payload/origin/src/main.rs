#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        "ebreak",
"1:",
        "li a7, 63",
        "ecall",
        "li t0, 1",
        "ble a0, t0, 1b",
        "li a7, 64",
        "ecall",
        "li a7, 93",
        "ecall",
        options(noreturn)
    )
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
