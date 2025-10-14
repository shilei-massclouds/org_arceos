use alloc::collections::BTreeMap;
use axhal::mem::kallsyms_size;

static mut KALLSYMS: BTreeMap<usize, &str> = BTreeMap::new();

pub fn init_kallsyms() {
    let size = kallsyms_size();
    if size == 0 {
        panic!("No kallsyms area.");
    }
    debug!("Kallsyms size: {:#x}", size);

    // Skip head_magic and size field (4bytes + 4bytes).
    let va = 4 + 4 + _kallsyms as usize;
    error!("kallsyms: {} {:#X}", kallsyms_size(), va);

    unsafe {
        let ptr = va as *const u8;
        let body = core::slice::from_raw_parts(ptr, size);
        let body = core::str::from_utf8(&body).unwrap();
        trace!("Got linux kallsyms {}", body);
        for line in body.split('\n') {
            if line.is_empty() {
                break;
            }
            let (addr, name) = line.split_once(' ').unwrap();
            let addr = usize::from_str_radix(addr, 16).unwrap();
            KALLSYMS.insert(addr, name);
        }
    }
}

pub fn get_ksym(addr: usize) -> Option<&'static str> {
    let cursor = unsafe {
        KALLSYMS.lower_bound(core::range::Bound::Excluded(&addr))
    };
    if let Some((_, ksym)) = cursor.peek_prev() {
        Some(*ksym)
    } else {
        None
    }

    //let cursor = map.lower_bound(Bound::Excluded(&2));
    //assert_eq!(cursor.peek_prev(), Some((&2, &"b")));
}

unsafe extern "C" {
    fn _kallsyms();
}
