use alloc::collections::BTreeMap;
use axhal::mem::phys_to_virt;

const PFLASH_START: usize = 0x2200_0000;

static mut KALLSYMS: BTreeMap<usize, &str> = BTreeMap::new();

pub fn init_kallsyms() {
    let va = phys_to_virt(PFLASH_START.into()).as_usize();

    unsafe {
        let head_ptr = va as *const u32;
        let head_magic = core::mem::transmute::<u32, [u8; 4]>(*head_ptr);
        assert_eq!(head_magic, [b'k', b'a', b'l', b'l']);

        let size_ptr = head_ptr.add(1);
        let size = u32::from_be(*size_ptr) as usize;
        debug!("Got linux kallsyms size: {:#x}", size);

        let body_ptr = size_ptr.add(1) as *const u8;
        let body = core::slice::from_raw_parts(body_ptr, size);
        let body = core::str::from_utf8(&body).unwrap();
        trace!("Got linux kallsyms {}", body);

        let tail_ptr = body_ptr.add(size) as *const u32;
        let tail_magic = core::mem::transmute::<u32, [u8; 4]>(*tail_ptr);
        assert_eq!(tail_magic, [b's', b'y', b'm', b's']);

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
