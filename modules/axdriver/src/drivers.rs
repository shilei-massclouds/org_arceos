//! Defines types and probe methods of all supported devices.

#![allow(unused_imports, dead_code)]

use crate::AxDeviceEnum;
use axdriver_base::DeviceType;

#[cfg(feature = "virtio")]
use crate::virtio::{self, VirtIoDevMeta};

#[cfg(feature = "bus-pci")]
use axdriver_pci::{DeviceFunction, DeviceFunctionInfo, PciRoot};

pub use super::dummy::*;

pub trait DriverProbe {
    fn probe_global() -> Option<AxDeviceEnum> {
        None
    }

    #[cfg(bus = "mmio")]
    fn probe_mmio(_mmio_base: usize, _mmio_size: usize) -> Option<AxDeviceEnum> {
        None
    }

    #[cfg(bus = "pci")]
    fn probe_pci(
        _root: &mut PciRoot,
        _bdf: DeviceFunction,
        _dev_info: &DeviceFunctionInfo,
    ) -> Option<AxDeviceEnum> {
        None
    }
}

#[cfg(net_dev = "virtio-net")]
register_net_driver!(
    <virtio::VirtIoNet as VirtIoDevMeta>::Driver,
    <virtio::VirtIoNet as VirtIoDevMeta>::Device
);

#[cfg(all(block_dev = "virtio-blk", not(linux_adaptor)))]
register_block_driver!(
    <virtio::VirtIoBlk as VirtIoDevMeta>::Driver,
    <virtio::VirtIoBlk as VirtIoDevMeta>::Device
);

#[cfg(display_dev = "virtio-gpu")]
register_display_driver!(
    <virtio::VirtIoGpu as VirtIoDevMeta>::Driver,
    <virtio::VirtIoGpu as VirtIoDevMeta>::Device
);

cfg_if::cfg_if! {
    if #[cfg(linux_adaptor)] {
        use crate::BaseDriverOps;
        use crate::BlockDriverOps;
        use crate::DevResult;
        use crate::DevError;
        pub struct LinuxVirtIOBlkDrv;
        pub struct LinuxVirtIOBlkDev {
            size: usize,
        }
        const BLOCK_SIZE: usize = 512;
        register_block_driver!(LinuxVirtIOBlkDrv, LinuxVirtIOBlkDev);

        impl DriverProbe for LinuxVirtIOBlkDrv {
            fn probe_global() -> Option<AxDeviceEnum> {
                info!("****probe");
                Some(AxDeviceEnum::from_block(
                    LinuxVirtIOBlkDev {
                        size: 131072 * 512,
                    }
                ))
            }
        }

        impl BaseDriverOps for LinuxVirtIOBlkDev {
            fn device_type(&self) -> DeviceType {
                DeviceType::Block
            }
            fn device_name(&self) -> &str {
                "linux_virtio_blk"
            }
        }

        impl BlockDriverOps for LinuxVirtIOBlkDev {
            #[inline]
            fn num_blocks(&self) -> u64 {
                (self.size / BLOCK_SIZE) as u64
            }

            #[inline]
            fn block_size(&self) -> usize {
                BLOCK_SIZE
            }

            fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
                use axhal::arch::{irqs_enabled, enable_irqs};
                let block_id = block_id as usize;
                enable_irqs();
                error!("Read block: id [{}] size {} irq {}", block_id, buf.len(), irqs_enabled());

                if buf.len() % BLOCK_SIZE != 0 {
                    return Err(DevError::InvalidParam);
                }
                if block_id * BLOCK_SIZE + buf.len() > self.size {
                    return Err(DevError::Io);
                }

                let ret = unsafe {
                    cl_read_block(block_id,
                        buf.as_mut_ptr(), buf.len())
                };
                error!("Read block: OK irq {}", irqs_enabled());
                Ok(())
            }

            fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
                let block_id = block_id as usize;
                info!("Write block: id [{}] size {}", block_id, buf.len());

                if buf.len() % BLOCK_SIZE != 0 {
                    return Err(DevError::InvalidParam);
                }
                if block_id * BLOCK_SIZE + buf.len() > self.size {
                    return Err(DevError::Io);
                }

                unsafe {
                    cl_write_block(block_id, buf.as_ptr(), buf.len());
                }
                Ok(())
            }

            fn flush(&mut self) -> DevResult {
                //Ok(())
                unimplemented!();
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(block_dev = "ramdisk")] {
        pub struct RamDiskDriver;
        register_block_driver!(RamDiskDriver, axdriver_block::ramdisk::RamDisk);

        impl DriverProbe for RamDiskDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                // TODO: format RAM disk
                Some(AxDeviceEnum::from_block(
                    axdriver_block::ramdisk::RamDisk::new(0x100_0000), // 16 MiB
                ))
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(block_dev = "bcm2835-sdhci")]{
        pub struct BcmSdhciDriver;
        register_block_driver!(MmckDriver, axdriver_block::bcm2835sdhci::SDHCIDriver);

        impl DriverProbe for BcmSdhciDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                debug!("mmc probe");
                axdriver_block::bcm2835sdhci::SDHCIDriver::try_new().ok().map(AxDeviceEnum::from_block)
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(net_dev = "ixgbe")] {
        use crate::ixgbe::IxgbeHalImpl;
        use axhal::mem::phys_to_virt;
        pub struct IxgbeDriver;
        register_net_driver!(IxgbeDriver, axdriver_net::ixgbe::IxgbeNic<IxgbeHalImpl, 1024, 1>);
        impl DriverProbe for IxgbeDriver {
            #[cfg(bus = "pci")]
            fn probe_pci(
                    root: &mut axdriver_pci::PciRoot,
                    bdf: axdriver_pci::DeviceFunction,
                    dev_info: &axdriver_pci::DeviceFunctionInfo,
                ) -> Option<crate::AxDeviceEnum> {
                    use axdriver_net::ixgbe::{INTEL_82599, INTEL_VEND, IxgbeNic};
                    if dev_info.vendor_id == INTEL_VEND && dev_info.device_id == INTEL_82599 {
                        // Intel 10Gb Network
                        info!("ixgbe PCI device found at {:?}", bdf);

                        // Initialize the device
                        // These can be changed according to the requirments specified in the ixgbe init function.
                        const QN: u16 = 1;
                        const QS: usize = 1024;
                        let bar_info = root.bar_info(bdf, 0).unwrap();
                        match bar_info {
                            axdriver_pci::BarInfo::Memory {
                                address,
                                size,
                                ..
                            } => {
                                let ixgbe_nic = IxgbeNic::<IxgbeHalImpl, QS, QN>::init(
                                    phys_to_virt((address as usize).into()).into(),
                                    size as usize
                                )
                                .expect("failed to initialize ixgbe device");
                                return Some(AxDeviceEnum::from_net(ixgbe_nic));
                            }
                            axdriver_pci::BarInfo::IO { .. } => {
                                error!("ixgbe: BAR0 is of I/O type");
                                return None;
                            }
                        }
                    }
                    None
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(net_dev = "fxmac")]{
        use axalloc::global_allocator;
        use axhal::mem::PAGE_SIZE_4K;

        #[crate_interface::impl_interface]
        impl axdriver_net::fxmac::KernelFunc for FXmacDriver {
            fn virt_to_phys(addr: usize) -> usize {
                axhal::mem::virt_to_phys(addr.into()).into()
            }

            fn phys_to_virt(addr: usize) -> usize {
                axhal::mem::phys_to_virt(addr.into()).into()
            }

            fn dma_alloc_coherent(pages: usize) -> (usize, usize) {
                let Ok(vaddr) = global_allocator().alloc_pages(pages, PAGE_SIZE_4K) else {
                    error!("failed to alloc pages");
                    return (0, 0);
                };
                let paddr = axhal::mem::virt_to_phys((vaddr).into());
                debug!("alloc pages @ vaddr={:#x}, paddr={:#x}", vaddr, paddr);
                (vaddr, paddr.as_usize())
            }

            fn dma_free_coherent(vaddr: usize, pages: usize) {
                global_allocator().dealloc_pages(vaddr, pages);
            }

            fn dma_request_irq(_irq: usize, _handler: fn()) {
                warn!("unimplemented dma_request_irq for fxmax");
            }
        }

        register_net_driver!(FXmacDriver, axdriver_net::fxmac::FXmacNic);

        pub struct FXmacDriver;
        impl DriverProbe for FXmacDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                info!("fxmac for phytiumpi probe global");
                axdriver_net::fxmac::FXmacNic::init(0).ok().map(AxDeviceEnum::from_net)
            }
        }
    }
}

unsafe extern "C" {
    fn cl_read_block(blk_nr: usize, rbuf: *mut u8, count: usize) -> i32;
    fn cl_write_block(blk_nr: usize, wbuf: *const u8, count: usize) -> i32;
}
