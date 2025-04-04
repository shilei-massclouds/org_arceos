use axdriver::prelude::*;

const BLOCK_SIZE: usize = 512;

/// A disk device with a cursor.
pub struct Disk {
    block_id: u64,
    offset: usize,
    //dev: AxBlockDevice,
}

impl Disk {
    /// Create a new disk.
    pub fn new(/*dev: AxBlockDevice*/) -> Self {
        //assert_eq!(BLOCK_SIZE, dev.block_size());
        Self {
            block_id: 0,
            offset: 0,
            //dev,
        }
    }

    /// Get the size of the disk.
    pub fn size(&self) -> u64 {
        131072 * 512
        //self.dev.num_blocks() * BLOCK_SIZE as u64
    }

    /// Get the position of the cursor.
    pub fn position(&self) -> u64 {
        unimplemented!();
        //self.block_id * BLOCK_SIZE as u64 + self.offset as u64
    }

    /// Set the position of the cursor.
    pub fn set_position(&mut self, pos: u64) {
        self.block_id = pos / BLOCK_SIZE as u64;
        self.offset = pos as usize % BLOCK_SIZE;
    }

    /// Read within one block, returns the number of bytes read.
    pub fn read_one(&mut self, buf: &mut [u8]) -> DevResult<usize> {
        error!("blk_id {} offset: {}, buf_len: {}, BLOCK_SIZE: {}",
               self.block_id, self.offset, buf.len(), BLOCK_SIZE);
        let mut rbuf = [0u8; 4096];
        let blk_nr = self.block_id as usize;
        let ret = unsafe { cl_read_block(blk_nr, rbuf.as_mut_ptr(), 4096) };

        error!("buf: {}, {}, {}", rbuf[0], rbuf[1], rbuf[2]);
        let start = self.offset;
        let count = buf.len().min(4096 - self.offset);
        buf[..count].copy_from_slice(&rbuf[start..start + count]);
        self.offset += count;
        if self.offset >= BLOCK_SIZE {
            self.block_id += 1;
            self.offset -= BLOCK_SIZE;
        }
        return Ok(count);
        //unimplemented!();
        /*
        let read_size = if self.offset == 0 && buf.len() >= BLOCK_SIZE {
            // whole block
            self.dev
                .read_block(self.block_id, &mut buf[0..BLOCK_SIZE])?;
            self.block_id += 1;
            BLOCK_SIZE
        } else {
            // partial block
            let mut data = [0u8; BLOCK_SIZE];
            let start = self.offset;
            let count = buf.len().min(BLOCK_SIZE - self.offset);

            self.dev.read_block(self.block_id, &mut data)?;
            buf[..count].copy_from_slice(&data[start..start + count]);

            self.offset += count;
            if self.offset >= BLOCK_SIZE {
                self.block_id += 1;
                self.offset -= BLOCK_SIZE;
            }
            count
        };
        Ok(read_size)
        */
    }

    /// Write within one block, returns the number of bytes written.
    pub fn write_one(&mut self, buf: &[u8]) -> DevResult<usize> {
        Ok(buf.len())
        //unimplemented!();
        /*
        let write_size = if self.offset == 0 && buf.len() >= BLOCK_SIZE {
            // whole block
            self.dev.write_block(self.block_id, &buf[0..BLOCK_SIZE])?;
            self.block_id += 1;
            BLOCK_SIZE
        } else {
            // partial block
            let mut data = [0u8; BLOCK_SIZE];
            let start = self.offset;
            let count = buf.len().min(BLOCK_SIZE - self.offset);

            self.dev.read_block(self.block_id, &mut data)?;
            data[start..start + count].copy_from_slice(&buf[..count]);
            self.dev.write_block(self.block_id, &data)?;

            self.offset += count;
            if self.offset >= BLOCK_SIZE {
                self.block_id += 1;
                self.offset -= BLOCK_SIZE;
            }
            count
        };
        Ok(write_size)
        */
    }
}

unsafe extern "C" {
    fn cl_read_block(blk_nr: usize, rbuf: *mut u8, count: usize) -> i32;
}
