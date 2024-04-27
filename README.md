# LK Model (based on ArceOS)

A validation model of modular operating system based on ArceOS.

Now we start from monolithic kernel mode which provides compatibility with Linux-Syscall.

🚧 Working In Progress.

## Features & TODOs

* [x] Architecture: riscv64, x86_64
* [x] Platform: virt (riscv64), QEMU pc-q35 (x86_64)

## Environment

WSL2: [ Ubuntu 22.04.1 LTS (GNU/Linux 4.19.128-microsoft-standard x86_64) ]

## Steps

1. Install toolchain for riscv64

   ```sh
   apt install gcc-riscv64-linux-gnu
   ```

2. Clone repo and enter project directory 'org_arceos'

   ```sh
   git clone git@github.com:shilei-massclouds/org_arceos.git
   cd org_arceos
   ```

3. Copy ld.so & libc.so to directory *./payload* for riscv64 & x86_64

   ```sh
   cp /usr/riscv64-linux-gnu/lib/libc.so.6 ./payload/riscv64/
   cp /usr/riscv64-linux-gnu/lib/ld-linux-riscv64-lp64d.so.1 ./payload/riscv64/

   cp /lib/x86_64-linux-gnu/libc.so.6 ./payload/x86_64/
   cp /lib64/ld-linux-x86-64.so.2 ./payload/x86_64/
   ```

4. Construct linux image (fat32)

   For riscv64:

   ```sh
   make linux_img
   ```

   For x86_64:

   ```sh
   make linux_img ARCH=x86_64
   ```

   > Remove current [riscv64|x86_64]_disk.img first if it exists.

5. Run it

   For riscv64:

   ```sh
   make run
   ```

   For x86_64:

   ```sh
   make run ARCH=x86_64
   ```

6. Drink a cup of tea and wait
