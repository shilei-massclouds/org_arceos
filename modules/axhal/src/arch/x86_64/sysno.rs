///
/// Linux syscall
///

pub const LINUX_SYSCALL_READ: usize = 0x0;
pub const LINUX_SYSCALL_WRITE: usize = 0x1;
pub const LINUX_SYSCALL_CLOSE: usize = 0x3;
pub const LINUX_SYSCALL_MMAP: usize = 0x9;
pub const LINUX_SYSCALL_MPROTECT: usize = 0xa;
pub const LINUX_SYSCALL_BRK: usize = 0xc;
pub const LINUX_SYSCALL_ACCESS: usize = 0x15;
pub const LINUX_SYSCALL_EXIT: usize = 0x3c;
pub const LINUX_SYSCALL_UNAME: usize = 0x3f;

pub const LINUX_SYSCALL_ARCH_PRCTL: usize = 0x9e;
pub const LINUX_SYSCALL_SET_TID_ADDRESS: usize = 0xda;
pub const LINUX_SYSCALL_CLOCK_GETTIME: usize = 0xe4;
pub const LINUX_SYSCALL_EXIT_GROUP: usize = 0xe7;
pub const LINUX_SYSCALL_OPENAT: usize = 0x101;
pub const LINUX_SYSCALL_FSTATAT: usize = 0x106;
pub const LINUX_SYSCALL_SET_ROBUST_LIST: usize = 0x111;
pub const LINUX_SYSCALL_PRLIMIT64: usize = 0x12e;
pub const LINUX_SYSCALL_GETRANDOM: usize = 0x13e;
pub const LINUX_SYSCALL_RSEQ: usize = 0x14e;

/*
pub const LINUX_SYSCALL_GETCWD: usize = 0x11;
pub const LINUX_SYSCALL_IOCTL: usize = 0x1d;
pub const LINUX_SYSCALL_MKDIRAT: usize = 0x22;
pub const LINUX_SYSCALL_UNLINKAT: usize = 0x23;
pub const LINUX_SYSCALL_FACCESSAT: usize = 0x30;
pub const LINUX_SYSCALL_CHDIR: usize = 0x31;
pub const LINUX_SYSCALL_CHMODAT: usize = 0x35;
pub const LINUX_SYSCALL_CHOWNAT: usize = 0x36;
pub const LINUX_SYSCALL_GETDENTS64: usize = 0x3d;
pub const LINUX_SYSCALL_WRITEV: usize = 0x42;
pub const LINUX_SYSCALL_READLINKAT: usize = 0x4e;
pub const LINUX_SYSCALL_TGKILL: usize = 0x83;
pub const LINUX_SYSCALL_GETPID: usize = 0xac;
pub const LINUX_SYSCALL_GETGID: usize = 0xb0;
pub const LINUX_SYSCALL_GETTID: usize = 0xb2;
pub const LINUX_SYSCALL_MUNMAP: usize = 0xd7;
pub const LINUX_SYSCALL_MSYNC: usize = 0xe3;
*/

/*
pub const LINUX_SYSCALL_RT_SIGACTION: usize = 0x86;
pub const LINUX_SYSCALL_RT_SIGPROCMASK: usize = 0x87;
*/
