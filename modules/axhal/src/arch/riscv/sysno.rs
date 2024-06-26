///
/// Linux syscall
///

pub const LINUX_SYSCALL_GETCWD: usize = 0x11;
pub const LINUX_SYSCALL_IOCTL: usize = 0x1d;
pub const LINUX_SYSCALL_MKDIRAT: usize = 0x22;
pub const LINUX_SYSCALL_UNLINKAT: usize = 0x23;
pub const LINUX_SYSCALL_FACCESSAT: usize = 0x30;
pub const LINUX_SYSCALL_CHDIR: usize = 0x31;
pub const LINUX_SYSCALL_FCHMODAT: usize = 0x35;
pub const LINUX_SYSCALL_FCHOWNAT: usize = 0x36;
pub const LINUX_SYSCALL_OPENAT: usize = 0x38;
pub const LINUX_SYSCALL_CLOSE: usize = 0x39;
pub const LINUX_SYSCALL_GETDENTS64: usize = 0x3d;
pub const LINUX_SYSCALL_READ: usize = 0x3f;
pub const LINUX_SYSCALL_WRITE: usize = 0x40;
pub const LINUX_SYSCALL_WRITEV: usize = 0x42;
pub const LINUX_SYSCALL_READLINKAT: usize = 0x4e;
pub const LINUX_SYSCALL_FSTATAT: usize = 0x4f;
pub const LINUX_SYSCALL_EXIT: usize = 0x5d;
pub const LINUX_SYSCALL_EXIT_GROUP: usize = 0x5e;
pub const LINUX_SYSCALL_TGKILL: usize = 0x83;
pub const LINUX_SYSCALL_UNAME: usize = 0xa0;
pub const LINUX_SYSCALL_GETPID: usize = 0xac;
pub const LINUX_SYSCALL_GETGID: usize = 0xb0;
pub const LINUX_SYSCALL_GETTID: usize = 0xb2;
pub const LINUX_SYSCALL_BRK: usize = 0xd6;
pub const LINUX_SYSCALL_MUNMAP: usize = 0xd7;
pub const LINUX_SYSCALL_MMAP: usize = 0xde;
pub const LINUX_SYSCALL_MPROTECT: usize = 0xe2;
pub const LINUX_SYSCALL_MSYNC: usize = 0xe3;
pub const LINUX_SYSCALL_PRLIMIT64: usize = 0x105;
pub const LINUX_SYSCALL_GETRANDOM: usize = 0x116;
pub const LINUX_SYSCALL_RSEQ: usize = 0x125;

pub const LINUX_SYSCALL_SET_TID_ADDRESS: usize = 0x60;
pub const LINUX_SYSCALL_SET_ROBUST_LIST: usize = 0x63;
pub const LINUX_SYSCALL_CLOCK_GETTIME: usize = 0x71;
pub const LINUX_SYSCALL_RT_SIGACTION: usize = 0x86;
pub const LINUX_SYSCALL_RT_SIGPROCMASK: usize = 0x87;
