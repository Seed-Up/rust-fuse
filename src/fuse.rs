//!
//! FUSE native interface declarations (as of libosxfuse-2.5.5).
//!

#![allow(non_camel_case_types, missing_docs, dead_code)]

use fuse_opts::fuse_args;

cfg_if! {
    if #[cfg(feature="rust-mount")] {
        use fuse_opts::{FuseOpts, MetaFuseOpt};
        use std::ffi::CStr;
        use std::slice;
    }
}
//
// FUSE kernel (see fuse_kernel.h for details)
//

pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 8;
pub const FUSE_ROOT_ID: u64 = 1;

#[repr(C)]
#[derive(Debug)]
pub struct fuse_attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    #[cfg(target_os = "macos")]
    pub crtime: i64,            // OS X only
    pub atimensec: i32,
    pub mtimensec: i32,
    pub ctimensec: i32,
    #[cfg(target_os = "macos")]
    pub crtimensec: i32,        // OS X only
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    #[cfg(target_os = "macos")]
    pub flags: u32,             // OS X only, see chflags(2)
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_kstatfs {
    pub blocks: u64,            // Total blocks (in units of frsize)
    pub bfree: u64,             // Free blocks
    pub bavail: u64,            // Free blocks for unprivileged users
    pub files: u64,             // Total inodes
    pub ffree: u64,             // Free inodes
    pub bsize: u32,             // Filesystem block size
    pub namelen: u32,           // Maximum filename length
    pub frsize: u32,            // Fundamental file system block size
    pub padding: u32,
    pub spare: [u32; 6],
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_file_lock {
    pub start: u64,
    pub end: u64,
    pub typ: u32,
    pub pid: u32,
}

pub mod consts {
    // Bitmasks for fuse_setattr_in.valid
    pub const FATTR_MODE: u32               = 1 << 0;
    pub const FATTR_UID: u32                = 1 << 1;
    pub const FATTR_GID: u32                = 1 << 2;
    pub const FATTR_SIZE: u32               = 1 << 3;
    pub const FATTR_ATIME: u32              = 1 << 4;
    pub const FATTR_MTIME: u32              = 1 << 5;
    pub const FATTR_FH: u32                 = 1 << 6;
    #[cfg(target_os = "macos")]
    pub const FATTR_CRTIME: u32             = 1 << 28;  // OS X only
    #[cfg(target_os = "macos")]
    pub const FATTR_CHGTIME: u32            = 1 << 29;  // OS X only
    #[cfg(target_os = "macos")]
    pub const FATTR_BKUPTIME: u32           = 1 << 30;  // OS X only
    #[cfg(target_os = "macos")]
    pub const FATTR_FLAGS: u32              = 1 << 31;  // OS X only

    // Flags returned by the open request
    pub const FOPEN_DIRECT_IO: u32          = 1 << 0;   // bypass page cache for this open file
    pub const FOPEN_KEEP_CACHE: u32         = 1 << 1;   // don't invalidate the data cache on open
    #[cfg(target_os = "macos")]
    pub const FOPEN_PURGE_ATTR: u32         = 1 << 30;  // OS X only
    #[cfg(target_os = "macos")]
    pub const FOPEN_PURGE_UBC: u32          = 1 << 31;  // OS X only

    // Init request/reply flags
    pub const FUSE_ASYNC_READ: u32          = 1 << 0;
    pub const FUSE_POSIX_LOCKS: u32         = 1 << 1;
    pub const FUSE_FILE_OPS: u32            = 1 << 2;
    pub const FUSE_ATOMIC_O_TRUNC: u32      = 1 << 3;
    pub const FUSE_EXPORT_SUPPORT: u32      = 1 << 4;
    pub const FUSE_BIG_WRITES: u32          = 1 << 5;
    pub const FUSE_DONT_MASK: u32           = 1 << 6;
    #[cfg(target_os = "macos")]
    pub const FUSE_CASE_INSENSITIVE: u32    = 1 << 29;  // OS X only
    #[cfg(target_os = "macos")]
    pub const FUSE_VOL_RENAME: u32          = 1 << 30;  // OS X only
    #[cfg(target_os = "macos")]
    pub const FUSE_XTIMES: u32              = 1 << 31;  // OS X only

    // Release flags
    pub const FUSE_RELEASE_FLUSH: u32       = 1 << 0;
}

#[repr(C)]
#[derive(Debug)]
pub enum fuse_opcode {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2,            // no reply
    FUSE_GETATTR = 3,
    FUSE_SETATTR = 4,
    FUSE_READLINK = 5,
    FUSE_SYMLINK = 6,
    FUSE_MKNOD = 8,
    FUSE_MKDIR = 9,
    FUSE_UNLINK = 10,
    FUSE_RMDIR = 11,
    FUSE_RENAME = 12,
    FUSE_LINK = 13,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_WRITE = 16,
    FUSE_STATFS = 17,
    FUSE_RELEASE = 18,
    FUSE_FSYNC = 20,
    FUSE_SETXATTR = 21,
    FUSE_GETXATTR = 22,
    FUSE_LISTXATTR = 23,
    FUSE_REMOVEXATTR = 24,
    FUSE_FLUSH = 25,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_FSYNCDIR = 30,
    FUSE_GETLK = 31,
    FUSE_SETLK = 32,
    FUSE_SETLKW = 33,
    FUSE_ACCESS = 34,
    FUSE_CREATE = 35,
    FUSE_INTERRUPT = 36,
    FUSE_BMAP = 37,
    FUSE_DESTROY = 38,
    #[cfg(target_os = "macos")]
    FUSE_SETVOLNAME = 61,       // OS X only
    #[cfg(target_os = "macos")]
    FUSE_GETXTIMES = 62,        // OS X only
    #[cfg(target_os = "macos")]
    FUSE_EXCHANGE = 63,         // OS X only
}

// FIXME: Hopefully Rust will once have a more convenient way of converting primitive to enum
impl fuse_opcode {
    pub fn from_u32 (n: u32) -> Option<fuse_opcode> {
        match n {
            1 => Some(fuse_opcode::FUSE_LOOKUP),
            2 => Some(fuse_opcode::FUSE_FORGET),
            3 => Some(fuse_opcode::FUSE_GETATTR),
            4 => Some(fuse_opcode::FUSE_SETATTR),
            5 => Some(fuse_opcode::FUSE_READLINK),
            6 => Some(fuse_opcode::FUSE_SYMLINK),
            8 => Some(fuse_opcode::FUSE_MKNOD),
            9 => Some(fuse_opcode::FUSE_MKDIR),
            10 => Some(fuse_opcode::FUSE_UNLINK),
            11 => Some(fuse_opcode::FUSE_RMDIR),
            12 => Some(fuse_opcode::FUSE_RENAME),
            13 => Some(fuse_opcode::FUSE_LINK),
            14 => Some(fuse_opcode::FUSE_OPEN),
            15 => Some(fuse_opcode::FUSE_READ),
            16 => Some(fuse_opcode::FUSE_WRITE),
            17 => Some(fuse_opcode::FUSE_STATFS),
            18 => Some(fuse_opcode::FUSE_RELEASE),
            20 => Some(fuse_opcode::FUSE_FSYNC),
            21 => Some(fuse_opcode::FUSE_SETXATTR),
            22 => Some(fuse_opcode::FUSE_GETXATTR),
            23 => Some(fuse_opcode::FUSE_LISTXATTR),
            24 => Some(fuse_opcode::FUSE_REMOVEXATTR),
            25 => Some(fuse_opcode::FUSE_FLUSH),
            26 => Some(fuse_opcode::FUSE_INIT),
            27 => Some(fuse_opcode::FUSE_OPENDIR),
            28 => Some(fuse_opcode::FUSE_READDIR),
            29 => Some(fuse_opcode::FUSE_RELEASEDIR),
            30 => Some(fuse_opcode::FUSE_FSYNCDIR),
            31 => Some(fuse_opcode::FUSE_GETLK),
            32 => Some(fuse_opcode::FUSE_SETLK),
            33 => Some(fuse_opcode::FUSE_SETLKW),
            34 => Some(fuse_opcode::FUSE_ACCESS),
            35 => Some(fuse_opcode::FUSE_CREATE),
            36 => Some(fuse_opcode::FUSE_INTERRUPT),
            37 => Some(fuse_opcode::FUSE_BMAP),
            38 => Some(fuse_opcode::FUSE_DESTROY),
            #[cfg(target_os = "macos")]
            61 => Some(fuse_opcode::FUSE_SETVOLNAME),
            #[cfg(target_os = "macos")]
            62 => Some(fuse_opcode::FUSE_GETXTIMES),
            #[cfg(target_os = "macos")]
            63 => Some(fuse_opcode::FUSE_EXCHANGE),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_entry_out {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: i64,
    pub attr_valid: i64,
    pub entry_valid_nsec: i32,
    pub attr_valid_nsec: i32,
    pub attr: fuse_attr,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_forget_in {
    pub nlookup: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_attr_out {
    pub attr_valid: i64,
    pub attr_valid_nsec: i32,
    pub dummy: u32,
    pub attr: fuse_attr,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug)]
pub struct fuse_getxtimes_out { // OS X only
    pub bkuptime: i64,
    pub crtime: i64,
    pub bkuptimensec: i32,
    pub crtimensec: i32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_mknod_in {
    pub mode: u32,
    pub rdev: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_mkdir_in {
    pub mode: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_rename_in {
    pub newdir: u64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug)]
pub struct fuse_exchange_in {   // OS X only
    pub olddir: u64,
    pub newdir: u64,
    pub options: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_link_in {
    pub oldnodeid: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_setattr_in {
    pub valid: u32,
    pub padding: u32,
    pub fh: u64,
    pub size: u64,
    pub unused1: u64,
    pub atime: i64,
    pub mtime: i64,
    pub unused2: u64,
    pub atimensec: i32,
    pub mtimensec: i32,
    pub unused3: u32,
    pub mode: u32,
    pub unused4: u32,
    pub uid: u32,
    pub gid: u32,
    pub unused5: u32,
    #[cfg(target_os = "macos")]
    pub bkuptime: i64,          // OS X only
    #[cfg(target_os = "macos")]
    pub chgtime: i64,           // OS X only
    #[cfg(target_os = "macos")]
    pub crtime: i64,            // OS X only
    #[cfg(target_os = "macos")]
    pub bkuptimensec: i32,      // OS X only
    #[cfg(target_os = "macos")]
    pub chgtimensec: i32,       // OS X only
    #[cfg(target_os = "macos")]
    pub crtimensec: i32,        // OS X only
    #[cfg(target_os = "macos")]
    pub flags: u32,             // OS X only
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_open_in {
    pub flags: u32,
    pub mode: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_open_out {
    pub fh: u64,
    pub open_flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_release_in {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_flush_in {
    pub fh: u64,
    pub unused: u32,
    pub padding: u32,
    pub lock_owner: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_read_in {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_write_in {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_write_out {
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_statfs_out {
    pub st: fuse_kstatfs,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_fsync_in {
    pub fh: u64,
    pub fsync_flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_setxattr_in {
    pub size: u32,
    pub flags: u32,
    #[cfg(target_os = "macos")]
    pub position: u32,          // OS X only
    #[cfg(target_os = "macos")]
    pub padding: u32,           // OS X only
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_getxattr_in {
    pub size: u32,
    pub padding: u32,
    #[cfg(target_os = "macos")]
    pub position: u32,          // OS X only
    #[cfg(target_os = "macos")]
    pub padding2: u32,          // OS X only
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_getxattr_out {
    pub size: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_lk_in {
    pub fh: u64,
    pub owner: u64,
    pub lk: fuse_file_lock,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_lk_out {
    pub lk: fuse_file_lock,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_access_in {
    pub mask: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_init_in {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_init_out {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub unused: u32,
    pub max_write: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_interrupt_in {
    pub unique: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_bmap_in {
    pub block: u64,
    pub blocksize: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_bmap_out {
    pub block: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_in_header {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_out_header {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct fuse_dirent {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub typ: u32,
    // followed by name of namelen bytes
}

#[cfg(feature="rust-mount")]
use std::ffi::CString;
#[cfg(feature="rust-mount")]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

#[cfg(feature="rust-mount")]
use libc::getuid;
#[cfg(feature="rust-mount")]
use libc::getgid;
#[cfg(feature="rust-mount")]
use libc::mount;
#[cfg(feature="rust-mount")]
use std::fs::OpenOptions;
#[cfg(feature="rust-mount")]
use std::os::unix::io::AsRawFd;
#[cfg(feature="rust-mount")]
use std::os::unix::io::IntoRawFd;

use std;

mod sys {
    #[cfg(not(feature="rust-mount"))]
    use libc::{c_int, c_char};
    #[cfg(not(feature="rust-mount"))]
    use super::fuse_args;
    extern "system" {
        #[cfg(not(feature="rust-mount"))]
        pub fn fuse_mount_compat25(mountpoint: *const c_char, args: *const fuse_args) -> c_int;
        #[cfg(not(feature="rust-mount"))]
        pub fn fuse_unmount_compat22 (mountpoint: *const c_char);
    }
}

#[cfg(feature="rust-mount")]
fn fuse_mount_sys(mountpoint: &PathBuf, flags: u64, mnt_opts: &FuseOpts) -> i32
{
    // TODO:Check mountpoint
    // TODO:Check nonempty
    // TODO:Check auto_umount
    let f = OpenOptions::new().read(true).write(true).open("/dev/fuse").unwrap();

    let opts = format!("fd={},{}",
                       f.as_raw_fd(),
                       mnt_opts.to_string());
    info!("{}", opts);
    // TODO: Add kernel opt
    // 
    //TODO: understand:
    /*
	strcpy(type, mo->blkdev ? "fuseblk" : "fuse");
	if (mo->subtype) {
		strcat(type, ".");
		strcat(type, mo->subtype);
	}
	strcpy(source,
	       mo->fsname ? mo->fsname : (mo->subtype ? mo->subtype : devname));
    */
    let c_sources = CString::new("/dev/fuse").unwrap();
    let c_mnt = CString::new(mountpoint.as_os_str().as_bytes()).unwrap();
    let c_fs = CString::new("fuse").unwrap();
    let c_opts = CString::new(opts).unwrap();
    info!("MOUNT({:?} {:?} {:?} {:?})", c_sources, c_mnt, c_fs, c_opts);
    let res = unsafe{
        #[cfg(target_pointer_width = "32")]
        let flags = flags as u32;
        mount(c_sources.as_ptr(), c_mnt.as_ptr(), c_fs.as_ptr(), flags, c_opts.as_ptr() as *mut c_void)
    };
    if res < 0 {
        return res;
    } else {
        return f.into_raw_fd();
    }
}

// /usr/include/sys/mount.h
const MS_NOSUID :u64 = 2;
const MS_NODEV  :u64 = 4;
const FUSE_COMMFD_ENV: &str = "_FUSE_COMMFD";

cfg_if! {
    if #[cfg(feature = "rust-mount")] {
        use sendfd::UnixSendFd;
        use std::process::{Command, Stdio};
        use std::os::unix::net::UnixStream;
        use libc::{self, c_void};
        use errno::errno;
        use std::mem;

        fn fuse_mount_fusermount(mountpoint: &PathBuf, _: &fuse_args, mnt_opts: &FuseOpts) -> i32
        {
            let (sock1, sock2) = match UnixStream::pair() {
                Ok(res) => res,
                Err(err) => {
                    error!("{:?}", err);
                    return -1;
                }
            };
            let fd = sock2.as_raw_fd();

            unsafe {
                libc::fcntl(fd, libc::F_SETFD, 0);
            }
            let mut fusermount = Command::new("fusermount");
            if mnt_opts.opts_fuse.len() > 0 {
                fusermount.arg("-o").arg(
                    mnt_opts.opts_fuse.iter()
                    .map(|x| x.to_string()).collect::<Vec<String>>().join(",")
                    );
            }
            if mnt_opts.opts_fusermount.len() > 0 {
                fusermount.arg("-o").arg(
                    mnt_opts.opts_fusermount.iter()
                    .map(|x| x.to_string()).collect::<Vec<String>>().join(",")
                    );
            }

            match fusermount
                .arg("--")
                .arg(mountpoint)
                .env(FUSE_COMMFD_ENV, format!("{}", fd))
                .stdout(Stdio::inherit())
                .spawn() {
                    Ok(_) => (),
                    Err(err) => {
                        error!("{:?}", err);
                        return -1;
                    }
                };
            let res = sock1.recvfd().unwrap_or(-1);
            if is_opt_fusemount!(AutoUnmount, mnt_opts) {
                info!("forget fusermount socket");
                mem::forget(sock1);
            }
            return res;
        }

        fn fuse_kern_mount(mountpoint: &PathBuf, args: &fuse_args) -> i32
        {
            let flags = MS_NOSUID | MS_NODEV;
            let mut mnt_opts = FuseOpts::new();
            mnt_opts.fuse_opt_parse(args);

            if let None = get_opt_fuse!(Uid, mnt_opts) {
                mnt_opts.add_opt(MetaFuseOpt::Uid(unsafe{getuid()}));
            }
            if let None = get_opt_fuse!(Gid, mnt_opts) {
                mnt_opts.add_opt(MetaFuseOpt::Gid(unsafe{getgid()}));
            }
            if let None = get_opt_fuse!(RootMode, mnt_opts) {
                mnt_opts.add_opt(MetaFuseOpt::RootMode(40755));
            }
            // TODO: check if allow_other and allow_root aren't mutually active
            // TODO: check if help
            // TODO: get kernel/other flags options

            let mut res = fuse_mount_sys(mountpoint, flags, &mnt_opts);
            if cfg!(not(feature = "nofusermount")) && res < 0 {
                let err = errno().0;
                error!("fuse_mount_sys errno: {}", err);
                // TODO: error
                if err == libc::EPERM {
                    warn!("fuse_mount_sys EPERM: backing to fusermount...");
                    res = fuse_mount_fusermount(mountpoint, args, &mnt_opts);
                } else {
                    panic!("Err {}: fuse_kern_mount panic !", err);
                }
            }
            info!("fantafs: fuse_mount_compat25: fd={}", res);
            res
        }

        fn fuse_opt_parse(args: &fuse_args) -> Vec<String> {
            let argv: Vec<&str> = unsafe {
                let paths: &[*const _] = slice::from_raw_parts(args.argv, args.argc as usize);
                paths.iter().map(
                    |cs| CStr::from_ptr(*cs).to_str().expect("Error convert argv")
                    ).collect()
            };

            argv.iter().filter_map(|&arg| {
                if let ("-o", opt) = arg.split_at(2) {
                    let opt_name_len = opt.find('=').unwrap_or(opt.len());
                    let (pattern, _) = opt.split_at(opt_name_len);
                    match pattern {
                        "allow_other" 
                            | "auto_unmount"
                            | "default_permissions"
                            | "rootmode"
                            | "blkdev"
                            | "blksize"
                            | "max_read"
                            | "fd"
                            | "user_id"
                            | "fsname"
                            | "subtype" => {
                                Some(String::from(opt))
                            }
                        _ => None
                    }
                } else {
                    None
                }
            }).collect()
        }

        pub fn fuse_mount_compat25(mountpoint: &PathBuf, args: &fuse_args) -> std::io::Result<i32>
        {
            Ok(fuse_kern_mount(mountpoint, args))
        }
    }
}
#[cfg(not(feature="rust-mount"))]
pub fn fuse_mount_compat25(mountpoint: &PathBuf, args: &fuse_args) -> std::io::Result<i32>
{
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mnt = try!(CString::new(mountpoint.as_os_str().as_bytes()));
    let fd = unsafe { sys::fuse_mount_compat25(mnt.as_ptr(), args) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}
