//!
//! A session runs a filesystem implementation while it is being mounted
//! to a specific mount point. A session begins by mounting the filesystem
//! and ends by unmounting it. While the filesystem is mounted, the session
//! loop receives, dispatches and replies to kernel requests for filesystem
//! operations under its mount point.
//!

use std::io;
use std::ffi::OsStr;
use std::fmt;
use std::path::{PathBuf, Path};
use thread_scoped::{scoped, JoinGuard};
use libc::{EAGAIN, EINTR, ENODEV, ENOENT};
use channel::{self, Channel};
use Filesystem;
use request;
use failure::Error;

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on OS X
/// and 128k on other systems.
pub const MAX_WRITE_SIZE: usize = 16*1024*1024;

/// Size of the buffer for reading a request from the kernel. Since the kernel may send
/// up to MAX_WRITE_SIZE bytes in a write request, we use that value plus some extra space.
const BUFFER_SIZE: usize = MAX_WRITE_SIZE + 4096;

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem operation implementations
    pub filesystem: FS,
    /// Communication channel to the kernel driver
    ch: Channel,
    /// FUSE protocol major version
    pub proto_major: u32,
    /// FUSE protocol minor version
    pub proto_minor: u32,
    /// True if the filesystem is initialized (init operation done)
    pub initialized: bool,
    /// True if the filesystem was destroyed (destroy operation done)
    pub destroyed: bool,
}

impl<FS: Filesystem> Session<FS> {
    /// Create a new session by mounting the given filesystem to the given mountpoint
    pub fn new (filesystem: FS, mountpoint: &Path, options: &[&OsStr]) -> Result<Session<FS>, Error> {
        info!("Mounting {}", mountpoint.display());
        Channel::new(mountpoint, options).map(
            |ch| Session {
                filesystem: filesystem,
                ch: ch,
                proto_major: 0,
                proto_minor: 0,
                initialized: false,
                destroyed: false,
            })
    }

    /// Return path of the mounted filesystem
    pub fn mountpoint (&self) -> &Path {
        &self.ch.mountpoint()
    }

    /// Returns an asynchronous rust session that can run in a custom event
    /// loop. The file descriptor is set to nonblocking to ensure it works
    /// correctly from tokio.
    #[cfg(feature = "mio")]
    pub fn evented(self) -> io::Result<FuseEvented<FS>> {
        self.ch.set_nonblocking(true)?;
        Ok(FuseEvented(self))
    }

    /// Receive a single kernel request and dispatches it to method calls into
    /// te filesystem. This method is meant to be used in an event loop, with
    /// mio.
    ///
    /// Takes a buffer to allow reducing allocations.
    pub fn handle_one_req(&mut self, buf: &mut Vec<u8>) -> Result<(), Error> {
        match self.ch.receive(buf) {
            Ok(()) => match request::request(self.ch.sender(), &buf) {
                    // Dispatch request
                    Some(req) => Ok(request::dispatch(&req, self)?),
                    // Quit loop on illegal request
                    None => Err(io::Error::last_os_error().into()),
            },
            Err(err) => match err.raw_os_error() {
                    // Operation interrupted. Accordingly to FUSE, this is safe to retry
                    Some(ENOENT) => Ok(()),
                    // Interrupted system call, retry
                    Some(EINTR) => Ok(()),
                    // Explicitly try again
                    Some(EAGAIN) => Ok(()),
                    // Filesystem was unmounted, quit the loop
                    Some(ENODEV) => Ok(()),
                    // Unhandled error
                    _ => return Err(err.into()),
            },
        }
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    pub fn run (&mut self) -> Result<(), Error> {
        // Buffer for receiving requests from the kernel. Only one is allocated and
        // it is reused immediately after dispatching to conserve memory and allocations.
        let mut buffer: Vec<u8> = Vec::with_capacity(BUFFER_SIZE);
        loop {
            // Read the next request from the given channel to kernel driver
            // The kernel driver makes sure that we get exactly one request per read
            match self.ch.receive(&mut buffer) {
                Ok(()) => match request::request(self.ch.sender(), &buffer) {
                    // Dispatch request
                    Some(req) => request::dispatch(&req, self)?,
                    // Quit loop on illegal request
                    None => break,
                },
                Err(err) => match err.raw_os_error() {
                    // Operation interrupted. Accordingly to FUSE, this is safe to retry
                    Some(ENOENT) => continue,
                    // Interrupted system call, retry
                    Some(EINTR) => continue,
                    // Explicitly try again
                    Some(EAGAIN) => continue,
                    // Filesystem was unmounted, quit the loop
                    Some(ENODEV) => break,
                    // Unhandled error
                    _ => return Err(err.into()),
                },
            }
        }
        Ok(())
    }
}

impl<'a, FS: Filesystem+Send+'a> Session<FS> {
    /// Run the session loop in a background thread
    pub unsafe fn spawn (self) -> Result<BackgroundSession<'a>, Error> {
        BackgroundSession::new(self)
    }
}

impl<FS: Filesystem> Drop for Session<FS> {
    fn drop (&mut self) {
        info!("Unmounted {}", self.mountpoint().display());
    }
}

/// The background session data structure
pub struct BackgroundSession<'a> {
    /// Path of the mounted filesystem
    pub mountpoint: PathBuf,
    /// Thread guard of the background session
    pub guard: JoinGuard<'a, io::Result<()>>,
}

impl<'a> BackgroundSession<'a> {
    /// Create a new background session for the given session by running its
    /// session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the given session ends.
    pub unsafe fn new<FS: Filesystem+Send+'a> (se: Session<FS>) -> Result<BackgroundSession<'a>, Error> {
        let mountpoint = se.mountpoint().to_path_buf();
        let guard = scoped(move || {
            let mut se = se;
            if let Err(_) = se.run() {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
        Ok(BackgroundSession { mountpoint: mountpoint, guard: guard })
    }
}

impl<'a> Drop for BackgroundSession<'a> {
    fn drop (&mut self) {
        info!("Unmounting {}", self.mountpoint.display());
        // Unmounting the filesystem will eventually end the session loop,
        // drop the session and hence end the background thread.
        match channel::unmount(&self.mountpoint) {
            Ok(()) => (),
            Err(err) => error!("Failed to unmount {}: {}", self.mountpoint.display(), err),
        }
    }
}

// replace with #[derive(Debug)] if Debug ever gets implemented for
// thread_scoped::JoinGuard
impl<'a> fmt::Debug for BackgroundSession<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "BackgroundSession {{ mountpoint: {:?}, guard: JoinGuard<()> }}", self.mountpoint)
    }
}

cfg_if! {
    if #[cfg(feature = "mio")] {
        use mio::{Evented, Poll, Token, Ready, PollOpt};
        use mio::unix::EventedFd;

        ///
        /// A FuseEvented provides a way to use the FUSE filesystem in a custom event
        /// loop. It implements the mio Evented trait, so it can be polled for
        /// readiness.
        ///
        /// ```rust
        /// # extern crate rust_fuse;
        /// # extern crate mio;
        /// # use rust_fuse::mount_evented;
        ///
        /// let FUSE: mio::Token = Token(0);
        /// let poll = mio::Poll::new()?;
        /// let fuse_handle = mount_evented(fs, mountpoint, &[])?;
        /// // Start listening for incoming connections
        /// poll.register(&fuse_handle, FUSE, mio::Ready::readable(),
        ///               mio::PollOpt::edge())?;
        /// // Other potential registers here
        /// 
        /// // Create storage for events
        /// let mut events = mio::Events::with_capacity(1024);
        /// loop {
        ///     poll.poll(&mut events, None)?;
        /// 
        ///     for event in events.iter() {
        ///         match event.token() {
        ///             FUSE => {
        ///                 fuse_handle.handle_one();
        ///             }
        ///             // Handle other registers
        ///             _ => unreachable!(),
        ///         }
        ///     }
        /// }
        /// # }
        /// ```
        ///
        // TODO: Drop
        #[derive(Debug)]
        pub struct FuseEvented<FS: Filesystem>(Session<FS>);

        impl<FS: Filesystem>  Evented for FuseEvented<FS> {
            fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
                EventedFd(&self.0.ch.fd).register(poll, token, interest, opts)
            }
            fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
                EventedFd(&self.0.ch.fd).reregister(poll, token, interest, opts)
            }
            fn deregister(&self, poll: &Poll) -> io::Result<()> {
                EventedFd(&self.0.ch.fd).deregister(poll)
            }
        }

        impl<FS: Filesystem> FuseEvented<FS> {
            /// Read and execute one fuse's request before returning
            pub fn handle_one_req(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
                self.0.handle_one_req(buf)
            }
        }
    }
}
