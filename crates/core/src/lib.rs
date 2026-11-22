//! PawKey's insides, kept apart from the window so they can be tested alone.

pub mod keyfile;
pub mod qr;
pub mod sync;
pub mod totp;
pub mod vault;

/// Keeps secrets out of crash dumps: no core file, and (on Linux and
/// Android) not dumpable, which also keeps other programs of the same user
/// from attaching a debugger and reading memory. Called first thing.
pub fn harden_process() {
    #[cfg(unix)]
    unsafe {
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}
