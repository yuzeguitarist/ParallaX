//! Linux epoll publication compatibility control for the TSan runtime.
//!
//! Both `same-fd` and `duplicate-fd` are race-free and must exit successfully.
//! The latter exercises OwnedFd::try_clone -> fcntl(F_DUPFD_CLOEXEC), used by
//! Mio's cloned registry. LLVM runtimes missing the interceptor from
//! https://github.com/llvm/llvm-project/pull/221064 report a false data race.
//! Run with the same instrumented std and runtime used for application tests.
//! This is a positive control, never an expected-race/negative canary.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Linux x86_64 UAPI. Keeping the control dependency-free avoids invoking
    // Tokio or substituting another runtime for the synchronization under test.
    const CLOEXEC: i32 = 0o2_000_000;
    const EPOLL_CTL_ADD: i32 = 1;
    const EPOLLIN: u32 = 1;
    const EXPECTED: usize = 0x51a7_c0de;

    #[repr(C, packed)]
    struct EpollEvent {
        events: u32,
        data: u64,
    }

    unsafe extern "C" {
        fn epoll_create1(flags: i32) -> i32;
        fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32;
        fn epoll_wait(epfd: i32, events: *mut EpollEvent, count: i32, timeout: i32) -> i32;
        fn eventfd(value: u32, flags: i32) -> i32;
    }

    fn owned(fd: i32) -> OwnedFd {
        assert!(
            fd >= 0,
            "descriptor creation: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: the successful syscall just returned an owned descriptor.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    pub fn run() {
        let mode = std::env::args_os()
            .nth(1)
            .expect("same-fd or duplicate-fd")
            .into_string()
            .expect("ASCII publication mode");
        assert!(matches!(mode.as_str(), "same-fd" | "duplicate-fd"));
        // SAFETY: flags are valid Linux UAPI values.
        let poll = Arc::new(owned(unsafe { epoll_create1(CLOEXEC) }));
        let registry = if mode == "duplicate-fd" {
            Arc::new(poll.try_clone().expect("duplicate the epoll descriptor"))
        } else {
            Arc::clone(&poll)
        };
        let reader_poll = Arc::clone(&poll);
        let reader = std::thread::spawn(move || {
            let mut event = EpollEvent { events: 0, data: 0 };
            // SAFETY: event is writable storage for exactly one kernel event;
            // the epoll descriptor remains owned throughout this call.
            let count = unsafe { epoll_wait(reader_poll.as_raw_fd(), &mut event, 1, 10_000) };
            assert_eq!(count, 1, "expected a real event, not timeout/error");
            assert_ne!(event.events & EPOLLIN, 0);
            let address = event.data as usize;
            assert_ne!(address, 0);
            // SAFETY: the sole event is registered below, after initializing
            // the atomic. Its Box stays alive until this thread is joined.
            // The kernel's epoll_ctl -> epoll_wait publication is the ONLY
            // synchronization between that initialization and this load.
            let value = unsafe { &*(address as *const AtomicUsize) };
            assert_eq!(value.load(Ordering::Acquire), EXPECTED);
        });

        // Create an already-ready source before initializing the value. There
        // is no write/read or channel exchange to accidentally publish it.
        // SAFETY: value and flags are valid Linux UAPI arguments.
        let ready = owned(unsafe { eventfd(1, CLOEXEC) });
        // This MUST stay after spawn: initializing before thread creation would
        // add a separate happens-before edge and make the control vacuous.
        let value = Box::new(AtomicUsize::new(EXPECTED));
        let mut event = EpollEvent {
            events: EPOLLIN,
            data: (&*value as *const AtomicUsize) as u64,
        };
        // SAFETY: both descriptors and event storage remain valid. epoll copies
        // the event, including its token, before exposing it to the waiter.
        let result = unsafe {
            epoll_ctl(
                registry.as_raw_fd(),
                EPOLL_CTL_ADD,
                ready.as_raw_fd(),
                &mut event,
            )
        };
        assert_eq!(result, 0, "epoll_ctl: {}", std::io::Error::last_os_error());
        reader.join().expect("the publication reader must succeed");
        assert_eq!(value.load(Ordering::Relaxed), EXPECTED);
        println!("sanitizer-epoll-publication-control-complete: {mode}");
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    linux::run();
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("epoll publication control requires Linux x86_64");
}
