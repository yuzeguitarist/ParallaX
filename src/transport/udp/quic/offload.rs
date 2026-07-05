//! Linux UDP segmentation/aggregation offload (GSO/GRO) for the QUIC carrier.
//!
//! The driver sends one QUIC datagram per `send_to` and reads one per `recv_from`.
//! On a bulk transfer that is one syscall per ~1252-byte packet — at line rate the
//! process burns its time in kernel transitions, not crypto. This module batches
//! that I/O on Linux with the kernel's generic offloads:
//!
//! * **GSO (`UDP_SEGMENT`)** — hand the kernel one large buffer plus a segment size;
//!   it slices the buffer into equal-sized datagrams (the last may be smaller) and
//!   emits them individually on the wire. One `sendmsg` replaces N `send_to`s.
//! * **GRO (`UDP_GRO`)** — the kernel coalesces consecutive same-flow datagrams into
//!   one `recvmsg` buffer and reports the segment size via a control message; the
//!   caller re-splits it into the original datagrams.
//!
//! **Covertness invariant:** these are host-local kernel offloads. GSO segments are
//! transmitted as independent datagrams of exactly the same sizes the per-datagram
//! path would have sent; GRO only changes how *inbound* bytes are gathered for the
//! local read. Neither changes a single byte, size, or count on the wire. Every path
//! degrades to the plain `send_to`/`recv_from` behaviour when the kernel lacks the
//! offload (older kernels, non-Linux), so correctness never depends on it.

#[cfg(target_os = "linux")]
pub use linux::{enable_gro, enable_recv_ecn, recv_gro, send_gso, send_mmsg};

// Public diagnostics surface: a stats endpoint reads `offload_stats()`. Not yet wired
// to a caller in-crate, so allow the unused re-export rather than fabricate one.
#[allow(unused_imports)]
pub use stats::{offload_stats, OffloadStats};
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
pub(super) use stats::{record_gro_read, record_gso_call, record_gso_fallback};

/// The ECN codepoint ECT(0) (RFC 3168): the low two bits of the IP TOS / IPv6 traffic
/// class byte set to `0b10`. A real Safari QUIC flow marks essentially every datagram
/// ECT(0) from the first Initial (confirmed against a live capture), so a ParallaX
/// flow that leaves datagrams Not-ECT is the actual passive distinguisher — marking
/// ECT(0) is camouflage-positive, not just RFC-permitted (RFC 9000 §13.4).
#[cfg(unix)]
const ECN_ECT0: libc::c_int = 0b10;

/// Mark all egress datagrams on `socket` as ECT(0) by setting the ECN bits of the IP
/// TOS (IPv4) / traffic-class (IPv6) byte. Best-effort and wire-shaping only in the
/// IP header's 2 ECN bits — the QUIC payload, sizes, and counts are untouched. A
/// kernel that rejects the option just leaves datagrams Not-ECT (the prior behaviour).
/// Returns whether the option took, for the recv-side ECN-validation default + tests.
#[cfg(unix)]
pub fn enable_ect0<S: std::os::fd::AsFd>(socket: &S, is_ipv6: bool) -> bool {
    use std::os::fd::AsRawFd;
    let fd = socket.as_fd().as_raw_fd();
    let tos: libc::c_int = ECN_ECT0;
    // IPv4 uses IP_TOS; IPv6 uses IPV6_TCLASS. A dual-stack v6 socket carries v4-mapped
    // traffic in the v6 header, so for a v6 bind set the v6 traffic class.
    let (level, optname) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
    } else {
        (libc::IPPROTO_IP, libc::IP_TOS)
    };
    // SAFETY: setsockopt with a pointer to a stack-local c_int of matching length on a
    // valid borrowed fd; it only mutates this socket's option state.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            (&tos as *const libc::c_int).cast(),
            std::mem::size_of_val(&tos) as libc::socklen_t,
        )
    };
    rc == 0
}

#[cfg(not(unix))]
pub fn enable_ect0<S>(_socket: &S, _is_ipv6: bool) -> bool {
    false
}

/// Process-wide GSO/GRO offload counters (PR #120 follow-up #1). PR #120 shipped the
/// Linux GSO/GRO batching with no way to tell, on a running server, whether the
/// kernel offload is actually engaging or whether every flush silently takes the
/// per-datagram fallback — so the throughput win could not be confirmed. These
/// counters make the offload observable: the GSO hit/fallback split and the GRO
/// coalescing factor. They are pure host-local bookkeeping (no wire effect) and the
/// recording API is platform-agnostic so the test runs on every target, even where
/// the syscalls do not exist.
mod stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// One process-wide counter set. Singleton in [`COUNTERS`].
    struct Counters {
        /// GSO `sendmsg` calls the kernel accepted (a multi-datagram run sent in one
        /// syscall).
        gso_calls: AtomicU64,
        /// Datagrams emitted via accepted GSO calls (each would have cost one `send_to`
        /// on the per-datagram path).
        gso_datagrams: AtomicU64,
        /// Runs that fell back to per-datagram `send_to` (no GSO, oversized, transient
        /// error, short count, or not-writable).
        gso_fallback_runs: AtomicU64,
        /// `recvmsg` reads on the GRO path.
        gro_reads: AtomicU64,
        /// Datagrams recovered from GRO reads (the re-split chunk count). Equal to
        /// `gro_reads` with no coalescing; above it when the kernel gathered several
        /// datagrams per read.
        gro_coalesced_datagrams: AtomicU64,
    }

    static COUNTERS: Counters = Counters {
        gso_calls: AtomicU64::new(0),
        gso_datagrams: AtomicU64::new(0),
        gso_fallback_runs: AtomicU64::new(0),
        gro_reads: AtomicU64::new(0),
        gro_coalesced_datagrams: AtomicU64::new(0),
    };

    /// Record one accepted GSO call that emitted `datagrams` datagrams.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn record_gso_call(datagrams: u64) {
        COUNTERS.gso_calls.fetch_add(1, Ordering::Relaxed);
        COUNTERS
            .gso_datagrams
            .fetch_add(datagrams, Ordering::Relaxed);
    }

    /// Record one run that fell back to the per-datagram path.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn record_gso_fallback() {
        COUNTERS.gso_fallback_runs.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one GRO `recvmsg` that yielded `datagrams` datagrams after re-splitting.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn record_gro_read(datagrams: u64) {
        COUNTERS.gro_reads.fetch_add(1, Ordering::Relaxed);
        COUNTERS
            .gro_coalesced_datagrams
            .fetch_add(datagrams, Ordering::Relaxed);
    }

    /// A point-in-time snapshot of the offload counters, for diagnostics / a stats
    /// endpoint. GSO hit ratio = `gso_calls / (gso_calls + gso_fallback_runs)`; GRO
    /// coalescing factor = `gro_coalesced_datagrams / gro_reads`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    #[allow(dead_code)] // diagnostics snapshot; read by tests + a future stats endpoint
    pub struct OffloadStats {
        pub gso_calls: u64,
        pub gso_datagrams: u64,
        pub gso_fallback_runs: u64,
        pub gro_reads: u64,
        pub gro_coalesced_datagrams: u64,
    }

    /// Read the current process-wide offload counters.
    #[allow(dead_code)] // diagnostics accessor; exercised by the offload stats test
    pub fn offload_stats() -> OffloadStats {
        OffloadStats {
            gso_calls: COUNTERS.gso_calls.load(Ordering::Relaxed),
            gso_datagrams: COUNTERS.gso_datagrams.load(Ordering::Relaxed),
            gso_fallback_runs: COUNTERS.gso_fallback_runs.load(Ordering::Relaxed),
            gro_reads: COUNTERS.gro_reads.load(Ordering::Relaxed),
            gro_coalesced_datagrams: COUNTERS.gro_coalesced_datagrams.load(Ordering::Relaxed),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn recorders_increment_the_snapshot() {
            // The counters are process-wide, so assert on the DELTA across recordings,
            // not absolute values (another test in the same process may have touched
            // them). The recorders are platform-agnostic, so this runs everywhere —
            // covering the bookkeeping even on targets without the GSO/GRO syscalls.
            let before = offload_stats();
            record_gso_call(64);
            record_gso_call(8);
            record_gso_fallback();
            record_gro_read(42);
            let after = offload_stats();
            assert_eq!(after.gso_calls - before.gso_calls, 2);
            assert_eq!(after.gso_datagrams - before.gso_datagrams, 72);
            assert_eq!(after.gso_fallback_runs - before.gso_fallback_runs, 1);
            assert_eq!(after.gro_reads - before.gro_reads, 1);
            assert_eq!(
                after.gro_coalesced_datagrams - before.gro_coalesced_datagrams,
                42
            );
        }
    }
}

/// The kernel's hard ceiling on segments per `UDP_SEGMENT` send (`UDP_MAX_SEGMENTS`
/// = `1 << 6` in `net/ipv4/udp.c`). A `sendmsg` whose GSO buffer holds more than
/// this many segments fails with `EINVAL`; [`gso_runs`] therefore caps each emitted
/// run at this length so a long bulk flight is sent as several full-rate GSO calls
/// rather than one over-long call that the kernel rejects (forcing the whole run
/// onto the slow per-datagram fallback — i.e. GSO would never apply to exactly the
/// bulk transfers it exists for).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const UDP_MAX_GSO_SEGMENTS: usize = 64;

/// The kernel's ceiling on the TOTAL byte size of one `UDP_SEGMENT` super-buffer.
/// A GSO send is still one `sendmsg` on one UDP socket, so it is bounded by the
/// single-UDP-datagram maximum: `udp_sendmsg` rejects `len > 0xFFFF` outright
/// (`-EMSGSIZE`) and the IPv4 append path subtracts the 20-byte IP + 8-byte UDP
/// headers from the 65535 `IP_MAX_MTU`, leaving 65507 payload bytes (IPv6 allows
/// 65527; using the v4 bound is safe for both). Without a byte cap, a run of
/// [`UDP_MAX_GSO_SEGMENTS`] segments overflows this whenever `segment_size >
/// 65507 / 64 ≈ 1023` — i.e. at EVERY real QUIC datagram size, including the
/// default 1252 (64 × 1252 = 80128) and PMTUD-raised sizes — so each full-size
/// bulk run would fail `sendmsg` and take the fallback path, meaning GSO never
/// engaged for exactly the bulk transfers it exists for.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const UDP_MAX_GSO_BYTES: usize = 65507;

/// Splits a GSO send batch into runs of consecutive datagrams that share a peer and
/// a length (the unit a single `UDP_SEGMENT` call can emit: equal-sized segments,
/// optionally one shorter tail), each capped at [`UDP_MAX_GSO_SEGMENTS`] segments
/// AND [`UDP_MAX_GSO_BYTES`] total bytes.
///
/// Returns, for each run, the half-open index range into `batch` and the segment
/// size. A run of length 1 is a degenerate batch the caller may send with a plain
/// `send_to`. This is pure (no I/O, no platform dependency) so the grouping contract
/// is unit-tested on every target, even where the GSO syscall does not exist.
///
/// The contract a `UDP_SEGMENT` send requires: every segment in one call is
/// `segment_size` bytes except the final one, which may be `<= segment_size`, and at
/// most `UDP_MAX_SEGMENTS` segments total. We keep it stricter and simpler — a run is
/// all-equal-size, and a strictly-smaller datagram both ends the current run and
/// starts the next — because the QUIC sender emits uniform full-size datagrams during
/// bulk flights and only short control packets (ACKs, close) otherwise, so this
/// captures the bulk runs without ever mis-segmenting a mixed batch. A run longer
/// than either cap is split into back-to-back full-size sub-runs (the trailing
/// sub-run carries the remainder), so the wire output is unchanged — only the syscall
/// boundary moves.
///
/// Used on Linux by the GSO send path; on other targets only the unit tests
/// exercise it, so the unused-warning allowance is scoped to non-Linux.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn gso_runs(batch: &[(Vec<u8>, std::net::SocketAddr)]) -> Vec<GsoRun> {
    let mut runs = Vec::new();
    let mut i = 0;
    while i < batch.len() {
        let (ref first_buf, peer) = batch[i];
        let size = first_buf.len();
        // Per-run segment budget: the kernel's segment-count cap AND its total-byte
        // cap (one GSO super-buffer is still one UDP datagram, <= UDP_MAX_GSO_BYTES;
        // exceeding it makes sendmsg fail EMSGSIZE and the whole run take the
        // fallback). `size.max(1)` guards the (never-emitted) empty datagram from a
        // division by zero; the outer `.max(1)` keeps a degenerate oversized
        // datagram as a single-segment run instead of an empty one.
        let max_segs = UDP_MAX_GSO_SEGMENTS
            .min(UDP_MAX_GSO_BYTES / size.max(1))
            .max(1);
        let mut j = i + 1;
        // Extend while same peer + same size AND the run stays within both caps.
        while j < batch.len() && j - i < max_segs && batch[j].1 == peer && batch[j].0.len() == size
        {
            j += 1;
        }
        runs.push(GsoRun {
            range: i..j,
            peer,
            segment_size: size,
        });
        i = j;
    }
    runs
}

/// One maximal same-peer, same-size run produced by [`gso_runs`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct GsoRun {
    pub range: std::ops::Range<usize>,
    pub peer: std::net::SocketAddr,
    pub segment_size: usize,
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::net::SocketAddr;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

    use socket2::{socklen_t, SockAddr};

    /// A cmsg control buffer that is `cmsghdr`-aligned. A bare `[u8; N]` has
    /// alignment 1, but the kernel/`CMSG_*` macros reinterpret `msg_control` as a
    /// `libc::cmsghdr` whose first field (`cmsg_len`) needs 8-byte alignment on
    /// 64-bit Linux; writing/reading it through an under-aligned pointer is UB.
    /// Backing the bytes with an `align(8)` newtype makes `as_mut_ptr()` return a
    /// correctly aligned pointer (offset-0 field of an 8-aligned struct).
    #[repr(C, align(8))]
    struct CmsgBuf<const N: usize>([u8; N]);

    impl<const N: usize> CmsgBuf<N> {
        fn zeroed() -> Self {
            Self([0u8; N])
        }
        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn len(&self) -> usize {
            self.0.len()
        }
    }

    /// Control-buffer size for one u16 `UDP_SEGMENT` cmsg (GSO send).
    const GSO_CMSG_LEN: usize =
        (unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) }) as usize;
    /// Control-buffer size for the two cmsgs a GRO read may attach: the `int`
    /// segment size (the kernel `put_cmsg`s UDP_GRO as `sizeof(int)`, see
    /// `udp_cmsg_recv` in net/ipv4/udp.c) and the `int` ECN/TOS value. Sizing for
    /// one would truncate the other.
    const GRO_CMSG_LEN: usize = (unsafe {
        libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32)
            + libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32)
    }) as usize;

    /// `setsockopt(UDP_GRO)` — enable generic receive offload on the carrier socket.
    /// Best-effort: a kernel without `UDP_GRO` (pre-5.0) just leaves it off and the
    /// caller keeps reading one datagram per `recvmsg`. Returns whether it took.
    pub fn enable_gro<S: AsFd>(socket: &S) -> bool {
        let fd = socket.as_fd().as_raw_fd();
        let on: libc::c_int = 1;
        // SAFETY: setsockopt with a pointer to a stack-local c_int of matching length
        // on a valid borrowed fd; it only mutates this socket's option state.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_UDP,
                libc::UDP_GRO,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of_val(&on) as libc::socklen_t,
            )
        };
        rc == 0
    }

    /// Send `segments.len()` bytes worth of `segment_size`-sized datagrams to `peer`
    /// in one `sendmsg`, asking the kernel to slice the buffer via `UDP_SEGMENT`. The
    /// final segment may be shorter than `segment_size` (RFC-legal GSO tail).
    ///
    /// Returns the number of payload bytes the kernel accepted. On any error (kernel
    /// without GSO, `EIO`, message too large) the caller must fall back to
    /// per-datagram `send_to`; we surface the error rather than silently dropping.
    pub fn send_gso(
        fd: BorrowedFd<'_>,
        segments: &[u8],
        segment_size: usize,
        peer: SocketAddr,
    ) -> io::Result<usize> {
        let addr = SockAddr::from(peer);
        let mut iov = libc::iovec {
            iov_base: segments.as_ptr() as *mut libc::c_void,
            iov_len: segments.len(),
        };

        // Control buffer for one u16 UDP_SEGMENT cmsg, cmsghdr-aligned.
        let mut cmsg_buf = CmsgBuf::<GSO_CMSG_LEN>::zeroed();

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = addr.as_ptr() as *mut libc::c_void;
        msg.msg_namelen = addr.len();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;

        // SAFETY: msg.msg_control points at cmsg_buf with msg_controllen set to its
        // length, so CMSG_FIRSTHDR returns a pointer within that buffer (or null).
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            debug_assert!(!cmsg.is_null());
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = libc::UDP_SEGMENT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
            // The UDP_SEGMENT cmsg is a u16; a segment larger than that cannot be
            // expressed. The carrier's MAX_DATAGRAM (1252) is far below this, and DPLPMTUD
            // is capped well under 65535, so this only guards a future invariant break —
            // a debug_assert documents it without a release-path branch.
            debug_assert!(
                segment_size <= u16::MAX as usize,
                "GSO segment_size {segment_size} exceeds the u16 UDP_SEGMENT field"
            );
            let seg = segment_size as u16;
            std::ptr::copy_nonoverlapping(
                (&seg as *const u16).cast::<u8>(),
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<u16>(),
            );
            // msg_controllen must cover exactly the cmsg we wrote.
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as _;

            let sent = libc::sendmsg(fd.as_raw_fd(), &msg, 0);
            if sent < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(sent as usize)
            }
        }
    }

    /// Send a batch of independent datagrams in one `sendmmsg(2)`, returning how many
    /// the kernel accepted (a prefix of `batch`). This is the GSO-fallback fast path:
    /// when a run cannot use `UDP_SEGMENT` (mixed sizes, an older kernel, an oversized
    /// run, a transient error), the per-datagram path would otherwise spend one
    /// `send_to` syscall — and one async wakeup — per packet. `sendmmsg` collapses
    /// them into a single syscall while keeping each datagram an independent message
    /// (its own destination, its own size), so the bytes/sizes/count on the wire are
    /// identical to the per-datagram loop.
    ///
    /// Returns `Ok(n)` where `n` is the number of leading datagrams sent (the kernel
    /// sends a prefix and reports a short count on `EAGAIN`/`EWOULDBLOCK` after the
    /// first message, or a hard error on the very first). The caller resends the
    /// `batch[n..]` remainder via the awaiting per-datagram fallback, so no bytes are
    /// ever dropped. An empty batch returns `Ok(0)`.
    pub fn send_mmsg(fd: BorrowedFd<'_>, batch: &[(Vec<u8>, SocketAddr)]) -> io::Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }
        // Parallel backing storage that must outlive the syscall: one SockAddr, one
        // iovec, and one mmsghdr per datagram. The mmsghdr's msg_hdr points into the
        // addrs/iovs vectors, so all three must stay put for the sendmmsg call.
        let addrs: Vec<SockAddr> = batch
            .iter()
            .map(|(_, peer)| SockAddr::from(*peer))
            .collect();
        let mut iovs: Vec<libc::iovec> = batch
            .iter()
            .map(|(dg, _)| libc::iovec {
                iov_base: dg.as_ptr() as *mut libc::c_void,
                iov_len: dg.len(),
            })
            .collect();
        // SAFETY: mmsghdr is a C struct of plain integers/pointers; zeroed is a valid
        // initial state before we fill msg_hdr below.
        let mut msgs: Vec<libc::mmsghdr> = (0..batch.len())
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        for (i, msg) in msgs.iter_mut().enumerate() {
            msg.msg_hdr.msg_name = addrs[i].as_ptr() as *mut libc::c_void;
            msg.msg_hdr.msg_namelen = addrs[i].len();
            msg.msg_hdr.msg_iov = &mut iovs[i];
            msg.msg_hdr.msg_iovlen = 1;
            // msg_len is an out field the kernel fills with bytes sent for this message.
        }
        // SAFETY: msgs/addrs/iovs are live for the call; each mmsghdr's msg_hdr points
        // at the matching addr + iov, all with correct lengths. sendmmsg writes only
        // each mmsghdr's msg_len out field.
        let n = unsafe {
            libc::sendmmsg(
                fd.as_raw_fd(),
                msgs.as_mut_ptr(),
                msgs.len() as libc::c_uint,
                0,
            )
        };
        if n < 0 {
            // A hard error before the first message was sent (e.g. EAGAIN with nothing
            // sent). The caller resends the whole batch per-datagram.
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// A GRO read: the bytes the kernel coalesced and the segment size to re-split
    /// them by. `segment_size == total` (no GRO cmsg) means one ordinary datagram.
    /// The caller re-splits with `buf[..total].chunks(segment_size)` — each chunk is
    /// one of the original datagrams (the last may be shorter).
    pub struct GroSegments {
        pub peer: SocketAddr,
        pub total: usize,
        pub segment_size: usize,
        /// The ECN codepoint from the IP TOS / IPv6 traffic-class byte's low 2 bits
        /// (RFC 3168): 0 = Not-ECT, 0b10 = ECT(0), 0b01 = ECT(1), 0b11 = CE. GRO only
        /// coalesces same-ECN datagrams (a kernel invariant), so one value covers every
        /// segment of the read. 0 when the TOS cmsg is absent (IP_RECVTOS off / older
        /// kernel), which reads as Not-ECT.
        pub ecn: u8,
    }

    /// Enable receiving the inbound ECN codepoint (the IP TOS / IPv6 traffic-class
    /// byte) as a control message, so [`recv_gro`] can read per-datagram ECN. Paired
    /// with egress ECT(0): the server must count inbound CE marks to echo them in
    /// ACK_ECN (RFC 9000 §13.4). Best-effort; without it `recv_gro` reports Not-ECT.
    pub fn enable_recv_ecn<S: AsFd>(socket: &S, is_ipv6: bool) -> bool {
        let fd = socket.as_fd().as_raw_fd();
        let on: libc::c_int = 1;
        let (level, optname) = if is_ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS)
        } else {
            (libc::IPPROTO_IP, libc::IP_RECVTOS)
        };
        // SAFETY: setsockopt with a stack c_int of matching length on a valid fd.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                optname,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of_val(&on) as libc::socklen_t,
            )
        };
        rc == 0
    }

    /// Receive one (possibly GRO-coalesced) read into `buf` via `recvmsg`, returning
    /// the peer, total bytes, and per-segment size. Without a `UDP_GRO` cmsg the
    /// segment size equals the total (a single datagram), so the caller's split is a
    /// no-op and behaviour matches `recv_from`.
    pub fn recv_gro(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<GroSegments> {
        use socket2::SockAddrStorage;

        let mut storage = SockAddrStorage::zeroed();
        let storage_len = storage.size_of();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // Room for both control messages the kernel may attach (see GRO_CMSG_LEN),
        // cmsghdr-aligned.
        let mut cmsg_buf = CmsgBuf::<GRO_CMSG_LEN>::zeroed();

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        // SockAddrStorage is repr(transparent) over libc::sockaddr_storage, so its
        // pointer is a valid msg_name the kernel fills with the source address.
        msg.msg_name = (&mut storage as *mut SockAddrStorage).cast::<libc::c_void>();
        msg.msg_namelen = storage_len;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;

        // SAFETY: all msghdr pointers reference live stack buffers with matching
        // lengths set above; recvmsg only writes within them.
        let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // If `buf` was too small for the (GRO-coalesced) read, the kernel sets
        // MSG_TRUNC and `n` is the *untruncated* size. Splitting a truncated buffer
        // would feed a corrupt tail datagram to QUIC (and silently lose the rest), so
        // reject the read; the caller drops it like any other bad datagram. With the
        // 64 KiB GRO buffer the driver allocates this should never fire, but a buffer
        // smaller than the kernel's coalesced maximum must fail loudly, not corrupt.
        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(io::Error::other("GRO recvmsg truncated (buffer too small)"));
        }
        let total = n as usize;

        // The kernel wrote msg_namelen bytes of source address into `storage`.
        // SAFETY: the kernel set ss_family and wrote a valid sockaddr of msg_namelen
        // bytes; SockAddrStorage carries that storage verbatim.
        let peer = unsafe { SockAddr::new(storage, msg.msg_namelen as socklen_t) }
            .as_socket()
            .ok_or_else(|| io::Error::other("recvmsg returned a non-IP peer"))?;

        // Default: no GRO cmsg => one datagram of `total` bytes; no TOS cmsg => Not-ECT.
        let mut segment_size = total;
        let mut ecn: u8 = 0;
        // MSG_CTRUNC: the control buffer was too small for every cmsg the kernel
        // wanted to attach, so any cmsg that IS present may not be the full set (and
        // a partially-copied trailing cmsg is possible in principle). Treat the
        // control data as untrusted: keep the defaults — one segment of `total`
        // bytes (mis-splitting on a bogus segment size would corrupt every chunk)
        // and Not-ECT (never invent a CE/ECT mark from garbage). The payload itself
        // is intact (that would be MSG_TRUNC, handled above), so the read still
        // yields one valid datagram. GRO_CMSG_LEN sizes the buffer for both cmsgs
        // we enable, so this only fires if the kernel ever attaches more.
        let ctruncated = msg.msg_flags & libc::MSG_CTRUNC != 0;
        // SAFETY: msg is fully initialized by recvmsg; CMSG_* walk only within
        // cmsg_buf as bounded by msg_controllen. Scan ALL cmsgs (do not break early):
        // the kernel may attach both the UDP_GRO segment size and the ECN/TOS value.
        // Every CMSG_DATA read below is length-guarded by the cmsg's own cmsg_len
        // (never read more payload bytes than the kernel wrote), and copies into
        // local integers via copy_nonoverlapping, so no alignment is assumed on the
        // cmsg payload pointer.
        if !ctruncated {
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    let level = (*cmsg).cmsg_level;
                    let kind = (*cmsg).cmsg_type;
                    // Payload bytes in this cmsg: cmsg_len minus the aligned header
                    // (CMSG_LEN(0)). saturating_sub so a malformed header can never
                    // wrap into a huge length.
                    let data_len =
                        ((*cmsg).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                    if level == libc::SOL_UDP && kind == libc::UDP_GRO {
                        // The kernel delivers the GRO segment size as a full native
                        // `int` (`put_cmsg(.., sizeof(int), &gso_size)` in
                        // net/ipv4/udp.c). Read the whole int native-endian — reading
                        // only the first two bytes would yield the (zero) high half on
                        // big-endian. Guarded on cmsg_len so a short/foreign cmsg is
                        // ignored rather than over-read.
                        if data_len >= std::mem::size_of::<libc::c_int>() {
                            let mut seg: libc::c_int = 0;
                            std::ptr::copy_nonoverlapping(
                                libc::CMSG_DATA(cmsg),
                                (&mut seg as *mut libc::c_int).cast::<u8>(),
                                std::mem::size_of::<libc::c_int>(),
                            );
                            if seg > 0 {
                                segment_size = seg as usize;
                            }
                        }
                    } else if (level == libc::IPPROTO_IP && kind == libc::IP_TOS)
                        || (level == libc::IPPROTO_IPV6 && kind == libc::IPV6_TCLASS)
                    {
                        // The TOS/traffic-class value arrives in two shapes: IPv4
                        // IP_TOS is a single byte (`ip_cmsg_recv_tos`), IPv6
                        // IPV6_TCLASS is a full native `int` (`ip6_datagram_recv_ctl`).
                        // Dispatch on the delivered length: an int must be read whole
                        // and native-endian — taking its first byte reads the MSB on
                        // big-endian, silently zeroing the ECN field (CE marks lost).
                        // A one-byte payload IS the TOS byte (no endianness). Low 2
                        // bits = the ECN field (RFC 3168).
                        if data_len >= std::mem::size_of::<libc::c_int>() {
                            let mut tos: libc::c_int = 0;
                            std::ptr::copy_nonoverlapping(
                                libc::CMSG_DATA(cmsg),
                                (&mut tos as *mut libc::c_int).cast::<u8>(),
                                std::mem::size_of::<libc::c_int>(),
                            );
                            ecn = (tos & 0b11) as u8;
                        } else if data_len >= 1 {
                            let mut tos_byte: u8 = 0;
                            std::ptr::copy_nonoverlapping(
                                libc::CMSG_DATA(cmsg),
                                &mut tos_byte as *mut u8,
                                1,
                            );
                            ecn = tos_byte & 0b11;
                        }
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }
        }

        Ok(GroSegments {
            peer,
            total,
            segment_size,
            ecn,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn dg(len: usize, peer: SocketAddr) -> (Vec<u8>, SocketAddr) {
        (vec![0u8; len], peer)
    }

    #[test]
    fn empty_batch_has_no_runs() {
        assert!(gso_runs(&[]).is_empty());
    }

    #[test]
    fn uniform_same_peer_run_is_one_run() {
        let p = addr("10.0.0.1:443");
        let batch = vec![dg(1252, p), dg(1252, p), dg(1252, p)];
        let runs = gso_runs(&batch);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].range, 0..3);
        assert_eq!(runs[0].segment_size, 1252);
        assert_eq!(runs[0].peer, p);
    }

    #[test]
    fn smaller_tail_ends_the_run_and_starts_a_new_one() {
        // Bulk flight of full datagrams then a short trailing packet (e.g. the last
        // STREAM frame): the short one must NOT be folded into the GSO run.
        let p = addr("10.0.0.1:443");
        let batch = vec![dg(1252, p), dg(1252, p), dg(40, p)];
        let runs = gso_runs(&batch);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].range, 0..2);
        assert_eq!(runs[0].segment_size, 1252);
        assert_eq!(runs[1].range, 2..3);
        assert_eq!(runs[1].segment_size, 40);
    }

    #[test]
    fn different_peer_breaks_the_run() {
        let p1 = addr("10.0.0.1:443");
        let p2 = addr("10.0.0.2:443");
        let batch = vec![dg(1252, p1), dg(1252, p2)];
        let runs = gso_runs(&batch);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].peer, p1);
        assert_eq!(runs[1].peer, p2);
    }

    #[test]
    fn long_run_is_split_at_the_segment_cap() {
        // A bulk flight far longer than the kernel's per-send caps must be split
        // into sub-runs within BOTH limits (<=UDP_MAX_GSO_SEGMENTS segments and
        // <=UDP_MAX_GSO_BYTES total), never one over-long run the kernel would
        // reject (EINVAL past the segment cap, EMSGSIZE past the byte cap).
        let p = addr("10.0.0.1:443");
        let n = UDP_MAX_GSO_SEGMENTS * 2 + 5;
        let batch: Vec<_> = (0..n).map(|_| dg(1252, p)).collect();
        let runs = gso_runs(&batch);
        assert!(
            runs.iter().all(|r| r.range.len() <= UDP_MAX_GSO_SEGMENTS),
            "no run may exceed the segment cap"
        );
        // Coverage is still exact and contiguous.
        let covered: usize = runs.iter().map(|r| r.range.len()).sum();
        assert_eq!(covered, n);
        let mut next = 0;
        for r in &runs {
            assert_eq!(r.range.start, next);
            next = r.range.end;
        }
        assert_eq!(next, n);
        // At 1252 bytes/segment the byte cap binds first: the fullest legal run is
        // UDP_MAX_GSO_BYTES / 1252 = 52 segments (< the 64-segment cap), and the
        // first run must be exactly full (not under-filled).
        let effective = UDP_MAX_GSO_SEGMENTS.min(UDP_MAX_GSO_BYTES / 1252);
        assert_eq!(effective, 52, "byte cap binds at the default datagram size");
        assert_eq!(runs[0].range.len(), effective);
    }

    /// No emitted run may concatenate to more bytes than one `UDP_SEGMENT`
    /// super-buffer can carry (one UDP datagram): a run past UDP_MAX_GSO_BYTES
    /// makes `sendmsg` fail EMSGSIZE, so EVERY full-size bulk run would fall back
    /// to per-datagram sends — GSO would never engage at real QUIC datagram sizes
    /// (64 x 1252 = 80128; 64 x 1452 PMTUD-raised = 92928; both > 65507). Checks
    /// representative segment sizes and proves the wire output (which datagrams,
    /// in which order, with which sizes) is untouched by where the run boundaries
    /// fall.
    #[test]
    fn no_run_exceeds_the_single_gso_buffer_byte_limit() {
        let p = addr("10.0.0.1:443");
        // Default QUIC datagram, PMTUD-raised, small control, and the pathological
        // single-datagram maximum.
        for &seg in &[1252usize, 1452, 40, UDP_MAX_GSO_BYTES] {
            let n = 200; // several caps' worth of segments
            let batch: Vec<_> = (0..n).map(|_| dg(seg, p)).collect();
            let runs = gso_runs(&batch);
            for r in &runs {
                assert!(
                    r.range.len() <= UDP_MAX_GSO_SEGMENTS,
                    "seg={seg}: run of {} segments exceeds the segment cap",
                    r.range.len()
                );
                assert!(
                    r.range.len() * r.segment_size <= UDP_MAX_GSO_BYTES,
                    "seg={seg}: run of {} segments x {} bytes = {} exceeds the \
                     single-buffer byte limit {}",
                    r.range.len(),
                    r.segment_size,
                    r.range.len() * r.segment_size,
                    UDP_MAX_GSO_BYTES
                );
                assert_eq!(r.segment_size, seg, "seg={seg}: segment size preserved");
            }
            // Wire output unchanged: the runs tile 0..n contiguously in order, so
            // exactly the original datagrams go out, in the original order, with
            // the original sizes — only the syscall boundaries move.
            let mut next = 0;
            for r in &runs {
                assert_eq!(r.range.start, next, "seg={seg}: runs are contiguous");
                next = r.range.end;
            }
            assert_eq!(next, n, "seg={seg}: every datagram covered exactly once");
        }
    }

    /// Below the byte-cap crossover (segment_size <= UDP_MAX_GSO_BYTES / 64 = 1023)
    /// the 64-segment cap still binds unchanged — the byte cap must not shrink
    /// small-datagram runs.
    #[test]
    fn segment_cap_still_binds_for_small_segments() {
        let p = addr("10.0.0.1:443");
        let seg = 1000; // 64 x 1000 = 64000 <= 65507: the segment cap binds
        let n = UDP_MAX_GSO_SEGMENTS + 10;
        let batch: Vec<_> = (0..n).map(|_| dg(seg, p)).collect();
        let runs = gso_runs(&batch);
        assert_eq!(runs.len(), 2);
        assert_eq!(
            runs[0].range.len(),
            UDP_MAX_GSO_SEGMENTS,
            "first run is exactly the segment cap"
        );
        assert_eq!(runs[1].range.len(), 10);
    }

    #[test]
    fn runs_cover_every_datagram_exactly_once() {
        let p1 = addr("10.0.0.1:443");
        let p2 = addr("10.0.0.2:443");
        let batch = vec![
            dg(1252, p1),
            dg(1252, p1),
            dg(33, p1),
            dg(1252, p2),
            dg(1252, p1),
        ];
        let runs = gso_runs(&batch);
        let covered: usize = runs.iter().map(|r| r.range.len()).sum();
        assert_eq!(covered, batch.len());
        // Contiguous, non-overlapping, in order.
        let mut next = 0;
        for r in &runs {
            assert_eq!(r.range.start, next);
            next = r.range.end;
        }
        assert_eq!(next, batch.len());
    }

    /// `send_mmsg` delivers a batch of independent datagrams to their destination in
    /// one syscall, each as a distinct message (own size, own bytes), matching what a
    /// per-datagram `send_to` loop would have put on the wire. Linux-only (the syscall
    /// does not exist elsewhere); compiled everywhere via the Linux cfg, run on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn send_mmsg_delivers_each_datagram_verbatim() {
        use std::net::UdpSocket;
        use std::os::fd::AsFd;

        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();

        // Three differently-sized datagrams to the same peer (a mixed run GSO would
        // reject, exactly the fallback case sendmmsg now batches).
        let batch = vec![
            (vec![1u8; 1252], rx_addr),
            (vec![2u8; 40], rx_addr),
            (vec![3u8; 700], rx_addr),
        ];
        let sent = super::linux::send_mmsg(tx.as_fd(), &batch).unwrap();
        assert_eq!(sent, 3, "all three datagrams sent in one sendmmsg");

        // Each arrives as its own datagram with its own length and payload, in order.
        for (expected, _) in &batch {
            let mut buf = vec![0u8; 2048];
            let n = rx.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], &expected[..], "datagram delivered verbatim");
        }
    }

    /// `recv_gro` recovers the inbound ECN codepoint from the IPv4 `IP_TOS` cmsg,
    /// whose payload the kernel delivers as a SINGLE byte (`ip_cmsg_recv_tos`) —
    /// exercising the one-byte branch of the length-dispatched TOS read. Loopback:
    /// tx marks ECT(0), rx must read 0b10, not Not-ECT.
    #[cfg(target_os = "linux")]
    #[test]
    fn recv_gro_reads_ecn_from_ipv4_tos_cmsg() {
        use std::net::UdpSocket;
        use std::os::fd::AsFd;

        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        assert!(linux::enable_recv_ecn(&rx, false), "IP_RECVTOS set");
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(enable_ect0(&tx, false), "egress ECT(0) set");
        tx.send_to(&[0xAB; 100], rx.local_addr().unwrap()).unwrap();

        let mut buf = [0u8; 2048];
        let segs = linux::recv_gro(rx.as_fd(), &mut buf).unwrap();
        assert_eq!(segs.total, 100);
        assert_eq!(segs.segment_size, 100, "no GRO cmsg => one datagram");
        assert_eq!(segs.ecn, 0b10, "ECT(0) recovered from the IP_TOS cmsg");
        assert_eq!(&buf[..100], &[0xAB; 100][..]);
    }

    /// `recv_gro` recovers the inbound ECN codepoint from the IPv6 `IPV6_TCLASS`
    /// cmsg, whose payload the kernel delivers as a full native `int`
    /// (`ip6_datagram_recv_ctl`) — exercising the whole-int branch whose old
    /// first-byte read was the big-endian CE-loss bug. Skips (passes vacuously)
    /// where the host has no IPv6 loopback.
    #[cfg(target_os = "linux")]
    #[test]
    fn recv_gro_reads_ecn_from_ipv6_tclass_cmsg() {
        use std::net::UdpSocket;
        use std::os::fd::AsFd;

        let Ok(rx) = UdpSocket::bind("[::1]:0") else {
            eprintln!("no IPv6 loopback on this host; skipping");
            return;
        };
        rx.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        assert!(linux::enable_recv_ecn(&rx, true), "IPV6_RECVTCLASS set");
        let tx = UdpSocket::bind("[::1]:0").unwrap();
        assert!(enable_ect0(&tx, true), "egress ECT(0) set");
        tx.send_to(&[0xCD; 64], rx.local_addr().unwrap()).unwrap();

        let mut buf = [0u8; 2048];
        let segs = linux::recv_gro(rx.as_fd(), &mut buf).unwrap();
        assert_eq!(segs.total, 64);
        assert_eq!(segs.ecn, 0b10, "ECT(0) recovered from the int TCLASS cmsg");
    }

    /// `enable_ect0` sets the IP TOS byte's ECN bits to ECT(0) on the socket; read it
    /// back via getsockopt to prove the option took (so egress datagrams are marked,
    /// matching Safari). Unix-only (the sockopt is POSIX); runs on macOS + Linux.
    #[cfg(unix)]
    #[test]
    fn enable_ect0_sets_the_ip_tos_ecn_bits() {
        use std::net::UdpSocket;
        use std::os::fd::{AsFd, AsRawFd};

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(enable_ect0(&sock.as_fd(), false), "IP_TOS ECT(0) set on v4");

        // Read the TOS back: its low two bits must be ECT(0) = 0b10.
        let fd = sock.as_raw_fd();
        let mut tos: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt into a stack c_int with matching length on a valid fd.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TOS,
                (&mut tos as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt IP_TOS");
        assert_eq!(tos & 0b11, 0b10, "ECN field is ECT(0)");
    }
}
