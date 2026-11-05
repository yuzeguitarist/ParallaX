//! Inspect output reallocations before old allocations are freed.
//! The allocator always moves and zero-initializes allocations, so inspecting
//! their full byte ranges is defined and the regression is deterministic.
//! This allocator exists only in this isolated integration-test executable.

use parallax::crypto::session::{AeadCodec, CipherSuite};
use parallax::protocol::data::{DataRecordCodec, CLIENT_TO_SERVER_AAD};
use parallax::traffic::PaddingProfile;
use rand::{rngs::StdRng, SeedableRng};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

const MARKER: &[u8] = b"SENSITIVE_PREFIX";
static TRACKED: AtomicUsize = AtomicUsize::new(0);
static FREED_WITH_PLAINTEXT: AtomicUsize = AtomicUsize::new(0);
static TRACKED_GROWTHS: AtomicUsize = AtomicUsize::new(0);

struct MovingAllocator;

// SAFETY: all allocation/deallocation pairs use System with the original
// alignment. Reallocation preserves the old allocation on failure and copies
// exactly min(old_size, new_size) initialized bytes before freeing it.
unsafe impl GlobalAlloc for MovingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: caller supplies the valid nonzero allocation layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: caller supplies the valid nonzero allocation layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: this pointer/layout pair came from this System-backed allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: GlobalAlloc's realloc contract guarantees nonzero new_size
        // and a valid layout for the original alignment.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: new_layout is valid as established above.
        let next = unsafe { System.alloc_zeroed(new_layout) };
        if next.is_null() {
            return next;
        }
        if TRACKED.load(Ordering::SeqCst) == ptr as usize {
            // SAFETY: the allocation is live, has layout.size() bytes, and our
            // alloc/realloc implementations initialize every byte. Observation
            // occurs before copying/freeing and does not allocate recursively.
            let old = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if old.windows(MARKER.len()).any(|window| window == MARKER) {
                FREED_WITH_PLAINTEXT.fetch_add(1, Ordering::SeqCst);
            }
            TRACKED_GROWTHS.fetch_add(1, Ordering::SeqCst);
            TRACKED.store(next as usize, Ordering::SeqCst);
        }
        // SAFETY: allocations are distinct and each is valid for the copied
        // range. The original allocation remains live until after the copy.
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, next, layout.size().min(new_size));
            System.dealloc(ptr, layout);
        }
        next
    }
}

#[global_allocator]
static ALLOCATOR: MovingAllocator = MovingAllocator;

struct Tracking;

impl Tracking {
    fn start(out: &mut Vec<u8>) -> Self {
        assert_ne!(out.capacity(), 0);
        FREED_WITH_PLAINTEXT.store(0, Ordering::SeqCst);
        TRACKED_GROWTHS.store(0, Ordering::SeqCst);
        assert_eq!(TRACKED.swap(out.as_mut_ptr() as usize, Ordering::SeqCst), 0);
        Self
    }
}

impl Drop for Tracking {
    fn drop(&mut self) {
        TRACKED.store(0, Ordering::SeqCst);
    }
}

fn codec(suite: CipherSuite) -> DataRecordCodec {
    DataRecordCodec::new(
        AeadCodec::new_with_suite(suite, [0x31; 32], [0x49; 12]),
        PaddingProfile::new(0, 0).unwrap(),
        CLIENT_TO_SERVER_AAD,
    )
}

#[test]
fn failed_serial_batch_never_frees_an_output_allocation_containing_batch_plaintext() {
    let prefix = b"caller-prefix";
    for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
        let mut sealer = codec(suite);
        let mut rng = StdRng::seed_from_u64(0xA110_CAFE);
        let first = sealer.seal(MARKER, &mut rng).unwrap();
        let second = sealer.seal(&vec![0x5a; 4096], &mut rng).unwrap();
        let mut third = sealer.seal(b"invalid-last-record", &mut rng).unwrap();
        *third.last_mut().unwrap() ^= 1;
        let mut input = [first.as_slice(), second.as_slice(), third.as_slice()].concat();
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(prefix);
        assert!(prefix.len() + MARKER.len() <= out.capacity());
        assert!(input.len() > out.capacity());
        let mut opener = codec(suite);
        let tracking = Tracking::start(&mut out);
        let result = opener.open_concat_records(&mut input, &mut out);
        drop(tracking);
        assert!(result.is_err());
        assert_eq!(out, prefix);
        assert!(input.iter().all(|byte| *byte == 0));
        assert!(
            TRACKED_GROWTHS.load(Ordering::SeqCst) > 0,
            "the allocation observer did not exercise output growth"
        );
        assert_eq!(
            FREED_WITH_PLAINTEXT.load(Ordering::SeqCst),
            0,
            "an old output allocation was freed with authenticated prefix plaintext"
        );
    }
}
