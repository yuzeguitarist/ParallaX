//! Intentional defects used ONLY to verify sanitizer detection before testing
//! ParallaX. A nonzero exit without the expected diagnostic is NOT a pass.

use std::hint::black_box;

#[inline(never)]
fn address_defect() {
    let pointer = Box::into_raw(Box::new(42_u64));
    unsafe {
        drop(Box::from_raw(pointer));
        // Intentional use after free; volatile prevents deleting the access.
        black_box(std::ptr::read_volatile(pointer));
    }
}

static mut RACY_VALUE: u64 = 0;

#[inline(never)]
fn race_defect() {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let peer = std::sync::Arc::clone(&barrier);
    let thread = std::thread::spawn(move || {
        peer.wait();
        for i in 0..10_000 {
            unsafe { std::ptr::write_volatile(std::ptr::addr_of_mut!(RACY_VALUE), i) };
        }
    });
    barrier.wait();
    for i in 0..10_000 {
        unsafe { std::ptr::write_volatile(std::ptr::addr_of_mut!(RACY_VALUE), i) };
    }
    thread.join().unwrap();
}

#[inline(never)]
fn leak_defect() {
    // The allocating thread exits so its stack cannot accidentally keep the
    // forgotten allocation reachable by LSan's conservative root scan.
    std::thread::spawn(|| {
        let bytes = vec![0x5a_u8; 65_537];
        black_box(&bytes);
        std::mem::forget(bytes);
    })
    .join()
    .unwrap();
}

fn main() {
    let mode = std::env::args_os()
        .nth(1)
        .expect("good/address/thread/leak")
        .into_string()
        .expect("ASCII canary mode");
    match mode.as_str() {
        "good" => {
            let value = std::sync::Arc::new(std::sync::Mutex::new(vec![7_u8; 256]));
            let peer = std::sync::Arc::clone(&value);
            std::thread::spawn(move || peer.lock().unwrap().push(9))
                .join()
                .unwrap();
            assert_eq!(value.lock().unwrap().len(), 257);
            println!("sanitizer-good-control-complete");
        }
        "address" => address_defect(),
        "thread" => race_defect(),
        "leak" => leak_defect(),
        _ => panic!("unknown canary mode"),
    }
}
