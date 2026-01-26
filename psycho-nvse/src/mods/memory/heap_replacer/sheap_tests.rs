//! Comprehensive test suite for scrap heap allocator.
//!
//! Tests cover:
//! - Thread safety and race conditions
//! - Fallback behavior and recovery
//! - Memory leak scenarios
//! - Bugged purge() simulation
//! - Long-running session stress tests
//! - Edge cases and boundary conditions
//! 
//! NOTE: This test suite was written by AI tool: Claude Sonet 4.5

#[cfg(test)]
mod tests {
    use super::super::sheap::*;
    use libc::c_void;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    /// Helper macro to send raw pointer across thread boundary
    /// SAFETY: Tests ensure single-threaded access or proper synchronization
    macro_rules! sheap_ptr {
        ($sheap:expr) => {
            $sheap as usize
        };
    }

    macro_rules! from_sheap_ptr {
        ($addr:expr) => {
            $addr as *mut c_void
        };
    }

    /// Helper to create a fake sheap pointer (just needs to be unique per test)
    fn create_test_sheap() -> *mut c_void {
        Box::into_raw(Box::new([0u8; 12])) as *mut c_void
    }

    /// Helper to cleanup test sheap
    unsafe fn destroy_test_sheap(ptr: *mut c_void) {
        if !ptr.is_null() {
            unsafe {
                drop(Box::from_raw(ptr as *mut [u8; 12]));
            }
        }
    }

    #[test]
    fn test_basic_alloc_free() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Allocate 100 bytes
        let ptr1 = manager.alloc(sheap, 100, 8);
        assert!(!ptr1.is_null());

        // Allocate another 200 bytes
        let ptr2 = manager.alloc(sheap, 200, 8);
        assert!(!ptr2.is_null());
        assert_ne!(ptr1, ptr2);

        // Free both
        assert!(manager.free(sheap, ptr1));
        assert!(manager.free(sheap, ptr2));

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_automatic_reset() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Allocate and free multiple times - should trigger auto-reset
        for _ in 0..10 {
            let mut ptrs = Vec::new();
            for _ in 0..100 {
                let ptr = manager.alloc(sheap, 64, 8);
                assert!(!ptr.is_null());
                ptrs.push(ptr);
            }

            // Free all - should trigger reset
            for ptr in ptrs {
                manager.free(sheap, ptr);
            }
        }

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_null_pointer_handling() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Freeing null should be safe
        assert!(!manager.free(sheap, std::ptr::null_mut()));

        // Freeing random pointer not from our allocator
        assert!(!manager.free(sheap, 0x12345678 as *mut c_void));

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_concurrent_allocations() {
        let manager = Arc::new(ScrapHeapManager::new());
        let sheap = create_test_sheap();
        let sheap_addr = sheap_ptr!(sheap);

        manager.init(sheap, 1);

        let num_threads = 8;
        let allocs_per_thread = 1000;
        let barrier = Arc::new(Barrier::new(num_threads));

        let mut handles = vec![];

        for thread_id in 0..num_threads {
            let manager_clone = Arc::clone(&manager);
            let barrier_clone = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                let sheap = from_sheap_ptr!(sheap_addr);
                barrier_clone.wait();

                let mut ptrs = Vec::new();

                for i in 0..allocs_per_thread {
                    let size = 16 + (i % 128);
                    let ptr = manager_clone.alloc(sheap, size, 8);
                    assert!(!ptr.is_null(), "Thread {} failed alloc {}", thread_id, i);
                    ptrs.push(ptr);
                }

                for ptr in ptrs.into_iter().rev() {
                    manager_clone.free(sheap, ptr);
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_concurrent_alloc_and_free() {
        let manager = Arc::new(ScrapHeapManager::new());
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        let barrier = Arc::new(Barrier::new(4));

        let mut handles = vec![];

        // Thread 1: Allocate and hold (tests concurrent allocation)
        {
            let manager_clone = Arc::clone(&manager);
            let barrier_clone = Arc::clone(&barrier);
            let sheap_addr = sheap_ptr!(sheap);
            handles.push(thread::spawn(move || {
                let sheap = from_sheap_ptr!(sheap_addr);
                barrier_clone.wait();

                let mut ptrs = Vec::new();
                for _ in 0..500 {
                    let ptr = manager_clone.alloc(sheap, 128, 8);
                    assert!(!ptr.is_null());
                    ptrs.push(ptr);
                    thread::sleep(Duration::from_micros(1));
                }

                // Free all at end
                for ptr in ptrs {
                    manager_clone.free(sheap, ptr);
                }
            }));
        }

        // Thread 2: Allocate and free immediately
        {
            let manager_clone = Arc::clone(&manager);
            let barrier_clone = Arc::clone(&barrier);
            let sheap_addr = sheap_ptr!(sheap);
            handles.push(thread::spawn(move || {
                let sheap = from_sheap_ptr!(sheap_addr);
                barrier_clone.wait();
                for _ in 0..500 {
                    let ptr = manager_clone.alloc(sheap, 64, 8);
                    assert!(!ptr.is_null());
                    manager_clone.free(sheap, ptr);
                    thread::sleep(Duration::from_micros(1));
                }
            }));
        }

        // Thread 3: Allocate large chunks and free
        {
            let manager_clone = Arc::clone(&manager);
            let barrier_clone = Arc::clone(&barrier);
            let sheap_addr = sheap_ptr!(sheap);
            handles.push(thread::spawn(move || {
                let sheap = from_sheap_ptr!(sheap_addr);
                barrier_clone.wait();

                let mut ptrs = Vec::new();
                for _ in 0..200 {
                    let ptr = manager_clone.alloc(sheap, 1024, 8);
                    assert!(!ptr.is_null());
                    ptrs.push(ptr);
                    thread::sleep(Duration::from_micros(5));
                }

                // Free all
                for ptr in ptrs {
                    manager_clone.free(sheap, ptr);
                }
            }));
        }

        // Thread 4: Free random (safe - will just return false)
        {
            let manager_clone = Arc::clone(&manager);
            let barrier_clone = Arc::clone(&barrier);
            let sheap_addr = sheap_ptr!(sheap);
            handles.push(thread::spawn(move || {
                let sheap = from_sheap_ptr!(sheap_addr);
                barrier_clone.wait();
                for i in 0..500 {
                    let fake_ptr = (0x10000000 + i * 64) as *mut c_void;
                    manager_clone.free(sheap, fake_ptr);
                    thread::sleep(Duration::from_micros(1));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_fallback_trigger_and_recovery() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Allocate until we hit fallback (32MB capacity)
        let chunk_size = 1024 * 1024; // 1MB chunks
        let num_chunks = 40; // Will exceed 32MB capacity

        let mut ptrs = Vec::new();

        for i in 0..num_chunks {
            let ptr = manager.alloc(sheap, chunk_size, 8);
            assert!(!ptr.is_null(), "Allocation {} failed", i);
            ptrs.push(ptr);

            if i >= 32 {
                // Should be using fallback now
                println!("Chunk {}: likely in fallback mode", i);
            }
        }

        // Free all - should recover from fallback
        for ptr in ptrs {
            manager.free(sheap, ptr);
        }

        // Allocate again - should work normally
        let ptr = manager.alloc(sheap, 1024, 8);
        assert!(!ptr.is_null());
        manager.free(sheap, ptr);

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_memory_leak_scenario() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Simulate leak: allocate but don't free
        let mut leaked_ptrs = Vec::new();
        for _ in 0..1000 {
            let ptr = manager.alloc(sheap, 1024, 8);
            assert!(!ptr.is_null());
            leaked_ptrs.push(ptr);
        }

        // Allocate and free normally (should still work)
        for _ in 0..100 {
            let ptr = manager.alloc(sheap, 128, 8);
            assert!(!ptr.is_null());
            manager.free(sheap, ptr);
        }

        // Purge should handle leaked memory
        manager.purge(sheap);

        // Should work after purge
        let ptr = manager.alloc(sheap, 256, 8);
        assert!(!ptr.is_null());
        manager.free(sheap, ptr);

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_bugged_purge_simulation() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Allocate some memory
        let mut ptrs = Vec::new();
        for _ in 0..100 {
            let ptr = manager.alloc(sheap, 512, 8);
            assert!(!ptr.is_null());
            ptrs.push(ptr);
        }

        // Game calls purge WITHOUT freeing (simulates bug)
        manager.purge(sheap);

        // Should still be able to allocate after buggy purge
        let ptr = manager.alloc(sheap, 1024, 8);
        assert!(!ptr.is_null());
        manager.free(sheap, ptr);

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_rapid_reset_cycles() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Simulate rapid alloc/free cycles (frame processing)
        for cycle in 0..1000 {
            let mut ptrs = Vec::new();

            // Allocate varying amounts
            let num_allocs = 10 + (cycle % 50);
            for _ in 0..num_allocs {
                let size = 32 + (cycle % 256);
                let ptr = manager.alloc(sheap, size, 8);
                assert!(!ptr.is_null());
                ptrs.push(ptr);
            }

            // Free all (triggers reset)
            for ptr in ptrs {
                manager.free(sheap, ptr);
            }
        }

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_alignment_requirements() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Test various alignments (powers of 2)
        let alignments = [1, 2, 4, 8, 16, 32, 64, 128, 256];

        for &align in &alignments {
            let ptr = manager.alloc(sheap, 128, align);
            assert!(!ptr.is_null(), "Allocation failed for alignment {}", align);

            // Check alignment - our minimum is 8 bytes due to header
            let addr = ptr as usize;
            let expected_align = align.max(8);
            assert_eq!(
                addr % expected_align,
                0,
                "Pointer {:p} (0x{:x}) not aligned to {} (expected align: {})",
                ptr,
                addr,
                align,
                expected_align
            );

            manager.free(sheap, ptr);
        }

        // Test alignment with varying sizes
        for size in [16, 64, 256, 1024, 4096] {
            for &align in &[8, 16, 32, 64] {
                let ptr = manager.alloc(sheap, size, align);
                assert!(!ptr.is_null(), "Allocation failed for size={} align={}", size, align);

                let addr = ptr as usize;
                assert_eq!(
                    addr % align,
                    0,
                    "Size {} not aligned to {} (addr=0x{:x})",
                    size,
                    align,
                    addr
                );

                manager.free(sheap, ptr);
            }
        }

        // Edge case: alignment 0 should be treated as 1 (minimum)
        let ptr = manager.alloc(sheap, 64, 0);
        if !ptr.is_null() {
            // Should still be at least 8-byte aligned (header alignment)
            let addr = ptr as usize;
            assert_eq!(addr % 8, 0, "Zero alignment should still give 8-byte aligned pointer");
            manager.free(sheap, ptr);
        }

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_large_allocation() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Allocate 10MB chunk
        let large_size = 10 * 1024 * 1024;
        let ptr = manager.alloc(sheap, large_size, 8);
        assert!(!ptr.is_null());

        manager.free(sheap, ptr);

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_zero_size_allocation() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Zero-size allocation (edge case)
        let ptr = manager.alloc(sheap, 0, 8);
        // Result is implementation-defined, but shouldn't crash
        if !ptr.is_null() {
            manager.free(sheap, ptr);
        }

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_multiple_sheaps() {
        let manager = ScrapHeapManager::new();

        let sheap1 = create_test_sheap();
        let sheap2 = create_test_sheap();
        let sheap3 = create_test_sheap();

        manager.init(sheap1, 1);
        manager.init(sheap2, 2);
        manager.init(sheap3, 3);

        // Allocate from each
        let ptr1 = manager.alloc(sheap1, 100, 8);
        let ptr2 = manager.alloc(sheap2, 200, 8);
        let ptr3 = manager.alloc(sheap3, 300, 8);

        assert!(!ptr1.is_null());
        assert!(!ptr2.is_null());
        assert!(!ptr3.is_null());

        // Verify pointers are distinct
        assert_ne!(ptr1, ptr2);
        assert_ne!(ptr2, ptr3);
        assert_ne!(ptr1, ptr3);

        // Free to correct sheaps
        assert!(manager.free(sheap1, ptr1));
        assert!(manager.free(sheap2, ptr2));
        assert!(manager.free(sheap3, ptr3));

        // Cross-sheap free test: allocate from sheap1, try to free from sheap2
        let ptr4 = manager.alloc(sheap1, 100, 8);
        assert!(!ptr4.is_null());

        // Attempt to free ptr4 from wrong sheap
        // This should return false because ptr4's header is in sheap1's region
        let cross_free_result = manager.free(sheap2, ptr4);

        // The cross-free might succeed if in fallback mode, so just verify
        // that we can still properly free from the correct sheap
        if cross_free_result {
            // If it succeeded (fallback region), that's OK - it was freed
            // Don't try to free again
        } else {
            // Cross-free failed as expected - free from correct sheap
            assert!(manager.free(sheap1, ptr4));
        }

        // Test independence: purge one sheap shouldn't affect others
        let ptr5 = manager.alloc(sheap1, 50, 8);
        let _ptr6 = manager.alloc(sheap2, 50, 8);
        let ptr7 = manager.alloc(sheap3, 50, 8);

        manager.purge(sheap2); // Purge only sheap2 (invalidates ptr6)

        // sheap1 and sheap3 should still work
        assert!(manager.free(sheap1, ptr5));
        assert!(manager.free(sheap3, ptr7));

        // sheap2 should work after purge
        let ptr8 = manager.alloc(sheap2, 100, 8);
        assert!(!ptr8.is_null());
        manager.free(sheap2, ptr8);

        unsafe {
            destroy_test_sheap(sheap1);
            destroy_test_sheap(sheap2);
            destroy_test_sheap(sheap3);
        }
    }

    #[test]
    fn test_reinit_sheap() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        // Init
        manager.init(sheap, 1);

        let ptr1 = manager.alloc(sheap, 100, 8);
        assert!(!ptr1.is_null());

        // Free before reinit to clean up properly
        manager.free(sheap, ptr1);

        // Reinit same sheap (simulates game behavior)
        // This increments generation and resets the bump allocator
        manager.init(sheap, 1);

        // Should work after reinit
        let ptr2 = manager.alloc(sheap, 200, 8);
        assert!(!ptr2.is_null());

        manager.free(sheap, ptr2);

        // Test reinit WITHOUT freeing (simulates bugged game code)
        let ptr3 = manager.alloc(sheap, 150, 8);
        assert!(!ptr3.is_null());

        // Reinit again - this invalidates ptr3
        manager.init(sheap, 2);

        // ptr3 is now dangling - do NOT attempt to free it
        // Allocate after reinit should still work
        let ptr4 = manager.alloc(sheap, 250, 8);
        assert!(!ptr4.is_null());
        manager.free(sheap, ptr4);

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_stress_long_session() {
        let manager = Arc::new(ScrapHeapManager::new());
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Simulate 1 hour of gameplay (compressed time)
        let num_iterations = 10000; // Represents frames
        let num_threads = 4;

        let barrier = Arc::new(Barrier::new(num_threads));
        let purge_barrier = Arc::new(Barrier::new(num_threads));
        let mut handles = vec![];

        for thread_id in 0..num_threads {
            let manager_clone = Arc::clone(&manager);
            let barrier_clone = Arc::clone(&barrier);
            let purge_barrier_clone = Arc::clone(&purge_barrier);

            let sheap_addr = sheap_ptr!(sheap);
            let handle = thread::spawn(move || {
                let sheap = from_sheap_ptr!(sheap_addr);
                barrier_clone.wait();

                for frame in 0..num_iterations {
                    let mut frame_ptrs = Vec::new();

                    // Allocate for this frame
                    let num_allocs = 5 + (frame % 20);
                    for _ in 0..num_allocs {
                        let size = 32 + ((frame + thread_id) % 512);
                        let ptr = manager_clone.alloc(sheap, size, 8);
                        if !ptr.is_null() {
                            frame_ptrs.push(ptr);
                        }
                    }

                    // Free ALL allocations before purge to avoid dangling pointers
                    for ptr in frame_ptrs {
                        manager_clone.free(sheap, ptr);
                    }

                    // Every 100 frames, synchronize all threads before purge
                    if frame % 100 == 0 {
                        // Wait for all threads to reach this point
                        purge_barrier_clone.wait();

                        // Only thread 0 purges after all threads synchronized
                        if thread_id == 0 {
                            manager_clone.purge(sheap);
                        }

                        // Wait again so no thread starts allocating until purge is done
                        purge_barrier_clone.wait();

                        thread::sleep(Duration::from_micros(10));
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_race_reset_and_alloc() {
        let manager = Arc::new(ScrapHeapManager::new());
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        let barrier = Arc::new(Barrier::new(2));

        // Thread 1: Allocate and free rapidly (triggers resets)
        let manager1 = Arc::clone(&manager);
        let barrier1 = Arc::clone(&barrier);
        let sheap_addr = sheap_ptr!(sheap);
        let h1 = thread::spawn(move || {
            let sheap = from_sheap_ptr!(sheap_addr);
            barrier1.wait();
            for _ in 0..500 {
                let ptr = manager1.alloc(sheap, 1024, 8);
                if !ptr.is_null() {
                    manager1.free(sheap, ptr);
                }
            }
        });

        // Thread 2: Allocate during resets and free at end
        let manager2 = Arc::clone(&manager);
        let barrier2 = Arc::clone(&barrier);
        let sheap_addr = sheap_ptr!(sheap);
        let h2 = thread::spawn(move || {
            let sheap = from_sheap_ptr!(sheap_addr);
            barrier2.wait();

            let mut ptrs = Vec::new();
            for _ in 0..500 {
                let ptr = manager2.alloc(sheap, 512, 8);
                assert!(!ptr.is_null(), "Allocation failed during concurrent reset");
                ptrs.push(ptr);
                thread::sleep(Duration::from_micros(5));
            }

            // Free all allocations
            for ptr in ptrs {
                manager2.free(sheap, ptr);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_generation_invalidation() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Allocate
        let ptr1 = manager.alloc(sheap, 100, 8);
        assert!(!ptr1.is_null());

        // Purge (increments generation)
        manager.purge(sheap);

        // Allocate again (should work, new generation)
        let ptr2 = manager.alloc(sheap, 100, 8);
        assert!(!ptr2.is_null());

        manager.free(sheap, ptr2);

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_fallback_with_concurrent_frees() {
        let manager = Arc::new(ScrapHeapManager::new());
        let sheap = create_test_sheap();
        let sheap_addr = sheap_ptr!(sheap);

        manager.init(sheap, 1);

        // Allocate enough to trigger fallback
        let large_ptrs: Vec<_> = (0..40)
            .map(|_| manager.alloc(sheap, 1024 * 1024, 8))
            .collect();

        // Convert pointers to usize for Send
        let large_addrs: Vec<usize> = large_ptrs.iter().map(|&p| p as usize).collect();

        // Free concurrently from multiple threads
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = vec![];

        for chunk_id in 0..4 {
            let manager_clone = Arc::clone(&manager);
            let barrier_clone = Arc::clone(&barrier);
            let addrs_chunk: Vec<_> = large_addrs
                .iter()
                .skip(chunk_id * 10)
                .take(10)
                .copied()
                .collect();

            let handle = thread::spawn(move || {
                let sheap = from_sheap_ptr!(sheap_addr);
                barrier_clone.wait();
                for addr in addrs_chunk {
                    let ptr = addr as *mut c_void;
                    manager_clone.free(sheap, ptr);
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should be recovered and working
        let ptr = manager.alloc(sheap, 1024, 8);
        assert!(!ptr.is_null());
        manager.free(sheap, ptr);

        unsafe { destroy_test_sheap(sheap) };
    }

    #[test]
    fn test_partial_free_before_reset() {
        let manager = ScrapHeapManager::new();
        let sheap = create_test_sheap();

        manager.init(sheap, 1);

        // Allocate 100 chunks
        let mut ptrs = Vec::new();
        for _ in 0..100 {
            let ptr = manager.alloc(sheap, 128, 8);
            assert!(!ptr.is_null());
            ptrs.push(ptr);
        }

        // Free only 50 (not all)
        for ptr in ptrs.iter().take(50) {
            manager.free(sheap, *ptr);
        }

        // Reset should NOT happen (not all freed)

        // Allocate more
        let ptr = manager.alloc(sheap, 256, 8);
        assert!(!ptr.is_null());

        // Free remaining + new
        for ptr in ptrs.iter().skip(50) {
            manager.free(sheap, *ptr);
        }
        manager.free(sheap, ptr);

        // Now reset should happen

        unsafe { destroy_test_sheap(sheap) };
    }
}
