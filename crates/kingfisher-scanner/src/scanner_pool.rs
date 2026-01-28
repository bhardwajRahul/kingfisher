//! Thread-local scanner pool for efficient multi-threaded scanning.

use std::cell::UnsafeCell;
use std::sync::Arc;

use thread_local::ThreadLocal;
use vectorscan_rs::{BlockDatabase, BlockScanner};

/// A pool of Vectorscan block scanners for efficient multi-threaded scanning.
///
/// Each thread gets its own scanner instance to avoid contention.
pub struct ScannerPool {
    db: Arc<BlockDatabase>,
    scanners: ThreadLocal<UnsafeCell<Option<BlockScanner<'static>>>>,
}

// Safety: Each thread only accesses its own scanner instance
unsafe impl Send for ScannerPool {}
unsafe impl Sync for ScannerPool {}

impl ScannerPool {
    /// Creates a new scanner pool from a compiled Vectorscan database.
    pub fn new(db: Arc<BlockDatabase>) -> Self {
        Self { db, scanners: ThreadLocal::new() }
    }

    /// Executes a function with a thread-local scanner.
    ///
    /// This ensures each thread has its own scanner instance, avoiding
    /// the need for locking during scanning operations.
    pub fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut BlockScanner<'_>) -> R,
    {
        let cell = self.scanners.get_or(|| UnsafeCell::new(None));

        // Safety: ThreadLocal guarantees only the current thread accesses this cell
        let scanner_opt = unsafe { &mut *cell.get() };

        // Create scanner if it doesn't exist
        // We extend the lifetime - this is safe because the database outlives the scanner pool
        if scanner_opt.is_none() {
            let db_ref: &'static BlockDatabase =
                unsafe { std::mem::transmute::<&BlockDatabase, &'static BlockDatabase>(&self.db) };
            *scanner_opt = Some(BlockScanner::new(db_ref).expect("Failed to create BlockScanner"));
        }

        f(scanner_opt.as_mut().unwrap())
    }
}
