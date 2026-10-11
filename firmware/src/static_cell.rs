//! A `static`-friendly cell for FFI state that must keep a stable address.
//!
//! `SyncUnsafeCell` is not stable on the toolchain this firmware targets, so
//! the small wrapper below fills the same role: it lifts the `Sync` bound and
//! hands out a raw pointer, leaving the synchronisation reasoning to the type
//! that uses it.

use core::cell::UnsafeCell;

#[repr(transparent)]
pub struct StaticCell<T>(UnsafeCell<T>);

// SAFETY: the cell itself never synchronises anything; it only permits the
// value to live in a `static`. Callers must ensure mutation happens during
// single-threaded initialisation, after which the value is read-only.
unsafe impl<T> Sync for StaticCell<T> {}

impl<T> StaticCell<T> {
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// A raw pointer to the contained value, valid for the cell's lifetime.
    pub fn get(&self) -> *mut T {
        self.0.get()
    }
}
