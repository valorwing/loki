use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicUsize;

pub struct Slot<T> {
    pub seq: AtomicUsize,
    pub value: UnsafeCell<MaybeUninit<T>>,
}

unsafe impl<T: Send> Sync for Slot<T> {}
unsafe impl<T: Send> Send for Slot<T> {}
