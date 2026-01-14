use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use crate::common::mpmc_queue::slot::Slot;

#[repr(align(64))]
struct CacheLine<T>(T);

pub struct MpmcQueue<T> {
    // hot path
    enqueue_pos: CacheLine<AtomicUsize>,
    dequeue_pos: CacheLine<AtomicUsize>,

    // mostly read-only
    buffer_len: usize,
    buffer: Vec<Slot<T>>,
    mask: usize,

    // cold path
    not_empty: Condvar,
    not_full: Condvar,
    wait_lock: Mutex<()>,
}

unsafe impl<T: Send> Sync for MpmcQueue<T> {}
unsafe impl<T: Send> Send for MpmcQueue<T> {}

impl<T> MpmcQueue<T> {
    const SPIN_TRIES: u8 = 64;

    pub fn with_capacity(capacity: usize) -> Self {
        assert!(
            capacity >= 2 && capacity.is_power_of_two(),
            "capacity must be power of two >= 2"
        );

        let mut buffer = Vec::with_capacity(capacity);
        for i in 0..capacity {
            buffer.push(Slot {
                seq: AtomicUsize::new(i),
                value: UnsafeCell::new(MaybeUninit::uninit()),
            });
        }
        let buffer_len = buffer.len();
        Self {
            buffer,
            buffer_len,
            mask: capacity - 1,
            enqueue_pos: CacheLine(AtomicUsize::new(0)),
            dequeue_pos: CacheLine(AtomicUsize::new(0)),
            wait_lock: Mutex::new(()),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
        }
    }

    /// Non-blocking push: Ok(()) on success, Err(value) if full.
    pub fn push(&self, value: T) -> Result<(), T> {
        let v = value;
        loop {
            let pos = self.enqueue_pos.0.load(Ordering::Relaxed);
            let idx = pos & self.mask;
            let slot = &self.buffer[idx];
            let seq = slot.seq.load(Ordering::Acquire);

            if seq == pos {
                if self
                    .enqueue_pos
                    .0
                    .compare_exchange_weak(pos, pos + 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    unsafe {
                        let ptr = (*slot.value.get()).as_mut_ptr();
                        ptr::write(ptr, v);
                    }
                    slot.seq.store(pos + 1, Ordering::Release);
                    // Notify one consumer if they are waiting
                    self.not_empty.notify_one();
                    return Ok(());
                } else {
                    std::hint::spin_loop();
                    continue;
                }
            } else if seq < pos {
                // full
                return Err(v);
            } else {
                continue;
            }
        }
    }

    /// Non-blocking pop: Some(T) on success, None if empty.
    pub fn pop(&self) -> Option<T> {
        loop {
            let pos = self.dequeue_pos.0.load(Ordering::Relaxed);
            let idx = pos & self.mask;
            let slot = &self.buffer[idx];
            let seq = slot.seq.load(Ordering::Acquire);

            if seq == pos + 1 {
                if self
                    .dequeue_pos
                    .0
                    .compare_exchange_weak(pos, pos + 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    let val = unsafe {
                        let ptr = (*slot.value.get()).as_ptr();
                        ptr::read(ptr)
                    };
                    // Mark the slot as free
                    slot.seq.store(pos + self.buffer_len, Ordering::Release);
                    // Notify one manufacturer if they are waiting

                    self.not_full.notify_one();

                    return Some(val);
                } else {
                    continue;
                }
            } else if seq <= pos {
                return None;
            } else {
                continue;
            }
        }
    }

    /// Blocking push: will wait until a space becomes available.
    pub fn push_blocking(&self, mut value: T) {
        loop {
            // fast-path
            match self.push(value) {
                Ok(()) => return,
                Err(v) => value = v,
            }
            let mut spins = 0;
            while spins < Self::SPIN_TRIES {
                if !self.is_full() {
                    break;
                }
                std::hint::spin_loop();
                spins += 1;
            }

            // 2) real blocking
            let mut guard = self.wait_lock.lock().unwrap();

            while self.is_full() {
                guard = self.not_full.wait(guard).unwrap();
            }
            // unlock + retry
        }
    }

    /// Blocking pop: will wait until the element appears.
    pub fn pop_blocking(&self) -> T {
        loop {
            // fast-path
            if let Some(v) = self.pop() {
                return v;
            }
            let mut spins = 0;
            while spins < Self::SPIN_TRIES {
                if !self.is_empty() {
                    break;
                }
                std::hint::spin_loop();
                spins += 1;
            }

            // 2) blocking

            let mut guard = self.wait_lock.lock().unwrap();

            while self.is_empty() {
                guard = self.not_empty.wait(guard).unwrap();
            }
        }
    }

    /// Flood-safe queue size (approximately accurate).
    /// Calculated by the difference between cursors; the result is limited by capacity.
    pub fn len(&self) -> usize {
        let r = self.dequeue_pos.0.load(Ordering::Relaxed);
        let w = self.enqueue_pos.0.load(Ordering::Relaxed);
        let diff = w.wrapping_sub(r);
        diff.min(self.buffer_len)
    }

    pub fn capacity(&self) -> usize {
        self.buffer_len
    }

    pub fn is_empty(&self) -> bool {
        let r = self.dequeue_pos.0.load(Ordering::Relaxed);
        let w = self.enqueue_pos.0.load(Ordering::Relaxed);
        w == r
    }

    pub fn is_full(&self) -> bool {
        let r = self.dequeue_pos.0.load(Ordering::Relaxed);
        let w = self.enqueue_pos.0.load(Ordering::Relaxed);
        w.wrapping_sub(r) == self.buffer_len
    }
}

impl<T> Drop for MpmcQueue<T> {
    fn drop(&mut self) {
        let r = self.dequeue_pos.0.load(Ordering::Relaxed);
        let w = self.enqueue_pos.0.load(Ordering::Relaxed);
        for pos in r..w {
            let idx = pos & self.mask;
            let slot = &self.buffer[idx];
            let seq = slot.seq.load(Ordering::Relaxed);
            if seq == pos + 1 {
                unsafe {
                    let ptr = (*slot.value.get()).as_mut_ptr();
                    ptr::drop_in_place(ptr);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_len_and_nonblocking() {
        let q = MpmcQueue::with_capacity(8);
        assert_eq!(q.len(), 0);
        assert!(q.push(1).is_ok());
        assert_eq!(q.len(), 1);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn test_blocking_push_pop() {
        let q = Arc::new(MpmcQueue::with_capacity(4));
        let prod = q.clone();
        let cons = q.clone();

        let p = thread::spawn(move || {
            for i in 0..10 {
                prod.push_blocking(i);
                // a slight delay to verify that the lock is functioning
                if i % 2 == 0 {
                    thread::sleep(Duration::from_millis(5));
                }
            }
        });

        let c = thread::spawn(move || {
            let mut got = Vec::new();
            for _ in 0..10 {
                let v = cons.pop_blocking();
                got.push(v);
                // emulate consumer behavior
                thread::sleep(Duration::from_millis(10));
            }
            got
        });

        p.join().unwrap();
        let got = c.join().unwrap();
        assert_eq!(got.len(), 10);
        assert_eq!(got[0], 0);
        assert_eq!(got[9], 9);
    }
}
