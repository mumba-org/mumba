// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    future::Future,
    ptr,
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use futures::{
    pin_mut,
    task::{waker_ref, ArcWake},
};

// Randomly generated values to indicate the state of the current thread.
const WAITING: i32 = 0x25de_74d1;
const WOKEN: i32 = 0x72d3_2c9f;

const FUTEX_WAIT_PRIVATE: libc::c_int = libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: libc::c_int = libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG;

thread_local!(static PER_THREAD_WAKER: Arc<Waker> = Arc::new(Waker(AtomicI32::new(WAITING))));

#[repr(transparent)]
struct Waker(AtomicI32);

extern "C" {
    #[cfg_attr(target_os = "android", link_name = "__errno")]
    #[cfg_attr(target_os = "linux", link_name = "__errno_location")]
    fn errno_location() -> *mut libc::c_int;
}

impl ArcWake for Waker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        let state = arc_self.0.swap(WOKEN, Ordering::Release);
        if state == WAITING {
            // The thread hasn't already been woken up so wake it up now. Safe because this doesn't
            // modify any memory and we check the return value.
            let res = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    &arc_self.0,
                    FUTEX_WAKE_PRIVATE,
                    libc::INT_MAX,                        // val
                    ptr::null() as *const libc::timespec, // timeout
                    ptr::null() as *const libc::c_int,    // uaddr2
                    0_i32,                                // val3
                )
            };
            if res < 0 {
                panic!("unexpected error from FUTEX_WAKE_PRIVATE: {}", unsafe {
                    *errno_location()
                });
            }
        }
    }
}

/// Run a future to completion on the current thread.
///
/// This method will block the current thread until `f` completes. Useful when you need to call an
/// async fn from a non-async context.
pub fn block_on<F: Future>(f: F) -> F::Output {
    pin_mut!(f);

    PER_THREAD_WAKER.with(|thread_waker| {
        let waker = waker_ref(thread_waker);
        let mut cx = Context::from_waker(&waker);

        loop {
            if let Poll::Ready(t) = f.as_mut().poll(&mut cx) {
                return t;
            }

            let state = thread_waker.0.swap(WAITING, Ordering::Acquire);
            if state == WAITING {
                // If we weren't already woken up then wait until we are. Safe because this doesn't
                // modify any memory and we check the return value.
                let res = unsafe {
                    libc::syscall(
                        libc::SYS_futex,
                        &thread_waker.0,
                        FUTEX_WAIT_PRIVATE,
                        state,
                        ptr::null() as *const libc::timespec, // timeout
                        ptr::null() as *const libc::c_int,    // uaddr2
                        0_i32,                                // val3
                    )
                };

                if res < 0 {
                    // Safe because libc guarantees that this is a valid pointer.
                    match unsafe { *errno_location() } {
                        libc::EAGAIN | libc::EINTR => {}
                        e => panic!("unexpected error from FUTEX_WAIT_PRIVATE: {}", e),
                    }
                }

                // Clear the state to prevent unnecessary extra loop iterations and also to allow
                // nested usage of `block_on`.
                thread_waker.0.store(WAITING, Ordering::Release);
            }
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{
        future::Future,
        pin::Pin,
        sync::{
            mpsc::{channel, Sender},
            Arc,
        },
        task::{Context, Poll, Waker},
        thread,
        time::Duration,
    };

    use super::super::super::sync::SpinLock;

    struct TimerState {
        fired: bool,
        waker: Option<Waker>,
    }
    struct Timer {
        state: Arc<SpinLock<TimerState>>,
    }

    impl Future for Timer {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
            let mut state = self.state.lock();
            if state.fired {
                return Poll::Ready(());
            }

            state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn start_timer(dur: Duration, notify: Option<Sender<()>>) -> Timer {
        let state = Arc::new(SpinLock::new(TimerState {
            fired: false,
            waker: None,
        }));

        let thread_state = Arc::clone(&state);
        thread::spawn(move || {
            thread::sleep(dur);
            let mut ts = thread_state.lock();
            ts.fired = true;
            if let Some(waker) = ts.waker.take() {
                waker.wake();
            }
            drop(ts);

            if let Some(tx) = notify {
                tx.send(()).expect("Failed to send completion notification");
            }
        });

        Timer { state }
    }

    #[test]
    fn it_works() {
        block_on(start_timer(Duration::from_millis(100), None));
    }

    #[test]
    fn nested() {
        async fn inner() {
            block_on(start_timer(Duration::from_millis(100), None));
        }

        block_on(inner());
    }

    #[test]
    fn ready_before_poll() {
        let (tx, rx) = channel();

        let timer = start_timer(Duration::from_millis(50), Some(tx));

        rx.recv()
            .expect("Failed to receive completion notification");

        // We know the timer has already fired so the poll should complete immediately.
        block_on(timer);
    }
}
