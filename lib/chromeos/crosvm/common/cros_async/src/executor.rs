// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;

use async_task::Task;

use super::{
    poll_source::Error as PollError, uring_executor::use_uring, AsyncResult, FdExecutor, IntoAsync,
    IoSourceExt, PollSource, URingExecutor, UringSource,
};

pub(crate) fn async_uring_from<'a, F: IntoAsync + Send + 'a>(
    f: F,
    ex: &URingExecutor,
) -> AsyncResult<Box<dyn IoSourceExt<F> + Send + 'a>> {
    Ok(UringSource::new(f, ex).map(|u| Box::new(u) as Box<dyn IoSourceExt<F> + Send>)?)
}

/// Creates a concrete `IoSourceExt` using the fd_executor.
pub(crate) fn async_poll_from<'a, F: IntoAsync + Send + 'a>(
    f: F,
    ex: &FdExecutor,
) -> AsyncResult<Box<dyn IoSourceExt<F> + Send + 'a>> {
    Ok(PollSource::new(f, ex).map(|u| Box::new(u) as Box<dyn IoSourceExt<F> + Send>)?)
}

/// An executor for scheduling tasks that poll futures to completion.
///
/// All asynchronous operations must run within an executor, which is capable of spawning futures as
/// tasks. This executor also provides a mechanism for performing asynchronous I/O operations.
///
/// The returned type is a cheap, clonable handle to the underlying executor. Cloning it will only
/// create a new reference, not a new executor.
///
/// # Examples
///
/// Concurrently wait for multiple files to become readable/writable and then read/write the data.
///
/// ```
/// use std::cmp::min;
/// use std::error::Error;
/// use std::fs::{File, OpenOptions};
///
/// use cros_async::{AsyncResult, Executor, IoSourceExt, complete3};
/// const CHUNK_SIZE: usize = 32;
///
/// // Write all bytes from `data` to `f`.
/// async fn write_file(f: &dyn IoSourceExt<File>, mut data: Vec<u8>) -> AsyncResult<()> {
///     while data.len() > 0 {
///         let (count, mut buf) = f.write_from_vec(None, data).await?;
///
///         data = buf.split_off(count);
///     }
///
///     Ok(())
/// }
///
/// // Transfer `len` bytes of data from `from` to `to`.
/// async fn transfer_data(
///     from: Box<dyn IoSourceExt<File>>,
///     to: Box<dyn IoSourceExt<File>>,
///     len: usize,
/// ) -> AsyncResult<usize> {
///     let mut rem = len;
///
///     while rem > 0 {
///         let buf = vec![0u8; min(rem, CHUNK_SIZE)];
///         let (count, mut data) = from.read_to_vec(None, buf).await?;
///
///         if count == 0 {
///             // End of file. Return the number of bytes transferred.
///             return Ok(len - rem);
///         }
///
///         data.truncate(count);
///         write_file(&*to, data).await?;
///
///         rem = rem.saturating_sub(count);
///     }
///
///     Ok(len)
/// }
///
/// # fn do_it() -> Result<(), Box<dyn Error>> {
///     let ex = Executor::new()?;
///
///     let (rx, tx) = sys_util::pipe(true)?;
///     let zero = File::open("/dev/zero")?;
///     let zero_bytes = CHUNK_SIZE * 7;
///     let zero_to_pipe = transfer_data(
///         ex.async_from(zero)?,
///         ex.async_from(tx.try_clone()?)?,
///         zero_bytes,
///     );
///
///     let rand = File::open("/dev/urandom")?;
///     let rand_bytes = CHUNK_SIZE * 19;
///     let rand_to_pipe = transfer_data(ex.async_from(rand)?, ex.async_from(tx)?, rand_bytes);
///
///     let null = OpenOptions::new().write(true).open("/dev/null")?;
///     let null_bytes = zero_bytes + rand_bytes;
///     let pipe_to_null = transfer_data(ex.async_from(rx)?, ex.async_from(null)?, null_bytes);
///
///     ex.run_until(complete3(
///         async { assert_eq!(pipe_to_null.await.unwrap(), null_bytes) },
///         async { assert_eq!(zero_to_pipe.await.unwrap(), zero_bytes) },
///         async { assert_eq!(rand_to_pipe.await.unwrap(), rand_bytes) },
///     ))?;
///
/// #     Ok(())
/// # }
///
/// # do_it().unwrap();
/// ```

#[derive(Clone)]
pub enum Executor {
    Uring(URingExecutor),
    Fd(FdExecutor),
}

impl Executor {
    /// Create a new `Executor`.
    pub fn new() -> AsyncResult<Self> {
        if use_uring() {
            Ok(URingExecutor::new().map(Executor::Uring)?)
        } else {
            Ok(FdExecutor::new()
                .map(Executor::Fd)
                .map_err(PollError::Executor)?)
        }
    }

    /// Create a new `Box<dyn IoSourceExt<F>>` associated with `self`. Callers may then use the
    /// returned `IoSourceExt` to directly start async operations without needing a separate
    /// reference to the executor.
    pub fn async_from<'a, F: IntoAsync + Send + 'a>(
        &self,
        f: F,
    ) -> AsyncResult<Box<dyn IoSourceExt<F> + Send + 'a>> {
        match self {
            Executor::Uring(ex) => async_uring_from(f, ex),
            Executor::Fd(ex) => async_poll_from(f, ex),
        }
    }

    /// Spawn a new future for this executor to run to completion. Callers may use the returned
    /// `Task` to await on the result of `f`. Dropping the returned `Task` will cancel `f`,
    /// preventing it from being polled again. To drop a `Task` without canceling the future
    /// associated with it use `Task::detach`. To cancel a task gracefully and wait until it is
    /// fully destroyed, use `Task::cancel`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use cros_async::AsyncResult;
    /// # fn example_spawn() -> AsyncResult<()> {
    /// #      use std::thread;
    ///
    /// #      use cros_async::Executor;
    ///       use futures::executor::block_on;
    ///
    /// #      let ex = Executor::new()?;
    ///
    /// #      // Spawn a thread that runs the executor.
    /// #      let ex2 = ex.clone();
    /// #      thread::spawn(move || ex2.run());
    ///
    ///       let task = ex.spawn(async { 7 + 13 });
    ///
    ///       let result = block_on(task);
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    ///
    /// # example_spawn().unwrap();
    /// ```
    pub fn spawn<F>(&self, f: F) -> Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match self {
            Executor::Uring(ex) => ex.spawn(f),
            Executor::Fd(ex) => ex.spawn(f),
        }
    }

    /// Spawn a thread-local task for this executor to drive to completion. Like `spawn` but without
    /// requiring `Send` on `F` or `F::Output`. This method should only be called from the same
    /// thread where `run()` or `run_until()` is called.
    ///
    /// # Panics
    ///
    /// `Executor::run` and `Executor::run_util` will panic if they try to poll a future that was
    /// added by calling `spawn_local` from a different thread.
    ///
    /// # Examples
    ///
    /// ```
    /// # use cros_async::AsyncResult;
    /// # fn example_spawn_local() -> AsyncResult<()> {
    /// #      use cros_async::Executor;
    ///
    /// #      let ex = Executor::new()?;
    ///
    ///       let task = ex.spawn_local(async { 7 + 13 });
    ///
    ///       let result = ex.run_until(task)?;
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    ///
    /// # example_spawn_local().unwrap();
    /// ```
    pub fn spawn_local<F>(&self, f: F) -> Task<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        match self {
            Executor::Uring(ex) => ex.spawn_local(f),
            Executor::Fd(ex) => ex.spawn_local(f),
        }
    }

    /// Run the provided closure on a dedicated thread where blocking is allowed.
    ///
    /// Callers may `await` on the returned `Task` to wait for the result of `f`. Dropping or
    /// canceling the returned `Task` may not cancel the operation if it was already started on a
    /// worker thread.
    ///
    /// # Panics
    ///
    /// `await`ing the `Task` after the `Executor` is dropped will panic if the work was not already
    /// completed.
    ///
    /// # Examples
    ///
    /// ```edition2018
    /// # use cros_async::Executor;
    ///
    /// # async fn do_it(ex: &Executor) {
    ///     let res = ex.spawn_blocking(move || {
    ///         // Do some CPU-intensive or blocking work here.
    ///
    ///         42
    ///     }).await;
    ///
    ///     assert_eq!(res, 42);
    /// # }
    ///
    /// # let ex = Executor::new().unwrap();
    /// # ex.run_until(do_it(&ex)).unwrap();
    /// ```
    pub fn spawn_blocking<F, R>(&self, f: F) -> Task<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        match self {
            Executor::Uring(ex) => ex.spawn_blocking(f),
            Executor::Fd(ex) => ex.spawn_blocking(f),
        }
    }

    /// Run the executor indefinitely, driving all spawned futures to completion. This method will
    /// block the current thread and only return in the case of an error.
    ///
    /// # Panics
    ///
    /// Once this method has been called on a thread, it may only be called on that thread from that
    /// point on. Attempting to call it from another thread will panic.
    ///
    /// # Examples
    ///
    /// ```
    /// # use cros_async::AsyncResult;
    /// # fn example_run() -> AsyncResult<()> {
    ///       use std::thread;
    ///
    ///       use cros_async::Executor;
    ///       use futures::executor::block_on;
    ///
    ///       let ex = Executor::new()?;
    ///
    ///       // Spawn a thread that runs the executor.
    ///       let ex2 = ex.clone();
    ///       thread::spawn(move || ex2.run());
    ///
    ///       let task = ex.spawn(async { 7 + 13 });
    ///
    ///       let result = block_on(task);
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    ///
    /// # example_run().unwrap();
    /// ```
    pub fn run(&self) -> AsyncResult<()> {
        match self {
            Executor::Uring(ex) => ex.run()?,
            Executor::Fd(ex) => ex.run().map_err(PollError::Executor)?,
        }

        Ok(())
    }

    /// Drive all futures spawned in this executor until `f` completes. This method will block the
    /// current thread only until `f` is complete and there may still be unfinished futures in the
    /// executor.
    ///
    /// # Panics
    ///
    /// Once this method has been called on a thread, from then onwards it may only be called on
    /// that thread. Attempting to call it from another thread will panic.
    ///
    /// # Examples
    ///
    /// ```
    /// # use cros_async::AsyncResult;
    /// # fn example_run_until() -> AsyncResult<()> {
    ///       use cros_async::Executor;
    ///
    ///       let ex = Executor::new()?;
    ///
    ///       let task = ex.spawn_local(async { 7 + 13 });
    ///
    ///       let result = ex.run_until(task)?;
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    ///
    /// # example_run_until().unwrap();
    /// ```
    pub fn run_until<F: Future>(&self, f: F) -> AsyncResult<F::Output> {
        match self {
            Executor::Uring(ex) => Ok(ex.run_until(f)?),
            Executor::Fd(ex) => Ok(ex.run_until(f).map_err(PollError::Executor)?),
        }
    }
}
