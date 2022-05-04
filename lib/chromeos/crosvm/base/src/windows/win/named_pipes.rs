// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use rand::Rng;
use std::{
    ffi::CString,
    fs::OpenOptions,
    io,
    io::Result,
    mem,
    os::windows::fs::OpenOptionsExt,
    process, ptr,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::{Event, RawDescriptor};
use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, IntoRawDescriptor, SafeDescriptor};
use serde::{Deserialize, Serialize};
use win_util::{SecurityAttributes, SelfRelativeSecurityDescriptor};
use winapi::{
    shared::{
        minwindef::{DWORD, LPCVOID, LPVOID, TRUE},
        winerror::{ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_CONNECTED},
    },
    um::{
        errhandlingapi::GetLastError,
        fileapi::{FlushFileBuffers, ReadFile, WriteFile},
        handleapi::INVALID_HANDLE_VALUE,
        ioapiset::{CancelIoEx, GetOverlappedResult},
        minwinbase::OVERLAPPED,
        namedpipeapi::{
            ConnectNamedPipe, GetNamedPipeInfo, PeekNamedPipe, SetNamedPipeHandleState,
        },
        winbase::{
            CreateNamedPipeA, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
            PIPE_ACCESS_DUPLEX, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_READMODE_MESSAGE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
            SECURITY_IDENTIFICATION,
        },
    },
};

/// The default buffer size for all named pipes in the system. If this size is too small, writers
/// on named pipes that expect not to block *can* block until the reading side empties the buffer.
///
/// The general rule is this should be *at least* as big as the largest message, otherwise
/// unexpected blocking behavior can result; for example, if too small, this can interact badly with
/// crate::platform::StreamChannel, which expects to be able to make a complete write before releasing
/// a lock that the opposite side needs to complete a read. This means that if the buffer is too
/// small:
///     * The writer can't complete its write and release the lock because the buffer is too small.
///     * The reader can't start reading because the lock is held by the writer, so it can't
///       relieve buffer pressure. Note that for message pipes, the reader couldn't do anything
///       to help anyway, because a message mode pipe should NOT have a partial read (which is
///       what we would need to relieve pressure).
///     * Conditions for deadlock are met, and both the reader & writer enter circular waiting.
pub const DEFAULT_BUFFER_SIZE: usize = 50 * 1024;

static NEXT_PIPE_INDEX: AtomicUsize = AtomicUsize::new(1);

/// Represents one end of a named pipe
#[derive(Serialize, Deserialize, Debug)]
pub struct PipeConnection {
    handle: SafeDescriptor,
    framing_mode: FramingMode,
    blocking_mode: BlockingMode,
}

/// Wraps the OVERLAPPED structure. Also keeps track of whether OVERLAPPED is being used by a
/// Readfile or WriteFile operation and holds onto the event object so it doesn't get dropped.
pub struct OverlappedWrapper {
    // Allocated on the heap so that the OVERLAPPED struct doesn't move when performing I/O
    // operations.
    overlapped: Box<OVERLAPPED>,
    // This field prevents the event handle from being dropped too early and allows callers to
    // be notified when a read or write overlapped operation has completed.
    h_event: Option<Event>,
    in_use: bool,
}

impl OverlappedWrapper {
    pub fn get_h_event_ref(&self) -> Option<&Event> {
        self.h_event.as_ref()
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq)]
pub enum FramingMode {
    Byte,
    Message,
}

impl FramingMode {
    fn to_readmode(self) -> DWORD {
        match self {
            FramingMode::Message => PIPE_READMODE_MESSAGE,
            FramingMode::Byte => PIPE_READMODE_BYTE,
        }
    }

    fn to_pipetype(self) -> DWORD {
        match self {
            FramingMode::Message => PIPE_TYPE_MESSAGE,
            FramingMode::Byte => PIPE_TYPE_BYTE,
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Debug)]
pub enum BlockingMode {
    /// Calls to read() block until data is received
    Wait,
    /// Calls to read() return immediately even if there is nothing read with error code 232
    /// (Rust maps this to BrokenPipe but it's actually ERROR_NO_DATA)
    ///
    /// NOTE: This mode is discouraged by the Windows API documentation.
    NoWait,
}

impl From<&BlockingMode> for DWORD {
    fn from(blocking_mode: &BlockingMode) -> DWORD {
        match blocking_mode {
            BlockingMode::Wait => PIPE_WAIT,
            BlockingMode::NoWait => PIPE_NOWAIT,
        }
    }
}

/// Sets the handle state for a named pipe in a rust friendly way.
/// This is safe if the pipe handle is open.
unsafe fn set_named_pipe_handle_state(
    pipe_handle: RawDescriptor,
    client_mode: &mut DWORD,
) -> Result<()> {
    // Safe when the pipe handle is open. Safety also requires checking the return value, which we
    // do below.
    let success_flag = SetNamedPipeHandleState(
        /* hNamedPipe= */ pipe_handle,
        /* lpMode= */ client_mode,
        /* lpMaxCollectionCount= */ ptr::null_mut(),
        /* lpCollectDataTimeout= */ ptr::null_mut(),
    );
    if success_flag == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn pair(
    framing_mode: &FramingMode,
    blocking_mode: &BlockingMode,
    timeout: u64,
) -> Result<(PipeConnection, PipeConnection)> {
    pair_with_buffer_size(
        framing_mode,
        blocking_mode,
        timeout,
        DEFAULT_BUFFER_SIZE,
        false,
    )
}

/// Creates a pair of handles connected to either end of a duplex named pipe.
///
/// The pipe created will have a semi-random name and a default set of security options that
/// help prevent common named-pipe based vulnerabilities. Specifically the pipe is set to reject
/// remote clients, allow only a single server instance, and prevent impersonation by the server
/// end of the pipe.
///
/// # Arguments
///
/// * `framing_mode`  - Whether the system should provide a simple byte stream (Byte) or an
///                     automatically framed sequence of messages (Message). In message mode it's an
///                     error to read fewer bytes than were sent in a message from the other end of
///                     the pipe.
/// * `blocking_mode` - Whether the system should wait on read() until data is available (Wait) or
///                     return immediately if there is nothing available (NoWait).
/// * `timeout`       - A timeout to apply for socket operations, in milliseconds.
///                     Setting this to zero will create sockets with the system
///                     default timeout.
/// * `buffer_size`   - The default buffer size for the named pipe. The system should expand the
///                     buffer automatically as needed, except in the case of NOWAIT pipes, where
///                     it will just fail writes that don't fit in the buffer.
/// # Return value
///
/// Returns a pair of pipes, of the form (server, client). Note that for some winapis, such as
/// FlushFileBuffers, the server & client ends WILL BEHAVE DIFFERENTLY.
pub fn pair_with_buffer_size(
    framing_mode: &FramingMode,
    blocking_mode: &BlockingMode,
    timeout: u64,
    buffer_size: usize,
    overlapped: bool,
) -> Result<(PipeConnection, PipeConnection)> {
    // Give the pipe a unique name to avoid accidental collisions
    let pipe_name = format!(
        r"\\.\pipe\crosvm_ipc.pid{}.{}.rand{}",
        process::id(),
        NEXT_PIPE_INDEX.fetch_add(1, Ordering::SeqCst),
        rand::thread_rng().gen::<u32>(),
    );

    let server_end = create_server_pipe(
        &pipe_name,
        framing_mode,
        blocking_mode,
        timeout,
        buffer_size,
        overlapped,
    )?;

    // Open the named pipe we just created as the client
    let client_end = create_client_pipe(&pipe_name, framing_mode, blocking_mode, overlapped)?;

    // Accept the client's connection
    // Not sure if this is strictly needed but I'm doing it just in case.
    // We expect at this point that the client will already be connected,
    // so we'll get a return code of 0 and an ERROR_PIPE_CONNECTED.
    // It's also OK if we get a return code of success.
    server_end.wait_for_client_connection()?;

    Ok((server_end, client_end))
}

/// Creates a PipeConnection for the server end of a named pipe with the given path and pipe
/// settings.
///
/// The pipe will be set to reject remote clients and allow only a single connection at a time.
///
/// # Arguments
///
/// * `pipe_name`     - The path of the named pipe to create. Should be in the form
///                     `\\.\pipe\<some-name>`.
/// * `framing_mode`  - Whether the system should provide a simple byte stream (Byte) or an
///                     automatically framed sequence of messages (Message). In message mode it's an
///                     error to read fewer bytes than were sent in a message from the other end of
///                     the pipe.
/// * `blocking_mode` - Whether the system should wait on read() until data is available (Wait) or
///                     return immediately if there is nothing available (NoWait).
/// * `timeout`       - A timeout to apply for socket operations, in milliseconds.
///                     Setting this to zero will create sockets with the system
///                     default timeout.
/// * `buffer_size`   - The default buffer size for the named pipe. The system should expand the
///                     buffer automatically as needed, except in the case of NOWAIT pipes, where
///                     it will just fail writes that don't fit in the buffer.
/// * `overlapped`    - Sets whether overlapped mode is set on the pipe.
pub fn create_server_pipe(
    pipe_name: &str,
    framing_mode: &FramingMode,
    blocking_mode: &BlockingMode,
    timeout: u64,
    buffer_size: usize,
    overlapped: bool,
) -> Result<PipeConnection> {
    let c_pipe_name = CString::new(pipe_name).unwrap();

    let mut open_mode_flags = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
    if overlapped {
        open_mode_flags |= FILE_FLAG_OVERLAPPED
    }

    // This sets flags so there will be an error if >1 instance (server end)
    // of this pipe name is opened because we expect exactly one.
    let server_handle = unsafe {
        // Safe because security attributes are valid, pipe_name is valid C string,
        // and we're checking the return code
        CreateNamedPipeA(
            c_pipe_name.as_ptr(),
            /* dwOpenMode= */
            open_mode_flags,
            /* dwPipeMode= */
            framing_mode.to_pipetype()
                | framing_mode.to_readmode()
                | DWORD::from(blocking_mode)
                | PIPE_REJECT_REMOTE_CLIENTS,
            /* nMaxInstances= */ 1,
            /* nOutBufferSize= */ buffer_size as DWORD,
            /* nInBufferSize= */ buffer_size as DWORD,
            /* nDefaultTimeOut= */ timeout as DWORD, // Default is 50ms
            /* lpSecurityAttributes= */
            SecurityAttributes::new_with_security_descriptor(
                SelfRelativeSecurityDescriptor::get_singleton(),
                /* inherit= */ true,
            )
            .as_mut(),
        )
    };

    if server_handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        unsafe {
            Ok(PipeConnection {
                handle: SafeDescriptor::from_raw_descriptor(server_handle),
                framing_mode: *framing_mode,
                blocking_mode: *blocking_mode,
            })
        }
    }
}

/// Creates a PipeConnection for the client end of a named pipe with the given path and pipe
/// settings.
///
/// The pipe will be set to prevent impersonation of the client by the server process.
///
/// # Arguments
///
/// * `pipe_name`     - The path of the named pipe to create. Should be in the form
///                     `\\.\pipe\<some-name>`.
/// * `framing_mode`  - Whether the system should provide a simple byte stream (Byte) or an
///                     automatically framed sequence of messages (Message). In message mode it's an
///                     error to read fewer bytes than were sent in a message from the other end of
///                     the pipe.
/// * `blocking_mode` - Whether the system should wait on read() until data is available (Wait) or
///                     return immediately if there is nothing available (NoWait).
/// * `overlapped`    - Sets whether the pipe is opened in overlapped mode.
pub fn create_client_pipe(
    pipe_name: &str,
    framing_mode: &FramingMode,
    blocking_mode: &BlockingMode,
    overlapped: bool,
) -> Result<PipeConnection> {
    let client_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .custom_flags(if overlapped { FILE_FLAG_OVERLAPPED } else { 0 })
        .open(pipe_name)?
        .into_raw_descriptor();

    let mut client_mode = framing_mode.to_readmode() | DWORD::from(blocking_mode);

    // Safe because client_handle's open() call did not return an error.
    unsafe {
        set_named_pipe_handle_state(client_handle, &mut client_mode)?;
    }

    Ok(PipeConnection {
        // Safe because client_handle is valid
        handle: unsafe { SafeDescriptor::from_raw_descriptor(client_handle) },
        framing_mode: *framing_mode,
        blocking_mode: *blocking_mode,
    })
}

// This is used to mark types which can be appropriately sent through the
// generic helper functions write_to_pipe and read_from_pipe.
pub trait PipeSendable {
    // Default values used to fill in new empty indexes when resizing a buffer to
    // a larger size.
    fn default() -> Self;
}
impl PipeSendable for u8 {
    fn default() -> Self {
        0
    }
}
impl PipeSendable for RawDescriptor {
    fn default() -> Self {
        ptr::null_mut()
    }
}

impl PipeConnection {
    pub fn try_clone(&self) -> Result<PipeConnection> {
        let copy_handle = self.handle.try_clone()?;
        Ok(PipeConnection {
            handle: copy_handle,
            framing_mode: self.framing_mode,
            blocking_mode: self.blocking_mode,
        })
    }

    /// Creates a PipeConnection from an existing RawDescriptor, and the underlying the framing &
    /// blocking modes.
    ///
    /// # Safety
    /// 1. rd is valid and ownership is transferred to this function when it is called.
    ///
    /// To avoid undefined behavior, framing_mode & blocking_modes must match those of the
    /// underlying pipe.
    pub unsafe fn from_raw_descriptor(
        rd: RawDescriptor,
        framing_mode: FramingMode,
        blocking_mode: BlockingMode,
    ) -> PipeConnection {
        PipeConnection {
            handle: SafeDescriptor::from_raw_descriptor(rd),
            framing_mode,
            blocking_mode,
        }
    }

    /// Reads bytes from the pipe into the provided buffer, up to the capacity of the buffer.
    /// Returns the number of bytes (not values) read.
    ///
    /// # Safety
    ///
    /// This is safe only when the following conditions hold:
    ///     1. The data on the other end of the pipe is a valid binary representation of data for
    ///     type T, and
    ///     2. The number of bytes read is a multiple of the size of T; this must be checked by
    ///     the caller.
    /// If buf's type is file descriptors, this is only safe when those file descriptors are valid
    /// for the process where this function was called.
    pub unsafe fn read<T: PipeSendable>(&self, buf: &mut [T]) -> Result<usize> {
        PipeConnection::read_internal(&self.handle, self.blocking_mode, buf, None)
    }

    /// Similar to `PipeConnection::read` except it also allows:
    ///     1. The same end of the named pipe to read and write at the same time in different
    ///        threads.
    ///     2. Asynchronous read and write (read and write won't block).
    ///
    /// When reading, it will not block, but instead an `OVERLAPPED` struct that contains an event
    /// (can be created with `PipeConnection::create_overlapped_struct`) will be passed into
    /// `ReadFile`. That event will be triggered when the read operation is complete.
    ///
    /// In order to get how many bytes were read, call `get_overlapped_result`. That function will
    /// also help with waiting until the read operation is complete.
    ///
    /// # Safety
    ///
    /// Same as `PipeConnection::read` safety comments. In addition, the pipe MUST be opened in
    /// overlapped mode otherwise there may be unexpected behavior.
    pub unsafe fn read_overlapped<T: PipeSendable>(
        &mut self,
        buf: &mut [T],
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> Result<()> {
        if overlapped_wrapper.in_use {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Overlapped struct already in use",
            ));
        }
        overlapped_wrapper.in_use = true;

        PipeConnection::read_internal(
            &self.handle,
            self.blocking_mode,
            buf,
            Some(&mut overlapped_wrapper.overlapped),
        )?;
        Ok(())
    }

    /// Helper for `read_overlapped` and `read`
    ///
    /// # Safety
    /// Comments `read_overlapped` or `read`, depending on which is used.
    unsafe fn read_internal<T: PipeSendable>(
        handle: &SafeDescriptor,
        blocking_mode: BlockingMode,
        buf: &mut [T],
        overlapped: Option<&mut OVERLAPPED>,
    ) -> Result<usize> {
        let max_bytes_to_read: DWORD = mem::size_of_val(buf) as DWORD;
        // Used to verify if ERROR_IO_PENDING should be an error.
        let is_overlapped = overlapped.is_some();

        // Safe because we cap the size of the read to the size of the buffer
        // and check the return code
        let mut bytes_read: DWORD = 0;
        let success_flag = ReadFile(
            handle.as_raw_descriptor(),
            buf.as_ptr() as LPVOID,
            max_bytes_to_read,
            match overlapped {
                Some(_) => std::ptr::null_mut(),
                None => &mut bytes_read,
            },
            match overlapped {
                Some(v) => v,
                None => std::ptr::null_mut(),
            },
        );

        if success_flag == 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(error_code)
                    if blocking_mode == BlockingMode::NoWait
                        && error_code == ERROR_NO_DATA as i32 =>
                {
                    // A NOWAIT pipe will return ERROR_NO_DATA when no data is available; however,
                    // this code is interpreted as a std::io::ErrorKind::BrokenPipe, which is not
                    // correct. For further details see:
                    // https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
                    // https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes
                    Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, e))
                }
                // ERROR_IO_PENDING, according the to docs, isn't really an error. This just means
                // that the ReadFile operation hasn't completed. In this case,
                // `get_overlapped_result` will wait until the operation is completed.
                Some(error_code) if error_code == ERROR_IO_PENDING as i32 && is_overlapped => {
                    return Ok(0);
                }
                _ => Err(e),
            }
        } else {
            Ok(bytes_read as usize)
        }
    }

    /// Gets the size in bytes of data in the pipe.
    ///
    /// Note that PeekNamedPipes (the underlying win32 API) will return zero if the packets have
    /// not finished writing on the producer side.
    pub fn get_available_byte_count(&self) -> io::Result<u32> {
        let mut total_bytes_avail: DWORD = 0;

        // Safe because the underlying pipe handle is guaranteed to be open, and the output values
        // live at valid memory locations.
        let res = unsafe {
            PeekNamedPipe(
                self.as_raw_descriptor(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut total_bytes_avail,
                ptr::null_mut(),
            )
        };

        if res == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(total_bytes_avail)
        }
    }

    /// Writes the bytes from a slice into the pipe. Returns the number of bytes written, which
    /// callers should check to ensure that it was the number expected.
    pub fn write<T: PipeSendable>(&self, buf: &[T]) -> Result<usize> {
        PipeConnection::write_internal(&self.handle, buf, None)
    }

    /// Similar to `PipeConnection::write` except it also allows:
    ///     1. The same end of the named pipe to read and write at the same time in different
    ///        threads.
    ///     2. Asynchronous read and write (read and write won't block).
    ///
    /// When writing, it will not block, but instead an `OVERLAPPED` struct that contains an event
    /// (can be created with `PipeConnection::create_overlapped_struct`) will be passed into
    /// `WriteFile`. That event will be triggered when the write operation is complete.
    ///
    /// In order to get how many bytes were written, call `get_overlapped_result`. That function will
    /// also help with waiting until the write operation is complete. The pipe must be opened in
    /// overlapped otherwise there may be unexpected behavior.
    pub fn write_overlapped<T: PipeSendable>(
        &mut self,
        buf: &[T],
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> Result<()> {
        if overlapped_wrapper.in_use {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Overlapped struct already in use",
            ));
        }
        overlapped_wrapper.in_use = true;

        PipeConnection::write_internal(
            &self.handle,
            buf,
            Some(&mut overlapped_wrapper.overlapped),
        )?;
        Ok(())
    }

    /// Helper for `write_overlapped` and `write`.
    fn write_internal<T: PipeSendable>(
        handle: &SafeDescriptor,
        buf: &[T],
        overlapped: Option<&mut OVERLAPPED>,
    ) -> Result<usize> {
        let bytes_to_write: DWORD = mem::size_of_val(buf) as DWORD;
        let is_overlapped = overlapped.is_some();

        // Safe because buf points to a valid region of memory whose size we have computed,
        // pipe has not been closed (as it's managed by this object), and we check the return
        // value for any errors
        unsafe {
            let mut bytes_written: DWORD = 0;
            let success_flag = WriteFile(
                handle.as_raw_descriptor(),
                buf.as_ptr() as LPCVOID,
                bytes_to_write,
                match overlapped {
                    Some(_) => std::ptr::null_mut(),
                    None => &mut bytes_written,
                },
                match overlapped {
                    Some(v) => v,
                    None => std::ptr::null_mut(),
                },
            );

            if success_flag == 0 {
                let err = io::Error::last_os_error().raw_os_error().unwrap() as u32;
                if err == ERROR_IO_PENDING && is_overlapped {
                    return Ok(0);
                }
                Err(io::Error::last_os_error())
            } else {
                Ok(bytes_written as usize)
            }
        }
    }

    /// Sets the blocking mode on the pipe.
    pub fn set_blocking(&mut self, blocking_mode: &BlockingMode) -> io::Result<()> {
        let mut client_mode = DWORD::from(blocking_mode) | self.framing_mode.to_readmode();
        self.blocking_mode = *blocking_mode;

        // Safe because the pipe has not been closed (it is managed by this object).
        unsafe { set_named_pipe_handle_state(self.handle.as_raw_descriptor(), &mut client_mode) }
    }

    /// For a server named pipe, waits for a client to connect
    pub fn wait_for_client_connection(&self) -> Result<()> {
        // Safe because the handle is valid and we're checking the return
        // code according to the documentation
        unsafe {
            let success_flag = ConnectNamedPipe(
                self.as_raw_descriptor(),
                /* lpOverlapped= */ ptr::null_mut(),
            );
            if success_flag == 0 && GetLastError() != ERROR_PIPE_CONNECTED {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Used for overlapped read and write operations.
    ///
    /// This will block until the ReadFile or WriteFile operation that also took in
    /// `overlapped_wrapper` is complete, assuming `overlapped_wrapper` was created from
    /// `create_overlapped_struct` or that OVERLAPPED.hEvent is set. This will also get
    /// the number of bytes that were read or written.
    pub fn get_overlapped_result(
        &mut self,
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> io::Result<u32> {
        if !overlapped_wrapper.in_use {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Overlapped struct is not in use",
            ));
        }
        let mut size_transferred = 0;
        // Safe as long as `overlapped_struct` isn't copied and also contains a valid event.
        // Also the named pipe handle must created with `FILE_FLAG_OVERLAPPED`.
        let res = unsafe {
            GetOverlappedResult(
                self.handle.as_raw_descriptor(),
                &mut *overlapped_wrapper.overlapped,
                &mut size_transferred,
                TRUE,
            )
        };
        overlapped_wrapper.in_use = false;
        if res == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(size_transferred)
        }
    }

    /// Creates a valid `OVERLAPPED` struct used to pass into `ReadFile` and `WriteFile` in order
    /// to perform asynchronous I/O. When passing in the OVERLAPPED struct, the Event object
    /// returned must not be dropped.
    ///
    /// There is an option to create the event object and set it to the `hEvent` field. If hEvent
    /// is not set and the named pipe handle was created with `FILE_FLAG_OVERLAPPED`, then the file
    /// handle will be signaled when the operation is complete. In other words, you can use
    /// `WaitForSingleObject` on the file handle. Not setting an event is highly discouraged by
    /// Microsoft though.
    pub fn create_overlapped_struct(include_event: bool) -> Result<OverlappedWrapper> {
        let mut overlapped = OVERLAPPED::default();
        let h_event = if include_event {
            Some(Event::new()?)
        } else {
            None
        };
        overlapped.hEvent = h_event.as_ref().unwrap().as_raw_descriptor();
        Ok(OverlappedWrapper {
            overlapped: Box::new(overlapped),
            h_event,
            in_use: false,
        })
    }

    /// Cancels I/O Operations in the current process. Since `lpOverlapped` is null, this will
    /// cancel all I/O requests for the file handle passed in.
    pub fn cancel_io(&mut self) -> Result<()> {
        let res = unsafe {
            CancelIoEx(
                self.handle.as_raw_descriptor(),
                /* lpOverlapped= */ std::ptr::null_mut(),
            )
        };
        if res == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Get the framing mode of the pipe.
    pub fn get_framing_mode(&self) -> FramingMode {
        self.framing_mode
    }

    /// Returns metadata about the connected NamedPipe.
    pub fn get_info(&self, is_server_connection: bool) -> Result<NamedPipeInfo> {
        let mut flags: u32 = 0;
        // Marked mutable because they are mutated in a system call
        #[allow(unused_mut)]
        let mut incoming_buffer_size: u32 = 0;
        #[allow(unused_mut)]
        let mut outgoing_buffer_size: u32 = 0;
        #[allow(unused_mut)]
        let mut max_instances: u32 = 0;
        // Client side with BYTE type are default flags
        if is_server_connection {
            flags |= 0x00000001 /* PIPE_SERVER_END */
        }
        if self.framing_mode == FramingMode::Message {
            flags |= 0x00000004 /* PIPE_TYPE_MESSAGE */
        }
        // Safe because we have allocated all pointers and own
        // them as mutable.
        let res = unsafe {
            GetNamedPipeInfo(
                self.as_raw_descriptor(),
                flags as *mut u32,
                outgoing_buffer_size as *mut u32,
                incoming_buffer_size as *mut u32,
                max_instances as *mut u32,
            )
        };

        if res == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(NamedPipeInfo {
                outgoing_buffer_size,
                incoming_buffer_size,
                max_instances,
            })
        }
    }

    /// For a server pipe, flush the pipe contents. This will
    /// block until the pipe is cleared by the client. Only
    /// call this if you are sure the client is reading the
    /// data!
    pub fn flush_data_blocking(&self) -> Result<()> {
        // Safe because the only buffers interacted with are
        // outside of Rust memory
        let res = unsafe { FlushFileBuffers(self.as_raw_descriptor()) };
        if res == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl AsRawDescriptor for PipeConnection {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.handle.as_raw_descriptor()
    }
}

impl IntoRawDescriptor for PipeConnection {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.handle.into_raw_descriptor()
    }
}

unsafe impl Send for PipeConnection {}
unsafe impl Sync for PipeConnection {}

impl io::Read for PipeConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // This is safe because PipeConnection::read is always safe for u8
        unsafe { PipeConnection::read(self, buf) }
    }
}

impl io::Write for PipeConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        PipeConnection::write(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A simple data struct representing
/// metadata about a NamedPipe.
pub struct NamedPipeInfo {
    pub outgoing_buffer_size: u32,
    pub incoming_buffer_size: u32,
    pub max_instances: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplex_pipe_stream() {
        let (p1, p2) = pair(&FramingMode::Byte, &BlockingMode::Wait, 0).unwrap();

        // Test both forward and reverse direction since the underlying APIs are a bit asymmetrical
        unsafe {
            for (dir, sender, receiver) in [("1 -> 2", &p1, &p2), ("2 -> 1", &p2, &p1)].iter() {
                println!("{}", dir);

                sender.write(&[75, 77, 54, 82, 76, 65]).unwrap();

                // Smaller than what we sent so we get multiple chunks
                let mut recv_buffer: [u8; 4] = [0; 4];

                let mut size = receiver.read(&mut recv_buffer).unwrap();
                assert_eq!(size, 4);
                assert_eq!(recv_buffer, [75, 77, 54, 82]);

                size = receiver.read(&mut recv_buffer).unwrap();
                assert_eq!(size, 2);
                assert_eq!(recv_buffer[0..2], [76, 65]);
            }
        }
    }

    #[test]
    fn available_byte_count_byte_mode() {
        let (p1, p2) = pair(&FramingMode::Byte, &BlockingMode::Wait, 0).unwrap();
        p1.write(&[1, 23, 45]).unwrap();
        assert_eq!(p2.get_available_byte_count().unwrap(), 3);

        // PeekNamedPipe should NOT touch the data in the pipe. So if we call it again, it should
        // yield the same value.
        assert_eq!(p2.get_available_byte_count().unwrap(), 3);
    }

    #[test]
    fn available_byte_count_message_mode() {
        let (p1, p2) = pair(&FramingMode::Message, &BlockingMode::Wait, 0).unwrap();
        p1.write(&[1, 23, 45]).unwrap();
        assert_eq!(p2.get_available_byte_count().unwrap(), 3);

        // PeekNamedPipe should NOT touch the data in the pipe. So if we call it again, it should
        // yield the same value.
        assert_eq!(p2.get_available_byte_count().unwrap(), 3);
    }

    #[test]
    fn available_byte_count_message_mode_multiple_messages() {
        let (p1, p2) = pair(&FramingMode::Message, &BlockingMode::Wait, 0).unwrap();
        p1.write(&[1, 2, 3]).unwrap();
        p1.write(&[4, 5]).unwrap();
        assert_eq!(p2.get_available_byte_count().unwrap(), 5);
    }

    #[test]
    fn duplex_pipe_message() {
        let (p1, p2) = pair(&FramingMode::Message, &BlockingMode::Wait, 0).unwrap();

        // Test both forward and reverse direction since the underlying APIs are a bit asymmetrical
        unsafe {
            for (dir, sender, receiver) in [("1 -> 2", &p1, &p2), ("2 -> 1", &p2, &p1)].iter() {
                println!("{}", dir);

                // Send 2 messages so that we can check that message framing works
                sender.write(&[1, 23, 45]).unwrap();
                sender.write(&[67, 89, 10]).unwrap();

                let mut recv_buffer: [u8; 5] = [0; 5]; // Larger than required for messages

                let mut size = receiver.read(&mut recv_buffer).unwrap();
                assert_eq!(size, 3);
                assert_eq!(recv_buffer[0..3], [1, 23, 45]);

                size = receiver.read(&mut recv_buffer).unwrap();
                assert_eq!(size, 3);
                assert_eq!(recv_buffer[0..3], [67, 89, 10]);
            }
        }
    }

    #[cfg(test)]
    fn duplex_nowait_helper(p1: &PipeConnection, p2: &PipeConnection) {
        let mut recv_buffer: [u8; 1] = [0; 1];

        // Test both forward and reverse direction since the underlying APIs are a bit asymmetrical
        unsafe {
            for (dir, sender, receiver) in [("1 -> 2", &p1, &p2), ("2 -> 1", &p2, &p1)].iter() {
                println!("{}", dir);
                sender.write(&[1]).unwrap();
                assert_eq!(receiver.read(&mut recv_buffer).unwrap(), 1); // Should succeed!
                assert_eq!(
                    receiver.read(&mut recv_buffer).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
        }
    }

    #[test]
    fn duplex_nowait() {
        let (p1, p2) = pair(&FramingMode::Byte, &BlockingMode::NoWait, 0).unwrap();
        duplex_nowait_helper(&p1, &p2);
    }

    #[test]
    fn duplex_nowait_set_after_creation() {
        // Tests non blocking setting after pipe creation
        let (mut p1, mut p2) = pair(&FramingMode::Byte, &BlockingMode::Wait, 0).unwrap();
        p1.set_blocking(&BlockingMode::NoWait)
            .expect("Failed to set blocking mode on pipe p1");
        p2.set_blocking(&BlockingMode::NoWait)
            .expect("Failed to set blocking mode on pipe p2");
        duplex_nowait_helper(&p1, &p2);
    }

    #[test]
    fn duplex_overlapped() {
        let pipe_name = generate_pipe_name();

        let mut p1 = create_server_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* timeout= */ 0,
            /* buffer_size= */ 1000,
            /* overlapped= */ true,
        )
        .unwrap();

        let mut p2 = create_client_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* overlapped= */ true,
        )
        .unwrap();

        // Safe because `read_overlapped` can be called since overlapped struct is created.
        unsafe {
            let mut p1_overlapped_wrapper =
                PipeConnection::create_overlapped_struct(/* include_event= */ true).unwrap();
            p1.write_overlapped(&[75, 77, 54, 82, 76, 65], &mut p1_overlapped_wrapper)
                .unwrap();
            let size = p1
                .get_overlapped_result(&mut p1_overlapped_wrapper)
                .unwrap();
            assert_eq!(size, 6);

            let mut recv_buffer: [u8; 6] = [0; 6];

            let mut p2_overlapped_wrapper =
                PipeConnection::create_overlapped_struct(/* include_event= */ true).unwrap();
            p2.read_overlapped(&mut recv_buffer, &mut p2_overlapped_wrapper)
                .unwrap();
            let size = p2
                .get_overlapped_result(&mut p2_overlapped_wrapper)
                .unwrap();
            assert_eq!(size, 6);
            assert_eq!(recv_buffer, [75, 77, 54, 82, 76, 65]);
        }
    }

    #[test]
    fn duplex_overlapped_test_in_use() {
        let pipe_name = generate_pipe_name();

        let mut p1 = create_server_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* timeout= */ 0,
            /* buffer_size= */ 1000,
            /* overlapped= */ true,
        )
        .unwrap();

        let mut p2 = create_client_pipe(
            &pipe_name,
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* overlapped= */ true,
        )
        .unwrap();
        let mut overlapped_wrapper =
            PipeConnection::create_overlapped_struct(/* include_event= */ true).unwrap();

        let res = p1.get_overlapped_result(&mut overlapped_wrapper);
        assert!(res.is_err());

        let res = p1.write_overlapped(&[75, 77, 54, 82, 76, 65], &mut overlapped_wrapper);
        assert!(res.is_ok());

        let res = p2.write_overlapped(&[75, 77, 54, 82, 76, 65], &mut overlapped_wrapper);
        assert!(res.is_err());

        let mut recv_buffer: [u8; 6] = [0; 6];
        let res = unsafe { p2.read_overlapped(&mut recv_buffer, &mut overlapped_wrapper) };
        assert!(res.is_err());

        let res = p1.get_overlapped_result(&mut overlapped_wrapper);
        assert!(res.is_ok());

        let mut recv_buffer: [u8; 6] = [0; 6];
        let res = unsafe { p2.read_overlapped(&mut recv_buffer, &mut overlapped_wrapper) };
        assert!(res.is_ok());
    }

    fn generate_pipe_name() -> String {
        format!(
            r"\\.\pipe\test-ipc-pipe-name.rand{}",
            rand::thread_rng().gen::<u64>(),
        )
    }
}
