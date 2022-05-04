// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod block;
mod console;
mod fs;
#[cfg(feature = "gpu")]
mod gpu;
mod handler;
mod mac80211_hwsim;
mod net;
#[cfg(feature = "audio")]
mod snd;
mod vsock;
mod wl;
mod worker;

pub use self::block::*;
pub use self::console::*;
pub use self::fs::*;
#[cfg(feature = "gpu")]
pub use self::gpu::*;
pub use self::handler::VhostUserHandler;
pub use self::mac80211_hwsim::*;
pub use self::net::*;
#[cfg(feature = "audio")]
pub use self::snd::*;
pub use self::vsock::*;
pub use self::wl::*;

use remain::sorted;
use thiserror::Error as ThisError;
use vm_memory::GuestMemoryError;
use vmm_vhost::Error as VhostError;

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// Failed to copy config to a buffer.
    #[error("failed to copy config to a buffer: {0}")]
    CopyConfig(std::io::Error),
    /// Failed to create `base::Event`.
    #[error("failed to create Event: {0}")]
    CreateEvent(base::Error),
    /// Failed to get config.
    #[error("failed to get config: {0}")]
    GetConfig(VhostError),
    /// Failed to get features.
    #[error("failed to get features: {0}")]
    GetFeatures(VhostError),
    /// Failed to get host address.
    #[error("failed to get host address: {0}")]
    GetHostAddress(GuestMemoryError),
    /// Failed to get protocol features.
    #[error("failed to get protocol features: {0}")]
    GetProtocolFeatures(VhostError),
    /// Failed to get number of queues.
    #[error("failed to get number of queues: {0}")]
    GetQueueNum(VhostError),
    /// Failed to get vring base offset.
    #[error("failed to get vring base offset: {0}")]
    GetVringBase(VhostError),
    /// Invalid config offset is given.
    #[error("invalid config offset is given: {data_len} + {offset} > {config_len}")]
    InvalidConfigOffset {
        data_len: u64,
        offset: u64,
        config_len: u64,
    },
    /// MSI-X config is unavailable.
    #[error("MSI-X config is unavailable")]
    MsixConfigUnavailable,
    /// MSI-X irqfd is unavailable.
    #[error("MSI-X irqfd is unavailable")]
    MsixIrqfdUnavailable,
    /// Failed to reset owner.
    #[error("failed to reset owner: {0}")]
    ResetOwner(VhostError),
    /// Failed to set config.
    #[error("failed to set config: {0}")]
    SetConfig(VhostError),
    /// Failed to set device request channel.
    #[error("failed to set device request channel: {0}")]
    SetDeviceRequestChannel(VhostError),
    /// Failed to set features.
    #[error("failed to set features: {0}")]
    SetFeatures(VhostError),
    /// Failed to set memory map regions.
    #[error("failed to set memory map regions: {0}")]
    SetMemTable(VhostError),
    /// Failed to set owner.
    #[error("failed to set owner: {0}")]
    SetOwner(VhostError),
    /// Failed to set protocol features.
    #[error("failed to set protocol features: {0}")]
    SetProtocolFeatures(VhostError),
    /// Failed to set vring address.
    #[error("failed to set vring address: {0}")]
    SetVringAddr(VhostError),
    /// Failed to set vring base offset.
    #[error("failed to set vring base offset: {0}")]
    SetVringBase(VhostError),
    /// Failed to set eventfd to signal used vring buffers.
    #[error("failed to set eventfd to signal used vring buffers: {0}")]
    SetVringCall(VhostError),
    /// Failed to enable or disable vring.
    #[error("failed to enable or disable vring: {0}")]
    SetVringEnable(VhostError),
    /// Failed to set eventfd for adding buffers to vring.
    #[error("failed to set eventfd for adding buffers to vring: {0}")]
    SetVringKick(VhostError),
    /// Failed to set the size of the queue.
    #[error("failed to set the size of the queue: {0}")]
    SetVringNum(VhostError),
    /// Failed to connect socket.
    #[error("failed to connect socket: {0}")]
    SocketConnect(std::io::Error),
    /// Failed to create Master from a UDS path.
    #[error("failed to connect to device socket while creating instance: {0}")]
    SocketConnectOnMasterCreate(VhostError),
    /// The tag for the Fs device was too long to fit in the config space.
    #[error("tag is too long: {len} > {max}")]
    TagTooLong { len: usize, max: usize },
}

pub type Result<T> = std::result::Result<T, Error>;
