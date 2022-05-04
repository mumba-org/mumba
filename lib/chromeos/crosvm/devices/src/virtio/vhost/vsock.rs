// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::{File, OpenOptions};
use std::os::unix::prelude::{FromRawFd, OpenOptionsExt};
use std::path::PathBuf;
use std::thread;

use anyhow::Context;
use base::{error, validate_raw_descriptor, warn, AsRawDescriptor, Event, RawDescriptor};
use data_model::{DataInit, Le64};
use serde::Deserialize;
use vhost::Vhost;
use vhost::Vsock as VhostVsockHandle;
use vm_memory::GuestMemory;

use super::worker::Worker;
use super::{Error, Result};
use crate::virtio::{copy_config, Interrupt, Queue, VirtioDevice, TYPE_VSOCK};

pub const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 3;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];
static VHOST_VSOCK_DEFAULT_PATH: &str = "/dev/vhost-vsock";

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VhostVsockConfig {
    #[serde(default)]
    pub device: VhostVsockDeviceParameter,
    pub cid: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum VhostVsockDeviceParameter {
    Path(PathBuf),
    Fd(RawDescriptor),
}

impl Default for VhostVsockDeviceParameter {
    fn default() -> Self {
        VhostVsockDeviceParameter::Path(PathBuf::from(VHOST_VSOCK_DEFAULT_PATH))
    }
}

pub struct Vsock {
    worker_kill_evt: Option<Event>,
    kill_evt: Option<Event>,
    vhost_handle: Option<VhostVsockHandle>,
    cid: u64,
    interrupts: Option<Vec<Event>>,
    avail_features: u64,
    acked_features: u64,
}

impl Vsock {
    /// Create a new virtio-vsock device with the given VM cid.
    pub fn new(base_features: u64, vhost_config: &VhostVsockConfig) -> anyhow::Result<Vsock> {
        let device_file = match &vhost_config.device {
            VhostVsockDeviceParameter::Fd(fd) => {
                let fd = validate_raw_descriptor(*fd)
                    .context("failed to validate fd for virtual socket device")?;
                // Safe because the `fd` is actually owned by this process and
                // we have a unique handle to it.
                unsafe { File::from_raw_fd(fd) }
            }
            VhostVsockDeviceParameter::Path(path) => OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(path)
                .context("failed to open virtual socket device")?,
        };

        let kill_evt = Event::new().map_err(Error::CreateKillEvent)?;
        let handle = VhostVsockHandle::new(device_file);

        let avail_features = base_features
            | 1 << virtio_sys::vhost::VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << virtio_sys::vhost::VIRTIO_RING_F_INDIRECT_DESC
            | 1 << virtio_sys::vhost::VIRTIO_RING_F_EVENT_IDX
            | 1 << virtio_sys::vhost::VHOST_F_LOG_ALL
            | 1 << virtio_sys::vhost::VIRTIO_F_ANY_LAYOUT;

        let mut interrupts = Vec::new();
        for _ in 0..NUM_QUEUES {
            interrupts.push(Event::new().map_err(Error::VhostIrqCreate)?);
        }

        Ok(Vsock {
            worker_kill_evt: Some(kill_evt.try_clone().map_err(Error::CloneKillEvent)?),
            kill_evt: Some(kill_evt),
            vhost_handle: Some(handle),
            cid: vhost_config.cid,
            interrupts: Some(interrupts),
            avail_features,
            acked_features: 0,
        })
    }

    pub fn new_for_testing(cid: u64, features: u64) -> Vsock {
        Vsock {
            worker_kill_evt: None,
            kill_evt: None,
            vhost_handle: None,
            cid,
            interrupts: None,
            avail_features: features,
            acked_features: 0,
        }
    }

    pub fn acked_features(&self) -> u64 {
        self.acked_features
    }
}

impl Drop for Vsock {
    fn drop(&mut self) {
        // Only kill the child if it claimed its event.
        if self.worker_kill_evt.is_none() {
            if let Some(kill_evt) = &self.kill_evt {
                // Ignore the result because there is nothing we can do about it.
                let _ = kill_evt.write(1);
            }
        }
    }
}

impl VirtioDevice for Vsock {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();

        if let Some(handle) = &self.vhost_handle {
            keep_rds.push(handle.as_raw_descriptor());
        }

        if let Some(interrupt) = &self.interrupts {
            for vhost_int in interrupt.iter() {
                keep_rds.push(vhost_int.as_raw_descriptor());
            }
        }

        if let Some(worker_kill_evt) = &self.worker_kill_evt {
            keep_rds.push(worker_kill_evt.as_raw_descriptor());
        }

        keep_rds
    }

    fn device_type(&self) -> u32 {
        TYPE_VSOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let cid = Le64::from(self.cid);
        copy_config(data, 0, DataInit::as_slice(&cid), offset);
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("vsock: virtio-vsock got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
    ) {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            error!("net: expected {} queues, got {}", NUM_QUEUES, queues.len());
            return;
        }

        if let Some(vhost_handle) = self.vhost_handle.take() {
            if let Some(interrupts) = self.interrupts.take() {
                if let Some(kill_evt) = self.worker_kill_evt.take() {
                    let acked_features = self.acked_features;
                    let cid = self.cid;
                    // The third vq is an event-only vq that is not handled by the vhost
                    // subsystem (but still needs to exist).  Split it off here.
                    let vhost_queues = queues[..2].to_vec();
                    let mut worker = Worker::new(
                        vhost_queues,
                        vhost_handle,
                        interrupts,
                        interrupt,
                        acked_features,
                        kill_evt,
                        None,
                    );
                    let activate_vqs = |handle: &VhostVsockHandle| -> Result<()> {
                        handle.set_cid(cid).map_err(Error::VhostVsockSetCid)?;
                        handle.start().map_err(Error::VhostVsockStart)?;
                        Ok(())
                    };
                    let result = worker.init(mem, queue_evts, QUEUE_SIZES, activate_vqs);
                    if let Err(e) = result {
                        error!("vpipe worker thread exited with error: {:?}", e);
                    }
                    let worker_result = thread::Builder::new()
                        .name("vhost_vsock".to_string())
                        .spawn(move || {
                            let cleanup_vqs = |_handle: &VhostVsockHandle| -> Result<()> { Ok(()) };
                            let result = worker.run(cleanup_vqs);
                            if let Err(e) = result {
                                error!("vsock worker thread exited with error: {:?}", e);
                            }
                        });

                    if let Err(e) = worker_result {
                        error!("failed to spawn vhost_vsock worker: {}", e);
                        return;
                    }
                }
            }
        }
    }

    fn on_device_sandboxed(&mut self) {
        // ignore the error but to log the error. We don't need to do
        // anything here because when activate, the other vhost set up
        // will be failed to stop the activate thread.
        if let Some(vhost_handle) = &self.vhost_handle {
            match vhost_handle.set_owner() {
                Ok(_) => {}
                Err(e) => error!("{}: failed to set owner: {:?}", self.debug_label(), e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::result::Result;

    use serde_keyvalue::*;

    use super::*;

    #[test]
    fn ack_features() {
        let cid = 5;
        let features: u64 = (1 << 20) | (1 << 49) | (1 << 2) | (1 << 19);
        let mut acked_features: u64 = 0;
        let mut unavailable_features: u64 = 0;

        let mut vsock = Vsock::new_for_testing(cid, features);
        assert_eq!(acked_features, vsock.acked_features());

        acked_features |= 1 << 2;
        vsock.ack_features(acked_features);
        assert_eq!(acked_features, vsock.acked_features());

        acked_features |= 1 << 49;
        vsock.ack_features(acked_features);
        assert_eq!(acked_features, vsock.acked_features());

        acked_features |= 1 << 60;
        unavailable_features |= 1 << 60;
        vsock.ack_features(acked_features);
        assert_eq!(
            acked_features & !unavailable_features,
            vsock.acked_features()
        );

        acked_features |= 1 << 1;
        unavailable_features |= 1 << 1;
        vsock.ack_features(acked_features);
        assert_eq!(
            acked_features & !unavailable_features,
            vsock.acked_features()
        );
    }

    #[test]
    fn read_config() {
        let cid = 0xfca9a559fdcb9756;
        let vsock = Vsock::new_for_testing(cid, 0);

        let mut buf = [0u8; 8];
        vsock.read_config(0, &mut buf);
        assert_eq!(cid, u64::from_le_bytes(buf));

        vsock.read_config(0, &mut buf[..4]);
        assert_eq!(
            (cid & 0xffffffff) as u32,
            u32::from_le_bytes(buf[..4].try_into().unwrap())
        );

        vsock.read_config(4, &mut buf[..4]);
        assert_eq!(
            (cid >> 32) as u32,
            u32::from_le_bytes(buf[..4].try_into().unwrap())
        );

        let data: [u8; 8] = [8, 226, 5, 46, 159, 59, 89, 77];
        buf.copy_from_slice(&data);

        vsock.read_config(12, &mut buf);
        assert_eq!(&buf, &data);
    }

    #[test]
    fn features() {
        let cid = 5;
        let features: u64 = 0xfc195ae8db88cff9;

        let vsock = Vsock::new_for_testing(cid, features);
        assert_eq!(features, vsock.features());
    }

    fn from_vsock_arg(options: &str) -> Result<VhostVsockConfig, ParseError> {
        from_key_values(options)
    }

    #[test]
    fn params_from_key_values() {
        // Fd device
        let params = from_vsock_arg("device=42,cid=56").unwrap();
        assert_eq!(
            params,
            VhostVsockConfig {
                device: VhostVsockDeviceParameter::Fd(42),
                cid: 56,
            }
        );
        // No key for fd device
        let params = from_vsock_arg("42,cid=56").unwrap();
        assert_eq!(
            params,
            VhostVsockConfig {
                device: VhostVsockDeviceParameter::Fd(42),
                cid: 56,
            }
        );
        // Path device
        let params = from_vsock_arg("device=/some/path,cid=56").unwrap();
        assert_eq!(
            params,
            VhostVsockConfig {
                device: VhostVsockDeviceParameter::Path("/some/path".into()),
                cid: 56,
            }
        );
        // No key for path device
        let params = from_vsock_arg("/some/path,cid=56").unwrap();
        assert_eq!(
            params,
            VhostVsockConfig {
                device: VhostVsockDeviceParameter::Path("/some/path".into()),
                cid: 56,
            }
        );
        // Default device
        let params = from_vsock_arg("cid=56").unwrap();
        assert_eq!(
            params,
            VhostVsockConfig {
                device: VhostVsockDeviceParameter::Path(VHOST_VSOCK_DEFAULT_PATH.into()),
                cid: 56,
            }
        );

        // No argument
        assert_eq!(
            from_vsock_arg("").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("missing field `cid`".into()),
                pos: 0
            }
        );
        // Missing cid
        assert_eq!(
            from_vsock_arg("device=42").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("missing field `cid`".into()),
                pos: 0,
            }
        );
        // Cid passed twice
        assert_eq!(
            from_vsock_arg("cid=42,cid=56").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("duplicate field `cid`".into()),
                pos: 0,
            }
        );
        // Device passed twice
        assert_eq!(
            from_vsock_arg("cid=56,device=42,device=/some/path").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("duplicate field `device`".into()),
                pos: 0,
            }
        );
        // Invalid argument
        assert_eq!(
            from_vsock_arg("invalid=foo").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError(
                    "unknown field `invalid`, expected `device` or `cid`".into()
                ),
                pos: 0,
            }
        );
    }
}
