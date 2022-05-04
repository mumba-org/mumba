// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod shm_streams;
mod shm_vios;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use self::shm_streams::*;

pub use self::shm_vios::*;

pub mod streams;

mod worker;

use std::thread;

use crate::virtio::{copy_config, DescriptorError, Interrupt, Queue, VirtioDevice, TYPE_SOUND};
use base::{error, Error as BaseError, Event, RawDescriptor};
use data_model::{DataInit, Le32};
use remain::sorted;
use sync::Mutex;
use vm_memory::GuestMemory;

use std::path::Path;
use std::sync::mpsc::{RecvError, SendError};
use std::sync::Arc;

use super::layout::*;
use streams::StreamMsg;
use worker::*;

use std::io::Error as IoError;
use thiserror::Error as ThisError;

const QUEUE_SIZES: &[u16] = &[64, 64, 64, 64];

#[sorted]
#[derive(ThisError, Debug)]
pub enum SoundError {
    #[error("The driver sent an invalid message")]
    BadDriverMsg,
    #[error("Failed to get event notifier from VioS client: {0}")]
    ClientEventNotifier(Error),
    #[error("Failed to create VioS client: {0}")]
    ClientNew(Error),
    #[error("Failed to create event pair: {0}")]
    CreateEvent(BaseError),
    #[error("Failed to create Reader from descriptor chain: {0}")]
    CreateReader(DescriptorError),
    #[error("Failed to create thread: {0}")]
    CreateThread(IoError),
    #[error("Failed to create Writer from descriptor chain: {0}")]
    CreateWriter(DescriptorError),
    #[error("Error with queue descriptor: {0}")]
    Descriptor(DescriptorError),
    #[error("Attempted a {0} operation while on the wrong state: {1}, this is a bug")]
    ImpossibleState(&'static str, &'static str),
    #[error("Error consuming queue event: {0}")]
    QueueEvt(BaseError),
    #[error("Failed to read/write from/to queue: {0}")]
    QueueIO(IoError),
    #[error("Failed to receive message: {0}")]
    StreamThreadRecv(RecvError),
    #[error("Failed to send message: {0}")]
    StreamThreadSend(SendError<StreamMsg>),
    #[error("Error creating WaitContext: {0}")]
    WaitCtx(BaseError),
}

pub type Result<T> = std::result::Result<T, SoundError>;

pub struct Sound {
    config: virtio_snd_config,
    virtio_features: u64,
    worker_thread: Option<thread::JoinHandle<bool>>,
    kill_evt: Option<Event>,
    vios_client: Arc<VioSClient>,
}

impl VirtioDevice for Sound {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.vios_client.keep_fds()
    }

    fn device_type(&self) -> u32 {
        TYPE_SOUND
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.config.as_slice(), offset);
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        error!("virtio-snd: driver attempted a config write which is not allowed by the spec");
    }

    fn features(&self) -> u64 {
        self.virtio_features
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<Event>,
    ) {
        if self.worker_thread.is_some() {
            error!("virtio-snd: Device is already active");
            return;
        }
        if queues.len() != 4 || queue_evts.len() != 4 {
            error!(
                "virtio-snd: device activated with wrong number of queues: {}, {}",
                queues.len(),
                queue_evts.len()
            );
            return;
        }
        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("virtio-snd: failed to create kill Event pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);
        let control_queue = queues.remove(0);
        let control_queue_evt = queue_evts.remove(0);
        let event_queue = queues.remove(0);
        let event_queue_evt = queue_evts.remove(0);
        let tx_queue = queues.remove(0);
        let tx_queue_evt = queue_evts.remove(0);
        let rx_queue = queues.remove(0);
        let rx_queue_evt = queue_evts.remove(0);

        let vios_client = self.vios_client.clone();
        if let Err(e) = vios_client.start_bg_thread() {
            error!("Failed to start vios background thread: {}", e);
        }

        let thread_result = thread::Builder::new()
            .name(String::from("virtio_snd"))
            .spawn(move || {
                match Worker::try_new(
                    vios_client,
                    Arc::new(interrupt),
                    mem,
                    Arc::new(Mutex::new(control_queue)),
                    control_queue_evt,
                    event_queue,
                    event_queue_evt,
                    Arc::new(Mutex::new(tx_queue)),
                    tx_queue_evt,
                    Arc::new(Mutex::new(rx_queue)),
                    rx_queue_evt,
                ) {
                    Ok(mut worker) => match worker.control_loop(kill_evt) {
                        Ok(_) => true,
                        Err(e) => {
                            error!("virtio-snd: Error in worker loop: {}", e);
                            false
                        }
                    },
                    Err(e) => {
                        error!("virtio-snd: Failed to create worker: {}", e);
                        false
                    }
                }
            });
        match thread_result {
            Err(e) => {
                error!("failed to spawn virtio_snd worker thread: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }

    fn reset(&mut self) -> bool {
        let mut ret = true;
        if let Some(kill_evt) = self.kill_evt.take() {
            if let Err(e) = kill_evt.write(1) {
                error!("virtio-snd: failed to notify the kill event: {}", e);
                ret = false;
            }
        } else if let Some(worker_thread) = self.worker_thread.take() {
            match worker_thread.join() {
                Err(e) => {
                    error!("virtio-snd: Worker thread panicked: {:?}", e);
                    ret = false;
                }
                Ok(worker_status) => {
                    ret = worker_status;
                }
            }
        }
        if let Err(e) = self.vios_client.stop_bg_thread() {
            error!("virtio-snd: Failed to stop vios background thread: {}", e);
            ret = false;
        }
        ret
    }
}

/// Creates a new virtio sound device connected to a VioS backend
pub fn new_sound<P: AsRef<Path>>(path: P, virtio_features: u64) -> Result<Sound> {
    let vios_client = Arc::new(VioSClient::try_new(path).map_err(SoundError::ClientNew)?);
    Ok(Sound {
        config: virtio_snd_config {
            jacks: Le32::from(vios_client.num_jacks()),
            streams: Le32::from(vios_client.num_streams()),
            chmaps: Le32::from(vios_client.num_chmaps()),
        },
        virtio_features,
        worker_thread: None,
        kill_evt: None,
        vios_client,
    })
}
