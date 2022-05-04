// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::raw::c_ulonglong;

use base::{error, Error as SysError, Event, PollToken, Tube, WaitContext};
use vhost::Vhost;
use vm_memory::GuestMemory;

use super::control_socket::{VhostDevRequest, VhostDevResponse};
use super::{Error, Result};
use crate::virtio::{Interrupt, Queue, SignalableInterrupt};
use libc::EIO;

/// Worker that takes care of running the vhost device.
pub struct Worker<T: Vhost> {
    interrupt: Interrupt,
    queues: Vec<Queue>,
    pub vhost_handle: T,
    pub vhost_interrupt: Vec<Event>,
    acked_features: u64,
    pub kill_evt: Event,
    pub response_tube: Option<Tube>,
}

impl<T: Vhost> Worker<T> {
    pub fn new(
        queues: Vec<Queue>,
        vhost_handle: T,
        vhost_interrupt: Vec<Event>,
        interrupt: Interrupt,
        acked_features: u64,
        kill_evt: Event,
        response_tube: Option<Tube>,
    ) -> Worker<T> {
        Worker {
            interrupt,
            queues,
            vhost_handle,
            vhost_interrupt,
            acked_features,
            kill_evt,
            response_tube,
        }
    }

    pub fn init<F1>(
        &mut self,
        mem: GuestMemory,
        queue_evts: Vec<Event>,
        queue_sizes: &[u16],
        activate_vqs: F1,
    ) -> Result<()>
    where
        F1: FnOnce(&T) -> Result<()>,
    {
        let avail_features = self
            .vhost_handle
            .get_features()
            .map_err(Error::VhostGetFeatures)?;

        let features: c_ulonglong = self.acked_features & avail_features;
        self.vhost_handle
            .set_features(features)
            .map_err(Error::VhostSetFeatures)?;

        self.vhost_handle
            .set_mem_table(&mem)
            .map_err(Error::VhostSetMemTable)?;

        for (queue_index, queue) in self.queues.iter().enumerate() {
            self.vhost_handle
                .set_vring_num(queue_index, queue.max_size)
                .map_err(Error::VhostSetVringNum)?;

            self.vhost_handle
                .set_vring_addr(
                    &mem,
                    queue_sizes[queue_index],
                    queue.actual_size(),
                    queue_index,
                    0,
                    queue.desc_table,
                    queue.used_ring,
                    queue.avail_ring,
                    None,
                )
                .map_err(Error::VhostSetVringAddr)?;
            self.vhost_handle
                .set_vring_base(queue_index, 0)
                .map_err(Error::VhostSetVringBase)?;
            self.set_vring_call_for_entry(queue_index, queue.vector as usize)?;
            self.vhost_handle
                .set_vring_kick(queue_index, &queue_evts[queue_index])
                .map_err(Error::VhostSetVringKick)?;
        }

        activate_vqs(&self.vhost_handle)?;
        Ok(())
    }

    pub fn run<F1>(&mut self, cleanup_vqs: F1) -> Result<()>
    where
        F1: FnOnce(&T) -> Result<()>,
    {
        #[derive(PollToken)]
        enum Token {
            VhostIrqi { index: usize },
            InterruptResample,
            Kill,
            ControlNotify,
        }

        let wait_ctx: WaitContext<Token> =
            WaitContext::build_with(&[(&self.kill_evt, Token::Kill)])
                .map_err(Error::CreateWaitContext)?;

        for (index, vhost_int) in self.vhost_interrupt.iter().enumerate() {
            wait_ctx
                .add(vhost_int, Token::VhostIrqi { index })
                .map_err(Error::CreateWaitContext)?;
        }
        if let Some(socket) = &self.response_tube {
            wait_ctx
                .add(socket, Token::ControlNotify)
                .map_err(Error::CreateWaitContext)?;
        }
        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .map_err(Error::CreateWaitContext)?;
        }

        'wait: loop {
            let events = wait_ctx.wait().map_err(Error::WaitError)?;

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::VhostIrqi { index } => {
                        self.vhost_interrupt[index]
                            .read()
                            .map_err(Error::VhostIrqRead)?;
                        self.interrupt.signal_used_queue(self.queues[index].vector);
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => {
                        let _ = self.kill_evt.read();
                        break 'wait;
                    }
                    Token::ControlNotify => {
                        if let Some(socket) = &self.response_tube {
                            match socket.recv() {
                                Ok(VhostDevRequest::MsixEntryChanged(index)) => {
                                    let mut qindex = 0;
                                    for (queue_index, queue) in self.queues.iter().enumerate() {
                                        if queue.vector == index as u16 {
                                            qindex = queue_index;
                                            break;
                                        }
                                    }
                                    let response =
                                        match self.set_vring_call_for_entry(qindex, index) {
                                            Ok(()) => VhostDevResponse::Ok,
                                            Err(e) => {
                                                error!(
                                                "Set vring call failed for masked entry {}: {:?}",
                                                index, e
                                            );
                                                VhostDevResponse::Err(SysError::new(EIO))
                                            }
                                        };
                                    if let Err(e) = socket.send(&response) {
                                        error!("Vhost failed to send VhostMsixEntryMasked Response for entry {}: {:?}", index, e);
                                    }
                                }
                                Ok(VhostDevRequest::MsixChanged) => {
                                    let response = match self.set_vring_calls() {
                                        Ok(()) => VhostDevResponse::Ok,
                                        Err(e) => {
                                            error!("Set vring calls failed: {:?}", e);
                                            VhostDevResponse::Err(SysError::new(EIO))
                                        }
                                    };
                                    if let Err(e) = socket.send(&response) {
                                        error!(
                                            "Vhost failed to send VhostMsixMasked Response: {:?}",
                                            e
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("Vhost failed to receive Control request: {:?}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
        cleanup_vqs(&self.vhost_handle)?;
        Ok(())
    }

    fn set_vring_call_for_entry(&self, queue_index: usize, vector: usize) -> Result<()> {
        // No response_socket means it doesn't have any control related
        // with the msix. Due to this, cannot use the direct irq fd but
        // should fall back to indirect irq fd.
        if self.response_tube.is_some() {
            if let Some(msix_config) = self.interrupt.get_msix_config() {
                let msix_config = msix_config.lock();
                let msix_masked = msix_config.masked();
                if msix_masked {
                    return Ok(());
                }
                if !msix_config.table_masked(vector) {
                    if let Some(irqfd) = msix_config.get_irqfd(vector) {
                        self.vhost_handle
                            .set_vring_call(queue_index, irqfd)
                            .map_err(Error::VhostSetVringCall)?;
                    } else {
                        self.vhost_handle
                            .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
                            .map_err(Error::VhostSetVringCall)?;
                    }
                    return Ok(());
                }
            }
        }

        self.vhost_handle
            .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
            .map_err(Error::VhostSetVringCall)?;
        Ok(())
    }

    fn set_vring_calls(&self) -> Result<()> {
        if let Some(msix_config) = self.interrupt.get_msix_config() {
            let msix_config = msix_config.lock();
            if msix_config.masked() {
                for (queue_index, _) in self.queues.iter().enumerate() {
                    self.vhost_handle
                        .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
                        .map_err(Error::VhostSetVringCall)?;
                }
            } else {
                for (queue_index, queue) in self.queues.iter().enumerate() {
                    let vector = queue.vector as usize;
                    if !msix_config.table_masked(vector) {
                        if let Some(irqfd) = msix_config.get_irqfd(vector) {
                            self.vhost_handle
                                .set_vring_call(queue_index, irqfd)
                                .map_err(Error::VhostSetVringCall)?;
                        } else {
                            self.vhost_handle
                                .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
                                .map_err(Error::VhostSetVringCall)?;
                        }
                    } else {
                        self.vhost_handle
                            .set_vring_call(queue_index, &self.vhost_interrupt[queue_index])
                            .map_err(Error::VhostSetVringCall)?;
                    }
                }
            }
        }
        Ok(())
    }
}
