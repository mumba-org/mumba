// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Read;
use std::ops::Deref;
use std::sync::{mpsc::Sender, Arc};
use std::thread;

use crate::virtio::{DescriptorChain, Interrupt, Queue, Reader, SignalableInterrupt, Writer};
use base::{error, warn, Event, PollToken, WaitContext};
use data_model::{DataInit, Le32};
use sync::Mutex;
use vm_memory::GuestMemory;

use super::super::constants::*;
use super::super::layout::*;
use super::streams::*;
use super::*;
use super::{Result, SoundError};

pub struct Worker {
    // Lock order: Must never hold more than one queue lock at the same time.
    interrupt: Arc<Interrupt>,
    control_queue: Arc<Mutex<Queue>>,
    control_queue_evt: Event,
    event_queue: Queue,
    event_queue_evt: Event,
    guest_memory: GuestMemory,
    vios_client: Arc<VioSClient>,
    streams: Vec<StreamProxy>,
    io_thread: Option<thread::JoinHandle<Result<()>>>,
    io_kill: Event,
}

impl Worker {
    /// Creates a new virtio-snd worker.
    pub fn try_new(
        vios_client: Arc<VioSClient>,
        interrupt: Arc<Interrupt>,
        guest_memory: GuestMemory,
        control_queue: Arc<Mutex<Queue>>,
        control_queue_evt: Event,
        event_queue: Queue,
        event_queue_evt: Event,
        tx_queue: Arc<Mutex<Queue>>,
        tx_queue_evt: Event,
        rx_queue: Arc<Mutex<Queue>>,
        rx_queue_evt: Event,
    ) -> Result<Worker> {
        let mut streams: Vec<StreamProxy> = Vec::with_capacity(vios_client.num_streams() as usize);
        {
            for stream_id in 0..vios_client.num_streams() {
                let capture = vios_client
                    .stream_info(stream_id)
                    .map(|i| i.direction == VIRTIO_SND_D_INPUT)
                    .unwrap_or(false);
                let io_queue = if capture { &rx_queue } else { &tx_queue };
                streams.push(Stream::try_new(
                    stream_id,
                    vios_client.clone(),
                    guest_memory.clone(),
                    interrupt.clone(),
                    control_queue.clone(),
                    io_queue.clone(),
                    capture,
                )?);
            }
        }
        let (self_kill_io, kill_io) = Event::new()
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(SoundError::CreateEvent)?;

        let interrupt_clone = interrupt.clone();
        let guest_memory_clone = guest_memory.clone();
        let senders: Vec<Sender<StreamMsg>> =
            streams.iter().map(|sp| sp.msg_sender().clone()).collect();
        let io_thread = thread::Builder::new()
            .name(String::from("virtio_snd_io"))
            .spawn(move || {
                try_set_real_time_priority();

                io_loop(
                    interrupt_clone,
                    guest_memory_clone,
                    tx_queue,
                    tx_queue_evt,
                    rx_queue,
                    rx_queue_evt,
                    senders,
                    kill_io,
                )
            })
            .map_err(SoundError::CreateThread)?;
        Ok(Worker {
            interrupt,
            control_queue,
            control_queue_evt,
            event_queue,
            event_queue_evt,
            guest_memory,
            vios_client,
            streams,
            io_thread: Some(io_thread),
            io_kill: self_kill_io,
        })
    }

    /// Emulates the virtio-snd device. It won't return until something is written to the kill_evt
    /// event or an unrecoverable error occurs.
    pub fn control_loop(&mut self, kill_evt: Event) -> Result<()> {
        let event_notifier = self
            .vios_client
            .get_event_notifier()
            .map_err(SoundError::ClientEventNotifier)?;
        #[derive(PollToken)]
        enum Token {
            ControlQAvailable,
            EventQAvailable,
            InterruptResample,
            EventTriggered,
            Kill,
        }
        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&self.control_queue_evt, Token::ControlQAvailable),
            (&self.event_queue_evt, Token::EventQAvailable),
            (&event_notifier, Token::EventTriggered),
            (&kill_evt, Token::Kill),
        ])
        .map_err(SoundError::WaitCtx)?;

        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .map_err(SoundError::WaitCtx)?;
        }
        'wait: loop {
            let wait_events = wait_ctx.wait().map_err(SoundError::WaitCtx)?;

            for wait_evt in wait_events.iter().filter(|e| e.is_readable) {
                match wait_evt.token {
                    Token::ControlQAvailable => {
                        self.control_queue_evt
                            .read()
                            .map_err(SoundError::QueueEvt)?;
                        self.process_controlq_buffers()?;
                    }
                    Token::EventQAvailable => {
                        // Just read from the event object to make sure the producer of such events
                        // never blocks. The buffers will only be used when actual virtio-snd
                        // events are triggered.
                        self.event_queue_evt.read().map_err(SoundError::QueueEvt)?;
                    }
                    Token::EventTriggered => {
                        event_notifier.read().map_err(SoundError::QueueEvt)?;
                        self.process_event_triggered()?;
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => {
                        let _ = kill_evt.read();
                        break 'wait;
                    }
                }
            }
        }
        Ok(())
    }

    fn stop_io_thread(&mut self) {
        if let Err(e) = self.io_kill.write(1) {
            error!(
                "virtio-snd: Failed to send Break msg to stream thread: {}",
                e
            );
        }
        if let Some(th) = self.io_thread.take() {
            match th.join() {
                Err(e) => {
                    error!("virtio-snd: Panic detected on stream thread: {:?}", e);
                }
                Ok(r) => {
                    if let Err(e) = r {
                        error!("virtio-snd: IO thread exited with and error: {}", e);
                    }
                }
            }
        }
    }

    // Pops and handles all available ontrol queue buffers. Logs minor errors, but returns an
    // Err if it encounters an unrecoverable error.
    fn process_controlq_buffers(&mut self) -> Result<()> {
        while let Some(avail_desc) = lock_pop_unlock(&self.control_queue, &self.guest_memory) {
            let mut reader = Reader::new(self.guest_memory.clone(), avail_desc.clone())
                .map_err(SoundError::Descriptor)?;
            let available_bytes = reader.available_bytes();
            if available_bytes < std::mem::size_of::<virtio_snd_hdr>() {
                error!(
                    "virtio-snd: Message received on control queue is too small: {}",
                    available_bytes
                );
                return reply_control_op_status(
                    VIRTIO_SND_S_BAD_MSG,
                    avail_desc,
                    &self.guest_memory,
                    &self.control_queue,
                    self.interrupt.deref(),
                );
            }
            let mut read_buf = vec![0u8; available_bytes];
            reader
                .read_exact(&mut read_buf)
                .map_err(SoundError::QueueIO)?;
            let mut code: Le32 = Default::default();
            // need to copy because the buffer may not be properly aligned
            code.as_mut_slice()
                .copy_from_slice(&read_buf[..std::mem::size_of::<Le32>()]);
            let request_type = code.to_native();
            match request_type {
                VIRTIO_SND_R_JACK_INFO => {
                    let (code, info_vec) = {
                        match self.parse_info_query(&read_buf) {
                            None => (VIRTIO_SND_S_BAD_MSG, Vec::new()),
                            Some((start_id, count)) => {
                                let end_id = start_id.saturating_add(count);
                                if end_id > self.vios_client.num_jacks() {
                                    error!(
                                        "virtio-snd: Requested info on invalid jacks ids: {}..{}",
                                        start_id,
                                        end_id - 1
                                    );
                                    (VIRTIO_SND_S_NOT_SUPP, Vec::new())
                                } else {
                                    (
                                        VIRTIO_SND_S_OK,
                                        // Safe to unwrap because we just ensured all the ids are valid
                                        (start_id..end_id)
                                            .map(|id| self.vios_client.jack_info(id).unwrap())
                                            .collect(),
                                    )
                                }
                            }
                        }
                    };
                    self.send_info_reply(avail_desc, code, info_vec)?;
                }
                VIRTIO_SND_R_JACK_REMAP => {
                    let code = if read_buf.len() != std::mem::size_of::<virtio_snd_jack_remap>() {
                        error!(
                        "virtio-snd: The driver sent the wrong number bytes for a jack_remap struct: {}",
                        read_buf.len()
                        );
                        VIRTIO_SND_S_BAD_MSG
                    } else {
                        let mut request: virtio_snd_jack_remap = Default::default();
                        request.as_mut_slice().copy_from_slice(&read_buf);
                        let jack_id = request.hdr.jack_id.to_native();
                        let association = request.association.to_native();
                        let sequence = request.sequence.to_native();
                        if let Err(e) = self.vios_client.remap_jack(jack_id, association, sequence)
                        {
                            error!("virtio-snd: Failed to remap jack: {}", e);
                            vios_error_to_status_code(e)
                        } else {
                            VIRTIO_SND_S_OK
                        }
                    };
                    let desc_index = avail_desc.index;
                    let mut writer = Writer::new(self.guest_memory.clone(), avail_desc)
                        .map_err(SoundError::Descriptor)?;
                    writer
                        .write_obj(virtio_snd_hdr {
                            code: Le32::from(code),
                        })
                        .map_err(SoundError::QueueIO)?;
                    {
                        let mut queue_lock = self.control_queue.lock();
                        queue_lock.add_used(
                            &self.guest_memory,
                            desc_index,
                            writer.bytes_written() as u32,
                        );
                        queue_lock.trigger_interrupt(&self.guest_memory, self.interrupt.deref());
                    }
                }
                VIRTIO_SND_R_CHMAP_INFO => {
                    let (code, info_vec) = {
                        match self.parse_info_query(&read_buf) {
                            None => (VIRTIO_SND_S_BAD_MSG, Vec::new()),
                            Some((start_id, count)) => {
                                let end_id = start_id.saturating_add(count);
                                if end_id > self.vios_client.num_chmaps() {
                                    error!(
                                        "virtio-snd: Requested info on invalid chmaps ids: {}..{}",
                                        start_id,
                                        end_id - 1
                                    );
                                    (VIRTIO_SND_S_NOT_SUPP, Vec::new())
                                } else {
                                    (
                                        VIRTIO_SND_S_OK,
                                        // Safe to unwrap because we just ensured all the ids are valid
                                        (start_id..end_id)
                                            .map(|id| self.vios_client.chmap_info(id).unwrap())
                                            .collect(),
                                    )
                                }
                            }
                        }
                    };
                    self.send_info_reply(avail_desc, code, info_vec)?;
                }
                VIRTIO_SND_R_PCM_INFO => {
                    let (code, info_vec) = {
                        match self.parse_info_query(&read_buf) {
                            None => (VIRTIO_SND_S_BAD_MSG, Vec::new()),
                            Some((start_id, count)) => {
                                let end_id = start_id.saturating_add(count);
                                if end_id > self.vios_client.num_streams() {
                                    error!(
                                        "virtio-snd: Requested info on invalid stream ids: {}..{}",
                                        start_id,
                                        end_id - 1
                                    );
                                    (VIRTIO_SND_S_NOT_SUPP, Vec::new())
                                } else {
                                    (
                                        VIRTIO_SND_S_OK,
                                        // Safe to unwrap because we just ensured all the ids are valid
                                        (start_id..end_id)
                                            .map(|id| self.vios_client.stream_info(id).unwrap())
                                            .collect(),
                                    )
                                }
                            }
                        }
                    };
                    self.send_info_reply(avail_desc, code, info_vec)?;
                }
                VIRTIO_SND_R_PCM_SET_PARAMS => self.process_set_params(avail_desc, &read_buf)?,
                VIRTIO_SND_R_PCM_PREPARE => {
                    self.try_parse_pcm_hdr_and_send_msg(&read_buf, StreamMsg::Prepare(avail_desc))?
                }
                VIRTIO_SND_R_PCM_RELEASE => {
                    self.try_parse_pcm_hdr_and_send_msg(&read_buf, StreamMsg::Release(avail_desc))?
                }
                VIRTIO_SND_R_PCM_START => {
                    self.try_parse_pcm_hdr_and_send_msg(&read_buf, StreamMsg::Start(avail_desc))?
                }
                VIRTIO_SND_R_PCM_STOP => {
                    self.try_parse_pcm_hdr_and_send_msg(&read_buf, StreamMsg::Stop(avail_desc))?
                }
                _ => {
                    error!(
                        "virtio-snd: Unknown control queue mesage code: {}",
                        request_type
                    );
                    reply_control_op_status(
                        VIRTIO_SND_S_NOT_SUPP,
                        avail_desc,
                        &self.guest_memory,
                        &self.control_queue,
                        self.interrupt.deref(),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn process_event_triggered(&mut self) -> Result<()> {
        while let Some(evt) = self.vios_client.pop_event() {
            if let Some(desc) = self.event_queue.pop(&self.guest_memory) {
                let desc_index = desc.index;
                let mut writer =
                    Writer::new(self.guest_memory.clone(), desc).map_err(SoundError::Descriptor)?;
                writer.write_obj(evt).map_err(SoundError::QueueIO)?;
                self.event_queue.add_used(
                    &self.guest_memory,
                    desc_index,
                    writer.bytes_written() as u32,
                );
                {
                    self.event_queue
                        .trigger_interrupt(&self.guest_memory, self.interrupt.deref());
                }
            } else {
                warn!("virtio-snd: Dropping event because there are no buffers in virtqueue");
            }
        }
        Ok(())
    }

    fn parse_info_query(&mut self, read_buf: &[u8]) -> Option<(u32, u32)> {
        if read_buf.len() != std::mem::size_of::<virtio_snd_query_info>() {
            error!(
                "virtio-snd: The driver sent the wrong number bytes for a pcm_info struct: {}",
                read_buf.len()
            );
            return None;
        }
        let mut query: virtio_snd_query_info = Default::default();
        query.as_mut_slice().copy_from_slice(read_buf);
        let start_id = query.start_id.to_native();
        let count = query.count.to_native();
        Some((start_id, count))
    }

    // Returns Err if it encounters an unrecoverable error, Ok otherwise
    fn process_set_params(&mut self, desc: DescriptorChain, read_buf: &[u8]) -> Result<()> {
        if read_buf.len() != std::mem::size_of::<virtio_snd_pcm_set_params>() {
            error!(
                "virtio-snd: The driver sent a buffer of the wrong size for a set_params struct: {}",
                read_buf.len()
                );
            return reply_control_op_status(
                VIRTIO_SND_S_BAD_MSG,
                desc,
                &self.guest_memory,
                &self.control_queue,
                self.interrupt.deref(),
            );
        }
        let mut params: virtio_snd_pcm_set_params = Default::default();
        params.as_mut_slice().copy_from_slice(read_buf);
        let stream_id = params.hdr.stream_id.to_native();
        if stream_id < self.vios_client.num_streams() {
            self.streams[stream_id as usize].send(StreamMsg::SetParams(desc, params))
        } else {
            error!(
                "virtio-snd: Driver requested operation on invalid stream: {}",
                stream_id
            );
            reply_control_op_status(
                VIRTIO_SND_S_BAD_MSG,
                desc,
                &self.guest_memory,
                &self.control_queue,
                self.interrupt.deref(),
            )
        }
    }

    // Returns Err if it encounters an unrecoverable error, Ok otherwise
    fn try_parse_pcm_hdr_and_send_msg(&mut self, read_buf: &[u8], msg: StreamMsg) -> Result<()> {
        if read_buf.len() != std::mem::size_of::<virtio_snd_pcm_hdr>() {
            error!(
                "virtio-snd: The driver sent a buffer too small to contain a header: {}",
                read_buf.len()
            );
            return reply_control_op_status(
                VIRTIO_SND_S_BAD_MSG,
                match msg {
                    StreamMsg::Prepare(d)
                    | StreamMsg::Start(d)
                    | StreamMsg::Stop(d)
                    | StreamMsg::Release(d) => d,
                    _ => panic!("virtio-snd: Can't handle message. This is a BUG!!"),
                },
                &self.guest_memory,
                &self.control_queue,
                self.interrupt.deref(),
            );
        }
        let mut pcm_hdr: virtio_snd_pcm_hdr = Default::default();
        pcm_hdr.as_mut_slice().copy_from_slice(read_buf);
        let stream_id = pcm_hdr.stream_id.to_native();
        if stream_id < self.vios_client.num_streams() {
            self.streams[stream_id as usize].send(msg)
        } else {
            error!(
                "virtio-snd: Driver requested operation on invalid stream: {}",
                stream_id
            );
            reply_control_op_status(
                VIRTIO_SND_S_BAD_MSG,
                match msg {
                    StreamMsg::Prepare(d)
                    | StreamMsg::Start(d)
                    | StreamMsg::Stop(d)
                    | StreamMsg::Release(d) => d,
                    _ => panic!("virtio-snd: Can't handle message. This is a BUG!!"),
                },
                &self.guest_memory,
                &self.control_queue,
                self.interrupt.deref(),
            )
        }
    }

    fn send_info_reply<T: DataInit>(
        &mut self,
        desc: DescriptorChain,
        code: u32,
        info_vec: Vec<T>,
    ) -> Result<()> {
        let desc_index = desc.index;
        let mut writer =
            Writer::new(self.guest_memory.clone(), desc).map_err(SoundError::Descriptor)?;
        writer
            .write_obj(virtio_snd_hdr {
                code: Le32::from(code),
            })
            .map_err(SoundError::QueueIO)?;
        for info in info_vec {
            writer.write_obj(info).map_err(SoundError::QueueIO)?;
        }
        {
            let mut queue_lock = self.control_queue.lock();
            queue_lock.add_used(
                &self.guest_memory,
                desc_index,
                writer.bytes_written() as u32,
            );
            queue_lock.trigger_interrupt(&self.guest_memory, self.interrupt.deref());
        }
        Ok(())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop_io_thread();
    }
}

fn io_loop(
    interrupt: Arc<Interrupt>,
    guest_memory: GuestMemory,
    tx_queue: Arc<Mutex<Queue>>,
    tx_queue_evt: Event,
    rx_queue: Arc<Mutex<Queue>>,
    rx_queue_evt: Event,
    senders: Vec<Sender<StreamMsg>>,
    kill_evt: Event,
) -> Result<()> {
    #[derive(PollToken)]
    enum Token {
        TxQAvailable,
        RxQAvailable,
        Kill,
    }
    let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
        (&tx_queue_evt, Token::TxQAvailable),
        (&rx_queue_evt, Token::RxQAvailable),
        (&kill_evt, Token::Kill),
    ])
    .map_err(SoundError::WaitCtx)?;

    'wait: loop {
        let wait_events = wait_ctx.wait().map_err(SoundError::WaitCtx)?;
        for wait_evt in wait_events.iter().filter(|e| e.is_readable) {
            let queue = match wait_evt.token {
                Token::TxQAvailable => {
                    tx_queue_evt.read().map_err(SoundError::QueueEvt)?;
                    &tx_queue
                }
                Token::RxQAvailable => {
                    rx_queue_evt.read().map_err(SoundError::QueueEvt)?;
                    &rx_queue
                }
                Token::Kill => {
                    let _ = kill_evt.read();
                    break 'wait;
                }
            };
            while let Some(avail_desc) = lock_pop_unlock(queue, &guest_memory) {
                let mut reader = Reader::new(guest_memory.clone(), avail_desc.clone())
                    .map_err(SoundError::Descriptor)?;
                let xfer: virtio_snd_pcm_xfer = reader.read_obj().map_err(SoundError::QueueIO)?;
                let stream_id = xfer.stream_id.to_native();
                if stream_id as usize >= senders.len() {
                    error!(
                        "virtio-snd: Driver sent buffer for invalid stream: {}",
                        stream_id
                    );
                    reply_pcm_buffer_status(
                        VIRTIO_SND_S_IO_ERR,
                        0,
                        avail_desc,
                        &guest_memory,
                        queue,
                        interrupt.deref(),
                    )?;
                } else {
                    StreamProxy::send_msg(
                        &senders[stream_id as usize],
                        StreamMsg::Buffer(avail_desc),
                    )?;
                }
            }
        }
    }
    Ok(())
}

// If queue.lock().pop() is used directly in the condition of a 'while' loop the lock is held over
// the entire loop block. Encapsulating it in this fuction guarantees that the lock is dropped
// immediately after pop() is called, which allows the code to remain somewhat simpler.
fn lock_pop_unlock(
    queue: &Arc<Mutex<Queue>>,
    guest_memory: &GuestMemory,
) -> Option<DescriptorChain> {
    queue.lock().pop(guest_memory)
}
