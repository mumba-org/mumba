// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The hypervisor memory service for manaTEE.

#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::cmp;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::env;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::ptr::null_mut;
use std::rc::Rc;
use std::result::Result as StdResult;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use balloon_control::{BalloonStats, BalloonTubeCommand, BalloonTubeResult};
use data_model::DataInit;
use libc::{recvfrom, MSG_PEEK, MSG_TRUNC};
use libsirenia::{
    build_info::BUILD_TIMESTAMP,
    linux::events::{AddEventSourceMutator, EventMultiplexer, EventSource, Mutator},
    sys,
    transport::{Error as TransportError, Transport, UnixServerTransport},
};
use serde::{Deserialize, Serialize};
use sys_util::{
    net::UnixSeqpacket,
    {error, handle_eintr_errno, info, pagesize, round_up_to_page_size, syslog, warn},
};

const CROS_GUEST_ID: u32 = 0;

#[repr(u32)]
enum MessageId {
    // GetBalloonStats(array<u32 id>) => (array<TaggedBalloonStats>);
    GetBalloonStats = 1,
    // RebalanceMemory(array<BalloonDelta> deltas) => (array<ActualBalloonDelta> actual);
    RebalanceMemory = 2,
    // PrepareVm(u64 mem_size, u64 init_mem_size) => (i32 res, u32 id, u64 shortfall);
    PrepareVm = 3,
    // FinishAddVm(u32 id) => i32
    FinishAddVm = 4,
    // RemoveVm(u32 id) => i32
    RemoveVm = 5,
}

impl TryFrom<u32> for MessageId {
    type Error = anyhow::Error;

    fn try_from(v: u32) -> Result<MessageId> {
        use MessageId::*;
        match v {
            v if v == GetBalloonStats as u32 => Ok(GetBalloonStats),
            v if v == RebalanceMemory as u32 => Ok(RebalanceMemory),
            v if v == PrepareVm as u32 => Ok(PrepareVm),
            v if v == FinishAddVm as u32 => Ok(FinishAddVm),
            v if v == RemoveVm as u32 => Ok(RemoveVm),
            _ => Err(anyhow!(format!("unknown message id {}", v))),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct MmsMessageHeader {
    len: u32,
    msg_type: u32,
}
// Safe because MmsMessageHeader only contains plain data.
unsafe impl DataInit for MmsMessageHeader {}

#[derive(Deserialize)]
struct GetBalloonStatsMsg {
    ids: Vec<u32>,
}

#[derive(Serialize)]
struct TaggedBalloonStats {
    id: u32,
    stats: BalloonStats,
    balloon_actual: u64,
}

#[derive(Serialize)]
struct GetBalloonStatsResp {
    all_stats: Vec<TaggedBalloonStats>,
}

#[derive(Deserialize, Debug)]
struct BalloonDelta {
    id: u32,
    #[serde(with = "i64_from_double")]
    delta: i64,
}

#[derive(Deserialize)]
struct RebalanceMemoryMsg {
    deltas: Vec<BalloonDelta>,
}

#[derive(Serialize)]
struct ActualBalloonDelta {
    id: u32,
    delta: i64,
}

#[derive(Serialize)]
struct RebalanceMemoryResp {
    actual_deltas: Vec<ActualBalloonDelta>,
}

#[derive(Deserialize, Debug)]
struct PrepareVmMsg {
    #[serde(with = "u64_from_double")]
    mem_size: u64,
    #[serde(with = "u64_from_double")]
    init_mem_size: u64,
}

#[derive(Serialize)]
struct PrepareVmResp {
    res: i32,
    id: u32,
    shortfall: u64,
}

fn error_prepare_vm_resp(res: i32) -> PrepareVmResp {
    PrepareVmResp {
        res,
        id: 0,
        shortfall: 0,
    }
}

#[derive(Deserialize)]
struct FinishAddVmMsg {
    id: u32,
}

#[derive(Deserialize)]
struct RemoveVmMsg {
    id: u32,
}

#[derive(Serialize)]
struct SimpleResp {
    res: i32,
}

// TODO(stevensd): use something other than json
macro_rules! from_double {
    ( $name:ident, $dest_type:ty ) => {
        mod $name {
            use serde::{Deserialize, Deserializer};

            pub fn deserialize<'de, D>(deserializer: D) -> Result<$dest_type, D::Error>
            where
                D: Deserializer<'de>,
            {
                Ok(f64::deserialize(deserializer)? as $dest_type)
            }
        }
    };
}

from_double!(u64_from_double, u64);
from_double!(i64_from_double, i64);

// In practice this won't overflow, since mem_size is checked to be less than the
// CrOS guest's total memory, so it will be significantly less than 2^64.
fn calculate_extra_bytes(mem_size: u64) -> u64 {
    // 3.2MB/GB for shmem xarray
    // 2MB/GB for EPT
    // 2MB/GB for page tables
    // 2MB/GB for kvm rmap
    // .5MB/GB for kvm gfn tracking
    // => 9.7MB/GB
    // TODO(stevensd): uprev/backport removal of rmap/gfn tracking to hypervisor
    let extra_bytes = round_up_to_page_size(mem_size as usize * 97 / 10240) as u64;
    // 6MB for crosvm
    extra_bytes + (6 * 1024 * 1024)
}

// Returns Ok(None) if EOF is encountered.
fn read_obj<T: DataInit>(connection: &mut Transport) -> Result<Option<T>> {
    let mut bytes = vec![0; mem::size_of::<T>()];
    match connection.r.read_exact(&mut bytes) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        e => e.context("failed to read bytes")?,
    };
    T::from_slice(&bytes)
        .context("failed to parse bytes")
        .map(|o| Some(*o))
}

fn sync_balloon_command(
    conn: &mut Transport,
    msg: BalloonTubeCommand,
) -> Result<BalloonTubeResult> {
    conn.w
        .write(&serde_json::ser::to_vec(&msg).unwrap())
        .with_context(|| "failed to issue command")?;

    let ret = unsafe {
        handle_eintr_errno!(recvfrom(
            conn.r.as_raw_fd(),
            null_mut(),
            0,
            MSG_TRUNC | MSG_PEEK,
            null_mut(),
            null_mut(),
        ))
    };
    if ret < 0 {
        bail!("Failed to get message size: {}", sys::errno());
    }
    let mut resp = vec![0; ret as usize];
    conn.r
        .read_exact(&mut resp)
        .with_context(|| "failed to read response")?;
    serde_json::from_slice(&resp).with_context(|| "failed to parse response")
}

fn adjust_balloon(client: &mut CrosVmClient, delta: i64) -> i64 {
    let target_size = if delta > 0 {
        client.balloon_size + (delta as u64)
    } else {
        client.balloon_size.saturating_sub(delta.abs() as u64)
    };
    let actual_delta = match sync_balloon_command(
        &mut client.client,
        BalloonTubeCommand::Adjust {
            num_bytes: target_size,
            allow_failure: true,
        },
    ) {
        Ok(BalloonTubeResult::Adjusted {
            num_bytes: actual_size,
        }) => {
            let actual_delta = (actual_size as i64) - (client.balloon_size as i64);
            client.balloon_size = actual_size;
            actual_delta
        }
        res => {
            error!("Error adjusting balloon {:?}", res);
            // Be pessimistic - if we were trying to reclaim memory, assume the balloon didn't
            // inflate at all, and if we were trying to release memory, assume nothing was
            // released. If the sibling is dead, then things will be sorted out when the VM
            // is removed.
            if delta > 0 {
                0
            } else {
                client.balloon_size = target_size;
                delta
            }
        }
    };

    actual_delta
}

fn get_control_server_path(id: u32) -> PathBuf {
    PathBuf::from(format!("/run/mms_control_{}.sock", id))
}

fn wait_for_hangup(conn: &Transport) {
    let mut fds = libc::pollfd {
        fd: conn.r.as_raw_fd(),
        events: libc::POLLHUP,
        revents: 0,
    };
    // Safe because we give a valid pointer to a list (of 1) FD and check the
    // return value.
    let mut ret = unsafe { handle_eintr_errno!(libc::poll(&mut fds, 1, 10 * 1000)) };
    if ret == 0 {
        if fds.revents == libc::POLLHUP {
            return;
        }
        warn!("Long wait for client hangup");
        // Safe because we give a valid pointer to a list (of 1) FD and check the
        // return value.
        ret = unsafe { handle_eintr_errno!(libc::poll(&mut fds, 1, -1)) };
    }

    if ret == -1 || (fds.revents & libc::POLLHUP) == 0 {
        error!(
            "Error cleaning up stale clients {} {}",
            sys::errno(),
            fds.revents
        );
    }
}

fn cleanup_control_server(id: u32, server: UnixServerTransport) {
    // Unlink the file to stop any new clients.
    if let Err(e) = std::fs::remove_file(get_control_server_path(id)) {
        warn!("Error unlinking control server {}: {:?}", id, e);
    }
    // Check if there is a pending client, and wait for the client to close if there is.
    match server.accept_with_timeout(Duration::ZERO) {
        Ok(conn) => {
            wait_for_hangup(&conn);
        }
        Err(e) => {
            if let TransportError::Accept(e) = e {
                if e.kind() != ErrorKind::TimedOut {
                    warn!("Error checking for trailing clients {}: {:?}", id, e);
                }
            }
        }
    }
}

#[derive(Debug)]
struct CrosVmClient {
    client: Transport,
    mem_size: u64,
    balloon_size: u64,
}

// About the flow for starting a new VM:
//
// MMS implements a small state machine for managing startup of new
// VMs. The states are as follows:
//
//  - Idle: MMS is not starting a new VM
//  - Pending: MMS is in the middle of starting a new VM
//  - Failed: MMS failed to start a new VM
//
// The following messages affect the state machine:
//
//  - PrepareVm: Reserves memory for the new VM. To allow the client to
//    deal with failures to reserve enough memory, this message can be sent
//    multiple times, and the reserved memory will continue to accumulate.
//      - I -> P or P -> P
//  - FinishAddVm: Finishes VM startup.
//      - P -> I or P -> F
//  - RemoveVm: Cleans up VM starting VM, if the id matches the id
//    of the starting VM.
//      - P -> I or F -> I
//  - Client crashes: Equivalent to removing the starting VM.
//
// Establishing a balloon control connection with a new VM is a two
// step process. When preparing for a new VM, MMS creates a new named
// domain socket, and when finishing adding a new VM, MMS accepts a connection
// from that socket. The connection-based approach allows MMS wait for
// the client to finish shutting down when removing a VM, and it also gives
// MMS a clean, race-free way to prevent any new VMs from starting and using
// a socket (by unlinking the socket).
struct StartingVmState {
    id: u32,
    server: UnixServerTransport,
    mem_size: u64,
    init_mem_size: u64,
    reserved_mem: u64,
    client: Option<Transport>,
    failed: bool,
}

impl Debug for StartingVmState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartingVmState")
            .field("id", &self.id)
            .finish()
    }
}

struct MmsState {
    cros_ctrl_connected: bool,
    pending_ctrl_connections: VecDeque<File>,
    clients: BTreeMap<u32, CrosVmClient>,
    starting_vm_state: Option<StartingVmState>,
    next_id: u32,
}

struct CtrlHandler {
    connection: Transport,
    state: Rc<RefCell<MmsState>>,
}

macro_rules! dispatch_message {
    ($self: ident, $fn: ident, $data: expr) => {
        serde_json::to_vec(
            &$self.$fn(&serde_json::from_slice(&$data).with_context(|| "failed to parse")?),
        )
        .with_context(|| "failed to serialize response")
    };
}

impl CtrlHandler {
    fn new(connection: Transport, state: Rc<RefCell<MmsState>>) -> Self {
        CtrlHandler { connection, state }
    }

    fn handle_balloon_stats(
        &mut self,
        GetBalloonStatsMsg { ids }: &GetBalloonStatsMsg,
    ) -> GetBalloonStatsResp {
        let mut state = self.state.borrow_mut();
        let mut all_stats = Vec::new();
        for id in ids {
            let client = match state.clients.get_mut(id) {
                Some(client) => client,
                None => {
                    warn!("Missing client for {}", id);
                    continue;
                }
            };
            match sync_balloon_command(&mut client.client, BalloonTubeCommand::Stats { id: 0 }) {
                Ok(BalloonTubeResult::Stats {
                    stats,
                    balloon_actual,
                    ..
                }) => {
                    all_stats.push(TaggedBalloonStats {
                        id: *id,
                        stats,
                        balloon_actual,
                    });
                }
                Ok(resp) => error!("Unexpected response {:?}", resp),
                Err(e) => error!("Error fetching stats {} {}", id, e),
            };
        }
        GetBalloonStatsResp { all_stats }
    }

    fn validate_rebalance_deltas(&self, deltas: &[BalloonDelta]) -> Result<()> {
        let state = self.state.borrow();
        let mut ids = BTreeSet::new();
        let mut total_delta = 0;
        let pagesize = pagesize();
        for delta in deltas {
            if delta.delta % (pagesize as i64) != 0 {
                bail!("invalid balloon config {:?}", delta);
            }
            if !ids.insert(delta.id) {
                bail!("duplicate id {}", delta.id);
            }

            let client = state
                .clients
                .get(&delta.id)
                .with_context(|| format!("unknown target id {}", delta.id))?;
            let new_size = if delta.delta > 0 {
                client.balloon_size.checked_add(delta.delta as u64)
            } else {
                delta
                    .delta
                    .checked_abs()
                    .and_then(|d| client.balloon_size.checked_sub(d as u64))
            }
            // Also catches underflow
            .with_context(|| format!("balloon overflow {} {}", client.balloon_size, delta.delta))?;

            if new_size > client.mem_size {
                bail!("overinflate balloon {} {}", new_size, client.mem_size);
            }

            total_delta += delta.delta;
        }
        if total_delta != 0 {
            bail!("unbalanced config {}", total_delta);
        }

        Ok(())
    }

    fn handle_rebalance_memory(
        &mut self,
        RebalanceMemoryMsg { deltas }: &RebalanceMemoryMsg,
    ) -> RebalanceMemoryResp {
        if let Err(err) = self.validate_rebalance_deltas(deltas) {
            error!("Invalid rebalance: {:?}", err);
            return RebalanceMemoryResp {
                actual_deltas: deltas
                    .iter()
                    .map(|delta| ActualBalloonDelta {
                        id: delta.id,
                        delta: 0,
                    })
                    .collect(),
            };
        }

        let mut state = self.state.borrow_mut();
        let mut slack: i64 = 0;
        let mut actual_deltas = Vec::new();

        // Inflate balloons to reclaim their memory.
        for delta in deltas {
            if delta.delta <= 0 {
                continue;
            }
            let client = state.clients.get_mut(&delta.id).unwrap();
            let actual_delta = adjust_balloon(client, delta.delta);
            if actual_delta != delta.delta {
                info!(
                    "balloon inflate mismatch id={} expected={} actual={}",
                    delta.id, delta.delta, actual_delta
                );
            }
            slack += actual_delta;
            actual_deltas.push(ActualBalloonDelta {
                id: delta.id,
                delta: actual_delta,
            });
        }

        // Deflate balloons to give reclaimed memory to other VMs
        for delta in deltas {
            if delta.delta >= 0 {
                continue;
            }
            let client = state.clients.get_mut(&delta.id).unwrap();
            let adjusted_delta = -cmp::min(delta.delta.abs(), slack);
            let actual_delta = adjust_balloon(client, adjusted_delta);
            if adjusted_delta != actual_delta {
                warn!(
                    "balloon deflate mismatch id={} expected={} actual={}",
                    delta.id, adjusted_delta, actual_delta
                );
            }
            slack += actual_delta;
            actual_deltas.push(ActualBalloonDelta {
                id: delta.id,
                delta: actual_delta,
            });
        }

        if slack != 0 {
            // This should not happen. It either require that a balloon over-inflates
            // in the first stage, or that a balloon fails to deflate as requested in
            // the second stage. Neither should be possible.
            error!("non-zero slack remaining: {}", slack);
        }

        RebalanceMemoryResp { actual_deltas }
    }

    fn prepare_vm(&mut self, msg: &PrepareVmMsg) -> PrepareVmResp {
        let mut state = self.state.borrow_mut();
        let already_reserved = match state.starting_vm_state.as_mut() {
            Some(vm_state) => {
                if vm_state.mem_size != msg.mem_size || vm_state.init_mem_size != msg.init_mem_size
                {
                    error!(
                        "prepare_vm mismatch with pending request {:?} {} {}",
                        msg, vm_state.mem_size, vm_state.init_mem_size
                    );
                    return error_prepare_vm_resp(-libc::EINVAL);
                }
                if vm_state.failed {
                    error!("prepare_vm mismatch with failed request {}", vm_state.id);
                    return error_prepare_vm_resp(-libc::EINVAL);
                }
                vm_state.reserved_mem
            }
            None => {
                if msg.mem_size % (pagesize() as u64) != 0
                    || msg.init_mem_size % (pagesize() as u64) != 0
                    || msg.init_mem_size > msg.mem_size
                {
                    error!("invalid prepare VM request {:?}", msg);
                    return error_prepare_vm_resp(-libc::EINVAL);
                }

                let crosvm_client = state.clients.get(&CROS_GUEST_ID).unwrap();
                if msg.mem_size >= crosvm_client.mem_size {
                    error!("Oversized guest {:?}", msg);
                    return error_prepare_vm_resp(-libc::EINVAL);
                }

                // Just panic on overflow - 2^32 VMs should be enough.
                let id = state.next_id;
                state.next_id = state.next_id.checked_add(1).unwrap();

                let path = get_control_server_path(id);
                let server = match UnixServerTransport::new(&path) {
                    Ok(server) => server,
                    Err(e) => {
                        error!("failed to create server for {}: {:?}", id, e);
                        return error_prepare_vm_resp(-libc::EIO);
                    }
                };
                state.starting_vm_state = Some(StartingVmState {
                    id,
                    server,
                    mem_size: msg.mem_size,
                    init_mem_size: msg.init_mem_size,
                    reserved_mem: 0,
                    client: None,
                    failed: false,
                });
                0
            }
        };

        let required_mem = msg.init_mem_size + calculate_extra_bytes(msg.mem_size);
        let crosvm_client = state.clients.get_mut(&CROS_GUEST_ID).unwrap();
        let new_reserved =
            adjust_balloon(crosvm_client, (required_mem - already_reserved) as i64) as u64;

        // starting_vm_state cannot be None here
        let vm_state = state.starting_vm_state.as_mut().unwrap();
        vm_state.reserved_mem += new_reserved;

        PrepareVmResp {
            res: if vm_state.reserved_mem == required_mem {
                0
            } else {
                -libc::ENOMEM
            },
            id: vm_state.id,
            shortfall: required_mem - vm_state.reserved_mem,
        }
    }

    fn finish_add_vm(&mut self, FinishAddVmMsg { id }: &FinishAddVmMsg) -> SimpleResp {
        let mut state = self.state.borrow_mut();
        let pending_id = match state.starting_vm_state.as_ref() {
            Some(vm_state) => {
                if vm_state.failed {
                    error!("pending failed vm in finish_add_vm {}", vm_state.id);
                    return SimpleResp { res: -libc::EINVAL };
                }
                Some(vm_state.id)
            }
            None => None,
        };
        if Some(*id) != pending_id {
            error!("id mismatch in finish_add_vm {} {:?}", id, pending_id);
            return SimpleResp { res: -libc::EINVAL };
        }
        // starting_vm_state cannot be None here
        let vm_state = state.starting_vm_state.as_mut().unwrap();

        let balloon_size = (vm_state.mem_size - vm_state.init_mem_size) as i64;
        let required_mem = vm_state.init_mem_size + calculate_extra_bytes(vm_state.mem_size);
        let client = if required_mem == vm_state.reserved_mem {
            match vm_state.server.accept_with_timeout(Duration::from_secs(10)) {
                Ok(client) => {
                    let mut client = CrosVmClient {
                        client,
                        mem_size: vm_state.mem_size,
                        balloon_size: 0,
                    };
                    if adjust_balloon(&mut client, balloon_size) != balloon_size {
                        error!("Failed to inflate new client balloon");
                        Err((-libc::ENOMEM, Some(client.client)))
                    } else {
                        Ok(client)
                    }
                }
                Err(msg) => {
                    error!("Failed to connect to vm: {:?}", msg);
                    Err((-libc::EIO, None))
                }
            }
        } else {
            error!(
                "Mismatch memory for added VM: required={} reserved={}",
                required_mem, vm_state.reserved_mem
            );
            Err((-libc::ENOMEM, None))
        };

        match client {
            Ok(client) => {
                let vm_state = state.starting_vm_state.take().unwrap();
                state.clients.insert(vm_state.id, client);
                cleanup_control_server(vm_state.id, vm_state.server);
                SimpleResp { res: 0 }
            }
            Err((res, client)) => {
                vm_state.failed = true;
                vm_state.client = client;
                SimpleResp { res }
            }
        }
    }

    fn remove_vm(&mut self, RemoveVmMsg { id }: &RemoveVmMsg) -> SimpleResp {
        if *id == CROS_GUEST_ID {
            error!("Invalid id in remove_vm {}", CROS_GUEST_ID);
            return SimpleResp { res: -libc::EINVAL };
        }
        let mut state = self.state.borrow_mut();
        let released_mem = match state.clients.remove(id) {
            None => {
                let pending_id = state.starting_vm_state.as_ref().map(|state| state.id);
                if Some(*id) != pending_id {
                    error!("Unknown id in remove_vm {}", *id);
                    return SimpleResp { res: -libc::EINVAL };
                }
                let vm_state = state.starting_vm_state.take().unwrap();
                cleanup_control_server(vm_state.id, vm_state.server);
                if let Some(client) = vm_state.client {
                    wait_for_hangup(&client);
                }
                vm_state.reserved_mem
            }
            Some(client) => {
                wait_for_hangup(&client.client);
                client.mem_size - client.balloon_size + calculate_extra_bytes(client.mem_size)
            }
        };

        let crosvm_client = state.clients.get_mut(&CROS_GUEST_ID).unwrap();
        let actual_released = adjust_balloon(crosvm_client, -(released_mem as i64));
        if actual_released != -(released_mem as i64) {
            error!(
                "Failed to release sibling memory back to CrOS guest {} {}",
                -(released_mem as i64),
                actual_released
            );
        }
        SimpleResp { res: 0 }
    }

    fn handle_message(&mut self) -> Result<()> {
        let header = match read_obj::<MmsMessageHeader>(&mut self.connection)
            .context("failed to read header")?
        {
            Some(header) => header,
            None => return Ok(()),
        };

        let mut bytes = vec![0; header.len as usize];
        self.connection
            .r
            .read_exact(&mut bytes)
            .with_context(|| "failed to read ctl message")?;

        let msg = match header.msg_type.try_into()? {
            MessageId::GetBalloonStats => dispatch_message!(self, handle_balloon_stats, bytes),
            MessageId::RebalanceMemory => dispatch_message!(self, handle_rebalance_memory, bytes),
            MessageId::PrepareVm => dispatch_message!(self, prepare_vm, bytes),
            MessageId::FinishAddVm => dispatch_message!(self, finish_add_vm, bytes),
            MessageId::RemoveVm => dispatch_message!(self, remove_vm, bytes),
        }?;

        let mut resp_bytes = Vec::new();
        let resp_header = MmsMessageHeader {
            len: msg.len() as u32,
            msg_type: header.msg_type,
        };
        resp_bytes.extend_from_slice(resp_header.as_slice());
        resp_bytes.extend_from_slice(&msg);
        self.connection
            .w
            .write_all(&resp_bytes)
            .with_context(|| "failed writing response")?;
        Ok(())
    }
}

impl Debug for CtrlHandler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CtrlHandler").finish()
    }
}

impl EventSource for CtrlHandler {
    fn on_event(&mut self) -> StdResult<Option<Box<dyn Mutator>>, String> {
        if let Err(msg) = self.handle_message() {
            error!("Error processing message {}", msg);
        };
        Ok(None)
    }

    fn on_hangup(&mut self) -> std::result::Result<Option<Box<dyn Mutator>>, String> {
        let mut state = self.state.borrow_mut();
        // Wait for all old non-cros VMs to go away
        let mut released_mem = 0;
        info!("waiting for stale crosvm clients to exit");
        for (id, client) in &state.clients {
            if *id == CROS_GUEST_ID {
                continue;
            }

            wait_for_hangup(&client.client);
            released_mem += (client.mem_size - client.balloon_size
                + calculate_extra_bytes(client.mem_size)) as i64;
        }
        state.clients.retain(|k, _| *k == CROS_GUEST_ID);

        if let Some(vm_state) = state.starting_vm_state.take() {
            info!("cleaning up control server");
            cleanup_control_server(vm_state.id, vm_state.server);

            if let Some(client) = vm_state.client {
                info!("cleaning up client");
                wait_for_hangup(&client);
            }

            released_mem += vm_state.reserved_mem as i64;
        }
        info!("all stale crosvm clients exited");

        let crosvm_client = state.clients.get_mut(&CROS_GUEST_ID).unwrap();
        let actual_released = adjust_balloon(crosvm_client, -released_mem);
        if actual_released != -released_mem {
            error!(
                "Failed to release sibling memory back to CrOS guest {} {}",
                -released_mem, actual_released
            );
        }

        state.cros_ctrl_connected = false;
        if let Some(ctrl_file) = state.pending_ctrl_connections.pop_front() {
            process_new_ctrl_connection(&mut state, self.state.clone(), ctrl_file)
        } else {
            Ok(None)
        }
    }
}

impl AsRawFd for CtrlHandler {
    fn as_raw_fd(&self) -> RawFd {
        self.connection.as_raw_fd()
    }
}

struct MmsBridge {
    bridge: UnixSeqpacket,
    state: Rc<RefCell<MmsState>>,
}

impl MmsBridge {
    fn new(bridge: UnixSeqpacket, state: Rc<RefCell<MmsState>>) -> Self {
        MmsBridge { bridge, state }
    }
}

fn process_new_ctrl_connection(
    state: &mut MmsState,
    state_rc: Rc<RefCell<MmsState>>,
    ctrl_file: File,
) -> StdResult<Option<Box<dyn Mutator>>, String> {
    if state.clients.len() != 1 {
        return Err("unknown crosvm clients".to_string());
    }

    let ctrl_file2 = ctrl_file
        .try_clone()
        .map_err(|e| format!("Clone error {:?}", e))?;
    let ctrl_connection = Transport::from_files(ctrl_file, ctrl_file2);

    let ctrl_handler = CtrlHandler::new(ctrl_connection, state_rc);

    state.cros_ctrl_connected = true;
    Ok(Some(Box::new(AddEventSourceMutator::from(ctrl_handler))))
}

impl EventSource for MmsBridge {
    fn on_event(&mut self) -> StdResult<Option<Box<dyn Mutator>>, String> {
        let mut state = self.state.borrow_mut();
        let ctrl_socket = match self.bridge.recv_as_vec_with_fds() {
            Ok((_, fd)) => fd[0],
            Err(err) => {
                return Err(format!(
                    "Error receiving ctrl socket from bridge: {:?}",
                    err
                ))
            }
        };
        // Safe because we own the fd.
        let ctrl_file = unsafe { File::from_raw_fd(ctrl_socket) };

        // Although the previous connection should generally be torn down before the
        // the new connection, it's possible that the teardown gets delayed. In particular,
        // we need to handle the case where the executor processes the hangup and new
        // connection in a single iteration - when that happens, the new connection is
        // processed before the hangup.
        if state.cros_ctrl_connected {
            state.pending_ctrl_connections.push_back(ctrl_file);
            warn!(
                "Duplicate control connection. Pending count is {}",
                state.pending_ctrl_connections.len()
            );
            return Ok(None);
        }

        process_new_ctrl_connection(&mut state, self.state.clone(), ctrl_file)
    }
}

impl AsRawFd for MmsBridge {
    fn as_raw_fd(&self) -> RawFd {
        self.bridge.as_raw_fd()
    }
}

impl Debug for MmsBridge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmsBridge").finish()
    }
}

fn main() {
    if let Err(e) = syslog::init() {
        eprintln!("Failed to initialize syslog: {}", e);
        return;
    }
    info!("starting ManaTEE memory service: {}", BUILD_TIMESTAMP);

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        error!("Usage: manatee_memory_service <CrOS guest memory in MiB> <MMS bridge socket path>");
        return;
    }
    let cros_mem = match args[1].parse::<u64>() {
        Ok(cros_mem) => match cros_mem.checked_mul(1024 * 1024) {
            Some(cros_mem) => cros_mem,
            None => {
                error!("Cros memory size overflow: {}", cros_mem);
                return;
            }
        },
        Err(e) => {
            error!("Error parsing cros memory size: {:?}", e);
            return;
        }
    };

    let bridge = match UnixSeqpacket::connect(PathBuf::from(&args[2])) {
        Ok(bridge) => bridge,
        Err(e) => {
            error!("Error connecting to MMS bridge {:?}", e);
            return;
        }
    };

    let crosvm_server = match UnixServerTransport::new(&get_control_server_path(CROS_GUEST_ID)) {
        Ok(server) => server,
        Err(e) => {
            error!("Failed to start cros guest server {:?}", e);
            return;
        }
    };
    let crosvm_client = match crosvm_server.accept_with_timeout(Duration::MAX) {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to connect to cros guest balloon {:?}", e);
            return;
        }
    };
    cleanup_control_server(CROS_GUEST_ID, crosvm_server);
    let mut clients = BTreeMap::new();
    clients.insert(
        CROS_GUEST_ID,
        CrosVmClient {
            client: crosvm_client,
            mem_size: cros_mem,
            balloon_size: 0,
        },
    );

    let state = Rc::new(RefCell::new(MmsState {
        cros_ctrl_connected: false,
        pending_ctrl_connections: VecDeque::new(),
        clients,
        starting_vm_state: None,
        next_id: CROS_GUEST_ID + 1,
    }));
    let mms_bridge = MmsBridge::new(bridge, state);

    let mut ctx = EventMultiplexer::new().unwrap();
    ctx.add_event(Box::new(mms_bridge)).unwrap();
    while !ctx.is_empty() {
        if let Err(e) = ctx.run_once() {
            error!("{}", e);
        };
    }

    info!("ManaTEE memory service exiting");
}
