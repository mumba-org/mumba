// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

use anyhow::{anyhow, bail, Context};
use argh::FromArgs;
use base::validate_raw_descriptor;
use base::{error, warn, Event, RawDescriptor};
use cros_async::{EventAsync, Executor, IntoAsync, IoSourceExt};
use futures::future::{AbortHandle, Abortable};
use hypervisor::ProtectionType;
use net_util::TapT;
use net_util::{MacAddress, Tap};
use sync::Mutex;
use virtio_sys::virtio_net;
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use super::{run_ctrl_queue, run_tx_queue, NetBackend, NET_EXECUTOR};
use crate::virtio;
use crate::virtio::net::validate_and_configure_tap;
use crate::virtio::net::{process_rx, NetError};
use crate::virtio::vhost::user::device::handler::{
    DeviceRequestHandler, Doorbell, VhostUserBackend,
};
use virtio::vhost::user::device::vvu::pci::VvuPciDevice;

struct TapConfig {
    host_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mac: MacAddress,
}

impl FromStr for TapConfig {
    type Err = anyhow::Error;

    fn from_str(arg: &str) -> Result<Self, Self::Err> {
        let args: Vec<&str> = arg.split(',').collect();
        if args.len() != 3 {
            bail!("TAP config must consist of 3 parts but {}", args.len());
        }

        let host_ip: Ipv4Addr = args[0]
            .parse()
            .map_err(|e| anyhow!("invalid IP address: {}", e))?;
        let netmask: Ipv4Addr = args[1]
            .parse()
            .map_err(|e| anyhow!("invalid net mask: {}", e))?;
        let mac: MacAddress = args[2]
            .parse()
            .map_err(|e| anyhow!("invalid MAC address: {}", e))?;

        Ok(Self {
            host_ip,
            netmask,
            mac,
        })
    }
}

impl<T: 'static> NetBackend<T>
where
    T: TapT + IntoAsync,
{
    fn new_from_config(config: &TapConfig) -> anyhow::Result<Self> {
        // Create a tap device.
        let tap = T::new(true /* vnet_hdr */, false /* multi_queue */)
            .context("failed to create tap device")?;
        tap.set_ip_addr(config.host_ip)
            .context("failed to set IP address")?;
        tap.set_netmask(config.netmask)
            .context("failed to set netmask")?;
        tap.set_mac_address(config.mac)
            .context("failed to set MAC address")?;

        Self::new(tap)
    }

    pub fn new_from_tap_fd(tap_fd: RawDescriptor) -> anyhow::Result<Self> {
        let tap_fd = validate_raw_descriptor(tap_fd).context("failed to validate tap fd")?;
        // Safe because we ensure that we get a unique handle to the fd.
        let tap = unsafe { T::from_raw_descriptor(tap_fd).context("failed to create tap device")? };

        Self::new(tap)
    }

    fn new(tap: T) -> anyhow::Result<Self> {
        let vq_pairs = Self::max_vq_pairs();
        validate_and_configure_tap(&tap, vq_pairs as u16)
            .context("failed to validate and configure tap")?;

        let avail_features = virtio::base_features(ProtectionType::Unprotected)
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CTRL_VQ
            | 1 << virtio_net::VIRTIO_NET_F_CTRL_GUEST_OFFLOADS
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_MTU
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let mtu = tap.mtu()?;

        Ok(Self {
            tap,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            workers: Default::default(),
            mtu,
        })
    }
}

async fn run_rx_queue<T: TapT>(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    mut tap: Box<dyn IoSourceExt<T>>,
    doorbell: Arc<Mutex<Doorbell>>,
    kick_evt: EventAsync,
) {
    loop {
        if let Err(e) = tap.wait_readable().await {
            error!("Failed to wait for tap device to become readable: {}", e);
            break;
        }
        match process_rx(&doorbell, &mut queue, &mem, tap.as_source_mut()) {
            Ok(()) => {}
            Err(NetError::RxDescriptorsExhausted) => {
                if let Err(e) = kick_evt.next_val().await {
                    error!("Failed to read kick event for rx queue: {}", e);
                    break;
                }
            }
            Err(e) => {
                error!("Failed to process rx queue: {}", e);
                break;
            }
        }
    }
}

/// Platform specific impl of VhostUserBackend::start_queue.
pub(super) fn start_queue<T: 'static + IntoAsync + TapT>(
    backend: &mut NetBackend<T>,
    idx: usize,
    mut queue: virtio::Queue,
    mem: GuestMemory,
    doorbell: Arc<Mutex<Doorbell>>,
    kick_evt: Event,
) -> anyhow::Result<()> {
    if let Some(handle) = backend.workers.get_mut(idx).and_then(Option::take) {
        warn!("Starting new queue handler without stopping old handler");
        handle.abort();
    }

    // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
    queue.ack_features(backend.acked_features);

    NET_EXECUTOR.with(|ex| {
        // Safe because the executor is initialized in main() below.
        let ex = ex.get().expect("Executor not initialized");

        let kick_evt =
            EventAsync::new(kick_evt.0, ex).context("failed to create EventAsync for kick_evt")?;
        let tap = backend
            .tap
            .try_clone()
            .context("failed to clone tap device")?;
        let (handle, registration) = AbortHandle::new_pair();
        match idx {
            0 => {
                let tap = ex
                    .async_from(tap)
                    .context("failed to create async tap device")?;

                ex.spawn_local(Abortable::new(
                    run_rx_queue(queue, mem, tap, doorbell, kick_evt),
                    registration,
                ))
                .detach();
            }
            1 => {
                ex.spawn_local(Abortable::new(
                    run_tx_queue(queue, mem, tap, doorbell, kick_evt),
                    registration,
                ))
                .detach();
            }
            2 => {
                ex.spawn_local(Abortable::new(
                    run_ctrl_queue(
                        queue,
                        mem,
                        tap,
                        doorbell,
                        kick_evt,
                        backend.acked_features,
                        1, /* vq_pairs */
                    ),
                    registration,
                ))
                .detach();
            }
            _ => bail!("attempted to start unknown queue: {}", idx),
        }

        backend.workers[idx] = Some(handle);
        Ok(())
    })
}

#[derive(FromArgs)]
#[argh(description = "")]
struct Options {
    #[argh(
        option,
        description = "TAP device config. (e.g. \
        \"/path/to/sock,10.0.2.2,255.255.255.0,12:34:56:78:9a:bc\")",
        arg_name = "SOCKET_PATH,IP_ADDR,NET_MASK,MAC_ADDR"
    )]
    device: Vec<String>,
    #[argh(
        option,
        description = "TAP FD with a socket path",
        arg_name = "SOCKET_PATH,TAP_FD"
    )]
    tap_fd: Vec<String>,
    #[argh(
        option,
        description = "TAP device config for virtio-vhost-user. \
                       (e.g. \"0000:00:07.0,10.0.2.2,255.255.255.0,12:34:56:78:9a:bc\")",
        arg_name = "DEVICE,IP_ADDR,NET_MASK,MAC_ADDR"
    )]
    vvu_device: Vec<String>,
    #[argh(
        option,
        description = "TAP FD with a vfio device name for virtio-vhost-user",
        arg_name = "DEVICE,TAP_FD"
    )]
    vvu_tap_fd: Vec<String>,
}

enum Connection {
    Socket(String),
    Vfio(String),
}

fn new_backend_from_device_arg(arg: &str) -> anyhow::Result<(String, NetBackend<Tap>)> {
    let pos = match arg.find(',') {
        Some(p) => p,
        None => {
            bail!("device must take comma-separated argument");
        }
    };
    let conn = &arg[0..pos];
    let cfg = &arg[pos + 1..]
        .parse::<TapConfig>()
        .context("failed to parse tap config")?;
    let backend = NetBackend::<Tap>::new_from_config(cfg).context("failed to create NetBackend")?;
    Ok((conn.to_string(), backend))
}

fn new_backend_from_tapfd_arg(arg: &str) -> anyhow::Result<(String, NetBackend<Tap>)> {
    let pos = match arg.find(',') {
        Some(p) => p,
        None => {
            bail!("'tap-fd' flag must take comma-separated argument");
        }
    };
    let conn = &arg[0..pos];
    let tap_fd = &arg[pos + 1..]
        .parse::<i32>()
        .context("failed to parse tap-fd")?;
    let backend =
        NetBackend::<Tap>::new_from_tap_fd(*tap_fd).context("failed to create NetBackend")?;

    Ok((conn.to_string(), backend))
}

/// Starts a vhost-user net device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub(crate) fn start_device(program_name: &str, args: &[&str]) -> anyhow::Result<()> {
    let opts = match Options::from_args(&[program_name], args) {
        Ok(opts) => opts,
        Err(e) => {
            if e.status.is_err() {
                bail!(e.output);
            } else {
                println!("{}", e.output);
            }
            return Ok(());
        }
    };

    let num_devices =
        opts.device.len() + opts.tap_fd.len() + opts.vvu_device.len() + opts.vvu_tap_fd.len();

    if num_devices == 0 {
        bail!("no device option was passed");
    }

    let mut devices: Vec<(Connection, NetBackend<Tap>)> = Vec::with_capacity(num_devices);

    // vhost-user
    for arg in opts.device.iter() {
        devices.push(
            new_backend_from_device_arg(arg)
                .map(|(s, backend)| (Connection::Socket(s), backend))?,
        );
    }
    for arg in opts.tap_fd.iter() {
        devices.push(
            new_backend_from_tapfd_arg(arg).map(|(s, backend)| (Connection::Socket(s), backend))?,
        );
    }

    // virtio-vhost-user
    for arg in opts.vvu_device.iter() {
        devices.push(
            new_backend_from_device_arg(arg).map(|(s, backend)| (Connection::Vfio(s), backend))?,
        );
    }
    for arg in opts.vvu_tap_fd.iter() {
        devices.push(
            new_backend_from_tapfd_arg(arg).map(|(s, backend)| (Connection::Vfio(s), backend))?,
        );
    }

    let mut threads = Vec::with_capacity(num_devices);

    for (conn, backend) in devices {
        match conn {
            Connection::Socket(socket) => {
                let ex = Executor::new().context("failed to create executor")?;
                let handler = DeviceRequestHandler::new(backend);
                threads.push(thread::spawn(move || {
                    NET_EXECUTOR.with(|thread_ex| {
                        let _ = thread_ex.set(ex.clone());
                    });
                    ex.run_until(handler.run(&socket, &ex))?
                }));
            }
            Connection::Vfio(device_name) => {
                let device =
                    VvuPciDevice::new(device_name.as_str(), NetBackend::<Tap>::MAX_QUEUE_NUM)?;
                let handler = DeviceRequestHandler::new(backend);
                let ex = Executor::new().context("failed to create executor")?;
                threads.push(thread::spawn(move || {
                    NET_EXECUTOR.with(|thread_ex| {
                        let _ = thread_ex.set(ex.clone());
                    });
                    ex.run_until(handler.run_vvu(device, &ex))?
                }));
            }
        };
    }

    for t in threads {
        match t.join() {
            Ok(r) => r?,
            Err(e) => bail!("thread panicked: {:?}", e),
        }
    }
    Ok(())
}
