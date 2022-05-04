// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod process;
mod vcpu;

use std::fs::File;
use std::io;
use std::io::Read;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use libc::{
    c_int, c_ulong, fcntl, ioctl, socketpair, AF_UNIX, EAGAIN, EBADF, EDEADLK, EEXIST, EINTR,
    EINVAL, ENOENT, EOVERFLOW, EPERM, FIOCLEX, F_SETPIPE_SZ, MS_NODEV, MS_NOEXEC, MS_NOSUID,
    MS_RDONLY, O_NONBLOCK, SIGCHLD, SOCK_SEQPACKET,
};

use anyhow::{anyhow, bail, Context, Result};
use protobuf::ProtobufError;
use remain::sorted;
use thiserror::Error;

use base::{
    add_fd_flags, block_signal, clear_signal, drop_capabilities, enable_core_scheduling, error,
    getegid, geteuid, info, pipe, register_rt_signal_handler, validate_raw_descriptor, warn,
    AsRawDescriptor, Descriptor, Error as SysError, Event, FromRawDescriptor, Killable, MmapError,
    PollToken, RawDescriptor, Result as SysResult, SignalFd, WaitContext, SIGRTMIN,
};
use kvm::{Cap, Datamatch, IoeventAddress, Kvm, Vcpu, VcpuExit, Vm};
use minijail::{self, Minijail};
use net_util::{Tap, TapT};
use vm_memory::{GuestMemory, MemoryPolicy};

use self::process::*;
use self::vcpu::*;
use crate::{Config, Executable};

const MAX_DATAGRAM_SIZE: usize = 4096;
const MAX_VCPU_DATAGRAM_SIZE: usize = 0x40000;
const CROSVM_GPU_SERVER_FD_ENV: &str = "CROSVM_GPU_SERVER_FD";

/// An error that occurs when communicating with the plugin process.
#[sorted]
#[derive(Error, Debug)]
pub enum CommError {
    #[error("failed to decode plugin request: {0}")]
    DecodeRequest(ProtobufError),
    #[error("failed to encode plugin response: {0}")]
    EncodeResponse(ProtobufError),
    #[error("plugin request socket has been hung up")]
    PluginSocketHup,
    #[error("failed to recv from plugin request socket: {0}")]
    PluginSocketRecv(SysError),
    #[error("failed to send to plugin request socket: {0}")]
    PluginSocketSend(SysError),
}

fn new_seqpacket_pair() -> SysResult<(UnixDatagram, UnixDatagram)> {
    let mut fds = [0, 0];
    unsafe {
        let ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds.as_mut_ptr());
        if ret == 0 {
            ioctl(fds[0], FIOCLEX);
            Ok((
                UnixDatagram::from_raw_descriptor(fds[0]),
                UnixDatagram::from_raw_descriptor(fds[1]),
            ))
        } else {
            Err(SysError::last())
        }
    }
}

struct VcpuPipe {
    crosvm_read: File,
    plugin_write: File,
    plugin_read: File,
    crosvm_write: File,
}

fn new_pipe_pair() -> SysResult<VcpuPipe> {
    let to_crosvm = pipe(true)?;
    let to_plugin = pipe(true)?;
    // Increasing the pipe size can be a nice-to-have to make sure that
    // messages get across atomically (and made sure that writes don't block),
    // though it's not necessary a hard requirement for things to work.
    let flags = unsafe {
        fcntl(
            to_crosvm.0.as_raw_descriptor(),
            F_SETPIPE_SZ,
            MAX_VCPU_DATAGRAM_SIZE as c_int,
        )
    };
    if flags < 0 || flags != MAX_VCPU_DATAGRAM_SIZE as i32 {
        warn!(
            "Failed to adjust size of crosvm pipe (result {}): {}",
            flags,
            SysError::last()
        );
    }
    let flags = unsafe {
        fcntl(
            to_plugin.0.as_raw_descriptor(),
            F_SETPIPE_SZ,
            MAX_VCPU_DATAGRAM_SIZE as c_int,
        )
    };
    if flags < 0 || flags != MAX_VCPU_DATAGRAM_SIZE as i32 {
        warn!(
            "Failed to adjust size of plugin pipe (result {}): {}",
            flags,
            SysError::last()
        );
    }
    Ok(VcpuPipe {
        crosvm_read: to_crosvm.0,
        plugin_write: to_crosvm.1,
        plugin_read: to_plugin.0,
        crosvm_write: to_plugin.1,
    })
}

fn proto_to_sys_err(e: ProtobufError) -> SysError {
    match e {
        ProtobufError::IoError(e) => SysError::new(e.raw_os_error().unwrap_or(EINVAL)),
        _ => SysError::new(EINVAL),
    }
}

fn io_to_sys_err(e: io::Error) -> SysError {
    SysError::new(e.raw_os_error().unwrap_or(EINVAL))
}

fn mmap_to_sys_err(e: MmapError) -> SysError {
    match e {
        MmapError::SystemCallFailed(e) => e,
        _ => SysError::new(EINVAL),
    }
}

fn create_plugin_jail(root: &Path, log_failures: bool, seccomp_policy: &Path) -> Result<Minijail> {
    // All child jails run in a new user namespace without any users mapped,
    // they run as nobody unless otherwise configured.
    let mut j = Minijail::new().context("failed to create jail")?;
    j.namespace_pids();
    j.namespace_user();
    j.uidmap(&format!("0 {0} 1", geteuid()))
        .context("failed to set uidmap for jail")?;
    j.gidmap(&format!("0 {0} 1", getegid()))
        .context("failed to set gidmap for jail")?;
    j.namespace_user_disable_setgroups();
    // Don't need any capabilities.
    j.use_caps(0);
    // Create a new mount namespace with an empty root FS.
    j.namespace_vfs();
    j.enter_pivot_root(root)
        .context("failed to set jail pivot root")?;
    // Run in an empty network namespace.
    j.namespace_net();
    j.no_new_privs();
    // By default we'll prioritize using the pre-compiled .bpf over the .policy
    // file (the .bpf is expected to be compiled using "trap" as the failure
    // behavior instead of the default "kill" behavior).
    // Refer to the code comment for the "seccomp-log-failures"
    // command-line parameter for an explanation about why the |log_failures|
    // flag forces the use of .policy files (and the build-time alternative to
    // this run-time flag).
    let bpf_policy_file = seccomp_policy.with_extension("bpf");
    if bpf_policy_file.exists() && !log_failures {
        j.parse_seccomp_program(&bpf_policy_file)
            .context("failed to parse jail seccomp BPF program")?;
    } else {
        // Use TSYNC only for the side effect of it using SECCOMP_RET_TRAP,
        // which will correctly kill the entire device process if a worker
        // thread commits a seccomp violation.
        j.set_seccomp_filter_tsync();
        if log_failures {
            j.log_seccomp_filter_failures();
        }
        j.parse_seccomp_filters(&seccomp_policy.with_extension("policy"))
            .context("failed to parse jail seccomp filter")?;
    }
    j.use_seccomp_filter();
    // Don't do init setup.
    j.run_as_init();

    // Create a tmpfs in the plugin's root directory so that we can bind mount it's executable
    // file into it.  The size=67108864 is size=64*1024*1024 or size=64MB.
    j.mount_with_data(
        Path::new("none"),
        Path::new("/"),
        "tmpfs",
        (MS_NOSUID | MS_NODEV | MS_NOEXEC) as usize,
        "size=67108864",
    )
    .context("failed to mount root")?;

    // Because we requested to "run as init", minijail will not mount /proc for us even though
    // plugin will be running in its own PID namespace, so we have to mount it ourselves.
    j.mount(
        Path::new("proc"),
        Path::new("/proc"),
        "proc",
        (MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY) as usize,
    )
    .context("failed to mount proc")?;

    Ok(j)
}

/// Each `PluginObject` represents one object that was instantiated by the guest using the `Create`
/// request.
///
/// Each such object has an ID associated with it that exists in an ID space shared by every variant
/// of `PluginObject`. This allows all the objects to be indexed in a single map, and allows for a
/// common destroy method.
///

/// In addition to the destory method, each object may have methods specific to its variant type.
/// These variant methods must be done by matching the variant to the expected type for that method.
/// For example, getting the dirty log from a `Memory` object starting with an ID:
///
/// ```ignore
/// match objects.get(&request_id) {
///    Some(&PluginObject::Memory { slot, length }) => vm.get_dirty_log(slot, &mut dirty_log[..]),
///    _ => return Err(SysError::new(ENOENT)),
/// }
/// ```
enum PluginObject {
    IoEvent {
        evt: Event,
        addr: IoeventAddress,
        length: u32,
        datamatch: u64,
    },
    Memory {
        slot: u32,
        length: usize,
    },
    IrqEvent {
        irq_id: u32,
        evt: Event,
    },
}

impl PluginObject {
    fn destroy(self, vm: &mut Vm) -> SysResult<()> {
        match self {
            PluginObject::IoEvent {
                evt,
                addr,
                length,
                datamatch,
            } => match length {
                0 => vm.unregister_ioevent(&evt, addr, Datamatch::AnyLength),
                1 => vm.unregister_ioevent(&evt, addr, Datamatch::U8(Some(datamatch as u8))),
                2 => vm.unregister_ioevent(&evt, addr, Datamatch::U16(Some(datamatch as u16))),
                4 => vm.unregister_ioevent(&evt, addr, Datamatch::U32(Some(datamatch as u32))),
                8 => vm.unregister_ioevent(&evt, addr, Datamatch::U64(Some(datamatch as u64))),
                _ => Err(SysError::new(EINVAL)),
            },
            PluginObject::Memory { slot, .. } => vm.remove_memory_region(slot).and(Ok(())),
            PluginObject::IrqEvent { irq_id, evt } => vm.unregister_irqfd(&evt, irq_id),
        }
    }
}

pub fn run_vcpus(
    kvm: &Kvm,
    vm: &Vm,
    plugin: &Process,
    vcpu_count: u32,
    kill_signaled: &Arc<AtomicBool>,
    exit_evt: &Event,
    vcpu_handles: &mut Vec<thread::JoinHandle<()>>,
) -> Result<()> {
    let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count) as usize));
    let use_kvm_signals = !kvm.check_extension(Cap::ImmediateExit);

    // If we need to force a vcpu to exit from a VM then a SIGRTMIN signal is sent
    // to that vcpu's thread.  If KVM is running the VM then it'll return -EINTR.
    // An issue is what to do when KVM isn't running the VM (where we could be
    // in the kernel or in the app).
    //
    // If KVM supports "immediate exit" then we set a signal handler that will
    // set the |immediate_exit| flag that tells KVM to return -EINTR before running
    // the VM.
    //
    // If KVM doesn't support immediate exit then we'll block SIGRTMIN in the app
    // and tell KVM to unblock SIGRTMIN before running the VM (at which point a blocked
    // signal might get asserted).  There's overhead to have KVM unblock and re-block
    // SIGRTMIN each time it runs the VM, so this mode should be avoided.

    if use_kvm_signals {
        unsafe {
            extern "C" fn handle_signal(_: c_int) {}
            // Our signal handler does nothing and is trivially async signal safe.
            // We need to install this signal handler even though we do block
            // the signal below, to ensure that this signal will interrupt
            // execution of KVM_RUN (this is implementation issue).
            register_rt_signal_handler(SIGRTMIN() + 0, handle_signal)
                .expect("failed to register vcpu signal handler");
        }
        // We do not really want the signal handler to run...
        block_signal(SIGRTMIN() + 0).expect("failed to block signal");
    } else {
        unsafe {
            extern "C" fn handle_signal(_: c_int) {
                Vcpu::set_local_immediate_exit(true);
            }
            register_rt_signal_handler(SIGRTMIN() + 0, handle_signal)
                .expect("failed to register vcpu signal handler");
        }
    }

    for cpu_id in 0..vcpu_count {
        let kill_signaled = kill_signaled.clone();
        let vcpu_thread_barrier = vcpu_thread_barrier.clone();
        let vcpu_exit_evt = exit_evt.try_clone().context("failed to clone event")?;
        let vcpu_plugin = plugin.create_vcpu(cpu_id)?;
        let vcpu = Vcpu::new(cpu_id as c_ulong, kvm, vm).context("error creating vcpu")?;

        vcpu_handles.push(
            thread::Builder::new()
                .name(format!("crosvm_vcpu{}", cpu_id))
                .spawn(move || {
                    if use_kvm_signals {
                        // Tell KVM to not block anything when entering kvm run
                        // because we will be using first RT signal to kick the VCPU.
                        vcpu.set_signal_mask(&[])
                            .expect("failed to set up KVM VCPU signal mask");
                    }

                    if let Err(e) = enable_core_scheduling() {
                        error!("Failed to enable core scheduling: {}", e);
                    }

                    let vcpu = vcpu
                        .to_runnable(Some(SIGRTMIN() + 0))
                        .expect("Failed to set thread id");

                    let res = vcpu_plugin.init(&vcpu);
                    vcpu_thread_barrier.wait();
                    if let Err(e) = res {
                        error!("failed to initialize vcpu {}: {}", cpu_id, e);
                    } else {
                        loop {
                            let mut interrupted_by_signal = false;
                            let run_res = vcpu.run();
                            match run_res {
                                Ok(run) => match run {
                                    VcpuExit::IoIn { port, mut size } => {
                                        let mut data = [0; 256];
                                        if size > data.len() {
                                            error!(
                                                "unsupported IoIn size of {} bytes at port {:#x}",
                                                size, port
                                            );
                                            size = data.len();
                                        }
                                        vcpu_plugin.io_read(port as u64, &mut data[..size], &vcpu);
                                        if let Err(e) = vcpu.set_data(&data[..size]) {
                                            error!(
                                                "failed to set return data for IoIn at port {:#x}: {}",
                                                port, e
                                            );
                                        }
                                    }
                                    VcpuExit::IoOut {
                                        port,
                                        mut size,
                                        data,
                                    } => {
                                        if size > data.len() {
                                            error!("unsupported IoOut size of {} bytes at port {:#x}", size, port);
                                            size = data.len();
                                        }
                                        vcpu_plugin.io_write(port as u64, &data[..size], &vcpu);
                                    }
                                    VcpuExit::MmioRead { address, size } => {
                                        let mut data = [0; 8];
                                        vcpu_plugin.mmio_read(
                                            address as u64,
                                            &mut data[..size],
                                            &vcpu,
                                        );
                                        // Setting data for mmio can not fail.
                                        let _ = vcpu.set_data(&data[..size]);
                                    }
                                    VcpuExit::MmioWrite {
                                        address,
                                        size,
                                        data,
                                    } => {
                                        vcpu_plugin.mmio_write(
                                            address as u64,
                                            &data[..size],
                                            &vcpu,
                                        );
                                    }
                                    VcpuExit::HypervHcall { input, params } => {
                                        let mut data = [0; 8];
                                        vcpu_plugin.hyperv_call(input, params, &mut data, &vcpu);
                                        // Setting data for hyperv call can not fail.
                                        let _ = vcpu.set_data(&data);
                                    }
                                    VcpuExit::HypervSynic {
                                        msr,
                                        control,
                                        evt_page,
                                        msg_page,
                                    } => {
                                        vcpu_plugin
                                            .hyperv_synic(msr, control, evt_page, msg_page, &vcpu);
                                    }
                                    VcpuExit::Hlt => break,
                                    VcpuExit::Shutdown => break,
                                    VcpuExit::InternalError => {
                                        error!("vcpu {} has internal error", cpu_id);
                                        break;
                                    }
                                    r => warn!("unexpected vcpu exit: {:?}", r),
                                },
                                Err(e) => match e.errno() {
                                    EINTR => interrupted_by_signal = true,
                                    EAGAIN => {}
                                    _ => {
                                        error!("vcpu hit unknown error: {}", e);
                                        break;
                                    }
                                },
                            }
                            if kill_signaled.load(Ordering::SeqCst) {
                                break;
                            }

                            // Only handle the pause request if kvm reported that it was
                            // interrupted by a signal.  This helps to entire that KVM has had a chance
                            // to finish emulating any IO that may have immediately happened.
                            // If we eagerly check pre_run() then any IO that we
                            // just reported to the plugin won't have been processed yet by KVM.
                            // Not eagerly calling pre_run() also helps to reduce
                            // any overhead from checking if a pause request is pending.
                            // The assumption is that pause requests aren't common
                            // or frequent so it's better to optimize for the non-pause execution paths.
                            if interrupted_by_signal {
                                if use_kvm_signals {
                                    clear_signal(SIGRTMIN() + 0)
                                        .expect("failed to clear pending signal");
                                } else {
                                    vcpu.set_immediate_exit(false);
                                }

                                if let Err(e) = vcpu_plugin.pre_run(&vcpu) {
                                    error!("failed to process pause on vcpu {}: {}", cpu_id, e);
                                    break;
                                }
                            }
                        }
                    }
                    vcpu_exit_evt
                        .write(1)
                        .expect("failed to signal vcpu exit event");
                })
                .context("error spawning vcpu thread")?,
        );
    }
    Ok(())
}

#[derive(PollToken)]
enum Token {
    Exit,
    ChildSignal,
    Stderr,
    Plugin { index: usize },
}

/// Run a VM with a plugin process specified by `cfg`.
///
/// Not every field of `cfg` will be used. In particular, most field that pertain to a specific
/// device are ignored because the plugin is responsible for emulating hardware.
pub fn run_config(cfg: Config) -> Result<()> {
    info!("crosvm starting plugin process");

    // Masking signals is inherently dangerous, since this can persist across clones/execs. Do this
    // before any jailed devices have been spawned, so that we can catch any of them that fail very
    // quickly.
    let sigchld_fd = SignalFd::new(SIGCHLD).context("failed to create signalfd")?;

    // Create a pipe to capture error messages from plugin and minijail.
    let (mut stderr_rd, stderr_wr) = pipe(true).context("failed to create stderr pipe")?;
    add_fd_flags(stderr_rd.as_raw_descriptor(), O_NONBLOCK)
        .context("error marking stderr nonblocking")?;

    #[allow(unused_mut)]
    let mut env_fds: Vec<(String, Descriptor)> = Vec::default();

    let _default_render_server_params = crate::platform::GpuRenderServerParameters {
        path: std::path::PathBuf::from("/usr/libexec/virgl_render_server"),
        cache_path: None,
        cache_size: None,
    };

    #[cfg(feature = "gpu")]
    let gpu_render_server_parameters = if let Some(parameters) = &cfg.gpu_render_server_parameters {
        Some(parameters)
    } else {
        if cfg!(feature = "plugin-render-server") {
            Some(&_default_render_server_params)
        } else {
            None
        }
    };

    #[cfg(feature = "gpu")]
    // Hold on to the render server jail so it keeps running until we exit run_config()
    let (_render_server_jail, _render_server_fd) =
        if let Some(parameters) = &gpu_render_server_parameters {
            let (jail, fd) = crate::platform::gpu::start_gpu_render_server(&cfg, parameters)?;
            env_fds.push((
                CROSVM_GPU_SERVER_FD_ENV.to_string(),
                Descriptor(fd.as_raw_descriptor()),
            ));
            (
                Some(crate::platform::jail_helpers::ScopedMinijail(jail)),
                Some(fd),
            )
        } else {
            (None, None)
        };

    let jail = if let Some(jail_config) = &cfg.jail_config {
        // An empty directory for jailed plugin pivot root.
        let root_path = match &cfg.plugin_root {
            Some(dir) => dir,
            None => Path::new(option_env!("DEFAULT_PIVOT_ROOT").unwrap_or("/var/empty")),
        };

        if root_path.is_relative() {
            bail!("path to the root directory must be absolute");
        }

        if !root_path.exists() {
            bail!("no root directory for jailed process to pivot root into");
        }

        if !root_path.is_dir() {
            bail!("specified root directory is not a directory");
        }

        let policy_path = jail_config.seccomp_policy_dir.join("plugin");
        let mut jail =
            create_plugin_jail(root_path, jail_config.seccomp_log_failures, &policy_path)?;

        // Update gid map of the jail if caller provided supplemental groups.
        if !cfg.plugin_gid_maps.is_empty() {
            let map = format!("0 {} 1", getegid())
                + &cfg
                    .plugin_gid_maps
                    .into_iter()
                    .map(|m| format!(",{} {} {}", m.inner, m.outer, m.count))
                    .collect::<String>();
            jail.gidmap(&map).context("failed to set gidmap for jail")?;
        }

        // Mount minimal set of devices (full, zero, urandom, etc). We can not use
        // jail.mount_dev() here because crosvm may not be running with CAP_SYS_ADMIN.
        let device_names = ["full", "null", "urandom", "zero"];
        for name in &device_names {
            let device = Path::new("/dev").join(&name);
            jail.mount_bind(&device, &device, true)
                .context("failed to mount dev")?;
        }

        for bind_mount in &cfg.plugin_mounts {
            jail.mount_bind(&bind_mount.src, &bind_mount.dst, bind_mount.writable)
                .with_context(|| {
                    format!(
                        "failed to bind mount {} -> {} as {} ",
                        bind_mount.src.display(),
                        bind_mount.dst.display(),
                        if bind_mount.writable {
                            "writable"
                        } else {
                            "read only"
                        }
                    )
                })?;
        }

        Some(jail)
    } else {
        None
    };

    let mut tap_interfaces: Vec<Tap> = Vec::new();
    if let Some(host_ip) = cfg.host_ip {
        if let Some(netmask) = cfg.netmask {
            if let Some(mac_address) = cfg.mac_address {
                let tap = Tap::new(false, false).context("error opening tap device")?;
                tap.set_ip_addr(host_ip).context("error setting tap ip")?;
                tap.set_netmask(netmask)
                    .context("error setting tap netmask")?;
                tap.set_mac_address(mac_address)
                    .context("error setting tap mac address")?;

                tap.enable().context("error enabling tap device")?;
                tap_interfaces.push(tap);
            }
        }
    }
    for tap_fd in cfg.tap_fd {
        // Safe because we ensure that we get a unique handle to the fd.
        let tap = unsafe {
            Tap::from_raw_descriptor(
                validate_raw_descriptor(tap_fd).context("failed to validate raw tap fd")?,
            )
            .context("failed to create tap device from raw fd")?
        };
        tap_interfaces.push(tap);
    }

    let plugin_args: Vec<&str> = cfg.params.iter().map(|s| &s[..]).collect();

    let plugin_path = match cfg.executable_path {
        Some(Executable::Plugin(ref plugin_path)) => plugin_path.as_path(),
        _ => panic!("Executable was not a plugin"),
    };
    let vcpu_count = cfg.vcpu_count.unwrap_or(1) as u32;
    let mem = GuestMemory::new(&[]).unwrap();
    let mut mem_policy = MemoryPolicy::empty();
    if cfg.hugepages {
        mem_policy |= MemoryPolicy::USE_HUGEPAGES;
    }
    mem.set_memory_policy(mem_policy);
    let kvm = Kvm::new_with_path(&cfg.kvm_device_path).context("error creating Kvm")?;
    let mut vm = Vm::new(&kvm, mem).context("error creating vm")?;
    vm.create_irq_chip()
        .context("failed to create kvm irqchip")?;
    vm.create_pit().context("failed to create kvm PIT")?;

    let mut plugin = Process::new(
        vcpu_count,
        plugin_path,
        &plugin_args,
        jail,
        stderr_wr,
        env_fds,
    )?;
    // Now that the jail for the plugin has been created and we had a chance to adjust gids there,
    // we can drop all our capabilities in case we had any.
    drop_capabilities().context("failed to drop process capabilities")?;

    let mut res = Ok(());
    // If Some, we will exit after enough time is passed to shutdown cleanly.
    let mut dying_instant: Option<Instant> = None;
    let duration_to_die = Duration::from_millis(1000);

    let exit_evt = Event::new().context("failed to create event")?;
    let kill_signaled = Arc::new(AtomicBool::new(false));
    let mut vcpu_handles = Vec::with_capacity(vcpu_count as usize);

    let wait_ctx = WaitContext::build_with(&[
        (&exit_evt, Token::Exit),
        (&sigchld_fd, Token::ChildSignal),
        (&stderr_rd, Token::Stderr),
    ])
    .context("failed to add control descriptors to wait context")?;

    let mut sockets_to_drop = Vec::new();
    let mut redo_wait_ctx_sockets = true;
    // In this loop, make every attempt to not return early. If an error is encountered, set `res`
    // to the error, set `dying_instant` to now, and signal the plugin that it will be killed soon.
    // If the plugin cannot be signaled because it is dead of `signal_kill` failed, simply break
    // from the poll loop so that the VCPU threads can be cleaned up.
    'wait: loop {
        // After we have waited long enough, it's time to give up and exit.
        if dying_instant
            .map(|i| i.elapsed() >= duration_to_die)
            .unwrap_or(false)
        {
            break;
        }

        if redo_wait_ctx_sockets {
            for (index, socket) in plugin.sockets().iter().enumerate() {
                wait_ctx
                    .add(socket, Token::Plugin { index })
                    .context("failed to add plugin sockets to wait context")?;
            }
        }

        let plugin_socket_count = plugin.sockets().len();
        let events = {
            let poll_res = match dying_instant {
                Some(inst) => wait_ctx.wait_timeout(duration_to_die - inst.elapsed()),
                None => wait_ctx.wait(),
            };
            match poll_res {
                Ok(v) => v,
                Err(e) => {
                    // Polling no longer works, time to break and cleanup,
                    if res.is_ok() {
                        res = Err(e).context("failed to poll all FDs");
                    }
                    break;
                }
            }
        };

        for event in events.iter().filter(|e| e.is_hungup) {
            if let Token::Stderr = event.token {
                let _ = wait_ctx.delete(&stderr_rd);
            }
        }

        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::Exit => {
                    // No need to check the exit event if we are already doing cleanup.
                    let _ = wait_ctx.delete(&exit_evt);
                    dying_instant.get_or_insert(Instant::now());
                    let sig_res = plugin.signal_kill();
                    if res.is_ok() && sig_res.is_err() {
                        res = sig_res.context("error sending kill signal to plugin on exit event");
                    }
                }
                Token::ChildSignal => {
                    // Print all available siginfo structs, then exit the loop.
                    loop {
                        match sigchld_fd.read() {
                            Ok(Some(siginfo)) => {
                                // If the plugin process has ended, there is no need to continue
                                // processing plugin connections, so we break early.
                                if siginfo.ssi_pid == plugin.pid() as u32 {
                                    break 'wait;
                                }
                                // Because SIGCHLD is not expected from anything other than the
                                // plugin process, report it as an error.
                                if res.is_ok() {
                                    res = Err(anyhow!(
                                        "process {} died with signal {}, status {}, and code {}",
                                        siginfo.ssi_pid,
                                        siginfo.ssi_signo,
                                        siginfo.ssi_status,
                                        siginfo.ssi_code,
                                    ));
                                }
                            }
                            Ok(None) => break, // No more signals to read.
                            Err(e) => {
                                // Something really must be messed up for this to happen, continue
                                // processing connections for a limited time.
                                if res.is_ok() {
                                    res = Err(e).context("failed to read signal fd");
                                }
                                break;
                            }
                        }
                    }
                    // As we only spawn the plugin process, getting a SIGCHLD can only mean
                    // something went wrong.
                    dying_instant.get_or_insert(Instant::now());
                    let sig_res = plugin.signal_kill();
                    if res.is_ok() && sig_res.is_err() {
                        res = sig_res.context("error sending kill signal to plugin on SIGCHLD");
                    }
                }
                Token::Stderr => loop {
                    let mut buf = [0u8; 4096];
                    match stderr_rd.read(&mut buf) {
                        Ok(len) => {
                            for l in String::from_utf8_lossy(&buf[0..len]).lines() {
                                error!("minijail/plugin: {}", l);
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Err(e) => {
                            error!("failed reading from stderr: {}", e);
                            break;
                        }
                    }
                },
                Token::Plugin { index } => {
                    match plugin.handle_socket(index, &kvm, &mut vm, &vcpu_handles, &tap_interfaces)
                    {
                        Ok(_) => {}
                        // A HUP is an expected event for a socket, so don't bother warning about
                        // it.
                        Err(CommError::PluginSocketHup) => sockets_to_drop.push(index),
                        // Only one connection out of potentially many is broken. Drop it, but don't
                        // start cleaning up. Because the error isn't returned, we will warn about
                        // it here.
                        Err(e) => {
                            warn!("error handling plugin socket: {}", e);
                            sockets_to_drop.push(index);
                        }
                    }
                }
            }
        }

        if vcpu_handles.is_empty() && dying_instant.is_none() && plugin.is_started() {
            let res = run_vcpus(
                &kvm,
                &vm,
                &plugin,
                vcpu_count,
                &kill_signaled,
                &exit_evt,
                &mut vcpu_handles,
            );
            if let Err(e) = res {
                dying_instant.get_or_insert(Instant::now());
                error!("failed to start vcpus: {}", e);
            }
        }

        redo_wait_ctx_sockets =
            !sockets_to_drop.is_empty() || plugin.sockets().len() != plugin_socket_count;

        // Cleanup all of the sockets that we have determined were disconnected or suffered some
        // other error.
        plugin.drop_sockets(&mut sockets_to_drop);
        sockets_to_drop.clear();

        if redo_wait_ctx_sockets {
            for socket in plugin.sockets() {
                let _ = wait_ctx.delete(socket);
            }
        }
    }

    // vcpu threads MUST see the kill signaled flag, otherwise they may re-enter the VM.
    kill_signaled.store(true, Ordering::SeqCst);
    // Depending on how we ended up here, the plugin process, or a VCPU thread waiting for requests
    // might be stuck. The `signal_kill` call will unstick all the VCPU threads by closing their
    // blocked connections.
    plugin
        .signal_kill()
        .context("error sending kill signal to plugin on cleanup")?;
    for handle in vcpu_handles {
        match handle.kill(SIGRTMIN() + 0) {
            Ok(_) => {
                if let Err(e) = handle.join() {
                    error!("failed to join vcpu thread: {:?}", e);
                }
            }
            Err(e) => error!("failed to kill vcpu thread: {}", e),
        }
    }

    match plugin.try_wait() {
        // The plugin has run out of time by now
        Ok(ProcessStatus::Running) => Err(anyhow!("plugin did not exit within timeout")),
        // Return an error discovered earlier in this function.
        Ok(ProcessStatus::Success) => res.map_err(anyhow::Error::msg),
        Ok(ProcessStatus::Fail(code)) => Err(anyhow!("plugin exited with error: {}", code)),
        Ok(ProcessStatus::Signal(code)) => Err(anyhow!("plugin exited with signal {}", code)),
        Err(e) => Err(anyhow!("error waiting for plugin to exit: {}", e)),
    }
}
