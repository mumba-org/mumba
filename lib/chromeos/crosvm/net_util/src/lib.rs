// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::fs::File;
use std::io::{Read, Result as IoResult, Write};
use std::mem;
use std::net;
use std::num::ParseIntError;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::str::FromStr;

use libc::EPERM;

use base::Error as SysError;
use base::FileReadWriteVolatile;
use base::{
    ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val, volatile_impl, AsRawDescriptor,
    FromRawDescriptor, IoctlNr, RawDescriptor,
};
use cros_async::IntoAsync;
use remain::sorted;
use thiserror::Error as ThisError;

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// Unable to clone tap interface.
    #[error("failed to clone tap interface: {0}")]
    CloneTap(SysError),
    /// Failed to create a socket.
    #[error("failed to create a socket: {0}")]
    CreateSocket(SysError),
    /// Unable to create tap interface.
    #[error("failed to create tap interface: {0}")]
    CreateTap(SysError),
    /// ioctl failed.
    #[error("ioctl failed: {0}")]
    IoctlError(SysError),
    /// Couldn't open /dev/net/tun.
    #[error("failed to open /dev/net/tun: {0}")]
    OpenTun(SysError),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn sys_error(&self) -> SysError {
        match *self {
            Error::CreateSocket(e) => e,
            Error::OpenTun(e) => e,
            Error::CreateTap(e) => e,
            Error::CloneTap(e) => e,
            Error::IoctlError(e) => e,
        }
    }
}

/// Create a sockaddr_in from an IPv4 address, and expose it as
/// an opaque sockaddr suitable for usage by socket ioctls.
fn create_sockaddr(ip_addr: net::Ipv4Addr) -> libc::sockaddr {
    // IPv4 addresses big-endian (network order), but Ipv4Addr will give us
    // a view of those bytes directly so we can avoid any endian trickiness.
    let addr_in = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: unsafe { mem::transmute(ip_addr.octets()) },
        sin_zero: [0; 8usize],
    };

    unsafe { mem::transmute(addr_in) }
}

/// Extract the IPv4 address from a sockaddr. Assumes the sockaddr is a sockaddr_in.
fn read_ipv4_addr(addr: &libc::sockaddr) -> net::Ipv4Addr {
    debug_assert_eq!(addr.sa_family as libc::c_int, libc::AF_INET);
    // This is safe because sockaddr and sockaddr_in are the same size, and we've checked that
    // this address is AF_INET.
    let in_addr: libc::sockaddr_in = unsafe { mem::transmute(*addr) };
    net::Ipv4Addr::from(in_addr.sin_addr.s_addr)
}

fn create_socket() -> Result<net::UdpSocket> {
    // This is safe since we check the return value.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Error::CreateSocket(SysError::last()));
    }

    // This is safe; nothing else will use or hold onto the raw sock fd.
    Ok(unsafe { net::UdpSocket::from_raw_fd(sock) })
}

#[sorted]
#[derive(ThisError, Debug)]
pub enum MacAddressError {
    /// Invalid number of octets.
    #[error("invalid number of octets: {0}")]
    InvalidNumOctets(usize),
    /// Failed to parse octet.
    #[error("failed to parse octet: {0}")]
    ParseOctet(ParseIntError),
}

/// An Ethernet mac address. This struct is compatible with the C `struct sockaddr`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MacAddress {
    family: libc::sa_family_t,
    addr: [u8; 6usize],
    __pad: [u8; 8usize],
}

impl MacAddress {
    pub fn octets(&self) -> [u8; 6usize] {
        self.addr
    }
}

impl FromStr for MacAddress {
    type Err = MacAddressError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let octets: Vec<&str> = s.split(':').collect();
        if octets.len() != 6usize {
            return Err(MacAddressError::InvalidNumOctets(octets.len()));
        }

        let mut result = MacAddress {
            family: libc::ARPHRD_ETHER,
            addr: [0; 6usize],
            __pad: [0; 8usize],
        };

        for (i, octet) in octets.iter().enumerate() {
            result.addr[i] = u8::from_str_radix(octet, 16).map_err(MacAddressError::ParseOctet)?;
        }

        Ok(result)
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.addr[4], self.addr[5]
        )
    }
}

/// Handle for a network tap interface.
///
/// For now, this simply wraps the file descriptor for the tap device so methods
/// can run ioctls on the interface. The tap interface fd will be closed when
/// Tap goes out of scope, and the kernel will clean up the interface
/// automatically.
#[derive(Debug)]
pub struct Tap {
    tap_file: File,
    if_name: [c_char; 16usize],
    if_flags: ::std::os::raw::c_short,
}

impl Tap {
    pub fn create_tap_with_ifreq(ifreq: &mut net_sys::ifreq) -> Result<Tap> {
        // Open calls are safe because we give a constant nul-terminated
        // string and verify the result.
        let fd = unsafe {
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const c_char,
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::OpenTun(SysError::last()));
        }

        // We just checked that the fd is valid.
        let tuntap = unsafe { File::from_raw_descriptor(fd) };
        // ioctl is safe since we call it with a valid tap fd and check the return
        // value.
        let ret = unsafe { ioctl_with_mut_ref(&tuntap, net_sys::TUNSETIFF(), ifreq) };

        if ret < 0 {
            let error = SysError::last();

            // In a non-root, test environment, we won't have permission to call this; allow
            if !(cfg!(test) && error.errno() == EPERM) {
                return Err(Error::CreateTap(error));
            }
        }

        // Safe since only the name is accessed, and it's copied out.
        Ok(Tap {
            tap_file: tuntap,
            if_name: unsafe { ifreq.ifr_ifrn.ifrn_name },
            if_flags: unsafe { ifreq.ifr_ifru.ifru_flags },
        })
    }
}

pub trait TapT: FileReadWriteVolatile + Read + Write + AsRawDescriptor + Send + Sized {
    /// Create a new tap interface named `name`, or open it if it already exists with the same
    /// parameters.
    ///
    /// Set the `vnet_hdr` flag to true to allow offloading on this tap, which will add an extra 12
    /// byte virtio net header to incoming frames. Offloading cannot be used if `vnet_hdr` is false.
    /// Set 'multi_vq' to true, if tap have multi virt queue pairs
    fn new_with_name(name: &[u8], vnet_hdr: bool, multi_vq: bool) -> Result<Self>;

    /// Create a new tap interface.
    ///
    /// Set the `vnet_hdr` flag to true to allow offloading on this tap,
    /// which will add an extra 12 byte virtio net header to incoming frames. Offloading cannot
    /// be used if `vnet_hdr` is false.
    /// Set 'multi_vq' to true, if tap have multi virt queue pairs
    fn new(vnet_hdr: bool, multi_vq: bool) -> Result<Self> {
        const TUNTAP_DEV_FORMAT: &[u8] = b"vmtap%d";
        Self::new_with_name(TUNTAP_DEV_FORMAT, vnet_hdr, multi_vq)
    }

    /// Change the origin tap into multiqueue taps, this means create other taps based on the
    /// origin tap.
    fn into_mq_taps(self, vq_pairs: u16) -> Result<Vec<Self>>;

    /// Get the host-side IP address for the tap interface.
    fn ip_addr(&self) -> Result<net::Ipv4Addr>;

    /// Set the host-side IP address for the tap interface.
    fn set_ip_addr(&self, ip_addr: net::Ipv4Addr) -> Result<()>;

    /// Get the netmask for the tap interface's subnet.
    fn netmask(&self) -> Result<net::Ipv4Addr>;

    /// Set the netmask for the subnet that the tap interface will exist on.
    fn set_netmask(&self, netmask: net::Ipv4Addr) -> Result<()>;

    /// Get the MTU for the tap interface.
    fn mtu(&self) -> Result<u16>;

    /// Set the MTU for the tap interface.
    fn set_mtu(&self, mtu: u16) -> Result<()>;

    /// Get the mac address for the tap interface.
    fn mac_address(&self) -> Result<MacAddress>;

    /// Set the mac address for the tap interface.
    fn set_mac_address(&self, mac_addr: MacAddress) -> Result<()>;

    /// Set the offload flags for the tap interface.
    fn set_offload(&self, flags: c_uint) -> Result<()>;

    /// Enable the tap interface.
    fn enable(&self) -> Result<()>;

    /// Set the size of the vnet hdr.
    fn set_vnet_hdr_size(&self, size: c_int) -> Result<()>;

    fn get_ifreq(&self) -> net_sys::ifreq;

    /// Get the interface flags
    fn if_flags(&self) -> i32;

    /// Try to clone
    fn try_clone(&self) -> Result<Self>;

    /// Convert raw descriptor to TapT.
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Result<Self>;
}

impl TapT for Tap {
    fn new_with_name(name: &[u8], vnet_hdr: bool, multi_vq: bool) -> Result<Tap> {
        // This is pretty messy because of the unions used by ifreq. Since we
        // don't call as_mut on the same union field more than once, this block
        // is safe.
        let mut ifreq: net_sys::ifreq = Default::default();
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            for (dst, src) in ifrn_name
                .iter_mut()
                // Add a zero terminator to the source string.
                .zip(name.iter().chain(std::iter::once(&0)))
            {
                *dst = *src as c_char;
            }
            ifreq.ifr_ifru.ifru_flags =
                (libc::IFF_TAP | libc::IFF_NO_PI | if vnet_hdr { libc::IFF_VNET_HDR } else { 0 })
                    as c_short;
            if multi_vq {
                ifreq.ifr_ifru.ifru_flags |= libc::IFF_MULTI_QUEUE as c_short;
            }
        }

        Tap::create_tap_with_ifreq(&mut ifreq)
    }

    fn into_mq_taps(self, vq_pairs: u16) -> Result<Vec<Tap>> {
        let mut taps: Vec<Tap> = Vec::new();

        if vq_pairs <= 1 {
            taps.push(self);
            return Ok(taps);
        }

        // Add other socket into the origin tap interface
        for _ in 0..vq_pairs - 1 {
            let mut ifreq = self.get_ifreq();
            let tap = Tap::create_tap_with_ifreq(&mut ifreq)?;

            tap.enable()?;

            taps.push(tap);
        }

        taps.insert(0, self);
        Ok(taps)
    }

    fn ip_addr(&self) -> Result<net::Ipv4Addr> {
        let sock = create_socket()?;
        let mut ifreq = self.get_ifreq();

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret = unsafe {
            ioctl_with_mut_ref(&sock, net_sys::sockios::SIOCGIFADDR as IoctlNr, &mut ifreq)
        };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        // We only access one field of the ifru union, hence this is safe.
        let addr = unsafe { ifreq.ifr_ifru.ifru_addr };

        Ok(read_ipv4_addr(&addr))
    }

    fn set_ip_addr(&self, ip_addr: net::Ipv4Addr) -> Result<()> {
        let sock = create_socket()?;
        let addr = create_sockaddr(ip_addr);

        let mut ifreq = self.get_ifreq();
        ifreq.ifr_ifru.ifru_addr = addr;

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret =
            unsafe { ioctl_with_ref(&sock, net_sys::sockios::SIOCSIFADDR as IoctlNr, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn netmask(&self) -> Result<net::Ipv4Addr> {
        let sock = create_socket()?;
        let mut ifreq = self.get_ifreq();

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret = unsafe {
            ioctl_with_mut_ref(
                &sock,
                net_sys::sockios::SIOCGIFNETMASK as IoctlNr,
                &mut ifreq,
            )
        };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        // We only access one field of the ifru union, hence this is safe.
        let addr = unsafe { ifreq.ifr_ifru.ifru_netmask };

        Ok(read_ipv4_addr(&addr))
    }

    fn set_netmask(&self, netmask: net::Ipv4Addr) -> Result<()> {
        let sock = create_socket()?;
        let addr = create_sockaddr(netmask);

        let mut ifreq = self.get_ifreq();
        ifreq.ifr_ifru.ifru_netmask = addr;

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret =
            unsafe { ioctl_with_ref(&sock, net_sys::sockios::SIOCSIFNETMASK as IoctlNr, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn mtu(&self) -> Result<u16> {
        let sock = create_socket()?;
        let mut ifreq = self.get_ifreq();

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret = unsafe {
            ioctl_with_mut_ref(&sock, net_sys::sockios::SIOCGIFMTU as IoctlNr, &mut ifreq)
        };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        // We only access one field of the ifru union, hence this is safe.
        let mtu = unsafe { ifreq.ifr_ifru.ifru_mtu } as u16;
        Ok(mtu)
    }

    fn set_mtu(&self, mtu: u16) -> Result<()> {
        let sock = create_socket()?;

        let mut ifreq = self.get_ifreq();
        ifreq.ifr_ifru.ifru_mtu = i32::from(mtu);

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret = unsafe { ioctl_with_ref(&sock, net_sys::sockios::SIOCSIFMTU as IoctlNr, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn mac_address(&self) -> Result<MacAddress> {
        let sock = create_socket()?;
        let mut ifreq = self.get_ifreq();

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret = unsafe {
            ioctl_with_mut_ref(
                &sock,
                net_sys::sockios::SIOCGIFHWADDR as IoctlNr,
                &mut ifreq,
            )
        };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        // We only access one field of the ifru union, hence this is safe.
        // This is safe since the MacAddress struct is already sized to match the C sockaddr
        // struct. The address family has also been checked.
        Ok(unsafe { mem::transmute(ifreq.ifr_ifru.ifru_hwaddr) })
    }

    fn set_mac_address(&self, mac_addr: MacAddress) -> Result<()> {
        let sock = create_socket()?;

        let mut ifreq = self.get_ifreq();

        // We only access one field of the ifru union, hence this is safe.
        unsafe {
            // This is safe since the MacAddress struct is already sized to match the C sockaddr
            // struct.
            ifreq.ifr_ifru.ifru_hwaddr = std::mem::transmute(mac_addr);
        }

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret =
            unsafe { ioctl_with_ref(&sock, net_sys::sockios::SIOCSIFHWADDR as IoctlNr, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn set_offload(&self, flags: c_uint) -> Result<()> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        let ret =
            unsafe { ioctl_with_val(&self.tap_file, net_sys::TUNSETOFFLOAD(), flags as c_ulong) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn enable(&self) -> Result<()> {
        let sock = create_socket()?;

        let mut ifreq = self.get_ifreq();
        ifreq.ifr_ifru.ifru_flags =
            (net_sys::net_device_flags::IFF_UP | net_sys::net_device_flags::IFF_RUNNING).0 as i16;

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret =
            unsafe { ioctl_with_ref(&sock, net_sys::sockios::SIOCSIFFLAGS as IoctlNr, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn set_vnet_hdr_size(&self, size: c_int) -> Result<()> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.tap_file, net_sys::TUNSETVNETHDRSZ(), &size) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn get_ifreq(&self) -> net_sys::ifreq {
        let mut ifreq: net_sys::ifreq = Default::default();

        // This sets the name of the interface, which is the only entry
        // in a single-field union.
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            ifrn_name.clone_from_slice(&self.if_name);
        }

        // This sets the flags with which the interface was created, which is the only entry we set
        // on the second union.
        ifreq.ifr_ifru.ifru_flags = self.if_flags;

        ifreq
    }

    fn if_flags(&self) -> i32 {
        self.if_flags.into()
    }

    fn try_clone(&self) -> Result<Tap> {
        self.tap_file
            .try_clone()
            .map(|tap_file| Tap {
                tap_file,
                if_name: self.if_name,
                if_flags: self.if_flags,
            })
            .map_err(SysError::from)
            .map_err(Error::CloneTap)
    }

    /// # Safety: fd is a valid FD and ownership of it is transferred when
    /// calling this function.
    unsafe fn from_raw_descriptor(fd: RawDescriptor) -> Result<Tap> {
        let tap_file = File::from_raw_descriptor(fd);

        // Get the interface name since we will need it for some ioctls.
        let mut ifreq: net_sys::ifreq = Default::default();
        let ret = ioctl_with_mut_ref(&tap_file, net_sys::TUNGETIFF(), &mut ifreq);

        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(Tap {
            tap_file,
            if_name: ifreq.ifr_ifrn.ifrn_name,
            if_flags: ifreq.ifr_ifru.ifru_flags,
        })
    }
}

impl Read for Tap {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.tap_file.read(buf)
    }
}

impl Write for Tap {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.tap_file.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.tap_file.as_raw_descriptor()
    }
}

impl AsRawDescriptor for Tap {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.tap_file.as_raw_descriptor()
    }
}

impl IntoAsync for Tap {}

volatile_impl!(Tap);

pub mod fakes {
    use super::*;
    use std::fs::remove_file;
    use std::fs::OpenOptions;

    const TMP_FILE: &str = "/tmp/crosvm_tap_test_file";

    pub struct FakeTap {
        tap_file: File,
    }

    impl TapT for FakeTap {
        fn new_with_name(_: &[u8], _: bool, _: bool) -> Result<FakeTap> {
            Ok(FakeTap {
                tap_file: OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create(true)
                    .open(TMP_FILE)
                    .unwrap(),
            })
        }

        fn into_mq_taps(self, _vq_pairs: u16) -> Result<Vec<FakeTap>> {
            Ok(Vec::new())
        }

        fn ip_addr(&self) -> Result<net::Ipv4Addr> {
            Ok(net::Ipv4Addr::new(1, 2, 3, 4))
        }

        fn set_ip_addr(&self, _: net::Ipv4Addr) -> Result<()> {
            Ok(())
        }

        fn netmask(&self) -> Result<net::Ipv4Addr> {
            Ok(net::Ipv4Addr::new(255, 255, 255, 252))
        }

        fn set_netmask(&self, _: net::Ipv4Addr) -> Result<()> {
            Ok(())
        }

        fn mtu(&self) -> Result<u16> {
            Ok(1500)
        }

        fn set_mtu(&self, _: u16) -> Result<()> {
            Ok(())
        }

        fn mac_address(&self) -> Result<MacAddress> {
            Ok("01:02:03:04:05:06".parse().unwrap())
        }

        fn set_mac_address(&self, _: MacAddress) -> Result<()> {
            Ok(())
        }

        fn set_offload(&self, _: c_uint) -> Result<()> {
            Ok(())
        }

        fn enable(&self) -> Result<()> {
            Ok(())
        }

        fn set_vnet_hdr_size(&self, _: c_int) -> Result<()> {
            Ok(())
        }

        fn get_ifreq(&self) -> net_sys::ifreq {
            let ifreq: net_sys::ifreq = Default::default();
            ifreq
        }

        fn if_flags(&self) -> i32 {
            libc::IFF_TAP
        }

        fn try_clone(&self) -> Result<Self> {
            unimplemented!()
        }

        /// # Safety: panics on call / does nothing.
        unsafe fn from_raw_descriptor(_descriptor: RawDescriptor) -> Result<Self> {
            unimplemented!()
        }
    }

    impl Drop for FakeTap {
        fn drop(&mut self) {
            let _ = remove_file(TMP_FILE);
        }
    }

    impl Read for FakeTap {
        fn read(&mut self, _: &mut [u8]) -> IoResult<usize> {
            Ok(0)
        }
    }

    impl Write for FakeTap {
        fn write(&mut self, _: &[u8]) -> IoResult<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    impl AsRawFd for FakeTap {
        fn as_raw_fd(&self) -> RawFd {
            self.tap_file.as_raw_descriptor()
        }
    }

    impl AsRawDescriptor for FakeTap {
        fn as_raw_descriptor(&self) -> RawDescriptor {
            self.tap_file.as_raw_descriptor()
        }
    }
    volatile_impl!(FakeTap);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_address() {
        assert!("01:02:03:04:05:06".parse::<MacAddress>().is_ok());
        assert!("01:06".parse::<MacAddress>().is_err());
        assert!("01:02:03:04:05:06:07:08:09".parse::<MacAddress>().is_err());
        assert!("not a mac address".parse::<MacAddress>().is_err());
    }

    #[test]
    fn tap_create() {
        Tap::new(true, false).unwrap();
    }

    #[test]
    fn tap_configure() {
        let tap = Tap::new(true, false).unwrap();
        let ip_addr: net::Ipv4Addr = "100.115.92.5".parse().unwrap();
        let netmask: net::Ipv4Addr = "255.255.255.252".parse().unwrap();
        let mac_addr: MacAddress = "a2:06:b9:3d:68:4d".parse().unwrap();

        let ret = tap.set_ip_addr(ip_addr);
        assert_ok_or_perm_denied(ret);
        let ret = tap.set_netmask(netmask);
        assert_ok_or_perm_denied(ret);
        let ret = tap.set_mac_address(mac_addr);
        assert_ok_or_perm_denied(ret);
    }

    /// This test will only work if the test is run with root permissions and, unlike other tests
    /// in this file, do not return PermissionDenied. They fail because the TAP FD is not
    /// initialized (as opposed to permission denial). Run this with "cargo test -- --ignored".
    #[test]
    #[ignore]
    fn root_only_tests() {
        // This line will fail to provide an initialized FD if the test is not run as root.
        let tap = Tap::new(true, false).unwrap();
        tap.set_vnet_hdr_size(16).unwrap();
        tap.set_offload(0).unwrap();
    }

    #[test]
    fn tap_enable() {
        let tap = Tap::new(true, false).unwrap();

        let ret = tap.enable();
        assert_ok_or_perm_denied(ret);
    }

    fn assert_ok_or_perm_denied<T>(res: Result<T>) {
        match res {
            // We won't have permission in test environments; allow that
            Ok(_t) => {}
            Err(Error::IoctlError(e)) if e.errno() == EPERM => {}
            Err(e) => panic!("Unexpected Error:\n{}", e),
        }
    }
}
