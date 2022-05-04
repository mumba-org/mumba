// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::interrupter::{Error as InterrupterError, Interrupter};
use super::xhci_backend_device::{BackendType, XhciBackendDevice};
use super::xhci_regs::{
    XhciRegs, MAX_PORTS, PORTSC_CONNECT_STATUS_CHANGE, PORTSC_CURRENT_CONNECT_STATUS,
    PORTSC_PORT_ENABLED, PORTSC_PORT_ENABLED_DISABLED_CHANGE, USB2_PORTS_END, USB2_PORTS_START,
    USB3_PORTS_END, USB3_PORTS_START, USB_STS_PORT_CHANGE_DETECT,
};
use crate::register_space::Register;
use remain::sorted;
use std::sync::{Arc, MutexGuard};
use sync::Mutex;
use thiserror::Error;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("all suitable ports already attached")]
    AllPortsAttached,
    #[error("device already detached from port {0}")]
    AlreadyDetached(u8),
    #[error("failed to attach device to port {port_id}: {reason}")]
    Attach {
        port_id: u8,
        reason: InterrupterError,
    },
    #[error("failed to detach device from port {port_id}: {reason}")]
    Detach {
        port_id: u8,
        reason: InterrupterError,
    },
    #[error("device {bus}:{addr}:{vid:04x}:{pid:04x} is not attached")]
    NoSuchDevice {
        bus: u8,
        addr: u8,
        vid: u16,
        pid: u16,
    },
    #[error("port {0} does not exist")]
    NoSuchPort(u8),
}

type Result<T> = std::result::Result<T, Error>;

/// A port on usb hub. It could have a device connected to it.
pub struct UsbPort {
    ty: BackendType,
    port_id: u8,
    portsc: Register<u32>,
    usbsts: Register<u32>,
    interrupter: Arc<Mutex<Interrupter>>,
    backend_device: Mutex<Option<Box<dyn XhciBackendDevice>>>,
}

impl UsbPort {
    /// Create a new usb port that has nothing connected to it.
    pub fn new(
        ty: BackendType,
        port_id: u8,
        portsc: Register<u32>,
        usbsts: Register<u32>,
        interrupter: Arc<Mutex<Interrupter>>,
    ) -> UsbPort {
        UsbPort {
            ty,
            port_id,
            portsc,
            usbsts,
            interrupter,
            backend_device: Mutex::new(None),
        }
    }

    fn port_id(&self) -> u8 {
        self.port_id
    }

    /// Detach current connected backend. Returns false when there is no backend connected.
    pub fn detach(&self) -> Result<()> {
        let mut locked = self.backend_device.lock();
        if locked.is_none() {
            return Err(Error::AlreadyDetached(self.port_id));
        }
        usb_debug!("device detached from port {}", self.port_id);
        *locked = None;
        self.send_device_disconnected_event()
            .map_err(|reason| Error::Detach {
                port_id: self.port_id,
                reason,
            })
    }

    /// Get current connected backend.
    pub fn get_backend_device(&self) -> MutexGuard<Option<Box<dyn XhciBackendDevice>>> {
        self.backend_device.lock()
    }

    fn is_attached(&self) -> bool {
        self.backend_device.lock().is_some()
    }

    fn reset(&self) -> std::result::Result<(), InterrupterError> {
        if self.is_attached() {
            self.send_device_connected_event()?;
        }
        Ok(())
    }

    fn attach(
        &self,
        device: Box<dyn XhciBackendDevice>,
    ) -> std::result::Result<(), InterrupterError> {
        usb_debug!("A backend is connected to port {}", self.port_id);
        let mut locked = self.backend_device.lock();
        assert!(locked.is_none());
        *locked = Some(device);
        self.send_device_connected_event()
    }

    /// Inform the guest kernel there is device connected to this port. It combines first few steps
    /// of USB device initialization process in xHCI spec 4.3.
    pub fn send_device_connected_event(&self) -> std::result::Result<(), InterrupterError> {
        // xHCI spec 4.3.
        self.portsc.set_bits(
            PORTSC_CURRENT_CONNECT_STATUS
                | PORTSC_PORT_ENABLED
                | PORTSC_CONNECT_STATUS_CHANGE
                | PORTSC_PORT_ENABLED_DISABLED_CHANGE,
        );
        self.usbsts.set_bits(USB_STS_PORT_CHANGE_DETECT);
        self.interrupter
            .lock()
            .send_port_status_change_trb(self.port_id)
    }

    /// Inform the guest kernel that device has been detached.
    pub fn send_device_disconnected_event(&self) -> std::result::Result<(), InterrupterError> {
        // xHCI spec 4.3.
        self.portsc
            .set_bits(PORTSC_CONNECT_STATUS_CHANGE | PORTSC_PORT_ENABLED_DISABLED_CHANGE);
        self.portsc.clear_bits(PORTSC_CURRENT_CONNECT_STATUS);
        self.usbsts.set_bits(USB_STS_PORT_CHANGE_DETECT);
        self.interrupter
            .lock()
            .send_port_status_change_trb(self.port_id)
    }
}

/// UsbHub is a set of usb ports.
pub struct UsbHub {
    ports: Vec<Arc<UsbPort>>,
}

impl UsbHub {
    /// Create usb hub with no device attached.
    pub fn new(regs: &XhciRegs, interrupter: Arc<Mutex<Interrupter>>) -> UsbHub {
        let mut ports = Vec::new();
        // Each port should have a portsc register.
        assert_eq!(MAX_PORTS as usize, regs.portsc.len());

        for i in USB2_PORTS_START..USB2_PORTS_END {
            ports.push(Arc::new(UsbPort::new(
                BackendType::Usb2,
                i + 1,
                regs.portsc[i as usize].clone(),
                regs.usbsts.clone(),
                interrupter.clone(),
            )));
        }

        for i in USB3_PORTS_START..USB3_PORTS_END {
            ports.push(Arc::new(UsbPort::new(
                BackendType::Usb3,
                i + 1,
                regs.portsc[i as usize].clone(),
                regs.usbsts.clone(),
                interrupter.clone(),
            )));
        }
        UsbHub { ports }
    }

    /// Reset all ports.
    pub fn reset(&self) -> Result<()> {
        usb_debug!("reseting usb hub");
        for p in &self.ports {
            p.reset().map_err(|reason| Error::Detach {
                port_id: p.port_id(),
                reason,
            })?;
        }
        Ok(())
    }

    /// Get a specific port of the hub.
    pub fn get_port(&self, port_id: u8) -> Option<Arc<UsbPort>> {
        if port_id == 0 || port_id > MAX_PORTS {
            return None;
        }
        let port_index = (port_id - 1) as usize;
        Some(self.ports.get(port_index)?.clone())
    }

    /// Connect backend to next empty port.
    pub fn connect_backend(&self, backend: Box<dyn XhciBackendDevice>) -> Result<u8> {
        usb_debug!("Trying to connect backend to hub");
        for port in &self.ports {
            if port.is_attached() {
                continue;
            }
            if port.ty != backend.get_backend_type() {
                continue;
            }
            let port_id = port.port_id();
            port.attach(backend)
                .map_err(|reason| Error::Attach { port_id, reason })?;
            return Ok(port_id);
        }
        Err(Error::AllPortsAttached)
    }

    /// Disconnect device from port. Returns false if port id is not valid or could not be
    /// disonnected.
    pub fn disconnect_port(&self, port_id: u8) -> Result<()> {
        match self.get_port(port_id) {
            Some(port) => port.detach(),
            None => Err(Error::NoSuchPort(port_id)),
        }
    }
}
