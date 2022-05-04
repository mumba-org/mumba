// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Result;
use hypervisor::DeviceKind;

use crate::IrqChip;

pub trait IrqChipAArch64: IrqChip {
    // Clones this trait as a `Box` version of itself.
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipAArch64>>;

    // Get this as the super-trait IrqChip.
    fn as_irq_chip(&self) -> &dyn IrqChip;

    // Get this as the mutable super-trait IrqChip.
    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip;

    /// Get the version of VGIC that this chip is emulating. Currently KVM may either implement
    /// VGIC version 2 or 3.
    fn get_vgic_version(&self) -> DeviceKind;

    /// Once all the VCPUs have been enabled, finalize the irq chip.
    fn finalize(&self) -> Result<()>;
}
