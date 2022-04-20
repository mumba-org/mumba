// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_capability.h"

#include <memory>

#include <base/notreached.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/cellular/cellular.h"
#include "shill/cellular/cellular_capability_3gpp.h"
#include "shill/cellular/cellular_capability_cdma.h"
#include "shill/error.h"

namespace shill {

// All timeout values are in milliseconds
const int CellularCapability::kTimeoutActivate = 300000;
const int CellularCapability::kTimeoutConnect = 90000;
const int CellularCapability::kTimeoutDefault = 5000;
const int CellularCapability::kTimeoutDisconnect = 90000;
const int CellularCapability::kTimeoutEnable = 45000;
const int CellularCapability::kTimeoutGetLocation = 45000;
const int CellularCapability::kTimeoutRegister = 90000;
const int CellularCapability::kTimeoutReset = 90000;
const int CellularCapability::kTimeoutScan = 120000;
const int CellularCapability::kTimeoutSetInitialEpsBearer = 45000;
const int CellularCapability::kTimeoutSetupLocation = 45000;
const int CellularCapability::kTimeoutSetupSignal = 45000;

// static
std::unique_ptr<CellularCapability> CellularCapability::Create(
    Cellular::Type type,
    Cellular* cellular,
    ControlInterface* control_interface,
    Metrics* metrics,
    PendingActivationStore* pending_activation_store) {
  switch (type) {
    case Cellular::kType3gpp:
      return std::make_unique<CellularCapability3gpp>(
          cellular, control_interface, metrics, pending_activation_store);

    case Cellular::kTypeCdma:
      return std::make_unique<CellularCapabilityCdma>(
          cellular, control_interface, metrics, pending_activation_store);

    case Cellular::kTypeInvalid:
      break;
  }

  NOTREACHED();
  return nullptr;
}

CellularCapability::CellularCapability(
    Cellular* cellular,
    ControlInterface* control_interface,
    Metrics* metrics,
    PendingActivationStore* pending_activation_store)
    : cellular_(cellular),
      control_interface_(control_interface),
      metrics_(metrics),
      pending_activation_store_(pending_activation_store) {}

CellularCapability::~CellularCapability() = default;

}  // namespace shill
