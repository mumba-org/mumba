// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_ARC_VPN_DRIVER_H_
#define SHILL_VPN_ARC_VPN_DRIVER_H_

#include <string>

#include <gtest/gtest_prod.h>

#include "shill/error.h"
#include "shill/ipconfig.h"
#include "shill/vpn/vpn_driver.h"

namespace shill {

class ArcVpnDriver : public VPNDriver {
 public:
  ArcVpnDriver(Manager* manager, ProcessManager* process_manager);
  ArcVpnDriver(const ArcVpnDriver&) = delete;
  ArcVpnDriver& operator=(const ArcVpnDriver&) = delete;

  ~ArcVpnDriver() override = default;

  std::string GetProviderType() const override;

  base::TimeDelta ConnectAsync(EventHandler* handler) override;
  void Disconnect() override;
  void OnConnectTimeout() override;
  IPConfig::Properties GetIPProperties() const override;

 private:
  static const Property kProperties[];

  // Called in ConnectAsync() by PostTask(), to make sure |handler| is valid.
  void InvokeEventHandler(EventHandler* handler);

  base::WeakPtrFactory<ArcVpnDriver> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_VPN_ARC_VPN_DRIVER_H_
