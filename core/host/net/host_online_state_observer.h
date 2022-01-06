// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_NET_BROWSER_ONLINE_STATE_OBSERVER_H_
#define CONTENT_BROWSER_NET_BROWSER_ONLINE_STATE_OBSERVER_H_

#include "base/macros.h"
#include "core/host/notification_observer.h"
#include "core/host/notification_registrar.h"
#include "net/base/network_change_notifier.h"

namespace host {
class ApplicationProcessHost;

// Listens for changes to the online state and manages sending
// updates to each RenderProcess via RenderProcessHost IPC.
class HostOnlineStateObserver
    : public net::NetworkChangeNotifier::MaxBandwidthObserver,
      public NotificationObserver {
 public:
  HostOnlineStateObserver();
  ~HostOnlineStateObserver() override;

  // MaxBandwidthObserver implementation
  void OnMaxBandwidthChanged(
      double max_bandwidth_mbps,
      net::NetworkChangeNotifier::ConnectionType type) override;

  // NotificationObserver implementation
  void Observe(int type,
               const NotificationSource& source,
               const NotificationDetails& details) override;

 private:
  
  void OnMaxBandwidthChangedImpl(
    double max_bandwidth_mbps,
    net::NetworkChangeNotifier::ConnectionType type);
  
  void OnNetworkConnectionChanged(
    ApplicationProcessHost* process,
    double max_bandwidth_mbps,
    net::NetworkChangeNotifier::ConnectionType type);

  NotificationRegistrar registrar_;

  DISALLOW_COPY_AND_ASSIGN(HostOnlineStateObserver);
};

}  // namespace host

#endif  // CONTENT_BROWSER_NET_BROWSER_ONLINE_STATE_OBSERVER_H_
