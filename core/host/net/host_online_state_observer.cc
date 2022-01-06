// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/host_online_state_observer.h"

//#include "core/common/view_messages.h"
#include "core/host/application/application_process_host.h"
#include "core/host/notification_service.h"
#include "core/host/notification_types.h"
#include "core/host/host_thread.h"

namespace host {

HostOnlineStateObserver::HostOnlineStateObserver() {
  net::NetworkChangeNotifier::AddMaxBandwidthObserver(this);
  registrar_.Add(this, NOTIFICATION_RENDERER_PROCESS_CREATED,
                 NotificationService::AllSources());
}

HostOnlineStateObserver::~HostOnlineStateObserver() {
  net::NetworkChangeNotifier::RemoveMaxBandwidthObserver(this);
}

void HostOnlineStateObserver::OnMaxBandwidthChanged(
    double max_bandwidth_mbps,
    net::NetworkChangeNotifier::ConnectionType type) {
  DLOG(INFO) << "HostOnlineStateObserver::OnMaxBandwidthChanged";
  for (ApplicationProcessHost::iterator it(ApplicationProcessHost::AllHostsIterator());
       !it.IsAtEnd(); it.Advance()) {
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &HostOnlineStateObserver::OnNetworkConnectionChanged,
        base::Unretained(this),
        base::Unretained(it.GetCurrentValue()),
        max_bandwidth_mbps,
        type));
    }
}

void HostOnlineStateObserver::OnNetworkConnectionChanged(
  ApplicationProcessHost* process,
  double max_bandwidth_mbps,
  net::NetworkChangeNotifier::ConnectionType type) {
  DLOG(INFO) << "HostOnlineStateObserver::OnNetworkConnectionChanged";
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (auto* window = process->GetApplicationWindowInterface()) {
    window->OnNetworkConnectionChanged(type, max_bandwidth_mbps); 
  }
}

void HostOnlineStateObserver::OnMaxBandwidthChangedImpl(
    double max_bandwidth_mbps,
    net::NetworkChangeNotifier::ConnectionType type) {}

void HostOnlineStateObserver::Observe(
    int type,
    const NotificationSource& source,
    const NotificationDetails& details) {
  DCHECK_EQ(NOTIFICATION_RENDERER_PROCESS_CREATED, type);
 DLOG(INFO) << "HostOnlineStateObserver::Observe";
   
 ApplicationProcessHost* rph =
      Source<ApplicationProcessHost>(source).ptr();
  double max_bandwidth_mbps;
  net::NetworkChangeNotifier::ConnectionType connection_type;
  net::NetworkChangeNotifier::GetMaxBandwidthAndConnectionType(
      &max_bandwidth_mbps, &connection_type);
  if (auto* window = rph->GetApplicationWindowInterface()) {
    window->OnNetworkConnectionChanged(
      connection_type, max_bandwidth_mbps);
  }
}

}  // namespace host
