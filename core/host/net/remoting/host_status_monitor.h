// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_HOST_STATUS_MONITOR_H_
#define MUMBA_HOST_NET_HOST_STATUS_MONITOR_H_

#include "base/memory/ref_counted.h"
#include "base/observer_list.h"

namespace host {

class HostStatusObserver;

// Helper used to deliver host status notifications to observers.
class HostStatusMonitor : public base::RefCountedThreadSafe<HostStatusMonitor> {
 public:
  HostStatusMonitor();

  // Add/Remove |observer| to/from the list of status observers.
  void AddStatusObserver(HostStatusObserver* observer);
  void RemoveStatusObserver(HostStatusObserver* observer);

  const base::ObserverList<HostStatusObserver>& observers() {
    return observers_;
  };

 protected:
  friend class base::RefCountedThreadSafe<HostStatusMonitor>;

  base::ObserverList<HostStatusObserver> observers_;

  virtual ~HostStatusMonitor();
};

}  // namespace remoting

#endif  // REMOTING_HOST_HOST_STATUS_MONITOR_H_
