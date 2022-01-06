// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_VLOG_NET_LOG_H_
#define MUMBA_HOST_NET_VLOG_NET_LOG_H_

#include <memory>

#include "base/macros.h"
#include "net/log/net_log.h"

namespace host {

// Redirectes all networking events (i.e. events logged through net::NetLog) to
// VLOG(4). Note that an explicit reference to a net::NetLog object has to be
// passed to networking classes to receive the events. There is no global
// network events logger exists.
class VlogNetLog : public net::NetLog {
 public:
  VlogNetLog();
  ~VlogNetLog() override;

 private:
  class Observer;
  std::unique_ptr<Observer> observer_;

  DISALLOW_COPY_AND_ASSIGN(VlogNetLog);
};

}  // namespace host

#endif  // REMOTING_BASE_VLOG_NET_LOG_H_
