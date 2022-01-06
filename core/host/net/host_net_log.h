// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_HOST_NET_LOG_H_
#define MUMBA_HOST_NET_HOST_NET_LOG_H_

#include "base/macros.h"
#include "net/log/net_log.h"

namespace host {

class HostNetLog : public net::NetLog {
public:
  HostNetLog();
  ~HostNetLog() override;
private:
  DISALLOW_COPY_AND_ASSIGN(HostNetLog);
};

}

#endif