// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ROUTE_ROUTE_REQUEST_DELEGATE_H_
#define MUMBA_HOST_ROUTE_ROUTE_REQUEST_DELEGATE_H_

#include <memory>
#include <string>

#include "mojo/public/cpp/system/data_pipe.h"

namespace host {
class RouteRequest;

class RouteRequestDelegate {
public:
  virtual ~RouteRequestDelegate() {}
  virtual void OnResponseStarted(RouteRequest* request, int net_error) = 0;
  virtual void OnReadCompleted(RouteRequest* request, int bytes_read) = 0;
  virtual void OnStreamReadDataAvailable(RouteRequest* request, int net_error) = 0;
};

}  // namespace host

#endif
