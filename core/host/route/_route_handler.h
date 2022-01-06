// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_ROUTE_ROUTE_HANDLER_H_
#define MUMBA_CORE_HOST_ROUTE_ROUTE_HANDLER_H_

#include <string>

#include "base/macros.h"
#include "base/callback.h"
#include "base/uuid.h"
#include "core/shared/common/mojom/route.mojom.h"

namespace host {
class HostRpcService;
class RouteScheme;

/*
 * This points to the protobuf service idl implementation/handler
 * a handler have a one-to-many relationship with RouteScheme
 */

/*
 * FIXME: under the new Route architecture this is more generic
 *        and meant as a umbrella to HTTP, RPC, Torrent, etc..
 *        and not just "married" to RPC
 *
 *        See the changes we need to adapt the RPCUrlLoader on net side
 *        which is the primary consumer of this interface, so that instead
 *        of just talking direclty with RpcService(HostRpcService)
 *        it consumes whatever it needs from the RouteHandler itself
 *        which is a impl RpcRouteHandler or TorrentRouteHandler
 *
 *        How does it know which handler to use? from route entry manifest/header
 *        it will say something like > transport: "rpc/grpc" || transport: "http/http2" || transport: "file"
 */

class RouteHandler {
public:
  RouteHandler(const std::string& name);
  RouteHandler(common::mojom::RouteHandlerPtr handler);
  ~RouteHandler();

  const std::string& name() const {
    return handler_->name;
  }
  
  // this is the actual handler
  HostRpcService* service() const {
    return service_;
  }

  void set_service(HostRpcService* service) {
    service_ = service;
  }

  RouteScheme* collection() const {
    return collection_;
  }

  void set_collection(RouteScheme* collection) {
    collection_ = collection;
  }

private:
  friend class RouteModel;
  friend class RouteRegistry;

  common::mojom::RouteHandlerPtr handler_;
  base::UUID uuid_;
  HostRpcService* service_; 
  RouteScheme* collection_;

  DISALLOW_COPY_AND_ASSIGN(RouteHandler);
};

}

#endif