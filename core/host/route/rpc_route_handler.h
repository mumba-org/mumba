// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_RPC_ROUTE_HANDLER_H_
#define MUMBA_CORE_HOST_RPC_ROUTE_HANDLER_H_

#include <string>

#include "base/macros.h"
#include "base/callback.h"
#include "base/uuid.h"
#include "core/host/route/route_handler.h"

namespace host {

/*
 * FIX: under the new Route architecture this is more generic
 *      and meant as a umbrella to HTTP, RPC, Torrent, etc..
 *      and not just "married" to RPC
 *
 *      See the changes we need to adapt the RPCUrlLoader on net side
 *      which is the primary consumer of this interface, so that instead
 *      of just talking direclty with RpcService(HostRpcService)
 *      it consumes whatever it needs from the RouteHandler itself
 *      which is a impl RpcRouteHandler or TorrentRouteHandler
 *
 *      How does it know which handler to use? from route entry manifest/header
 *      it will say something like > transport: "rpc/grpc" || transport: "http/http2" || transport: "file"
 *
 *      caveat: RPC and HTTP are intermediated by a custom handler (the domain process of the application)
 *      while filesystem and torrent go straight to the resources that the route entry redirects to
 *
 *      one way to do this is maybe pass the payload to the handler(domain process) before any action is taken
 *      so the domain decides what to do with the received payload, which is a better solution in my opinion
 *
 *      so from the domain perspective it is the route handler, no matter what the resource is or from which network
 *      it is receiving, its completely agnostic from it, something that make the route entry a great indirection
 */

class RpcRouteHandler: public RouteHandler {
public:
  RpcRouteHandler();
  ~RpcRouteHandler();
private:
  
};

}

#endif