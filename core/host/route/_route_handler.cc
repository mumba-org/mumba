// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/route_handler.h"
#include "core/host/rpc/server/host_rpc_service.h"

namespace host {

RouteHandler::RouteHandler(const std::string& name): 
    service_(nullptr),
    collection_(nullptr) {
  uuid_ = base::UUID::generate();
  handler_ = common::mojom::RouteHandler::New();
  handler_->name = name;
}

RouteHandler::RouteHandler(common::mojom::RouteHandlerPtr handler):
    handler_(std::move(handler)),
    service_(nullptr),
    collection_(nullptr) {
   
}

RouteHandler::~RouteHandler() {

}


}