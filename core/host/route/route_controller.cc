// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/route_controller.h"

#include "core/host/route/route_registry.h"
#include "core/host/route/route_resolver.h"
#include "core/host/route/route_entry.h"

namespace host {

RouteController::RouteController(RouteResolver* resolver):
  resolver_(resolver),
  current_entry_(nullptr),
  weak_factory_(this) {

}

RouteController::~RouteController() {

}

RouteRegistry* RouteController::registry() const {
  return resolver_->registry();
}

RouteEntry* RouteController::GetCurrent() const {
  return current_entry_;
}

RouteEntry* RouteController::Get(size_t offset) const {
  return current_entry_;
}

void RouteController::GoTo(const std::string& scheme, const std::string& path, base::OnceCallback<void(int, RouteEntry*)> callback) {
  resolver_->ResolveAsync(scheme, 
                          path, 
                          base::Bind(&RouteController::OnEntryResolved, 
                                      weak_factory_.GetWeakPtr(),
                                      base::Passed(std::move(callback))));
}

void RouteController::GoTo(const GURL& url, base::OnceCallback<void(int, RouteEntry*)> callback) {
  std::string path = url.path().substr(1);
  resolver_->ResolveAsync(url.scheme(), 
                          path, 
                          base::Bind(&RouteController::OnEntryResolved, 
                                      weak_factory_.GetWeakPtr(),
                                      base::Passed(std::move(callback))));
}

void RouteController::OnEntryResolved(base::OnceCallback<void(int, RouteEntry*)> callback, int result, RouteEntry* entry) {
  current_entry_ = entry;
  std::move(callback).Run(result, entry);
}

}