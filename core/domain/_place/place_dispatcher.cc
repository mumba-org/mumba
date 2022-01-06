// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/place/place_dispatcher.h"

#include "base/uuid.h"
#include "base/files/file_path.h"
#include "base/task_scheduler/post_task.h"
#include "core/domain/domain_process.h"
#include "core/domain/domain_context.h"
#include "core/domain/domain_main_thread.h"

namespace domain {

PlaceDispatcher::PlaceDispatcher():
 binding_(this),
 //handler_(new Handler()),
 weak_factory_(this) {}
 
PlaceDispatcher::~PlaceDispatcher() {}

void PlaceDispatcher::Bind(common::mojom::PlaceDispatcherAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void PlaceDispatcher::PlaceLoad(common::mojom::PlaceHandlePtr handle, const std::string& url, PlaceLoadCallback cb) {
 // find the place node, and call load.. it will call its inner handler
 // to deal with the loading
}

void PlaceDispatcher::PlaceUnload(common::mojom::PlaceHandlePtr handle, const std::string& url, PlaceUnloadCallback cb) {
 // find the place node, and call unload.. it will call its inner handler
 // to deal with the unloading
}

}