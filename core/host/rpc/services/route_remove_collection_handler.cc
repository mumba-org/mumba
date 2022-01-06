// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/route_remove_collection_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char RouteRemoveCollectionHandler::kFullname[] = "/mumba.Mumba/RouteRemoveCollection";

RouteRemoveCollectionHandler::RouteRemoveCollectionHandler():
  fullname_(RouteRemoveCollectionHandler::kFullname) {

  Init();
}

RouteRemoveCollectionHandler::~RouteRemoveCollectionHandler() {}

base::StringPiece RouteRemoveCollectionHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void RouteRemoveCollectionHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void RouteRemoveCollectionHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& RouteRemoveCollectionHandler::output() const {
  // FIXME
  return fullname_;
}

}