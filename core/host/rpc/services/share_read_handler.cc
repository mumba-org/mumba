// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/share_read_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char ShareReadHandler::kFullname[] = "/mumba.Mumba/ShareRead";

ShareReadHandler::ShareReadHandler():
  fullname_(ShareReadHandler::kFullname) {

  Init();
}

ShareReadHandler::~ShareReadHandler() {}

base::StringPiece ShareReadHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ShareReadHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void ShareReadHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ShareReadHandler::output() const {
  // FIXME
  return fullname_;
}

}