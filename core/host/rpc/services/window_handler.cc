// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/window_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char WindowActivateHandler::kFullname[] = "/mumba.Mumba/WindowActivate";
const char WindowListHandler::kFullname[] = "/mumba.Mumba/WindowList";

WindowActivateHandler::WindowActivateHandler():
  fullname_(WindowActivateHandler::kFullname) {

  Init();
}

WindowActivateHandler::~WindowActivateHandler() {}

base::StringPiece WindowActivateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void WindowActivateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void WindowActivateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& WindowActivateHandler::output() const {
  // FIXME
  return fullname_;
}

WindowListHandler::WindowListHandler():
  fullname_(WindowListHandler::kFullname) {

  Init();
}

WindowListHandler::~WindowListHandler() {}

base::StringPiece WindowListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void WindowListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void WindowListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& WindowListHandler::output() const {
  // FIXME
  return fullname_;
}

}