// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/fetch_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char FetchCloseHandler::kFullname[] = "/mumba.Mumba/FetchClose";

FetchCloseHandler::FetchCloseHandler():
  fullname_(FetchCloseHandler::kFullname) {

  Init();
}

FetchCloseHandler::~FetchCloseHandler() {}

base::StringPiece FetchCloseHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FetchCloseHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FetchCloseHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FetchCloseHandler::output() const {
  // FIXME
  return fullname_;
}

const char FetchStartHandler::kFullname[] = "/mumba.Mumba/FetchStart";

FetchStartHandler::FetchStartHandler():
  fullname_(FetchStartHandler::kFullname) {

  Init();
}

FetchStartHandler::~FetchStartHandler() {}

base::StringPiece FetchStartHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FetchStartHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FetchStartHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FetchStartHandler::output() const {
  // FIXME
  return fullname_;
}

}