// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/worker_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char WorkerListHandler::kFullname[] = "/mumba.Mumba/WorkerList";
const char WorkerTerminateHandler::kFullname[] = "/mumba.Mumba/WorkerTerminate";

WorkerListHandler::WorkerListHandler():
  fullname_(WorkerListHandler::kFullname) {

  Init();
}

WorkerListHandler::~WorkerListHandler() {}

base::StringPiece WorkerListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void WorkerListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void WorkerListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& WorkerListHandler::output() const {
  // FIXME
  return fullname_;
}

WorkerTerminateHandler::WorkerTerminateHandler():
  fullname_(WorkerTerminateHandler::kFullname) {

  Init();
}

WorkerTerminateHandler::~WorkerTerminateHandler() {}

base::StringPiece WorkerTerminateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void WorkerTerminateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void WorkerTerminateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& WorkerTerminateHandler::output() const {
  // FIXME
  return fullname_;
}

}