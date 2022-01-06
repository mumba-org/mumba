// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/tab_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char TabActivateHandler::kFullname[] = "/mumba.Mumba/TabActivate";
const char TabListHandler::kFullname[] = "/mumba.Mumba/TabList";
const char TabCloseHandler::kFullname[] = "/mumba.Mumba/TabClose";

TabActivateHandler::TabActivateHandler():
  fullname_(TabActivateHandler::kFullname) {

  Init();
}

TabActivateHandler::~TabActivateHandler() {}

base::StringPiece TabActivateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void TabActivateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void TabActivateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& TabActivateHandler::output() const {
  // FIXME
  return fullname_;
}

TabListHandler::TabListHandler():
  fullname_(TabListHandler::kFullname) {

  Init();
}

TabListHandler::~TabListHandler() {}

base::StringPiece TabListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void TabListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void TabListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& TabListHandler::output() const {
  // FIXME
  return fullname_;
}

TabCloseHandler::TabCloseHandler():
  fullname_(TabCloseHandler::kFullname) {

  Init();
}

TabCloseHandler::~TabCloseHandler() {}

base::StringPiece TabCloseHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void TabCloseHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void TabCloseHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& TabCloseHandler::output() const {
  // FIXME
  return fullname_;
}

}