// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/keyboard_lock_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char KeyboardLockHandler::kFullname[] = "/mumba.Mumba/KeyboardLock";
const char KeyboardUnlockHandler::kFullname[] = "/mumba.Mumba/KeyboardUnlock";

KeyboardLockHandler::KeyboardLockHandler():
  fullname_(KeyboardLockHandler::kFullname) {

  Init();
}

KeyboardLockHandler::~KeyboardLockHandler() {}

base::StringPiece KeyboardLockHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void KeyboardLockHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void KeyboardLockHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& KeyboardLockHandler::output() const {
  // FIXME
  return fullname_;
}

KeyboardUnlockHandler::KeyboardUnlockHandler():
  fullname_(KeyboardUnlockHandler::kFullname) {

  Init();
}

KeyboardUnlockHandler::~KeyboardUnlockHandler() {}

base::StringPiece KeyboardUnlockHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void KeyboardUnlockHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void KeyboardUnlockHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& KeyboardUnlockHandler::output() const {
  // FIXME
  return fullname_;
}

}