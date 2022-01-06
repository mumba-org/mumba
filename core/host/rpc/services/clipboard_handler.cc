// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/clipboard_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char ClipboardReadHandler::kFullname[] = "/mumba.Mumba/ClipboardRead";

ClipboardReadHandler::ClipboardReadHandler():
  fullname_(ClipboardReadHandler::kFullname) {

  Init();
}

ClipboardReadHandler::~ClipboardReadHandler() {}

base::StringPiece ClipboardReadHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ClipboardReadHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void ClipboardReadHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ClipboardReadHandler::output() const {
  // FIXME
  return fullname_;
}

const char ClipboardReadTextHandler::kFullname[] = "/mumba.Mumba/ClipboardReadText";

ClipboardReadTextHandler::ClipboardReadTextHandler():
  fullname_(ClipboardReadTextHandler::kFullname) {

  Init();
}

ClipboardReadTextHandler::~ClipboardReadTextHandler() {}

base::StringPiece ClipboardReadTextHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ClipboardReadTextHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void ClipboardReadTextHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ClipboardReadTextHandler::output() const {
  // FIXME
  return fullname_;
}

const char ClipboardWriteHandler::kFullname[] = "/mumba.Mumba/ClipboardWrite";

ClipboardWriteHandler::ClipboardWriteHandler():
  fullname_(ClipboardWriteHandler::kFullname) {

  Init();
}

ClipboardWriteHandler::~ClipboardWriteHandler() {}

base::StringPiece ClipboardWriteHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ClipboardWriteHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void ClipboardWriteHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ClipboardWriteHandler::output() const {
  // FIXME
  return fullname_;
}

const char ClipboardWriteTextHandler::kFullname[] = "/mumba.Mumba/ClipboardWriteText";

ClipboardWriteTextHandler::ClipboardWriteTextHandler():
  fullname_(ClipboardWriteTextHandler::kFullname) {

  Init();
}

ClipboardWriteTextHandler::~ClipboardWriteTextHandler() {}

base::StringPiece ClipboardWriteTextHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ClipboardWriteTextHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void ClipboardWriteTextHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ClipboardWriteTextHandler::output() const {
  // FIXME
  return fullname_;
}

}