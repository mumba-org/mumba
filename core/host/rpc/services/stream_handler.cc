// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/stream_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char StreamListHandler::kFullname[] = "/mumba.Mumba/StreamList";
const char StreamWriteHandler::kFullname[] = "/mumba.Mumba/StreamWrite";
const char StreamReadHandler::kFullname[] = "/mumba.Mumba/StreamRead";

StreamListHandler::StreamListHandler():
  fullname_(StreamListHandler::kFullname) {

  Init();
}

StreamListHandler::~StreamListHandler() {}

base::StringPiece StreamListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void StreamListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void StreamListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& StreamListHandler::output() const {
  // FIXME
  return fullname_;
}

StreamWriteHandler::StreamWriteHandler():
  fullname_(StreamWriteHandler::kFullname) {

  Init();
}

StreamWriteHandler::~StreamWriteHandler() {}

base::StringPiece StreamWriteHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void StreamWriteHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void StreamWriteHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& StreamWriteHandler::output() const {
  // FIXME
  return fullname_;
}

StreamReadHandler::StreamReadHandler():
  fullname_(StreamReadHandler::kFullname) {

  Init();
}

StreamReadHandler::~StreamReadHandler() {}

base::StringPiece StreamReadHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void StreamReadHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void StreamReadHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& StreamReadHandler::output() const {
  // FIXME
  return fullname_;
}

}