// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/url_request_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char UrlRequestCloseHandler::kFullname[] = "/mumba.Mumba/UrlRequestClose";
const char UrlRequestStartHandler::kFullname[] = "/mumba.Mumba/UrlRequestStart";

UrlRequestCloseHandler::UrlRequestCloseHandler():
  fullname_(UrlRequestCloseHandler::kFullname) {

  Init();
}

UrlRequestCloseHandler::~UrlRequestCloseHandler() {}

base::StringPiece UrlRequestCloseHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void UrlRequestCloseHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void UrlRequestCloseHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& UrlRequestCloseHandler::output() const {
  // FIXME
  return fullname_;
}

UrlRequestStartHandler::UrlRequestStartHandler():
  fullname_(UrlRequestStartHandler::kFullname) {

  Init();
}

UrlRequestStartHandler::~UrlRequestStartHandler() {}

base::StringPiece UrlRequestStartHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void UrlRequestStartHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void UrlRequestStartHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& UrlRequestStartHandler::output() const {
  // FIXME
  return fullname_;
}

}