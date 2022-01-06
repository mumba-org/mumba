// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/websocket_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char WebsocketCloseHandler::kFullname[] = "/mumba.Mumba/WebsocketClose";
const char WebsocketSendHandler::kFullname[] = "/mumba.Mumba/WebsocketSend";
const char WebsocketStartHandler::kFullname[] = "/mumba.Mumba/WebsocketStart";

WebsocketCloseHandler::WebsocketCloseHandler():
  fullname_(WebsocketCloseHandler::kFullname) {

  Init();
}

WebsocketCloseHandler::~WebsocketCloseHandler() {}

base::StringPiece WebsocketCloseHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void WebsocketCloseHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void WebsocketCloseHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& WebsocketCloseHandler::output() const {
  // FIXME
  return fullname_;
}

WebsocketStartHandler::WebsocketStartHandler():
  fullname_(WebsocketStartHandler::kFullname) {

  Init();
}

WebsocketStartHandler::~WebsocketStartHandler() {}

base::StringPiece WebsocketStartHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void WebsocketStartHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void WebsocketStartHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& WebsocketStartHandler::output() const {
  // FIXME
  return fullname_;
}

WebsocketSendHandler::WebsocketSendHandler():
  fullname_(WebsocketSendHandler::kFullname) {

  Init();
}

WebsocketSendHandler::~WebsocketSendHandler() {}

base::StringPiece WebsocketSendHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void WebsocketSendHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void WebsocketSendHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& WebsocketSendHandler::output() const {
  // FIXME
  return fullname_;
}

}