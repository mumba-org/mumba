// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/dom_storage_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"


namespace host {

const char DomStorageGetHandler::kFullname[] = "/mumba.Mumba/DomStorageGet";

DomStorageGetHandler::DomStorageGetHandler():
  fullname_(DomStorageGetHandler::kFullname) {

  Init();
}

DomStorageGetHandler::~DomStorageGetHandler() {}

base::StringPiece DomStorageGetHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomStorageGetHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomStorageGetHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomStorageGetHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomStorageRemoveHandler::kFullname[] = "/mumba.Mumba/DomStorageRemove";

DomStorageRemoveHandler::DomStorageRemoveHandler():
  fullname_(DomStorageRemoveHandler::kFullname) {

  Init();
}

DomStorageRemoveHandler::~DomStorageRemoveHandler() {}

base::StringPiece DomStorageRemoveHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomStorageRemoveHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomStorageRemoveHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomStorageRemoveHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomStorageSetHandler::kFullname[] = "/mumba.Mumba/DomStorageSet";

DomStorageSetHandler::DomStorageSetHandler():
  fullname_(DomStorageSetHandler::kFullname) {

  Init();
}

DomStorageSetHandler::~DomStorageSetHandler() {}

base::StringPiece DomStorageSetHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomStorageSetHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomStorageSetHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomStorageSetHandler::output() const {
  // FIXME
  return fullname_;
}

}