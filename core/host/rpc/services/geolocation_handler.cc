// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/geolocation_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char GeolocationClearWatchHandler::kFullname[] = "/mumba.Mumba/GeolocationClearWatch";

GeolocationClearWatchHandler::GeolocationClearWatchHandler():
  fullname_(GeolocationClearWatchHandler::kFullname) {

  Init();
}

GeolocationClearWatchHandler::~GeolocationClearWatchHandler() {}

base::StringPiece GeolocationClearWatchHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void GeolocationClearWatchHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void GeolocationClearWatchHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& GeolocationClearWatchHandler::output() const {
  // FIXME
  return fullname_;
}

const char GeolocationGetCurrentPositionHandler::kFullname[] = "/mumba.Mumba/GeolocationGetCurrentPosition";

GeolocationGetCurrentPositionHandler::GeolocationGetCurrentPositionHandler():
  fullname_(GeolocationGetCurrentPositionHandler::kFullname) {

  Init();
}

GeolocationGetCurrentPositionHandler::~GeolocationGetCurrentPositionHandler() {}

base::StringPiece GeolocationGetCurrentPositionHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void GeolocationGetCurrentPositionHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void GeolocationGetCurrentPositionHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& GeolocationGetCurrentPositionHandler::output() const {
  // FIXME
  return fullname_;
}

const char GeolocationWatchPositionHandler::kFullname[] = "/mumba.Mumba/GeolocationWatchPosition";

GeolocationWatchPositionHandler::GeolocationWatchPositionHandler():
  fullname_(GeolocationWatchPositionHandler::kFullname) {

  Init();
}

GeolocationWatchPositionHandler::~GeolocationWatchPositionHandler() {}

base::StringPiece GeolocationWatchPositionHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void GeolocationWatchPositionHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void GeolocationWatchPositionHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& GeolocationWatchPositionHandler::output() const {
  // FIXME
  return fullname_;
}

}