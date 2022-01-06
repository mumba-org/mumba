// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/usb_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char UsbDeviceInfoHandler::kFullname[] = "/mumba.Mumba/UsbDeviceInfo";
const char UsbRequestDeviceHandler::kFullname[] = "/mumba.Mumba/UsbRequestDevice";
const char UsbGetDevicesHandler::kFullname[] = "/mumba.Mumba/UsbGetDevices";

UsbDeviceInfoHandler::UsbDeviceInfoHandler():
  fullname_(UsbDeviceInfoHandler::kFullname) {

  Init();
}

UsbDeviceInfoHandler::~UsbDeviceInfoHandler() {}

base::StringPiece UsbDeviceInfoHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void UsbDeviceInfoHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void UsbDeviceInfoHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& UsbDeviceInfoHandler::output() const {
  // FIXME
  return fullname_;
}

UsbRequestDeviceHandler::UsbRequestDeviceHandler():
  fullname_(UsbRequestDeviceHandler::kFullname) {

  Init();
}

UsbRequestDeviceHandler::~UsbRequestDeviceHandler() {}

base::StringPiece UsbRequestDeviceHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void UsbRequestDeviceHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void UsbRequestDeviceHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& UsbRequestDeviceHandler::output() const {
  // FIXME
  return fullname_;
}

UsbGetDevicesHandler::UsbGetDevicesHandler():
  fullname_(UsbGetDevicesHandler::kFullname) {

  Init();
}

UsbGetDevicesHandler::~UsbGetDevicesHandler() {}

base::StringPiece UsbGetDevicesHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void UsbGetDevicesHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void UsbGetDevicesHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& UsbGetDevicesHandler::output() const {
  // FIXME
  return fullname_;
}

}