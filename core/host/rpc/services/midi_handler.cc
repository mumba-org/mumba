// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/midi_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char MidiCloseHandler::kFullname[] = "/mumba.Mumba/MidiClose";
const char MidiOpenHandler::kFullname[] = "/mumba.Mumba/MidiOpen";
const char MidiSendHandler::kFullname[] = "/mumba.Mumba/MidiSend";

MidiCloseHandler::MidiCloseHandler():
  fullname_(MidiCloseHandler::kFullname) {

  Init();
}

MidiCloseHandler::~MidiCloseHandler() {}

base::StringPiece MidiCloseHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MidiCloseHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void MidiCloseHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MidiCloseHandler::output() const {
  // FIXME
  return fullname_;
}

MidiOpenHandler::MidiOpenHandler():
  fullname_(MidiOpenHandler::kFullname) {

  Init();
}

MidiOpenHandler::~MidiOpenHandler() {}

base::StringPiece MidiOpenHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MidiOpenHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void MidiOpenHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MidiOpenHandler::output() const {
  // FIXME
  return fullname_;
}

MidiSendHandler::MidiSendHandler():
  fullname_(MidiSendHandler::kFullname) {

  Init();
}

MidiSendHandler::~MidiSendHandler() {}

base::StringPiece MidiSendHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MidiSendHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void MidiSendHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MidiSendHandler::output() const {
  // FIXME
  return fullname_;
}

}