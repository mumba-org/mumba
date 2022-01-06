// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/remote_playback_watch_availability_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char RemotePlaybackWatchAvailabilityHandler::kFullname[] = "/mumba.Mumba/RemotePlaybackWatchAvailability";

RemotePlaybackWatchAvailabilityHandler::RemotePlaybackWatchAvailabilityHandler():
  fullname_(RemotePlaybackWatchAvailabilityHandler::kFullname) {

  Init();
}

RemotePlaybackWatchAvailabilityHandler::~RemotePlaybackWatchAvailabilityHandler() {}

base::StringPiece RemotePlaybackWatchAvailabilityHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void RemotePlaybackWatchAvailabilityHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void RemotePlaybackWatchAvailabilityHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& RemotePlaybackWatchAvailabilityHandler::output() const {
  // FIXME
  return fullname_;
}

}