// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/resource_throttle.h"

namespace host {

bool ResourceThrottle::MustProcessResponseBeforeReadingBody() {
  return false;
}

void ResourceThrottle::Cancel() {
  delegate_->Cancel();
}

void ResourceThrottle::CancelWithError(int error_code) {
  delegate_->CancelWithError(error_code);
}

void ResourceThrottle::Resume() {
  delegate_->Resume();
}

}  // namespace host
