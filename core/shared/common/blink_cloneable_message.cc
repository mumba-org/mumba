// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/blink_cloneable_message.h"

namespace common {

BlinkCloneableMessage::BlinkCloneableMessage() = default;
BlinkCloneableMessage::~BlinkCloneableMessage() = default;

BlinkCloneableMessage::BlinkCloneableMessage(BlinkCloneableMessage&&) = default;
BlinkCloneableMessage& BlinkCloneableMessage::operator=(
    BlinkCloneableMessage&&) = default;

}  // namespace common
