// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_ZYGOTE_ZYGOTE_MAIN_H_
#define CONTENT_ZYGOTE_ZYGOTE_MAIN_H_

#include <memory>
#include <vector>

#include "base/files/file_path.h"
#include "build/build_config.h"
#include "core/shared/common/content_export.h"

namespace common {
class ZygoteForkDelegate;
}

namespace zygote {

bool CONTENT_EXPORT ZygoteMain(
    std::vector<std::unique_ptr<common::ZygoteForkDelegate>> fork_delegates);

}  // namespace content

#endif  // CONTENT_ZYGOTE_ZYGOTE_MAIN_H_
