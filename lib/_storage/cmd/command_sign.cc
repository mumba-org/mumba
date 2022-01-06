// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

#include "base/command_line.h"

namespace storage {

const char kSign[] = "sign";
const char kSign_HelpShort[] =
    "sign: Public signature management commands.";
const char kSign_Help[] =
    R"(
        just a marker
)";

int RunSign(const std::vector<std::string>& args) {
  return 0;
}

}