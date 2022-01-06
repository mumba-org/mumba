// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

#include "base/command_line.h"

namespace storage {

const char kHelp[] = "help";
const char kHelp_HelpShort[] =
    "help: Does what you think.";
const char kHelp_Help[] =
    R"(gn help <anything>

  Yo dawg, I heard you like help on your help so I put help on the help in the
  help.

  You can also use "all" as the parameter to get all help at once.

Switches

  --markdown
      Format output in markdown syntax.

Example

  gn help --markdown all
      Dump all help to stdout in markdown format.
)";

int RunHelp(const std::vector<std::string>& args) {
  return 0;
}

}