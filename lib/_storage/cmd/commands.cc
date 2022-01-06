// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

namespace storage {

CommandInfo::CommandInfo()
    : help_short(nullptr),
      help(nullptr),
      runner(nullptr) {
}

CommandInfo::CommandInfo(const char* in_help_short,
                         const char* in_help,
                         CommandRunner in_runner)
    : help_short(in_help_short),
      help(in_help),
      runner(in_runner) {
}

const CommandInfoMap& GetCommands() {
  static CommandInfoMap info_map;
  if (info_map.empty()) {
    #define INSERT_COMMAND(cmd) \
        info_map[k##cmd] = CommandInfo(k##cmd##_HelpShort, \
                                       k##cmd##_Help, \
                                       &Run##cmd);
    INSERT_COMMAND(Blob)
    //INSERT_COMMAND(App)
    INSERT_COMMAND(Help)
    INSERT_COMMAND(Info)
    INSERT_COMMAND(Create)
    INSERT_COMMAND(Ls)
    INSERT_COMMAND(Sign)
    INSERT_COMMAND(Database)
//    INSERT_COMMAND(Query)
    INSERT_COMMAND(Session)
    INSERT_COMMAND(Put)
    INSERT_COMMAND(Get)
    INSERT_COMMAND(Sample)
    INSERT_COMMAND(Client)
    INSERT_COMMAND(Server)
    INSERT_COMMAND(Torrent)
    INSERT_COMMAND(Stop)
    INSERT_COMMAND(Start)
    INSERT_COMMAND(List)
    //INSERT_COMMAND(Copy)
    INSERT_COMMAND(Clone)

    #undef INSERT_COMMAND
  }
  return info_map;
}

}