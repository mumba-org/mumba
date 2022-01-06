// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_PATHS_H_
#define COMMON_PATHS_H_

#include "build/build_config.h"
#include "core/shared/common/content_export.h"

namespace base {
class FilePath;
}

namespace common {

enum {
  PATH_START = 1000,
  CHILD_PROCESS_EXE = PATH_START,
  DIR_APP,         // Directory where dlls and data reside.
  DIR_LOGS,        // Directory where logs should be written.
  DIR_ROOT,        // Mumba Root Directory
  DIR_RESOURCES,   // Directory containing separate file resources
  DIR_PROFILE,
  DIR_SOCKETS,
  PATH_END
};


bool CONTENT_EXPORT GetDefaultRootDirectory(base::FilePath* result);

// Call once to register the provider for the path keys defined above.
void CONTENT_EXPORT RegisterPathProvider();

}

#endif
