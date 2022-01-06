// Copyright (c) 2014 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/paths.h"

#include "base/files/file_util.h"
#include "base/path_service.h"
#include "base/threading/thread_restrictions.h"
#include "base/strings/string_util.h"

namespace common {

bool PathProvider(int key, base::FilePath* result) {
 
 bool create_dir = false;
 base::FilePath cur;

 switch (key) {
 case common::CHILD_PROCESS_EXE:
      return PathService::Get(base::FILE_EXE, result);
 case common::DIR_APP:
      return PathService::Get(base::DIR_MODULE, result);
 case common::DIR_LOGS:
      return PathService::Get(common::DIR_APP, result);
 case common::DIR_SOCKETS:
  if (!GetDefaultRootDirectory(&cur)) {
    //NOTREACHED();
    return false;
  }
  cur = cur.Append(FILE_PATH_LITERAL("tmp"));
  break;
 case common::DIR_ROOT:
     if (!GetDefaultRootDirectory(&cur)) {
       //NOTREACHED();
       return false;
     }
     create_dir = true;
     break;
 case common::DIR_PROFILE:
  if (!GetDefaultRootDirectory(&cur)) {
    //NOTREACHED();
    return false;
  }
  //cur = cur.Append(FILE_PATH_LITERAL("rootspace"));
  //create_dir = true;
  break;
 default:
    return false;
 }

 //base::ThreadRestrictions::ScopedAllowIO allow_io;
 if (create_dir && !base::PathExists(cur) &&
      !base::CreateDirectory(cur))
    return false;

  *result = cur;
  return true;
}

void RegisterPathProvider() {
 PathService::RegisterProvider(PathProvider, PATH_START, PATH_END);	
}

}