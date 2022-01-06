// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

#include "base/time/time.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/run_loop.h"
#include "base/message_loop/message_loop.h"
#include "base/task_scheduler/task_scheduler.h"
#include "storage/storage_file.h"
#include "storage/proto/storage.pb.h"
#include "storage/storage.h"
#include "storage/storage_utils.h"
#include "storage/storage_manager.h"
#include "storage/db/db.h"
#include "storage/backend/addr.h"
#include "storage/backend/storage_format.h"
#include "storage/backend/block_files.h"

namespace storage {
namespace {

void OnStorageCloned(base::Closure quit, const std::string& addr, int result) {
  if (result != 0) {
    printf("clone: error cloning '%s' = %d\n", addr.c_str(), result);
  } else {
    printf("clone: ok\n");
  }
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
    FROM_HERE,
    quit,
    base::TimeDelta::FromMilliseconds((60 * 1000) * 1));
}

}

const char kClone[] = "clone";
const char kClone_HelpShort[] =
    "clone: Clone a disk.";
const char kClone_Help[] =
    R"(
        just a marker
)";

int RunClone(const std::vector<std::string>& args) {
  int result = 0;
  bool force = false;
  base::RunLoop run_loop;
  base::FilePath current_dir;
  std::string addr;

  if (!base::GetCurrentDirectory(&current_dir)) {
    printf("error create: failed to get the current directory\n");
    return 1;
  }

  if (args.size() == 0) {
    printf("error add: no disk address specified\n");
    return 1;
  }

  addr = args[0];

  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir);
  manager->Init(base::Callback<void(int)>());

  manager->CloneStorage(addr,
    base::Bind(&OnStorageCloned, base::Passed(run_loop.QuitClosure()), addr));
  
  run_loop.Run();

  manager->Shutdown();

  return result;
}

}
