// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_piece.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "storage/storage.h"
#include "storage/storage_manager.h"
#include "storage/backend/manifest.h"

namespace storage {

namespace {

std::string StatusToString(storage_proto::StorageStatus status) {
  switch (status) {
    case storage_proto::STORAGE_STATUS_NONE:
      return std::string("none");
    case storage_proto::STORAGE_STATUS_OFFLINE:
      return std::string("offline");
    case storage_proto::STORAGE_STATUS_ONLINE:
      return std::string("online");
    case storage_proto::STORAGE_STATUS_ERROR:
      return std::string("error");  
    case storage_proto::STORAGE_STATUS_DISABLED:
      return std::string("disabled");
    default:
      NOTREACHED();
  }
  return std::string();
}

void OnStorageList(base::Closure quit, std::vector<const storage_proto::StorageState *> states, int64_t result) {
  for (const storage_proto::StorageState* state : states) {
    printf("address: %s local path: %s status: %s started: %ld\n", state->address().c_str(), state->local_path().c_str(), StatusToString(state->status()).c_str(), state->started_time());
  }
  quit.Run();
}

}

const char kList[] = "list";
const char kList_HelpShort[] =
    "list: list disks.";
const char kList_Help[] =
    R"(
        just a marker
)";

int RunList(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  base::FilePath current_dir;

  if (args.size() >= 1) {
    current_dir = base::FilePath(args[0]);
  } else {
    base::GetCurrentDirectory(&current_dir);
  }

  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir);

  manager->Init(base::Callback<void(int)>());
  
  manager->ListStorages(
    base::Bind(&OnStorageList, 
      base::Passed(run_loop.QuitClosure())));
  
  run_loop.Run();

  manager->Shutdown();
  
  return 0;
}

}