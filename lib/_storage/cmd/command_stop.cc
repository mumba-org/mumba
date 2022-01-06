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

void OnStorageStop(storage::Storage* disk, base::Closure quit, int64_t result) {
  quit.Run();
}

}

const char kStop[] = "stop";
const char kStop_HelpShort[] =
    "stop: stop a disk.";
const char kStop_Help[] =
    R"(
        just a marker
)";

int RunStop(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  base::FilePath current_dir;
  std::string name;

  if (args.size() >= 2) {
    current_dir = base::FilePath(args[0]);
    name = args[1];
  } else if (args.size() == 1) {
    base::GetCurrentDirectory(&current_dir);
    name = args[0];
  } else {
    printf("error stop: not enough arguments. missing <disk name>\n");
    return 1;
  }

  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir);
  manager->Init(base::Callback<void(int)>());
  
  Storage* disk = manager->GetStorage(name);
  if (!disk) {
    printf("error stop: failed to open disk '%s' at '%s'\n", name.c_str(), current_dir.value().c_str());
    return 1;
  }
  
  disk->Stop(
    base::Bind(&OnStorageStop, 
      base::Unretained(disk),
      base::Passed(run_loop.QuitClosure())));

  run_loop.Run();

  manager->Shutdown();
  
  return 0;
}

}