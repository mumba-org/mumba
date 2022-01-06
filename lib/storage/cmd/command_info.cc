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
#include "base/strings/string_number_conversions.h"
#include "storage/storage.h"
#include "storage/storage_manager.h"
#include "storage/backend/manifest.h"

namespace storage {

namespace {

void OnStorageGetInfo(base::Closure quit, storage_proto::StorageState info) {
  printf("version: %s\naddress: %s\npublic key: %s\nprivate key: %s\ncreator: %s\nentries: %ld\nsize: %ld\n",
      info.version().c_str(), 
      info.address().c_str(), 
      base::HexEncode(info.pubkey().data(), info.pubkey().size()).c_str(), 
      base::HexEncode(info.privkey().data(), info.privkey().size()).c_str(),
      info.creator().c_str(), 
      info.entry_count(), 
      info.size());
  quit.Run();
}

}

const char kInfo[] = "info";
const char kInfo_HelpShort[] =
    "info: describes a disk by reading its manifest and other infos.";
const char kInfo_Help[] =
    R"(
        just a marker
)";

int RunInfo(const std::vector<std::string>& args) {
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
    printf("error info: no disk name specified\n");
    return 1;
  }

  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir);
  manager->Init(base::Callback<void(int)>());
  //Storage* disk = manager->GetStorage(name);
  //if (!disk) {
  //  printf("error info: failed to open disk at '%s' at '%s'. not a valid disk repo.\n", name.c_str(), current_dir.value().c_str());
  //  return 1;
  //}
  
  manager->GetInfo(
    name,
    base::Bind(&OnStorageGetInfo, 
      base::Passed(run_loop.QuitClosure())));

  run_loop.Run();

  manager->Shutdown();
  
  return 0;
}

}