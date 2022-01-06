// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include "storage/cmd/commands.h"

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
#include "storage/storage_manager.h"
#include "storage/storage_utils.h"
#include "storage/db/db.h"
#include "storage/backend/addr.h"
#include "storage/backend/storage_format.h"
#include "storage/backend/block_files.h"

namespace storage {

namespace {

void OnAddFromPath(base::Closure quit, int64_t result) {
  if (result == 0) {
    printf("add: path added sucessfully\n");
  } else {
    printf("add: error adding path: %ld\n", result);
  }
  quit.Run();
}

void OnCopyEntry(base::Closure quit, int64_t result) {
  if (result == 0) {
    printf("copy: file copied sucessfully\n");
  } else {
    printf("copy: error copying file: %ld\n", result);
  }
  quit.Run();
}

}

const char kBlob[] = "blob";
const char kBlob_HelpShort[] =
    "blob: manage files.";
const char kBlob_Help[] =
    R"(
        just a marker
)";

int RunBlobAdd(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  base::FilePath src_dir;
  base::FilePath disk_dir;
  std::string storage_name;

  base::GetCurrentDirectory(&disk_dir);

  if (args.size() < 3) {
    printf("error add: not enough arguments. needs <storage-name> <src-path>\n");
    return 1;
  } 

  storage_name = args[1];
  src_dir = base::FilePath(args[2]);
  
  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(disk_dir);
  manager->Init(base::Callback<void(int)>(), true);
  
  manager->AddEntry(
        storage_name,
        src_dir, 
        base::Bind(&OnAddFromPath, 
          base::Passed(run_loop.QuitClosure())));

  run_loop.Run();
  
  manager->Shutdown();
  
  return 0;
}

int RunBlobCopy(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  std::string storage_name;
  std::string src_path;
  base::FilePath src_dir;
  base::FilePath disk_dir;
  base::FilePath dest_path;
  int src_index = 2;
  int dest_index = 3;

  if (args.size() < 4) {
    printf("error copy: not enough arguments. needs <storage-name> <entry-key> <dest-path>\n");
    return 1;
  }

  storage_name = args[1];

  if (args.size() >= 5) {
    src_dir = base::FilePath(args[2]);
    src_index++;
    dest_index++;
  } else {
    base::GetCurrentDirectory(&src_dir);
  }

  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(src_dir);
  manager->Init(base::Callback<void(int)>());
  //Storage* disk = manager->GetStorage("twitter");
  //if (!disk) {
  //  printf("error opening disk: failed to open disk at '%s'\n", src_dir.value().c_str());
  //  return 1;
  //}
  src_path = args[src_index];
  dest_path = base::FilePath(args[dest_index]);

  bool ok = false;
  base::UUID id = base::UUID::from_string(src_path, &ok);
  if (!ok) {
    printf("error db: failed to copy entry. '%s' not valid UUID\n", src_path.c_str());
    return 1;
  }
 
  manager->CopyEntry(
    storage_name,
    id,
    dest_path, 
    base::Bind(&OnCopyEntry, 
      base::Passed(run_loop.QuitClosure())));

  run_loop.Run();
  
  manager->Shutdown();

  return 0;
}

int RunBlob(const std::vector<std::string>& args) {
  if (args.size() > 0) {
    if (args[0] == "add" ) {
      return RunBlobAdd(args);
    } else if (args[0] == "copy" ) {
      return RunBlobCopy(args);
    } else {
      printf("blob: unknown command '%s'\n", args[0].c_str());
    }
  }
  return 1;
}

}