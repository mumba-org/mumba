// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_piece.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/uuid.h"
#include "base/run_loop.h"
#include "storage/storage.h"
#include "storage/storage_manager.h"
#include "storage/proto/storage.pb.h"
//#include "storage/block.h"
#include "net/base/net_errors.h"

namespace storage {

namespace {

// void OnStorageGetEntryManifest(storage::Storage* disk, base::Closure quit, std::unique_ptr<Block> block, int64_t result) {
//   if (result == net::OK) {
//     BlockPrinter printer(block.get());
//     printer.Print();
//   } else {
//     printf("no entry found. result = %ld\n", result);
//   }
//   quit.Run();
// }

void OnStorageListEntries(base::Closure quit, std::vector<std::unique_ptr<storage_proto::Info>> entries, int64_t result) {
  if (result == net::OK) {
    for (auto const& entry : entries) {
      std::string hash_str = base::HexEncode(entry->root_hash().data(), entry->root_hash().size());
      base::UUID id(reinterpret_cast<const uint8_t *>(entry->id().data()));
      printf("#uuid: %s path: %s hash: %s size: %ld inodes: %d total pieces: %ld/%ld\n",
        id.to_string().c_str(),
        entry->path().c_str(),
        hash_str.c_str(),
        entry->length(),
        entry->inodes().size(),
        entry->piece_count(),
        entry->piece_length());
    }   
  } else {
    printf("no entry found. result = %ld\n", result);
  }
  quit.Run();
}

}


const char kLs[] = "ls";
const char kLs_HelpShort[] =
    "ls: List the files recently added or that already exists in a disk.";
const char kLs_Help[] =
    R"(
        just a marker
)";

int RunLs(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  int key_offset = -1;
  base::FilePath current_dir;
  std::string name;

  if (args.size() >= 2) {
    current_dir = base::FilePath(args[0]);
    name = args[1];
  } else if (args.size() >= 1) {
    base::GetCurrentDirectory(&current_dir);
    name = args[0];
  } else {
    printf("error ls: no disk name specified\n");
    return 1;
  }
  
  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir);
  manager->Init(base::Callback<void(int)>(), true);
  //Storage* disk = manager->GetStorage(name);
  //if (!disk) {
  //  printf("error ls: failed to open disk at '%s'. not a valid disk repo.\n", current_dir.value().c_str());
  //  return 1;
  //}

  //std::string arg = key_offset == -1 ? std::string() : args[key_offset];
  //std::string query_string = "select name, kind, state, length, file_count, root_hash from registry";
  
  manager->ListEntries(
    //arg,
    //query_string,
    //"registry",
    name,
    base::Bind(&OnStorageListEntries, 
      base::Passed(run_loop.QuitClosure())));

  run_loop.Run();
  manager->Shutdown();
  return 0;
}

}