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
#include "storage/block.h"
#include "net/base/net_errors.h"

namespace storage {

namespace {

void OnStorageQuery(base::Closure quit, std::unique_ptr<Block> block, int64_t result) {
  if (result == net::OK) {
    BlockPrinter printer(block.get());
    printer.Print();
  } else {
    printf("query failed. result = %ld\n", result);
  }
  quit.Run();
}

}


const char kQuery[] = "query";
const char kQuery_HelpShort[] =
    "query: query disk.";
const char kQuery_Help[] =
    R"(
        just a marker
)";

int RunQuery(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  base::FilePath current_dir;
  int query_offset = -1;
  int catalog_offset = -1;

  if (args.size() >= 3) {
    current_dir = base::FilePath(args[0]);
    catalog_offset = 1;
    query_offset = 2;
  } else if (args.size() >= 2) {
    base::GetCurrentDirectory(&current_dir);
    catalog_offset = 0;
    query_offset = 1;
  } else {
    printf("query: not enough arguments. requires: <catalog> <query> ");
    return 1;
  }
  
  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir);
  manager->Init(base::Callback<void(int)>());
  //Storage* disk = manager->GetStorage("twitter");
  //if (!disk) {
  //  printf("error ls: failed to open disk at '%s'. not a valid disk repo.\n", current_dir.value().c_str());
  //  return 1;
  //}
  
  manager->Query(
    "twitter",
    args[query_offset],
    args[catalog_offset],
    base::Bind(&OnStorageQuery, 
      base::Passed(run_loop.QuitClosure())));

  run_loop.Run();

  manager->Shutdown();

  return 0;
}

}