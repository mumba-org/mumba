// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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
#include "storage/storage_utils.h"
#include "storage/storage_manager.h"
#include "storage/db/db.h"
#include "storage/backend/addr.h"
#include "storage/backend/storage_format.h"
#include "storage/backend/block_files.h"

namespace storage {
namespace {

void OnTorrentCreate(StorageManager* manager, const std::string& name, base::Closure quit, int64_t result) {
  if (result != 0) {
    printf("init: error creating torrent: %ld\n", result);
  }
  base::UUID id;
  bool ok = manager->GetUUID(name, "system", &id);
  if (!ok) {
    LOG(ERROR) << "no torrent recovered with name 'system'";
  }
  scoped_refptr<Torrent> system = manager->torrent_manager()->GetTorrent(id);
  if (!system) {
    LOG(ERROR) << "no system db recovered with uuid " << id.to_string(); 
  } else {
    //LOG(INFO) << "'system' db recovered with uuid " << id.to_string();
    system->db().Close();
  }
  quit.Run();
}

void OnBootstrap(StorageManager* manager, base::Closure quit, const std::string& name, int result) {
  printf("bootstrap done. %s\n", (result == 0 ? "ok": "failed"));
  if (result == 0) {
    Storage* disk = manager->CreateStorage(name);
    if (!disk) {
      printf("error create: failed to create disk '%s'\n", name.c_str());
    }
    std::vector<std::string> keyspaces;
    keyspaces.push_back("huginho");
    keyspaces.push_back("zezinho");
    keyspaces.push_back("luizinho");
    manager->CreateTorrent(
      name, 
      storage_proto::INFO_KVDB, 
      "system", 
      std::move(keyspaces), 
      base::Bind(&OnTorrentCreate, base::Unretained(manager), name, base::Passed(std::move(quit))));
  } else {
    quit.Run();   
  }
}

}

const char kCreate[] = "create";
const char kCreate_HelpShort[] =
    "create: Create a new disk.";
const char kCreate_Help[] =
    R"(
        just a marker
)";

int RunCreate(const std::vector<std::string>& args) {
  int result = 0;
  bool force = false;
  base::RunLoop run_loop;
  base::FilePath current_dir;
  std::string name;

  //base::FilePath current_dir("/home/fabiok/Storage");
  
  if (!base::GetCurrentDirectory(&current_dir)) {
    printf("error create: failed to get the current directory\n");
    return 1;
  }

  if (args.size() == 0) {
    printf("error create: no disk name specified\n");
    return 1;
  }

  name = args[0];

  if (args.size() > 1) {
    if (args[1] == "--force") {
      force = true;
    }
  }

  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir);
  manager->Init(base::Bind(&OnBootstrap, manager.get(), run_loop.QuitClosure(), name), false);//true /* batch_mode */);  
  run_loop.Run();
  printf("create: stopping manager...\n");
  manager->Shutdown();
  printf("create: end manager stop\n");
  manager.reset();

  return result;
}

}
