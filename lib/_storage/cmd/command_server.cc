// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

#include "base/command_line.h"
#include "base/callback.h"
#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_piece.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/run_loop.h"
#include "storage/storage_manager.h"
#include "storage/torrent_manager.h"
#include "net/base/net_errors.h"

namespace storage {

namespace {

void OnBootstrap(StorageManager* session, base::Closure quit, int result) {
  printf("bootstrap done. %s\n", (result == 0 ? "ok": "failed"));
  //std::move(quit).Run();
}

}


const char kServer[] = "server";
const char kServer_HelpShort[] =
    "server: start a server listener";
const char kServer_Help[] =
    R"(
        just a marker
)";

int RunServer(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  base::FilePath current_dir;
  if (!base::GetCurrentDirectory(&current_dir)) {
    printf("error server: failed to get the current directory\n");
    return 1;
  }
  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir); 
  manager->Init(base::Bind(&OnBootstrap, manager.get(), run_loop.QuitClosure()), false);
 
  run_loop.Run();

  manager->Shutdown();
  manager.reset();
  
  return 0;
}

}