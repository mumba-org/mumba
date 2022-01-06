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
#include "storage/storage_manager.h"
#include "storage/application.h"
#include "storage/code.h"
#include "storage/storage_utils.h"
#include "storage/db/db.h"

namespace storage {

// namespace {

// void OnAppCreated(base::Closure quit, const std::string& app_name, int64_t result) {
//   if (result == 0) {
//     printf("app created ok.\n");
//     //Application* app = disk->GetApplication(app_name);
//     //DCHECK(app);
//     //app->Close();
//   } else {
//     printf("failed create app. code %ld\n", result);
//   }
  
//   std::move(quit).Run();
// }

// void OnAppOpen(base::Closure quit, const std::string& app_name, int64_t result) {
//   if (result == 0) {
//     printf("app opened ok.\n");
//     //Application* app = disk->GetApplication(app_name);
//     //DCHECK(app);
//     //app->Close();
//   } else {
//     printf("failed open app. code %ld\n", result);
//   }
//   std::move(quit).Run();
// }

// void OnAppAdd(base::Closure quit, const std::string& app_name, const base::FilePath& path, int64_t result) {
//   if (result == 0) {
//     printf("app opened ok.\n");
//     //Application* app = disk->GetApplication(app_name);
//     //DCHECK(app);
//     //bool ok = app->AddExecutableFromPathForHostArch(path);
//     //if (ok) {
//     //  printf("ok. added executable %s\n", path.value().c_str());
//     //} else {
//     //  printf("failed adding executable %s\n", path.value().c_str());
//     //}
//     //app->Close();
//   } else {
//     printf("failed open app. code %ld\n", result);
//   }
//   std::move(quit).Run();
// }

// }

const char kApp[] = "app";
const char kApp_HelpShort[] =
    "app: commands to manage an application in a disk.";
const char kApp_Help[] =
    R"(
        just a marker
)";

int RunApp(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  bool create = false;
  bool open = false;
  bool add = false;
  std::string app_name;
  base::FilePath exe_path;
  
  base::FilePath current_dir;
  if (!base::GetCurrentDirectory(&current_dir)) {
    printf("error app: failed to get the current directory\n");
    return 1;
  }

  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir);
  manager->Init(base::Callback<void(int)>());
  // Storage* disk = manager->GetStorage("twitter");
  // if (!disk) {
  //   printf("error app: failed to open disk on '%s'\n", current_dir.value().c_str());
  //   return 1;
  // }

  if (args.size() > 1) {
    if (args[0] == "create" ) {
      create = true;
      app_name = args[1];
    } else if (args[0] == "open" ) {
      open = true;
      app_name = args[1];
    } else if (args[0] == "add" ) {
      add = true;
      if (args.size() < 3) {
        printf("error app: add. we need <app> and <executable-to-add>\n");
        return 1;
      }
      app_name = args[1];
      exe_path = base::FilePath(args[2]);
    } else {
      printf("error app: command unknown '%s'\n", args[1].c_str());
      return 1;
    }
  } else {
    printf("error app: not enough arguments\n");
    return 1;
  }
  
  // if (create) {
  //   manager->CreateApplication(
  //     "twitter",
  //     app_name,
  //     base::Bind(&OnAppCreated, base::Passed(run_loop.QuitClosure()), app_name));
  // } else if (open) {
  //   manager->OpenApplication(
  //     "twitter",
  //     app_name,
  //     base::Bind(&OnAppOpen, base::Passed(run_loop.QuitClosure()), app_name));
  // } else if (add) {
  //   manager->OpenApplication(
  //     "twitter",
  //     app_name,
  //     base::Bind(&OnAppAdd, base::Passed(run_loop.QuitClosure()), app_name, exe_path));
  // }
  
  run_loop.Run();
  
  manager->Shutdown();
  
  return 0;
}

}