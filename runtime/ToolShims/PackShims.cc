// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "PackShims.h"

#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/process/launch.h"
#include "base/threading/thread.h"
#include "base/files/file_util.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/strings/string_number_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/hash.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "db/db.h"
#include "db/sqliteInt.h"
#include "data/io/memory.h"
#include "data/ipc/reader.h"
#include "data/pretty_print.h"
#include "data/record_batch.h"
#include "data/status.h"
#include "data/table.h"
#include "data/type.h"
#include "data/type_traits.h"
#include "bundle/bundle.h"
#include "bundle/executable.h"
#include "bundle/repository.h"

void PrintHelp() {
  printf("usage: --type=[app, bundle] file(bundle or app)\nif --type=bundle [create/pack] [bundle name]\nif --type=app [out file] [input binary]\n");
}

int PackApp(const base::FilePath& file_path, const std::vector<std::string>& args, bool has_extra_argument) {
  bundle::Init();

  std::unique_ptr<bundle::Executable> file;

  if (base::PathExists(file_path)) {
    file = bundle::Executable::Open(file_path, false, false);    
  } else {
    file = bundle::Executable::Create(bundle::ExecutableType::kLIBRARY, file_path);
  }

  DCHECK(file);

  if (args.size() >= (has_extra_argument ? 3 : 2)) {
    //std::string command = args[1];
    //if (command == "put") {
      //if (!args.size() || args.size() < 3) {
       // printf("usage: [blob] put [exec file]\n");
       // return 1;
      //}
      std::string input_exe_str = has_extra_argument ? args[2] : args[1];
      base::FilePath input_exe(input_exe_str);// = //dir_path.AppendASCII(input_exe_str);
      if (!base::PathExists(input_exe)) {
        printf("pack app error: binary '%s' not found\n", input_exe_str.c_str());
        return 1;
      }

      //if (!CheckValidExtension(input_exe)) {
      //  printf("pack app error: extension '%s' not valid\n", ext);
      //  return 1; 
      //}

      file->SetExecutableForArch(bundle::Architecture::kLINUX_ELF_X86_64, input_exe);
    //} //else if (command == "get") {
      //file->ExtractBinaryPayload();
    //}
    file.reset();
  } else {
    std::vector<char*> argv_cstr;
    //char zfile[] = "/home/fabiok/rootfs/twitter.zip";
    //char input_file[] = "/home/fabiok/rootfs/twitter.bin";
    argv_cstr.reserve(2);
    bool support = file->SupportsArch(bundle::Architecture::kLINUX_ELF_X86_64);
    printf("checking '%s'..\nsupport for our architecture? %d\n", file_path.value().c_str(), support);
    printf("support for WASM architecture? %d\n", file->SupportsArch(bundle::Architecture::kANY_WASM_WASM));
    //printf("calling method 'hello' on %s...\n", file_str.c_str());
    //auto get_callback = file->Bind<void()>("hello");
    //if (get_callback) {
    //  std::move(get_callback).Call();
    //}
    // //char** argv = nullptr;
    // argv_cstr.push_back(const_cast<char*>(file->executable_path().value().c_str()));
    // argv_cstr.push_back(zfile);
    // argv_cstr.push_back(input_file);
    // argv_cstr.push_back(nullptr);
    // execvp(argv_cstr[0], argv_cstr.data());
    file.reset();
  }
  
  

  bundle::Shutdown();

  return 0;
}

int RepositoryTest() {
  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();
  
  base::FilePath dir_path("/home/fabiok/rootfs");
  
  bundle::Init();
  
  auto args = cmd->GetArgs();

  if (!args.size() || args.size() < 2) {
    printf("usage: [repo name] create/open\n");
    return 1;
  }

  std::string repo_name = args[0];  
  std::string command = args[1];  
  
  base::FilePath repo_path = dir_path.AppendASCII(repo_name);
  base::FilePath out_path = dir_path.AppendASCII("checkout_of_" + repo_name);
  //const char hello[] = "hello world";
  
  if (command == "create") {
    std::unique_ptr<bundle::Repository> repo = bundle::Repository::Create(
        bundle::RepositoryProfile::kCONTAINER, 
        repo_path);
    if (!repo) {
      printf("repo creation failed\n");
      bundle::Shutdown();
      return 1;
    }
    //if (!repo->Add(hello, arraysize(hello))) {
    //  printf("failed to add buffer\n");
    //}
    if (!repo->CheckoutHead(out_path)) {
      printf("failed to checkout to %s\n", out_path.value().c_str()); 
    }
    repo.reset();
  } else if (command == "open") {
    std::unique_ptr<bundle::Repository> repo = bundle::Repository::Open(repo_path);
    //if (!repo->Add(hello, arraysize(hello))) {
    //  printf("failed to add buffer\n");
    // }
    if (!repo) {
      printf("repo creation failed\n");
      bundle::Shutdown();
      return 1;
    }
    repo.reset();
  } else if (command == "destroy") {
    bundle::Repository::Destroy(repo_path);
  }

  bundle::Shutdown();

  return 0;
}

int PackBundle(const base::FilePath& dir, const std::vector<std::string>& args) { 
  bundle::Init();
  
  printf("processing bundle at: %s\n", dir.value().c_str());

  // > pack --type=bundle [dir] [bundle_name]
  
  if (args.size() < 2) {
    PrintHelp();
    return 1;
  }

  std::string command = args[0];
  std::string bundle_name = args[1];

  printf("command: %s\nbundle name: %s\n", command.c_str(), bundle_name.c_str());

  base::FilePath bundle_path = dir.AppendASCII(bundle_name);
  base::FilePath out_path = dir.AppendASCII("checkout_of_" + bundle_name);

  if (command == "create") {
    std::unique_ptr<bundle::Repository> repo = bundle::Repository::Create(
        bundle::RepositoryProfile::kCONTAINER, 
        bundle_path);
    if (!repo) {
      printf("repo creation failed\n");
      bundle::Shutdown();
      return 1;
    }
    //if (!repo->Add(hello, arraysize(hello))) {
    //  printf("failed to add buffer\n");
    //}
    if (!repo->CheckoutHead(out_path)) {
      printf("failed to checkout to %s\n", out_path.value().c_str()); 
    }

    repo.reset();
  } else if(command == "pack") {
    auto pack = bundle::Bundle::Open(bundle_path, out_path);
    if (!pack) {
      LOG(ERROR) << "error opening bundle " << bundle_path;
    }
    pack->PackTo(base::FilePath(bundle_path.value() + ".pantera"));
  } else {
    printf("invalid command '%s'\n", command.c_str());
    PrintHelp();
  }

  bundle::Shutdown();

  return 0;
}

int _mumba_pack_main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::FilePath path;

  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();

  if (!cmd->HasSwitch("type")) {
    DLOG(ERROR) << "type switch not defined";
    
    PrintHelp();
    return 1;
  }

  std::string type = cmd->GetSwitchValueASCII("type");

  auto args = cmd->GetArgs();
  
  if (!args.size() || args.size() < 1) {
    PrintHelp();
    return 1;
  }

  bool has_extra_argument = (args[0] == "pack");

  if (type == "bundle") {
    base::GetCurrentDirectory(&path);
    return PackBundle(path, args);
  } else if (type == "app") {
    path = base::FilePath(has_extra_argument? args[1] : args[0]);
    return PackApp(path, args, has_extra_argument);
  }

  PrintHelp();
  return 1;
}