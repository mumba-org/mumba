// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_startup.h"

#include "base/logging.h"
#include "base/bind.h"
#include "base/strings/stringprintf.h"
#include "base/files/file_util.h"
#include "core/shared/common/switches.h"
#include "core/host/host.h"
#include "core/host/host_thread.h"
#include "core/host/host_controller.h"
//#include "core/host/command/command_session.h"
//#include "core/host/command/command_response.h"

namespace host {  

// static 
 void HostStartup::ProcessCommandLineAlreadyRunning(
    const base::CommandLine& command_line,
    const base::FilePath& current_directory,
    const base::FilePath& startup_domain_dir,
    std::string* result) {
      
  bool ignore = false;
  scoped_refptr<HostController> controller = HostController::Instance();

  HostStartup::Launch(
      controller,  
      current_directory, 
      command_line, 
      true, 
      &ignore,
      result);
}

// static 
void HostStartup::ProcessCommandLine(
  scoped_refptr<HostController> controller,
  const base::FilePath& current_directory,
  const base::CommandLine& command_line, 
  bool already_running, 
  bool* normal_startup,
  std::string* result) {
  
  DLOG(INFO) << "HostStartup::Launch: NOT WORKING";

  // const base::CommandLine::StringVector& args = command_line.GetArgs();
  // if (args.size() > 0) {
  //   CommandSession* session = controller->NewCommandSession();
    
  //   DLOG(INFO) << "HostStartup::Launch: session->ExecuteCommandLine ...";
  //   CommandResponse* response = session->ExecuteCommandLine(current_directory, command_line);
  
  //   if (!response) {
  //     DLOG(INFO) << "HostStartup::Launch: no response";
  //     result->assign("no response");
  //   } else {
  //     DLOG(INFO) << "HostStartup::Launch: response ok";
  //     response->WriteFormattedOutput(result);
  //   }

  //   controller->DestroySession(session->id());  
  // }
  
  DLOG(INFO) << "HostStartup::Launch END";
}

void HostStartup::Launch(
  scoped_refptr<HostController> controller,
  const base::FilePath& current_directory,
  const base::CommandLine& command_line, 
  bool already_running, 
  bool* normal_startup,
  std::string* result) { 

  //std::string channel_id = IPC::Channel::GenerateUniqueRandomChannelID();
  //controller->LaunchReplProcess(channel_id);
  //result->assign(channel_id);
}

HostStartup::HostStartup() {
  
}

HostStartup::~HostStartup() {
  
}

}