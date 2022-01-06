// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_HOST_STARTUP_H_
#define MUMBA_HOST_HOST_STARTUP_H_

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/command_line.h"
#include "url/gurl.h"

namespace host {
class HostController;
class CommandSession;
class HostStartup {
public:
 static void ProcessCommandLineAlreadyRunning(const base::CommandLine& command_line,
    const base::FilePath& current_directory,
    const base::FilePath& startup_domain_dir,
    std::string* result);

 static void ProcessCommandLine(scoped_refptr<HostController> controller,
  const base::FilePath& current_directory, 
  const base::CommandLine& command_line, 
  bool already_running, 
  bool* normal_startup,
  std::string* result);

 static void Launch(scoped_refptr<HostController> controller,
  const base::FilePath& current_directory, 
  const base::CommandLine& command_line, 
  bool already_running, 
  bool* normal_startup,
  std::string* result);

 HostStartup();
 ~HostStartup();

private:

 DISALLOW_COPY_AND_ASSIGN(HostStartup);
};

}

#endif
