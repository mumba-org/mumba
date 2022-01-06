// Copyright (c) 2014 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/paths.h"

#include "base/base_paths.h"
#include "base/environment.h"
#include "base/files/file_util.h"
#include <memory>
//#include "base/nix/xdg_util.h"
#include "base/path_service.h"

//using base::nix::GetXDGDirectory;
//using base::nix::kXdgConfigHomeEnvVar;
//using base::nix::kDotConfigDir;

namespace common {
namespace {
 // TODO: hack til we figure how to get his from windows
 const base::FilePath::StringType kROOT_PATH = L"C:\\Users\\walkiria\\AppData\\Local";
}
 bool GetDefaultRootDirectory(base::FilePath* result) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  base::FilePath config_dir(kROOT_PATH);
  *result = config_dir.AppendASCII("Mumba");
  return true;
 }

}