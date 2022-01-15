// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_BUNDLE_CREATOR_H_
#define MUMBA_HOST_BUNDLE_CREATOR_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner_util.h"

namespace host {

class BundleCreator {
public:
  BundleCreator();
  ~BundleCreator();

  bool InitBundle(const std::string& name, const base::FilePath& path);
  bool PackBundle(const std::string& name, const base::FilePath& src, bool no_frontend);

private:

  bool CreateBaseDirectories(const std::string& identifier, const base::FilePath& base_dir, bool no_frontend, bool no_build);
  bool PackDirectory(const std::string& identifier, const base::FilePath& src_path, const base::FilePath& output_dir, bool no_frontend);
  bool PackCopyFiles(const std::string& identifier, const base::FilePath& app_base_path, const base::FilePath& input_dir, const base::FilePath& base_dir, bool no_frontend);
  bool CreateDefaultManifest(const std::string& name, const base::FilePath& path);

  bool CreateDotGNFile(const std::string& name, const base::FilePath& path);

  bool CreateSwiftMainBuildFile(const std::string& name_lower, const base::FilePath& path);
  bool CreateSwiftServiceBuildFile(const std::string& name, const base::FilePath& path);
  bool CreateSwiftApplicationBuildFile(const std::string& name, const base::FilePath& path);
  bool CreateSwiftProtoBuildFile(const std::string& name, const base::FilePath& path);

  bool CreateSwiftProtoSourceFiles(const std::string& name, const base::FilePath& path);
  bool CreateSwiftApplicationSourceFiles(const std::string& name, const base::FilePath& path);
  bool CreateSwiftServiceSourceFiles(const std::string& name, const base::FilePath& path);

  std::string Replace(const std::string& input, const std::string& source, const std::string& target) const;

  DISALLOW_COPY_AND_ASSIGN(BundleCreator);
};

}

#endif