// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_EXT4_EXT4_FILESYSTEM_BACKEND_H_
#define MUMBA_DOMAIN_NAMESPACE_EXT4_EXT4_FILESYSTEM_BACKEND_H_

#include "base/macros.h"
#include "base/files/file_path.h"
#include "core/shared/domain/storage/namespace_filesystem_backend.h"

namespace domain {

class Ext4FilesystemBackend : public NamespaceFilesystemBackend {
public:
  Ext4FilesystemBackend(const std::string& namespace_id, const base::FilePath& namespace_path);
  ~Ext4FilesystemBackend() override;

  bool Initialize() override;
  void Shutdown() override;

private:

  base::FilePath namespace_path_;
  base::FilePath mount_point_;
  std::string namespace_id_;

  DISALLOW_COPY_AND_ASSIGN(Ext4FilesystemBackend);
};

}


#endif