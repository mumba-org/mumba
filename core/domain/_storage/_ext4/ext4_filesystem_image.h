// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_EXT4_EXT4_FILESYSTEM_IMAGE_H_
#define MUMBA_DOMAIN_NAMESPACE_EXT4_EXT4_FILESYSTEM_IMAGE_H_

#include "base/macros.h"
#include "base/files/file_path.h"
#include "third_party/lwext4/include/ext4.h"

namespace domain {
class Ext4FilesystemBackend;

class Ext4FilesystemImage {
public:
  static bool Create(const base::FilePath& path);
  static std::unique_ptr<Ext4FilesystemImage> Open(const std::string& name, const base::FilePath& path);

  ~Ext4FilesystemImage();

  const std::string& name() const { return name_; }

private:
  Ext4FilesystemImage(const std::string& name, ext4_blockdev* block_dev);
 
  friend class Ext4FilesystemBackend;

  ext4_blockdev* block_dev_;
  std::string name_;

  DISALLOW_COPY_AND_ASSIGN(Ext4FilesystemImage);
};

}

#endif