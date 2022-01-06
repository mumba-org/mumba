// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/ext4/ext4_filesystem_image.h"
#include "core/shared/domain/storage/ext4/ext4_filesystem_image_creator.h"

#if defined(OS_LINUX)
#include "third_party/lwext4/blockdev/linux/file_dev.h"
#endif

namespace domain {

bool Ext4FilesystemImage::Create(const base::FilePath& path) {
  Ext4FilesystemImageCreator creator;
  Ext4FilesystemImageCreator::Options options;
  return creator.Create(path, options);
}

std::unique_ptr<Ext4FilesystemImage> Ext4FilesystemImage::Open(const std::string& name, const base::FilePath& path) {
  ext4_blockdev* block_dev = nullptr;
#if defined(OS_LINUX)
  file_dev_name_set(path.value().c_str());
  block_dev = file_dev_get();
#endif
  if (!block_dev) {
    printf(ext4_device_get failed";
    return {};
  }
  //ext4_device_unregister_all();

  if (ext4_device_register(block_dev, name.c_str()) != 0) {
    printf(ext4_device_register failed";
    return {};
  }

  return std::unique_ptr<Ext4FilesystemImage>(new Ext4FilesystemImage(name, block_dev));
}

Ext4FilesystemImage::Ext4FilesystemImage(const std::string& name, ext4_blockdev* block_dev): 
  block_dev_(block_dev),
  name_(name) {
  
}

Ext4FilesystemImage::~Ext4FilesystemImage() {

}

}
