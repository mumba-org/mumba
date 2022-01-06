// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/ext4/ext4_filesystem_image_creator.h"

#include "third_party/lwext4/include/ext4.h"
#include "third_party/lwext4/include/ext4_fs.h"
#include "third_party/lwext4/include/ext4_mkfs.h"
#if defined(OS_LINUX)
#include "third_party/lwext4/blockdev/linux/file_dev.h"
#elif defined(OS_WIN)
#include "third_party/lwext4/blockdev/windows/file_windows.h"
#endif

namespace domain {

const size_t kDefaultByteSize = 512;
const size_t kDefaultImageSize = kDefaultByteSize * 2480;
const char empty[kDefaultByteSize] = {0};

Ext4FilesystemImageCreator::Ext4FilesystemImageCreator() {

}

Ext4FilesystemImageCreator::~Ext4FilesystemImageCreator() {

}

bool Ext4FilesystemImageCreator::Create(const base::FilePath& path, const Options& options) {
  struct ext4_blockdev *bd;
  struct ext4_fs fs;
  struct ext4_mkfs_info info = {
    .block_size = 1024,
    .journal = true,
  };

  size_t disk_image_sz = options.size;

  if (options.size == 0) {
    disk_image_sz = kDefaultImageSize;   
  }

#if defined(OS_POSIX)
  size_t bw = 0;
  bool error = false;
 
  int fd = open(path.value().c_str(), O_RDWR | O_CREAT | O_LARGEFILE, 0660);

  if (fd == -1) {
    return false;
  }
  
  while (bw < disk_image_sz) {
    int b = write(fd, empty, kDefaultByteSize);
    if (b == -1) {
      error = true;
      break;
    }
    bw += b;
  }
  close(fd);
#endif

#if defined(OS_LINUX)  
  file_dev_name_set(path.value().c_str());
  bd = file_dev_get();
  if (!bd) {
    LOG(ERROR) << "open_filedev on " << path.value() << ": failed";
    return false;
  }
#endif

  int rc = ext4_mkfs(&fs, bd, &info, F_SET_EXT4);
  if (rc != EOK) {
    LOG(ERROR) << "ext4_mkfs error: " << rc;
    return false;
  }

  memset(&info, 0, sizeof(struct ext4_mkfs_info));
  rc = ext4_mkfs_read_info(bd, &info);
  if (rc != EOK) {
    LOG(ERROR) << "ext4_mkfs_read_info error: " << rc;
    return false;
  }

  return true;
}

}