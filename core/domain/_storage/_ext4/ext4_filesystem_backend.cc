// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/ext4/ext4_filesystem_backend.h"

#include "data/buffer.h"
#include "core/shared/domain/storage/ext4/ext4_filesystem_image.h"
#include "core/shared/domain/storage/namespace.h"

namespace domain {

//static 
// NamespaceFilesystemBackend* NamespaceFilesystemBackend::Create(const std::string& namespace_id, const base::FilePath& namespace_path) {
//   return new Ext4FilesystemBackend(namespace_id, namespace_path);
// }

Ext4FilesystemBackend::Ext4FilesystemBackend(const std::string& namespace_id, const base::FilePath& namespace_path): 
  namespace_path_(namespace_path),
  mount_point_("/"),
  namespace_id_(namespace_id) {
  
}

Ext4FilesystemBackend::~Ext4FilesystemBackend() {

}

bool Ext4FilesystemBackend::Initialize() {
  const size_t kBlockSize = 1024;
  size_t readed_size;
  char read_buffer[kBlockSize];
  
  base::FilePath image_path = namespace_path_.AppendASCII(namespace_id_ + "." + constants::kNamespaceFilesystemFileExtension);
  std::unique_ptr<Ext4FilesystemImage> image = Ext4FilesystemImage::Open(image_path.BaseName().value(), image_path);
 
  if (!image) {
    printf(image not found " << image_path.value();
    return false;
  }
  
  //DLOG(INFO) << "mouting image '" << image->name() << "' at '" << mount_point_ << "'";
  int rc = ext4_mount(image->name().c_str(), mount_point_.value().c_str(), false);
  if (rc != EOK) {
    printf(ext4_mount: rc = " << rc;
    return false;
  }

  rc = ext4_recover(mount_point_.value().c_str());
  if (rc != EOK && rc != ENOTSUP) {
    printf(ext4_recover: rc = " << rc;
    return false;
  }

  rc = ext4_journal_start(mount_point_.value().c_str());
  if (rc != EOK) {
    printf(ext4_journal_start: rc = " << rc;
    return false;
  }

  ext4_file fd;
  
  if (ext4_inode_exist("/test.txt", EXT4_DE_REG_FILE) != 0) {
    //DLOG(INFO) << "/test.txt do not exist. creating";
    size_t wb;
    char write_buffer[] = "hello world\0";
    rc = ext4_fopen(&fd, "/test.txt", "wb+");

    if (rc != EOK) {
      printf(ext4_fopen: rc = " << rc;
      return false;
    }

    rc = ext4_fwrite(&fd, write_buffer, strlen(write_buffer), &wb);

    if (rc != EOK) {
      printf(ext4_fwrite: rc = " << rc;
      ext4_fclose(&fd);
      return false;
    }

    ext4_fclose(&fd);
  } else {
    //DLOG(INFO) << "/test.txt exist. reading it";
    
    BufferBuilder builder;
    
    if (!builder.Reserve(kBlockSize * 4).ok()){
      return false;
    }
    
    rc = ext4_fopen(&fd, "/test.txt", "rb+");

    if (rc != EOK) {
      printf(ext4_fopen: rc = " << rc;
      return false;
    }

    rc = ext4_fread(&fd, &read_buffer[0], 1024, &readed_size);

    if (rc != EOK) {
      printf(ext4_fread: rc = " << rc;
      ext4_fclose(&fd);
      return false;
    }

    ext4_fclose(&fd);

    if (!builder.Append(read_buffer, readed_size).ok()) {
      return false;
    }

    std::shared_ptr<Buffer> buffer;
    if (!builder.Finish(&buffer).ok()) {
      return false;
    }

    base::StringPiece string(reinterpret_cast<const char *>(buffer->data()), buffer->size());

    //DLOG(INFO) << "test.txt contents: '" << string << "'";
  }

  return true;
}

void Ext4FilesystemBackend::Shutdown() {
  int rc = ext4_journal_stop(mount_point_.value().c_str());
  if (rc != EOK) {
    printf(rc = " << rc;
    return;
  }

  rc = ext4_umount(mount_point_.value().c_str());
  if (rc != EOK) {
    printf(rc = " << rc;
    return;
  }
}

}