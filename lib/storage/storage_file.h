// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_LIB_STORAGE_STORAGE_PACK_H_
#define MUMBA_LIB_STORAGE_STORAGE_PACK_H_

#include <memory>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/files/file.h"
#include "storage/proto/storage.pb.h"
#include "storage/storage_export.h"

namespace storage {

class STORAGE_EXPORT StorageFile {
public:
  enum Status {
    kOK = 0,
    // these basically means a corrupt file
    kERR_READ_HEADER = 1,
    kERR_READ_MANIFEST = 2,
    kERR_READ_CONTENT = 3,
    
    kERR_WRITE_HEADER = 4,
    kERR_WRITE_MANIFEST = 5,
    kERR_WRITE_CONTENT = 5,
  };
  
  static std::unique_ptr<StorageFile> CreateFromDir(const base::FilePath& content_dir, const base::FilePath& out_file);
  static std::unique_ptr<StorageFile> CreateFromZip(const base::FilePath& manifest_file, const base::FilePath& zip_file, const base::FilePath& out_file);
  static std::unique_ptr<StorageFile> Open(const base::FilePath& path);
  static bool Delete(const base::FilePath& path);

  ~StorageFile();

  const base::FilePath& file_path() const {
    return path_;
  }

  const base::FilePath& dir_path() const {
    return unpacked_dir_;
  }

  std::unique_ptr<storage_proto::StorageState> TransferStorageState() {
    return std::move(state_);
  }

  void Close();

private:
  
  StorageFile(const base::FilePath& path, std::unique_ptr<base::File> file);

  Status ReadOnce();
  Status WriteOnce(const std::string& manifest_contents, base::File* zip_file);

  Status ReadHeader();
  Status ReadStorageStateBlock();
  Status ExtractContentBlock();

  Status WriteHeader();
  Status WriteStorageStateBlock(const std::string& disk_state_data);
  Status WriteContentBlock(base::File* zip_file);

  //int version;
  //size_t manifest_block_size_;
  //size_t content_block_size_;
  base::FilePath path_; 

  base::FilePath unpacked_dir_; 
  
  std::unique_ptr<storage_proto::StorageState> state_;

  std::unique_ptr<base::File> file_;

  bool is_open_;

  DISALLOW_COPY_AND_ASSIGN(StorageFile);
};

}

#endif
