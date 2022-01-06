// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_STORAGE_FILE_STORAGE_H_
#define MUMBA_DOMAIN_STORAGE_FILE_STORAGE_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/storage.mojom.h"

namespace domain {
class StorageContext;

class CONTENT_EXPORT FileStorage {
public:
  FileStorage(scoped_refptr<StorageContext> context);
  ~FileStorage();

  void CreateFile(const std::string& torrent_name, const std::string& file, base::Callback<void(int)> cb);
  void AddFile(const std::string& torrent_name, const std::string& file, const std::string& path, base::Callback<void(int)> cb);
  void OpenFile(const std::string& torrent_name, const std::string& file, base::Callback<void(int)> cb);
  void DeleteFile(const std::string& torrent_name, const std::string& file, base::Callback<void(int)> cb);
  void RenameFile(const std::string& torrent_name, const std::string& input, const std::string& output, base::Callback<void(int)> cb);
  void ReadFile(const std::string& torrent_name, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void ReadFileOnce(const std::string& torrent_name, const std::string& file, int64_t offset, int64_t size, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb);
  void WriteFile(const std::string& torrent_name, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void WriteFileOnce(const std::string& torrent_name, const std::string& file, int64_t offset, int64_t size, std::vector<uint8_t> data, base::Callback<void(int, int)> cb);
  void CloseFile(const std::string& torrent_name, const std::string& file, base::Callback<void(int)> cb);
  void ListFiles(const std::string& torrent_name, base::Callback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> callback);
  
private:  
  scoped_refptr<StorageContext> context_;

  DISALLOW_COPY_AND_ASSIGN(FileStorage);
};

}

#endif