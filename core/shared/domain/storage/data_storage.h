// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_STORAGE_DATA_STORAGE_H_
#define MUMBA_DOMAIN_STORAGE_DATA_STORAGE_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/storage.mojom.h"

namespace domain {
class StorageContext;

class CONTENT_EXPORT DataStorage {
public:
  DataStorage(scoped_refptr<StorageContext> context);
  ~DataStorage();

  //void Open(const base::UUID& id, base::Callback<void(int)> cb);
  void Close(const std::string& db_name, base::Callback<void(int)> cb);
  //void Create(const base::UUID& id, base::Callback<void(int)> cb);
  void Drop(const std::string& db_name, base::Callback<void(int)> cb);
  void CreateKeyspace(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb);
  void DeleteKeyspace(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb);
  void ListKeyspaces(const std::string& db_name, base::Callback<void(int, int, const std::vector<std::string>&)> cb);
  void Put(const std::string& db_name, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void Get(const std::string& db_name, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void GetOnce(const std::string& db_name, const std::string& keyspace, const std::string& key, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb);
  void Delete(const std::string& db_name, const std::string& keyspace, const std::string& key, base::Callback<void(int)> cb);
  void DeleteAll(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb);

private:
  
  scoped_refptr<StorageContext> context_;

  DISALLOW_COPY_AND_ASSIGN(DataStorage);
};

}

#endif