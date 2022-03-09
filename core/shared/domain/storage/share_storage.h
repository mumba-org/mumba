// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_STORAGE_SHARE_STORAGE_H_
#define MUMBA_DOMAIN_STORAGE_SHARE_STORAGE_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/storage.mojom.h"

namespace domain {
class StorageContext;

class CONTENT_EXPORT ShareStorage {
public:
  ShareStorage(scoped_refptr<StorageContext> context);
  ~ShareStorage();

  void CreateShareWithPath(common::mojom::StorageType type, const std::string& name, std::vector<std::string> keyspaces, const std::string& source_path, bool in_memory, base::Callback<void(int)> cb);
  void CreateShareWithInfohash(common::mojom::StorageType type, const std::string& name, std::vector<std::string> keyspaces, const std::string& infohash, base::Callback<void(int)> cb);
  void AddShare(const base::UUID& id, const std::string& url, base::Callback<void(int)> cb);
  void OpenShare(common::mojom::StorageType type, const std::string& name, bool create_if_not_exists, base::Callback<void(int)> cb);
  void ShareExists(const std::string& name, base::Callback<void(int)> cb);
  void ReadShare(const base::UUID& id, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void WriteShare(const base::UUID& id, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void CloseShare(const std::string& name, base::Callback<void(int)> cb);
  void DeleteShare(const base::UUID& id, base::Callback<void(int)> cb);
  void ShareShare(const base::UUID& id, base::Callback<void(int)> cb);
  void UnshareShare(const base::UUID& id, base::Callback<void(int)> cb);
  void SubscribeShare(const base::UUID& id, base::Callback<void(int)> cb);
  void UnsubscribeShare(const base::UUID& id, base::Callback<void(int)> cb);

private:  
  scoped_refptr<StorageContext> context_;

  DISALLOW_COPY_AND_ASSIGN(ShareStorage);
};

}

#endif