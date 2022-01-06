// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_STORAGE_INDEX_H_
#define MUMBA_DOMAIN_STORAGE_INDEX_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/storage.mojom.h"

namespace domain {
class StorageContext;

class CONTENT_EXPORT StorageIndex {
public:
  StorageIndex(scoped_refptr<StorageContext> context);
  ~StorageIndex();

 // bool ResolveId(const std::string& address, base::UUID* id);
  void ResolveIdAsync(const std::string& address, base::Callback<void(base::UUID, int)> callback);

private:  
  scoped_refptr<StorageContext> context_;

  DISALLOW_COPY_AND_ASSIGN(StorageIndex);
};

}

#endif