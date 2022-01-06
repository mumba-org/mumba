// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_STORAGE_MANAGER_H_
#define MUMBA_HOST_APPLICATION_STORAGE_MANAGER_H_

#include <unordered_map>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/atomic_sequence_num.h"

namespace host {
class StorageContext;
class Workspace;
class Domain;

class StorageManager {
public:
  StorageManager(scoped_refptr<Workspace> workspace);
  ~StorageManager();

 scoped_refptr<StorageContext> CreateContext(Domain* shell);
 scoped_refptr<StorageContext> GetContext(int context_id);
 void DestroyContext(int context_id);  

private:
  scoped_refptr<Workspace> workspace_;
  base::AtomicSequenceNumber context_seq_;
  std::unordered_map<int, scoped_refptr<StorageContext>> contexts_;

  DISALLOW_COPY_AND_ASSIGN(StorageManager);
};

}

#endif