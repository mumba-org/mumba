// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_NAMESPACE_STORAGE_H_
#define MUMBA_DOMAIN_NAMESPACE_NAMESPACE_STORAGE_H_

#include <memory>
#include <vector>
#include <map>

#include "base/macros.h"
#include "base/callback.h"
#include "base/task_runner.h"
#include "base/memory/weak_ptr.h"
#include "base/files/file_path.h"
#include "base/atomic_sequence_num.h"
#include "base/synchronization/waitable_event.h"
#include "base/uuid.h"
//#include "core/shared/domain/storage/graph/graph_db.h"
#include "core/shared/domain/storage/filesystem.h"
#include "core/shared/domain/storage/database.h"

namespace domain {

class NamespaceStorage {
public:
  using Databases = std::vector<Database *>;
  using DatabasesIterator = Databases::iterator;
  using DatabasesConstIterator = Databases::const_iterator;

  class Delegate {
  public:
    virtual ~Delegate(){}
    virtual void OnNamespaceStorageInit(bool, base::Closure) = 0;
  };

  NamespaceStorage(Delegate* delegate, bool in_memory);
  ~NamespaceStorage();

  bool in_memory() const {
    return in_memory_;
  }

  //GraphDb* graph_db() const {
  //   return graph_db_.get();
  //}

  //const Filesystems& filesystems() const {
  //  return filesystems_;
 // }

  //FilesystemsIterator filesystems_begin() {
  //  return filesystems_.begin();
 // }

  //FilesystemsIterator filesystems_end() {
  //  return filesystems_.end();
 // }

  //FilesystemsConstIterator filesystems_begin() const {
  //  return filesystems_.begin();
 // }

  //FilesystemsConstIterator filesystems_end() const {
  //  return filesystems_.end();
  //}

  const Databases& databases() const {
    return databases_;
  }

  DatabasesIterator databases_begin() {
    return databases_.begin();
  }

  DatabasesIterator databases_end() {
    return databases_.end();
  }

  DatabasesConstIterator databases_begin() const {
    return databases_.begin();
  }

  DatabasesConstIterator databases_end() const {
    return databases_.end();
  }

  void Initialize(const base::UUID& id, 
    const base::FilePath& path,
    base::Closure on_init,
    scoped_refptr<base::TaskRunner> reply_to);

  void Shutdown();

  Filesystem* GetFilesystem() const;
  Database* GetDatabaseById(int id) const;

private:

  void OnFilesystemInitReply(int fs_id, int result);
  void OnDatabaseInitReply(int db_id, int result);
  //void OnGraphDbInitReply(int result);

  void MaybeNotifyDelegate();

  // enum {
  //   kGRAPH_EVENT = 0,
  //   kFILESYSTEM_EVENT = 1,
  //   kDATABASE_EVENT = 2,
  //   kMAX_EVENT = 3
  // };

  //std::unique_ptr<GraphDb> graph_db_;
  
  std::unique_ptr<Filesystem> filesystem_;

  Databases databases_;

  scoped_refptr<base::TaskRunner> reply_to_;

  // fs id to array offset index
  //std::map<int, int> fsid_map_;

  // db id to array offset index
  std::map<int, int> dbid_map_;

  bool in_memory_;

  //base::AtomicSequenceNumber fsid_sequence_;

  base::AtomicSequenceNumber dbid_sequence_;

  Delegate* delegate_;

  base::Closure on_init_;

  bool initialization_error_;

  //std::vector<base::WaitableEvent*> init_events_;
  //base::WaitableEvent init_events_[kMAX_EVENT];
  mutable int ev_count_;
  
  base::WeakPtrFactory<NamespaceStorage> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(NamespaceStorage);
};

}

#endif