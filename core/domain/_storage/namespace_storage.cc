// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/namespace_storage.h"

#include "base/bind.h"
#include "base/threading/thread_restrictions.h"
#include "core/shared/domain/storage/filesystem.h"
//#include "core/shared/domain/storage/namespace_database.h"
#include "net/base/net_errors.h"

namespace domain {

namespace {


base::FilePath GetFilesystemPath(
  const base::FilePath& namespaces_path, 
  const base::UUID& namespace_id) {
  return namespaces_path.AppendASCII(namespace_id.to_string()).AppendASCII("fs");
}

base::FilePath GetDatabasePath(
  const base::FilePath& namespaces_path, 
  const base::UUID& namespace_id) {
  return namespaces_path.AppendASCII(namespace_id.to_string()).AppendASCII("db");
}

//base::FilePath GetGraphPath(
//  const base::FilePath& namespaces_path, 
//  const base::UUID& namespace_id) {
//  return namespaces_path.AppendASCII(namespace_id.to_string()).AppendASCII("graph");
//}

}  

NamespaceStorage::NamespaceStorage(Delegate* delegate, bool in_memory):
  in_memory_(in_memory),
  delegate_(delegate),//std::move(delegate)),
  //init_events_{
  //   {base::WaitableEvent::ResetPolicy::AUTOMATIC, base::WaitableEvent::InitialState::NOT_SIGNALED},
  //   {base::WaitableEvent::ResetPolicy::AUTOMATIC, base::WaitableEvent::InitialState::NOT_SIGNALED},
  //   {base::WaitableEvent::ResetPolicy::AUTOMATIC, base::WaitableEvent::InitialState::NOT_SIGNALED}
  //},
  initialization_error_(false),
  ev_count_(3),
  weak_factory_(this) {

}

NamespaceStorage::~NamespaceStorage() {
  //for (auto it = filesystems_.begin(); it != filesystems_.end(); it++) {
  //  delete *it;
  //}

  for (auto it = databases_.begin(); it != databases_.end(); it++) {
    delete *it;
  }

  // for (auto it = init_events_.begin(); it != init_events_.end(); it++) {
  //   delete *it;
  // }

  filesystem_.reset();
  databases_.clear();
}

void NamespaceStorage::Initialize(
  const base::UUID& namespace_id, 
  const base::FilePath& namespaces_path,
  base::Closure on_init,
  scoped_refptr<base::TaskRunner> reply_to) {
  //base::ScopedAllowBaseSyncPrimitives allow;
  //base::ScopedAllowBaseSyncPrimitivesForTesting allow_sync;

  on_init_ = std::move(on_init);
  reply_to_ = reply_to;
  // for (size_t i = 0; i < 3; i++) {
  //   init_events_.push_back(
  //     new base::WaitableEvent(
  //       base::WaitableEvent::ResetPolicy::AUTOMATIC, 
  //       base::WaitableEvent::InitialState::NOT_SIGNALED)
  //     );
  // }

  base::FilePath fs_path = GetFilesystemPath(namespaces_path, namespace_id);
  base::FilePath db_path = GetDatabasePath(namespaces_path, namespace_id);
  //base::FilePath graph_path = GetGraphPath(namespaces_path, namespace_id);

  //graph_db_ = GraphDb::Open(dbid_sequence_.GetNext(), graph_path, in_memory_);

  int db_id = dbid_sequence_.GetNext();
  Database* db = new Database(db_id, db_path, in_memory_);
  databases_.push_back(db);
  dbid_map_.emplace(std::make_pair(db_id, 0));

  // cache filesystem
  //int cache_id = fsid_sequence_.GetNext();
  filesystem_.reset(new Filesystem(0, namespace_id, fs_path, in_memory_));
  //fsid_map_.emplace(std::make_pair(cache_id, 0));

  // executable fs (modules and apps)
  //int exec_id = fsid_sequence_.GetNext();
  //filesystems_.push_back(new Filesystem(FilesystemType::kExecutable, exec_id, namespace_id, fs_path, in_memory_));
  //fsid_map_.emplace(std::make_pair(exec_id, 1));

  //graph_db_->Initialize(
  //   base::Bind(&NamespaceStorage::OnGraphDbInitReply, 
  //     base::Unretained(this)));

  //LOG(INFO) << "Waiting graph...";

  //init_events_[kGRAPH_EVENT].Wait();
  
  //for (auto* fs : filesystems_) {
  filesystem_->Initialize(
      base::Bind(
        &NamespaceStorage::OnFilesystemInitReply, 
        base::Unretained(this)));
 // }

  //LOG(INFO) << "Waiting filesystem...";

  //init_events_[kFILESYSTEM_EVENT].Wait();

  //for (auto* db : databases_) {
  db->Initialize(
    base::Bind(
      &NamespaceStorage::OnDatabaseInitReply, 
      base::Unretained(this)));
  //}

  //LOG(INFO) << "Waiting db...";

  //init_events_[kDATABASE_EVENT].Wait();
  //for (auto it = init_events_.begin(); it != init_events_.end(); ++it) {
  //  (*it)->Wait();
  //  LOG(INFO) << "NamespaceStorage::Initialize: signaled";
  //}

  //LOG(INFO) << "NamespaceStorage::Initialize: End waiting";
  //delegate_->OnNamespaceStorageInit(true, on_init);
}

void NamespaceStorage::Shutdown() {
  //database_->Shutdown();
  //graph_db_->Shutdown();
  
  //for (auto* fs : filesystems_) {
  filesystem_->set_state(Filesystem::kShutdown);
  filesystem_->Shutdown();
  //}
  for (auto* db : databases_) {
    db->set_state(Database::kShutdown);
    db->Shutdown();
  }
}

Filesystem* NamespaceStorage::GetFilesystem() const {
  return filesystem_.get();
}

Database* NamespaceStorage::GetDatabaseById(int id) const {
  auto it = dbid_map_.find(id);
  if (it != dbid_map_.end()) {
    int index = it->second;
    return databases_[index];
  }
  return nullptr;
}

// Filesystem* NamespaceStorage::GetFilesystemByType(FilesystemType type) const {
//   for (auto* fs : filesystems_) {
//     if (fs->type() == type) {
//       return fs;
//     }
//   }
//   return nullptr;
// }

void NamespaceStorage::OnFilesystemInitReply(int fs_id, int result) {
  Filesystem* target = filesystem_.get();
  
  if (result != net::OK) {
    LOG(ERROR) << "filesystem initialization for id: " << fs_id << " failed";
    target->set_state(Filesystem::kError);
    initialization_error_ = true;
  } else {
    target->set_state(Filesystem::kInitialized);
  }
  
  // TODO: not thread safe
  //delegate_->OnFilesystemInit(result, fs_id, target->state());
  //init_events_[kFILESYSTEM_EVENT].Signal();
  MaybeNotifyDelegate();
}

void NamespaceStorage::OnDatabaseInitReply(int db_id, int result) {
  Database* target = nullptr;
  for (auto* db : databases_) {
    if (db->id() == db_id) {
      target = db;
      break;
    }
  }

  if (!target) {
    LOG(ERROR) << "database id: " << db_id << "not found";
    //init_events_[kDATABASE_EVENT].Signal();
    return;
  }

  if (result != net::OK) {
    LOG(ERROR) << "db initialization for id: " << db_id << " failed";
    target->set_state(Database::kError);
    initialization_error_ = true;
  } else {
    target->set_state(Database::kInitialized);
  }
  
  // TODO: not thread safe
  //delegate_->OnDatabaseInit(result, db_id, target->state());
  //init_events_[kDATABASE_EVENT].Signal();
  MaybeNotifyDelegate();
}

//void NamespaceStorage::OnGraphDbInitReply(int result) {
//  if (result != net::OK) {
//    LOG(ERROR) << "graph initialization failed";
    //database_->set_state(NamespaceDatabase::kError);
//    initialization_error_ = true;
//  } //else {
    //database_->set_state(NamespaceDatabase::kInitialized);
  //}
  // TODO: not thread safe
  //delegate_->OnGraphDbInit(result);
  //init_events_[kGRAPH_EVENT].Signal();
//  MaybeNotifyDelegate();
//}

void NamespaceStorage::MaybeNotifyDelegate() {
  ev_count_--;
  if (ev_count_ == 0) {
    reply_to_->PostTask(FROM_HERE, 
      base::BindOnce(&NamespaceStorage::Delegate::OnNamespaceStorageInit, 
        base::Unretained(delegate_),
        !initialization_error_, 
        base::Passed(std::move(on_init_)))
    );
    // release our ref-count on reference
    reply_to_ = nullptr;
  }
}

}