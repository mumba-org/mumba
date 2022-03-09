// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SHARE_SHARE_MANAGER_H_
#define MUMBA_HOST_SHARE_SHARE_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/uuid.h"
#include "core/host/database_policy.h"
#include "storage/storage.h"
#include "storage/storage_manager.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wignored-qualifiers"
#include "third_party/zetasql/parser/parse_tree.h"
#include "third_party/zetasql/parser/ast_node_kind.h"
#include "third_party/zetasql/parser/parser.h"
#include "third_party/zetasql/public/parse_resume_location.h"
#include "third_party/zetasql/base/status.h"
#pragma clang diagnostic pop

namespace storage {
class Torrent;
}

namespace host {
class ShareModel;
class Share;

class ShareManager {
public:
  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnSharesLoad(int r, int count) {}
    virtual void OnShareAdded(Share* share) {}
    virtual void OnShareRemoved(Share* share) {}
  };
  ShareManager(storage::StorageManager* storage_manager);
  ~ShareManager();

  ShareModel* model() const {
    return shares_.get();
  }

  void Init(std::unique_ptr<Share> system_share, DatabasePolicy policy);
  void Shutdown();
  
 
  storage::Storage* GetStorage(const std::string& name);

  void AddEntry(
    const std::string& domain,
    const base::FilePath& src,
    const base::UUID& id,
    base::Callback<void(int64_t)> callback,
    std::string name = std::string());

   // create and insert share
  bool HasUUID(const std::string& name, const base::UUID& uuid);
  bool GetUUID(const std::string& storage_name, const std::string& uuid_str, base::UUID* id);
  void CloneStorageWithDHTAddress(const std::string& dht_address_bytes, base::Callback<void(int)> callback);
  Share* CreateDatabaseShare(const std::string& domain, const std::vector<std::string>& keyspaces, bool in_memory = false);
  Share* CreateDatabaseShare(const std::string& domain, const std::string& name, const std::vector<std::string>& keyspaces, bool in_memory = false);
  Share* CreateShare(scoped_refptr<storage::Torrent> torrent, bool in_memory = false);
  Share* CreateShare(const std::string& domain, storage_proto::InfoKind type, const std::string& name, std::vector<std::string> keyspaces = std::vector<std::string>(), base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>(), bool in_memory = false);
  Share* CreateShare(const std::string& domain, storage_proto::InfoKind type, const base::UUID& id, const std::string& name, std::vector<std::string> keyspaces = std::vector<std::string>(), base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>(), bool in_memory = false);
  Share* CreateShare(const std::string& domain, 
                     storage_proto::InfoKind type, 
                     const base::UUID& id, 
                     const std::string& name, 
                     const std::vector<std::string>& create_statements, 
                     const std::vector<std::string>& insert_statements, 
                     bool key_value,
                     base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>(), 
                     bool in_memory = false);
  Share* CreateShareWithInfohash(const std::string& domain, storage_proto::InfoKind type, const base::UUID& id, const std::string& name, const std::string& infohash, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>(), bool in_memory = false);
  Share* GetShare(const base::UUID& uuid);
  Share* GetShare(const std::string& domain, const base::UUID& uuid);
  Share* GetShare(const std::string& domain, const std::string& name);
  Share* OpenShare(const std::string& domain, const base::UUID& id, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  Share* OpenShare(const std::string& domain, const std::string& name, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  void InsertShare(std::unique_ptr<Share> share);
  // just remove from in-memory index (not destructive)
  void RemoveShareFromCache(Share* share);
  void RemoveShareFromCache(const base::UUID& uuid);
  void RemoveShareFromCache(const std::string& domain, const std::string& name);
  // drop is more serious as it destroy the underlying data
  bool DropShare(const std::string& domain, const base::UUID& key);
  bool DropShare(const std::string& domain, const std::string& name);
  bool DropShare(Share* share);
  bool DropShare(const base::UUID& key);
  void CloseDatabase(const std::string& domain, const std::string& name, base::Callback<void(int64_t)> cb);
  void CloseDatabase(const std::string& domain, const base::UUID& key, base::Callback<void(int64_t)> cb);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

private:

  Share* CreateShareInternal(scoped_refptr<storage::Torrent> torrent, const std::string& domain_name, const std::vector<std::string>& keyspaces, bool in_memory);
  Share* CreateShareInternal(scoped_refptr<storage::Torrent> torrent, const std::vector<std::string>& keyspaces, bool in_memory);
  Share* CreateShareInternal(scoped_refptr<storage::Torrent> torrent, const std::vector<std::string>& create_stmts, const std::vector<std::string>& insert_stmts, bool in_memory);

  void InitImpl(std::unique_ptr<Share> system_share);
  void ShutdownImpl();

  void OnLoad(std::unique_ptr<Share> system_share, int r, int count);

  void NotifyShareAdded(Share* share);
  void NotifyShareRemoved(Share* share);
  void NotifySharesLoad(int r, int count);

  storage::StorageManager* storage_manager_;
  std::unique_ptr<ShareModel> shares_;
  std::vector<Observer*> observers_;

  base::WeakPtrFactory<ShareManager> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ShareManager);
};

}

#endif