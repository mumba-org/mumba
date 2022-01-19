// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/share/share_manager.h"

#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/paths.h"
#include "core/host/host_thread.h"
#include "core/host/share/share.h"
#include "core/host/share/share_model.h"
#include "core/host/workspace/workspace.h"
#include "storage/torrent.h"
#include "storage/storage_manager.h"
#include "storage/storage.h"

namespace host {

ShareManager::ShareManager(storage::StorageManager* storage_manager): 
  storage_manager_(storage_manager),
  weak_factory_(this) {
  
}

ShareManager::~ShareManager() {

}

void ShareManager::Init(std::unique_ptr<Share> system_share, DatabasePolicy policy) {
  scoped_refptr<ShareDatabase> db = system_share->db();
  shares_ = std::make_unique<ShareModel>(this, db, policy);
  InitImpl(std::move(system_share));
}

void ShareManager::Shutdown() {
  ShutdownImpl();
}

void ShareManager::InitImpl(std::unique_ptr<Share> system_share) {
  shares_->Load(base::Bind(&ShareManager::OnLoad, 
                  base::Unretained(this), 
                  base::Passed(std::move(system_share))));
}

void ShareManager::ShutdownImpl() {
  shares_.reset();
}

bool ShareManager::HasUUID(const std::string& name, const base::UUID& uuid) {
  return storage_manager_->HasUUID(name, uuid); 
}

bool ShareManager::GetUUID(const std::string& storage_name, const std::string& uuid_str, base::UUID* id) {
  return storage_manager_->GetUUID(storage_name, uuid_str, id);
}

void ShareManager::CloneStorageWithDHTAddress(const std::string& dht_address_bytes, base::Callback<void(int)> callback) {
  std::string dht_address_hex = base::HexEncode(dht_address_bytes.data(), dht_address_bytes.size());
  storage_manager_->CloneStorage(dht_address_hex, std::move(callback));
}

Share* ShareManager::CreateDatabaseShare(const std::string& domain, const std::string& name, const std::vector<std::string>& keyspaces, bool in_memory) {
  scoped_refptr<storage::Torrent> share_torrent;
  if (!in_memory) {
    share_torrent = storage_manager_->CreateTorrent(domain, storage_proto::InfoKind::INFO_DATA, name, keyspaces);
  } else {
    share_torrent = storage_manager_->NewTorrent(domain);
  }
  DCHECK(share_torrent);
  return CreateShareInternal(share_torrent, domain, keyspaces, in_memory);
}

Share* ShareManager::CreateDatabaseShare(const std::string& domain, const std::vector<std::string>& keyspaces, bool in_memory) {
  scoped_refptr<storage::Torrent> share_torrent;// = storage_manager_->CreateTorrent(domain, storage_proto::InfoKind::DATA, domain);
  if (!in_memory) {
    share_torrent = storage_manager_->CreateTorrent(domain, storage_proto::InfoKind::INFO_DATA, domain, keyspaces);
  } else {
    share_torrent = storage_manager_->NewTorrent(domain);
  }
  DCHECK(share_torrent);
  return CreateShareInternal(share_torrent, domain, keyspaces, in_memory);
}

Share* ShareManager::CreateShare(scoped_refptr<storage::Torrent> torrent, bool in_memory) {
  return CreateShareInternal(std::move(torrent), std::vector<std::string>(), in_memory); 
}

Share* ShareManager::GetShare(const base::UUID& uuid) {
  Share* reference = nullptr;
  // try to find a cached one, if theres none, lookup into the torrents
  // and create a new one
  reference = shares_->GetShareById(uuid);
  if (reference) {
    return reference;
  }
  scoped_refptr<storage::Torrent> share_torrent = storage_manager_->GetTorrent(uuid);
  if (!share_torrent) {
    // if theres not even a torrent, theres no share
    return nullptr;
  }
  std::unique_ptr<Share> share = std::make_unique<Share>(this, share_torrent->io_handler()->GetName(), share_torrent, std::vector<std::string>(), false);
  reference = share.get();
  InsertShare(std::move(share));  
  
  return reference;
}

Share* ShareManager::GetShare(const std::string& domain, const std::string& name) {
  Share* reference = nullptr;
  // try to find a cached one, if theres none, lookup into the torrents
  // and create a new one
  reference = shares_->GetShare(domain, name);
  if (reference) {
    return reference;
  }
  scoped_refptr<storage::Torrent> share_torrent = storage_manager_->GetTorrent(domain, name);
  if (!share_torrent) {
    return nullptr;
  }
  std::unique_ptr<Share> share = std::make_unique<Share>(this, domain, share_torrent, std::vector<std::string>(), false);
  reference = share.get();
  InsertShare(std::move(share));  
  
  return reference;  
}

Share* ShareManager::GetShare(const std::string& domain_name, const base::UUID& uuid) {
  Share* reference = nullptr;
  reference = shares_->GetShareById(uuid);
  if (reference) {
    return reference;
  }
  scoped_refptr<storage::Torrent> share_torrent = storage_manager_->GetTorrent(uuid);
  if (!share_torrent) {
    return nullptr;
  }
  std::unique_ptr<Share> share = std::make_unique<Share>(this, domain_name, share_torrent, std::vector<std::string>(), false);
  reference = share.get();
  InsertShare(std::move(share));  
  
  return reference;  
}

void ShareManager::InsertShare(std::unique_ptr<Share> share) {
  Share* reference = share.get();
  shares_->InsertShare(share->id(), std::move(share), false /* never persists as shares are 'cached torrents' */);
  NotifyShareAdded(reference);
}

Share* ShareManager::CreateShare(const std::string& domain_name, storage_proto::InfoKind type, const std::string& name, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb, bool in_memory) {
  return CreateShare(domain_name, type, base::UUID::generate(), name, std::move(keyspaces), std::move(cb));
}

Share* ShareManager::CreateShare(const std::string& domain_name, storage_proto::InfoKind type, const base::UUID& id, const std::string& name, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb, bool in_memory) {
  storage::Storage* storage = GetStorage(domain_name);
  
  if (!storage) {
    if (!cb.is_null())
      std::move(cb).Run(net::ERR_FAILED);
    return nullptr;
  }
  
  scoped_refptr<storage::Torrent> torrent = storage_manager_->torrent_manager()->NewTorrent(storage, id);
  
  if (!torrent) {
    if (!cb.is_null())
      std::move(cb).Run(net::ERR_FAILED);
    return nullptr; 
  }

  torrent->mutable_info()->set_path(name);

  if (type == storage_proto::INFO_DATA) {
    storage->CreateDatabase(torrent, std::move(keyspaces), std::move(cb));
  } else {
    storage->AddEntry(torrent, std::move(cb));    
  }

  return CreateShareInternal(torrent, domain_name, keyspaces, in_memory);  
}

Share* ShareManager::CreateShareWithInfohash(const std::string& domain, storage_proto::InfoKind type, const base::UUID& id, const std::string& name, const std::string& infohash, base::Callback<void(int64_t)> cb, bool in_memory) {
  scoped_refptr<storage::Torrent> torrent = storage_manager_->CreateTorrentWithInfohash(domain, type, id, name, infohash, std::move(cb));
  return CreateShareInternal(torrent, std::vector<std::string>(), in_memory);
}

Share* ShareManager::OpenShare(const std::string& domain, const base::UUID& id, base::Callback<void(int64_t)> cb) {
  Share* share = shares_->GetShareById(id);
  if (share) {
    scoped_refptr<storage::Torrent> t = share->torrent();
    if (!t->is_open()) {
      int r = t->Open();
      std::move(cb).Run(r);
    } else {
      std::move(cb).Run(net::OK);
    }
    return share;
  }
  scoped_refptr<storage::Torrent> torrent = storage_manager_->OpenTorrent(domain, id, std::move(cb));
  return CreateShareInternal(torrent, domain, std::vector<std::string>(), false);
}

Share* ShareManager::OpenShare(const std::string& domain, const std::string& name, base::Callback<void(int64_t)> cb) {
  Share* share = shares_->GetShare(domain, name);
  if (share) {
    scoped_refptr<storage::Torrent> t = share->torrent();
    if (!t->is_open()) {
      int r = t->Open();
      std::move(cb).Run(r);
    } else {
      std::move(cb).Run(net::OK);
    }
    return share;
  }
  scoped_refptr<storage::Torrent> torrent = storage_manager_->OpenTorrent(domain, name, std::move(cb));
  return CreateShareInternal(torrent, domain, std::vector<std::string>(), false);
}

void ShareManager::RemoveShareFromCache(Share* share) {
  NotifyShareRemoved(share);
  shares_->RemoveShare(share->id());
}

void ShareManager::RemoveShareFromCache(const base::UUID& uuid) {
  Share* share = shares_->GetShareById(uuid);
  if (share) {
    NotifyShareRemoved(share);
    shares_->RemoveShare(uuid);
  }
}

void ShareManager::RemoveShareFromCache(const std::string& domain, const std::string& name) {
  Share* share = shares_->GetShare(domain, name);
  if (share) {
    NotifyShareRemoved(share);
    shares_->RemoveShare(share->id());
  }
}

bool ShareManager::DropShare(const std::string& domain, const base::UUID& key) {
  bool result = storage_manager_->DeleteTorrent(domain, key);
  RemoveShareFromCache(key);
  return result;
}

bool ShareManager::DropShare(const std::string& domain, const std::string& name) {
  bool result = storage_manager_->DeleteTorrent(domain, name);
  RemoveShareFromCache(domain, name);
  return result;
}

bool ShareManager::DropShare(const base::UUID& key) {
  scoped_refptr<storage::Torrent> t = storage_manager_->GetTorrent(key);
  if (!t) {
    return false;
  }
  bool result = storage_manager_->DeleteTorrent(t); 
  RemoveShareFromCache(key);
  return result;
}

bool ShareManager::DropShare(Share* share) {
  scoped_refptr<storage::Torrent> t = storage_manager_->GetTorrent(share->id());
  if (!t) {
    return false;
  }
  bool result = storage_manager_->DeleteTorrent(t);
  RemoveShareFromCache(share);
  return result; 
}

void ShareManager::CloseDatabase(const std::string& domain, const std::string& name, base::Callback<void(int64_t)> cb) {
  return storage_manager_->CloseDatabase(domain, name, std::move(cb)); 
}

void ShareManager::CloseDatabase(const std::string& domain, const base::UUID& key, base::Callback<void(int64_t)> cb) {
  return storage_manager_->CloseDatabase(domain, key, std::move(cb)); 
}

Share* ShareManager::CreateShareInternal(scoped_refptr<storage::Torrent> torrent, const std::string& domain_name, const std::vector<std::string>& keyspaces, bool in_memory) {
  std::unique_ptr<Share> share = std::make_unique<Share>(this, domain_name, torrent, keyspaces, in_memory);
  Share* reference = share.get();
  InsertShare(std::move(share));
  return reference;
}

Share* ShareManager::CreateShareInternal(scoped_refptr<storage::Torrent> share_torrent, const std::vector<std::string>& keyspaces, bool in_memory) {
  DCHECK(share_torrent->io_handler());
  const std::string& domain = share_torrent->io_handler()->GetName();
  std::unique_ptr<Share> share = std::make_unique<Share>(this, domain, share_torrent, keyspaces, in_memory);
  Share* reference = share.get();
  InsertShare(std::move(share));  
  return reference;
}

storage::Storage* ShareManager::GetStorage(const std::string& name) {
  return storage_manager_->GetStorage(name);
}

void ShareManager::AddEntry(
  const std::string& domain_name,
  const base::FilePath& src,
  const base::UUID& id,
  base::Callback<void(int64_t)> callback,
  std::string name) {

  storage::Storage* domain = storage_manager_->GetStorage(domain_name);
  if (!domain) {
    DLOG(ERROR) << "storage for '" << domain_name << "' not found";
    callback.Run(net::ERR_FAILED);
    return;
  }
  scoped_refptr<storage::Torrent> t = storage_manager_->torrent_manager()->NewTorrent(domain, id);
  if (!t) {
    DLOG(ERROR) << "failed to create new torrent";
    callback.Run(net::ERR_FAILED);
    return;
  }
  domain->AddEntry(t, src, std::move(name), callback);
}

void ShareManager::AddObserver(Observer* observer) {
  observers_.push_back(observer);
}

void ShareManager::RemoveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void ShareManager::OnLoad(std::unique_ptr<Share> system_share, int r, int count) {
  // everything is loaded, so now we can insert the system share which holds the system ShareDatabase
  InsertShare(std::move(system_share));
  NotifySharesLoad(r, count);
}

void ShareManager::NotifySharesLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnSharesLoad(r, count);
  }
}

void ShareManager::NotifyShareAdded(Share* share) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnShareAdded(share);
  }
}

void ShareManager::NotifyShareRemoved(Share* share) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnShareRemoved(share);
  }
}

}