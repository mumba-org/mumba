// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/storage_manager.h"

#include "base/files/file_enumerator.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/task_scheduler/post_task.h"
#include "base/strings/string_number_conversions.h"
#include "storage/torrent.h"
#include "net/base/net_errors.h"
//#include "storage/data_catalog.h"
//#include "storage/tree_catalog.h"
//#include "storage/catalog.h"
#include "storage/hash.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"
#include "storage/storage.h"
#include "libtorrent/hex.hpp"
#include "libtorrent/sha1_hash.hpp"
#include "libtorrent/udp_socket.hpp"
#include "libtorrent/socket_io.hpp"
#include "libtorrent/torrent.hpp"
#include "libtorrent/aux_/socket_type.hpp"
#include "libtorrent/kademlia/ed25519.hpp"
#include "libtorrent/aux_/session_udp_sockets.hpp"
#include "libtorrent/aux_/session_impl.hpp"
#include "third_party/protobuf/src/google/protobuf/text_format.h"

namespace storage {

namespace {

static std::array<std::string, 1> dirs_to_ignore = { "ShaderCache" };

void OnDatabaseOpen(base::WaitableEvent* event, int64_t result) {
  //LOG(INFO) << "OnDatabaseOpen: result = " << result;
  if (event) {
    event->Signal();
  }
}

bool ShouldIgnoreDirectory(const std::string& dir_name) {
  for (const std::string& dir_to_ignore : dirs_to_ignore) {
    if (dir_to_ignore == dir_name) {
      return true;
    }
  }
  return false;
}

}

StorageManager::StorageManager(const base::FilePath& path):
  root_path_(path),
  main_runner_(base::ThreadTaskRunnerHandle::Get()),
  net_io_runner_(
    base::CreateSingleThreadTaskRunnerWithTraits(
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives(), 
        base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
        base::SingleThreadTaskRunnerThreadMode::DEDICATED)),
 // disk_frontend_task_runner_(base::CreateSingleThreadTaskRunnerWithTraits(
 //                 {base::MayBlock(), 
 //                  base::WithBaseSyncPrimitives(),
 //                  base::TaskPriority::USER_BLOCKING,
 //                 //base::TaskShutdownBehavior::BLOCK_SHUTDOWN},
 //                  base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
 //                  base::SingleThreadTaskRunnerThreadMode::DEDICATED)),
  //disk_backend_task_runner_(
  //   base::CreateSingleThreadTaskRunnerWithTraits(
  //    { base::MayBlock(), base::WithBaseSyncPrimitives(),
  //    base::TaskPriority::BACKGROUND},
  //    base::SingleThreadTaskRunnerThreadMode::DEDICATED
  //)),
  //db_task_runner_(base::CreateSingleThreadTaskRunnerWithTraits(
  //                {base::MayBlock(), 
  //                 base::WithBaseSyncPrimitives(),
  //                 base::TaskPriority::USER_BLOCKING,
  //                 base::TaskShutdownBehavior::BLOCK_SHUTDOWN},
  //                 base::SingleThreadTaskRunnerThreadMode::DEDICATED)),
  bootstrap_pending_(false),
  bootstraped_(false),
  batch_mode_(false),
  disk_started_counter_(0),
  io_context_(std::make_shared<libtorrent::io_context>()),
  init_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED),
  shutdown_event_(new base::WaitableEvent(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED)),
  is_shutting_down_(false) {
  //weak_factory_(this) {
  
}

StorageManager::~StorageManager() {
  // net_io_runner_ = nullptr;
  // disk_frontend_task_runner_ = nullptr;
  // disk_backend_task_runner_ = nullptr;
  // db_task_runner_ = nullptr;
  // io_context_ = nullptr;
  // torrent_manager_.reset();
}

bool StorageManager::has_dht() const {
  return torrent_manager_->has_dht();
}

Storage* StorageManager::CreateStorage(const std::string& name) {
  base::FilePath path = root_path_.AppendASCII(name);
  auto disk = Storage::Create(path,
                              torrent_manager_.get(), 
                              main_runner_, 
                              base::CreateSingleThreadTaskRunnerWithTraits(
                               { base::MayBlock(), 
                                 base::WithBaseSyncPrimitives(),
                                 base::TaskPriority::BACKGROUND},
                              base::SingleThreadTaskRunnerThreadMode::DEDICATED));
  if (!disk) {
    return nullptr;
  }
  disk_started_counter_++;
  base::WaitableEvent event{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
  disk->Start(base::Bind(&StorageManager::OnStorageStarted, base::Unretained(this), base::Unretained(&event)));
  event.Wait();
  Storage* result = disk.get();
  AddStorage(name, std::move(disk));
  return result;
}

Storage* StorageManager::CloneStorageImpl(const std::string& name, std::string id, const char* pkey) {
  base::FilePath path = root_path_.AppendASCII(name);
  auto disk = Storage::Clone(path,
                             torrent_manager_.get(), 
                             main_runner_, 
                             base::CreateSingleThreadTaskRunnerWithTraits(
                             { base::MayBlock(), 
                               base::WithBaseSyncPrimitives(),
                               base::TaskPriority::BACKGROUND},
                             base::SingleThreadTaskRunnerThreadMode::DEDICATED),
                            std::move(id),
                            pkey);
  if (!disk) {
    return nullptr;
  }
  disk_started_counter_++;
  base::WaitableEvent event{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
  disk->Start(base::Bind(&StorageManager::OnStorageStarted, base::Unretained(this), base::Unretained(&event)));
  event.Wait();
  Storage* result = disk.get();
  AddStorage(name, std::move(disk));
  return result;
}

Storage* StorageManager::OpenStorage(const std::string& name) {
  base::FilePath path = root_path_.AppendASCII(name);
  if (!OpenStorageInternal(path)) {
    return nullptr;
  }
  Storage* result = GetStorage(name);
  disk_started_counter_++;

  base::WaitableEvent event{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
  result->Start(base::Bind(&StorageManager::OnStorageStarted, base::Unretained(this), base::Unretained(&event)));
  event.Wait();
  //init_event_->Reset();
  return result;
}

Storage* StorageManager::GetStorage(const std::string& name) {
  base::AutoLock lock(disks_mutex_);
  auto it = disks_.find(name);
  if (it == disks_.end()) {
    return nullptr;
  }
  return it->second.get();
}

bool StorageManager::AddStorage(const std::string& name, std::unique_ptr<Storage> disk) {
  base::AutoLock lock(disks_mutex_);
  auto it = disks_.find(name);
  if (it != disks_.end()) {
    return false;
  }
  disks_.emplace(std::make_pair(name, std::move(disk)));
  return true;
}

bool StorageManager::RemoveStorage(const std::string& name, std::unique_ptr<Storage>* disk) {
  base::AutoLock lock(disks_mutex_);
  auto it = disks_.find(name);
  if (it == disks_.end()) {
    return false;
  }
  *disk = std::move(it->second);
  disks_.erase(it);
  return true;
}

void StorageManager::CloneStorage(const std::string& addr, const base::Callback<void(int)>& cb) {
  //LOG(INFO) << "StorageManager::CloneStorage";
  std::array<char, 32> pub_key;
  std::vector<uint8_t> data;

  if (addr.size() != 64) {
    LOG(ERROR) << "bad address '" << addr << "'. expected len of 40 have " << addr.size();
    cb.Run(net::ERR_FAILED);
    return;
  }

  if (!base::HexStringToBytes(addr, &data)) {
    LOG(ERROR) << "failed to convert back given hex address '" << addr << "' to actual bytes. is actually hex?";
    cb.Run(net::ERR_FAILED);
    return;
  }

  memcpy(pub_key.data(), reinterpret_cast<char *>(data.data()), 32);
  base::OnceCallback<void()> closure = base::BindOnce(&StorageManager::CloneStorageOnBootstrap, base::Unretained(this), base::Passed(std::move(pub_key)), cb);
  if (bootstraped_) {
    std::move(closure).Run();
  } else {
    task_list_mutex_.Acquire();
    scheduled_tasks_.push_back(std::move(closure));
    task_list_mutex_.Release();
  }
}

void StorageManager::CloneStorageOnBootstrap(std::array<char, 32> pub_key, const base::Callback<void(int)>& cb) {
  //LOG(INFO) << "StorageManager::CloneStorageOnBootstrap";
  if (!bootstraped_) {
    LOG(ERROR) << "clone failed: unable to find disk to clone as DHT network bootstrap failed";
    cb.Run(net::ERR_FAILED);
    return;
  }
  torrent_manager_->GetMutableItem(pub_key, base::Bind(&StorageManager::OnCloneStorage, base::Unretained(this), cb));
}

void StorageManager::ShareStorage(Storage* disk) {
  std::array<char, 32> pubkey;
  // first: iterate all entries and announce them on DHT
  // to serve them 
  std::vector<std::unique_ptr<storage_proto::Info>> infos = disk->GetAllEntriesInfos();
  for (auto it = infos.begin(); it != infos.end(); ++it) {
    base::UUID id(reinterpret_cast<const uint8_t *>((*it)->id().data()));
    if (!torrent_manager_->HasTorrent(id)) {
      //LOG(INFO) << "StorageManager::ShareStorage: adding torrent " << id.to_string();
      scoped_refptr<Torrent> torrent = torrent_manager_->NewTorrent(disk, std::move(*it));
      if (!torrent) {
        LOG(ERROR) << "StorageManager::ShareStorage: error while creating/adding torrent to torrent manager";
        continue;
      }
    } //else {
      //LOG(INFO) << "StorageManager::ShareStorage: torrent " << id.to_string() << " already added. Announcing...";
      //scoped_refptr<Torrent> torrent = torrent_manager_->GetTorrent(id);
      //LOG(INFO) << "StorageManager::ShareStorage: valid? " << torrent->handle().is_valid();
      //torrent->Announce();
      //LOG(INFO) << "StorageManager::ShareStorage: pausing " << id.to_string() << "...";
      //torrent->Pause();
      //LOG(INFO) << "StorageManager::ShareStorage: Now, resuming " << id.to_string() << "...";
      //torrent->Resume();
      //LOG(INFO) << "StorageManager::ShareStorage: after resume of " << id.to_string();
    //}
  }

  memcpy(pubkey.data(), disk->state()->pubkey().data(), 32);
  auto pk_hex = base::HexEncode(pubkey.data(), 32);
  // DLOG(INFO) << "StorageManager::ShareStorage: PutMutableItem => " << pk_hex;
  torrent_manager_->PutMutableItem(
      pubkey, 
      base::Bind(&StorageManager::WriteMutableDHTEntry, base::Unretained(this), base::Unretained(disk)),
      base::Bind(&StorageManager::OnWriteMutableDHTEntry, base::Unretained(this), base::Unretained(disk)));
}

void StorageManager::UnshareStorage(Storage* disk, base::Callback<void(int)> cb) {

}

void StorageManager::ListStorages(base::Callback<void(std::vector<const storage_proto::StorageState*>, int64_t)> cb) {
  std::vector<const storage_proto::StorageState*> list;
  disks_mutex_.Acquire();
  for (auto it = disks_.begin(); it != disks_.end(); ++it) {
    list.push_back(it->second->state());
  }
  disks_mutex_.Release();
  cb.Run(std::move(list), 0);
}

void StorageManager::AddBootstrapNode(const net::IPEndPoint& endpoint){
  bootstrap_routers_.push_back(endpoint);
}

void StorageManager::Init(const base::Callback<void(int)>& init_cb, bool batch_mode) {
  DLOG(INFO) << "StorageManager::Init";
  size_t disk_count = 0;
  batch_mode_ = batch_mode;
  if (!init_cb.is_null()) {
    init_cb_mutex_.Acquire();
    init_callback_ = init_cb;
    init_cb_mutex_.Release();
  }
  //disk_frontend_task_runner_->PostTask(
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::MayBlock(), base::WithBaseSyncPrimitives() },
    base::BindOnce(&StorageManager::InitImpl,
                    base::Unretained(this)));
  //if (init_callback_.is_null() || batch_mode) {
  init_event_.Wait();
  init_event_.Reset();
  ///}
  // initialize disks
  disks_mutex_.Acquire();
  disk_count = disks_.size();
  for (auto it = disks_.begin(); it != disks_.end(); ++it) {
    if (!it->second->is_initializing()) {
      DLOG(INFO) << "StorageManager::Init: initializing disk '" << it->first << "'";
      disk_started_counter_++;
      base::WaitableEvent* event =  batch_mode ? &init_event_ : nullptr;
      it->second->Start(base::Bind(
        &StorageManager::OnStorageStarted, 
          base::Unretained(this),
          base::Unretained(event)));
    }
  }
  disks_mutex_.Release();
  
  // if we have no disks, the callback would never be called on OnStorageStarted
  // so in that case we call it here
  if (disk_count == 0 && !init_cb.is_null()) {
    init_cb.Run(net::OK);
    init_cb_mutex_.Acquire();
    init_callback_ = base::Callback<void(int)>();
    init_cb_mutex_.Release();
  }
}

void StorageManager::Shutdown() {
  //DLOG(INFO) << "StorageManager::Shutdown";
  is_shutting_down_ = true;
  torrent_manager_->is_shutting_down_ = true;
  
  //if (disk_frontend_task_runner_ == base::ThreadTaskRunnerHandle::Get()) {
  //  ShutdownImpl(nullptr);
  //  DestroyTracker(nullptr);
  //} else {
  
  base::PostTaskWithTraits(
      FROM_HERE,
      { base::WithBaseSyncPrimitives(), base::MayBlock() },
      base::BindOnce(&StorageManager::ShutdownImpl,
      base::Unretained(this),
      base::Unretained(shutdown_event_.get())));
  
  //DLOG(INFO) << "StorageManager::Shutdown: waiting ShutdownImpl";
  shutdown_event_->Wait();
  //DLOG(INFO) << "StorageManager::Shutdown: end waiting ShutdownImpl";
  //}
  disks_mutex_.Acquire();
  for (auto it = disks_.begin(); it != disks_.end(); it++) {
    //DLOG(INFO) << "calling disk '" << it->first << "' stop";
    it->second->Stop();
    //DLOG(INFO) << "disk '" << it->first << "' stop end";
  }
  disks_mutex_.Release();
  net_io_runner_ = nullptr;
  //disk_frontend_task_runner_ = nullptr;
  //disk_backend_task_runner_ = nullptr;
 // db_task_runner_ = nullptr;
  io_context_ = nullptr;
  torrent_manager_.reset();
  //DLOG(INFO) << "StorageManager::Shutdown END";
}

void StorageManager::CopyFile(const std::string& disk_name, 
                           const base::UUID& key,
                           const base::FilePath& src, 
                           const CompletionCallback& callback) {
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    callback.Run(net::ERR_FAILED);
    return;
  }
  scoped_refptr<Torrent> t = torrent_manager_->GetOrCreateTorrent(disk, key);
  if (!t) {
    callback.Run(net::ERR_FAILED);
    return; 
  }
  disk->CopyFile(t, src, callback);
}

void StorageManager::CopyEntry(const std::string& disk_name, 
                            const base::UUID& src,
                            const base::FilePath& dest, 
                            const CompletionCallback& callback) {
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    callback.Run(net::ERR_FAILED);
    return;
  }
  scoped_refptr<Torrent> t = torrent_manager_->GetOrCreateTorrent(disk, src);
  if (!t) {
    callback.Run(net::ERR_FAILED);
    return; 
  }
  disk->CopyEntry(t, dest, callback);
}

void StorageManager::InitEntry(const std::string& disk_name,
                            const base::FilePath& src,
                            const CompletionCallback& callback) {
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    callback.Run(net::ERR_FAILED);
    return;
  }
  scoped_refptr<Torrent> t = torrent_manager_->NewTorrent(disk, base::UUID::generate());
  if (!t) {
    callback.Run(net::ERR_FAILED);
    return; 
  }
  disk->InitEntry(t, src, callback);
}

void StorageManager::GetInfo(const std::string& disk_name, base::Callback<void(storage_proto::StorageState)> callback) {
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    callback.Run(storage_proto::StorageState());
    return;
  }
  disk->GetInfo(std::move(callback));
}

//void StorageManager::Query(const std::string& disk_name,
//                        const std::string& query_string,
//                        const std::string& catalog_name,
//                        base::Callback<void(std::unique_ptr<Block>, int64_t)> callback) {
//  Storage* disk = GetStorage(disk_name);
//  if (!disk) {
//    callback.Run({}, net::ERR_FAILED);
//    return;
//  }
//  disk->Query(query_string, catalog_name, std::move(callback));
//}

scoped_refptr<Torrent> StorageManager::CreateTorrent(const std::string& disk_name, storage_proto::InfoKind type, const std::string& name, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) {
  return CreateTorrent(disk_name, type, base::UUID::generate(), name, std::move(keyspaces), std::move(cb));
}

scoped_refptr<Torrent> StorageManager::CreateTorrent(const std::string& disk_name, storage_proto::InfoKind type, const base::UUID& id, const std::string& name, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) {
  Storage* storage = GetStorage(disk_name);
  if (!storage) {
    return {};
  }
  
  scoped_refptr<Torrent> torrent = torrent_manager_->NewTorrent(storage, id);
  if (!torrent) {
    return {}; 
  }

  torrent->mutable_info()->set_path(name);

  if (type == storage_proto::INFO_DATA) {
    storage->CreateDatabase(torrent, std::move(keyspaces), std::move(cb));
  } else {
    storage->InitEntry(torrent, std::move(cb));    
  }
  return torrent;
}

scoped_refptr<Torrent> StorageManager::OpenTorrent(const std::string& disk_name, const std::string& name, base::Callback<void(int64_t)> cb) {
  base::UUID id;
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    return {};
  }
  if (!disk->GetUUID(name, &id)) {
    return scoped_refptr<Torrent>();
  }
  return OpenTorrent(disk_name, id, std::move(cb));
}

scoped_refptr<Torrent> StorageManager::OpenTorrent(const std::string& disk_name, const base::UUID& id, base::Callback<void(int64_t)> cb) {
  bool is_db = false;
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    return {};
  }

  scoped_refptr<Torrent> torrent = torrent_manager_->GetOrCreateTorrent(disk, id);
  if (!torrent) {
    return {}; 
  }

  int rc = torrent->Open();
  if (rc != 0) {
    return {};
  }

  if (torrent->info().kind() == storage_proto::INFO_DATA) {
    DLOG(INFO) << "OpenTorrent: torrent is a database. also opening the db handle..";
    disk->OpenDatabase(torrent, std::move(cb));
    is_db = true;
  }
  // this is not very good if we are returning
  // the torrent later
  if (!is_db && !cb.is_null()) {
    cb.Run(rc);
  }
  return torrent;
}

bool StorageManager::DeleteTorrent(const std::string& disk_name, const std::string& name) {
  base::UUID id;
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    return {};
  }
  if (!disk->GetUUID(name, &id)) {
    return false;
  }
  return DeleteTorrent(disk_name, id);
}
  
bool StorageManager::DeleteTorrent(const std::string& disk_name, const base::UUID& key) {
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    return false;
  }
  scoped_refptr<Torrent> torrent = torrent_manager_->GetOrCreateTorrent(disk, key);
  
  if (!torrent) {
    return false; 
  }

  return disk->DeleteTorrent(torrent).get() == 0;
}

void StorageManager::OpenDatabase(const std::string& disk_name, const base::UUID& key, base::Callback<void(int64_t)> cb) {
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    cb.Run(net::ERR_FAILED);
    return;
  }
  scoped_refptr<Torrent> t = torrent_manager_->GetOrCreateTorrent(disk, key);
  if (!t) {
    cb.Run(net::ERR_FAILED);
    return; 
  }
  // see if its opened already
  if (t->is_data() && t->is_open()) {
    cb.Run(net::OK);
    return;
  }
  disk->OpenDatabase(t, std::move(cb));
}

void StorageManager::CreateDatabase(const std::string& disk_name, const std::string& db_name, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) {
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    cb.Run(net::ERR_FAILED);
    return;
  }
  scoped_refptr<Torrent> t = torrent_manager_->NewTorrent(disk, base::UUID::generate());
  if (!t) {
    cb.Run(net::ERR_FAILED);
    return; 
  }
  t->mutable_info()->set_path(db_name);
  disk->CreateDatabase(t, std::move(keyspaces), std::move(cb));
}

// void StorageManager::OpenApplication(const std::string& disk_name, const std::string& key, base::Callback<void(int64_t)> cb) {
//   Storage* disk = GetStorage(disk_name);
//   if (!disk) {
//     cb.Run(net::ERR_FAILED);
//     return;
//   }
//   scoped_refptr<Torrent> t = torrent_manager_->GetTorrent(key);
//   if (!t) {
//     cb.Run(net::ERR_FAILED);
//     return; 
//   }
//   disk->OpenApplication(t, std::move(cb));
// }

// void StorageManager::CreateApplication(const std::string& disk_name, const std::string& key, base::Callback<void(int64_t)> cb) {
//   Storage* disk = GetStorage(disk_name);
//   if (!disk) {
//     cb.Run(net::ERR_FAILED);
//     return;
//   }
//   scoped_refptr<Torrent> t = torrent_manager_->NewTorrent(disk, key);
//   if (!t) {
//     cb.Run(net::ERR_FAILED);
//     return; 
//   }
//   disk->CreateApplication(t, std::move(cb));
// }

void StorageManager::GetEntryInfo(const std::string& disk_name, const base::UUID& key, base::Callback<void(storage_proto::Info, int64_t)> cb) {
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    cb.Run(storage_proto::Info(), net::ERR_FAILED);
    return;
  }
  scoped_refptr<Torrent> t = torrent_manager_->GetOrCreateTorrent(disk, key);
  if (!t) {
    cb.Run(storage_proto::Info(), net::ERR_FAILED);
    return; 
  }
  disk->GetEntryInfo(t, std::move(cb));
}

void StorageManager::ListEntries(const std::string& disk_name, base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb) {
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    cb.Run(std::vector<std::unique_ptr<storage_proto::Info>>(), net::ERR_FAILED);
    return;
  }
  disk->ListEntries(std::move(cb));
}


void StorageManager::InitImpl() {
  //int result = net::OK;
  DbInit();

  torrent_manager_.reset(new TorrentManager(this, io_context_, net_io_runner_));
  for (auto it = bootstrap_routers_.begin(); it != bootstrap_routers_.end(); ++it) {
    torrent_manager_->AddBootstrapNode(*it);
  }
  
  base::FileEnumerator disk_enum(root_path_, false, base::FileEnumerator::DIRECTORIES);
  for (base::FilePath disk_dir = disk_enum.Next(); !disk_dir.empty(); disk_dir = disk_enum.Next()) {
    std::string dir_name = disk_dir.BaseName().value();
    if (ShouldIgnoreDirectory(dir_name)) {
      continue;
    }
    // a real disk directory have at least 'index' file (and some block files)
    base::FilePath index_file = disk_dir.AppendASCII("index");
    if (!base::PathExists(index_file)) {
      continue;
    }
    if (!OpenStorageInternal(disk_dir)){
      DLOG(ERROR) << "failed to open disk at " << disk_dir;
      //result = net::ERR_FAILED;
    }
  }
  if (!batch_mode_) {
    bootstrap_pending_ = true;
    torrent_manager_->Start(base::Bind(&StorageManager::OnBootstrap, base::Unretained(this)));
  } 
  init_event_.Signal();
  //DLOG(INFO) << "StorageManager::StartImpl end";
}

//void StorageManager::UpdateImpl() {
//  torrent_manager_->Update(base::Bind(&StorageManager::OnBootstrap, base::Unretained(this)));
//}

void StorageManager::ShutdownImpl(base::WaitableEvent* stop_event) {
  //DLOG(INFO) << "StorageManager::ShutdownImpl";
  DbShutdown();
  if (!batch_mode_) {
    torrent_manager_->Shutdown(stop_event);
  } else {
    torrent_manager_->ReleaseTorrents();
    if (stop_event) {
      stop_event->Signal();
    }
  }
  //DLOG(INFO) << "StorageManager::ShutdownImpl END";
}

void StorageManager::DestroyTracker(base::WaitableEvent* stop_event) {
  //DLOG(INFO) << "StorageManager::DestroyTracker";
  // destroy the torrent handles
  //share_list_.clear();
  torrent_manager_.reset();
  if (stop_event) {
    stop_event->Signal();
  }
  //DLOG(INFO) << "StorageManager::DestroyTracker END";
}

bool StorageManager::OpenStorageInternal(const base::FilePath& path) {
  std::string name = path.BaseName().value();
  
  disks_mutex_.Acquire();
  auto it = disks_.find(name);
  // already opened. nothing to do
  if (it != disks_.end()) {
    disks_mutex_.Release();
    return true;
  }
  disks_mutex_.Release();

  auto disk = Storage::Open(
    path, 
    torrent_manager_.get(), 
    main_runner_, 
    //disk_frontend_task_runner_,
    base::CreateSingleThreadTaskRunnerWithTraits(
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives(),
        base::TaskPriority::BACKGROUND},
      base::SingleThreadTaskRunnerThreadMode::DEDICATED));
  if (!disk) {
    return false;
  }
  //DLOG(INFO) << "adding disk with name '" << name << "'";
  AddStorage(name, std::move(disk));
  return true;
}

void StorageManager::OnBootstrap(std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const& dht_nodes) {
  std::ostringstream outstr;
  bootstrap_pending_ = false;
  bootstraped_ = dht_nodes.size() > 0;
  outstr << "OnBootstrap. nodes = " << dht_nodes.size() << ":\n";
  for (auto it = dht_nodes.begin(); it != dht_nodes.end(); it++) {
    outstr << it->first.addr().to_string() << ":" << it->first.port() << "\n"; 
  }
  LOG(INFO) << outstr.str();

  task_list_mutex_.Acquire();
  if (scheduled_tasks_.size()) {
    for (auto it = scheduled_tasks_.begin(); it != scheduled_tasks_.end(); ++it) {
      main_runner_->PostTask(FROM_HERE, std::move(*it));
    }
    scheduled_tasks_.clear();
  }
  task_list_mutex_.Release();

  disk_list_mutex_.Acquire();
  if (bootstraped_ && disk_share_list_.size() > 0) {
    for (auto it = disk_share_list_.begin(); it != disk_share_list_.end(); ++it) {
      //DLOG(INFO) << "OnBootstrap sharing disk " << (*it)->address() << " " << (*it)->path();
      main_runner_->PostTask(FROM_HERE, base::BindOnce(&StorageManager::ShareStorage, base::Unretained(this), base::Unretained(*it)));
    }
    disk_share_list_.clear();
  }
  disk_list_mutex_.Release();

//  weak_factory_.InvalidateWeakPtrs();
  init_cb_mutex_.Acquire();
  if (disk_started_counter_ == 0 && !init_callback_.is_null()) {
    main_runner_->PostTask(FROM_HERE, base::Bind(init_callback_, dht_nodes.size() > 0 ? net::OK : net::ERR_FAILED));
    //init_callback_ = base::Callback<void(int)>();
  }
  init_cb_mutex_.Release();
  
  // release some steam
  std::vector<libtorrent::alert*> alerts;
  torrent_manager_->GetAlerts(&alerts);
}

void StorageManager::OnStorageStarted(base::WaitableEvent* sync, Storage* disk, int result) {
  disk_started_counter_--;
  if (disk && result == 0) {
    //DLOG(INFO) << "disk " << disk->address() << " started. owner? " << disk->is_owner();
    if (disk->status() != storage_proto::STORAGE_STATUS_DISABLED && disk->is_owner() && !batch_mode_) {
      if (!bootstraped_) {
        //DLOG(INFO) << "not bootstraped. adding disk " << disk->address() << " " << disk->path() << " to share list";
        disk_list_mutex_.Acquire();
        disk_share_list_.push_back(disk);
        disk_list_mutex_.Release();
      } else {
        //DLOG(INFO) << "bootstraped. sharing disk " << disk->address() << " " << disk->path();
        ShareStorage(disk);
      }
    }
  }
  if (disk_started_counter_ == 0) {
    // if theres a bootstrap pending, let it call the OnBootstrap call the init callback
    // if otherwise this is after the bootstrap, we should call it now
    if (!bootstrap_pending_ && !init_callback_.is_null() && !batch_mode_) {
      //DLOG(INFO) << "disk_started_counter == 0 on general manager initialization. calling callback..";
      init_callback_.Run(net::OK);
      init_callback_ = base::Callback<void(int)>();
    } else if (batch_mode_) {
      //DLOG(INFO) << "disk_started_counter == 0 and callback is null. so likely CreateStorage() or OpenStorage() were called. Signalling..";
    }
    if (sync) {
      sync->Signal();
    }
  }
}

void StorageManager::WriteMutableDHTEntry(Storage* disk,
                                       libtorrent::entry& entry, 
                                       std::array<char, 64>& signature, 
                                       std::int64_t& seq, 
                                       std::string const& salt) {
  //if (disk && result == 0) {

  //Catalog* registry = disk->GetCatalog("registry");
  scoped_refptr<Torrent> root_tree = disk->root_tree();
  if (!root_tree) {
    DLOG(ERROR) << "really bad. no root tree for disk " << disk->address() << " at " << disk->path();
    return;
  }

  storage_proto::StorageManifest manifest;
  manifest.set_name(disk->state()->address());
  manifest.set_creator(disk->state()->creator());
  manifest.set_pubkey(disk->state()->pubkey());

  const storage_proto::Info& info = root_tree->info();
  auto record = manifest.add_record();
  record->CopyFrom(info);
 // DLOG(INFO) << "sharing immutable address (registry database): " << base::HexEncode(info.root_hash().data(), info.root_hash().size()) << " for mutable address (disk): " << disk->address();

  entry = lt::entry(lt::entry::string_t);

  std::string& payload = entry.string();

  if (!manifest.SerializeToString(&payload)) {
    DLOG(ERROR) << "StorageManager::WriteMutableDHTEntry: error encoding protobuf to string";
    return;
  }

  // the DHT has a 1000 bytes limit. see if the payload has a safe lenght
  if (payload.size() > 1000) {
    DLOG(ERROR) << "StorageManager::WriteMutableDHTEntry: protobuf payload exceeds DHT storage limit. Want < 1000 have " << payload.size();
    return;
  }

  std::vector<char> buf;
  libtorrent::bencode(std::back_inserter(buf), entry);
  libtorrent::dht::signature sign;
  ++seq;

  //std::array<char, 32> pubkey;
  //memcpy(pubkey.begin(), disk->state()->pubkey().data(), 32);

  
  libtorrent::dht::public_key pubkey;
  libtorrent::dht::secret_key privkey;

  memcpy(pubkey.bytes.data(), disk->state()->pubkey().data(), 32);
  memcpy(privkey.bytes.data(), disk->state()->privkey().data(), 64);

  auto pubk_hex = base::HexEncode(pubkey.bytes.data(), 32);
  auto privk_hex = base::HexEncode(privkey.bytes.data(), 64);

  sign = libtorrent::dht::sign_mutable_item(
    buf, 
    salt, 
    libtorrent::dht::sequence_number(seq), 
    pubkey, 
    privkey);

  signature = sign.bytes;

  //}

  //if (!user_cb.is_null()) {
  //  main_runner_->PostTask(FROM_HERE, base::Bind(user_cb, result));
  //}
}

void StorageManager::OnWriteMutableDHTEntry(Storage* disk,
                                      libtorrent::dht::item const& item, 
                                      int num) {
  LOG(INFO) << "StorageManager::OnWriteMutableDHTEntry:\n" << 
   "  public key: " << base::HexEncode(item.pk().bytes.data(), 32) <<
   "  num: " << num << "\n\n";
  
  disk->set_sharing(true);

  // now, release some steam, so we can clear older alerts
  std::vector<libtorrent::alert*> alerts;
  torrent_manager_->GetAlerts(&alerts);

  //const auto& torrent_handles = share_list_[disk->address()];

  //for (const auto& torrent_handle : torrent_handles) {
  //  libtorrent::torrent_status status = torrent_handle.status();
  //    LOG(INFO) << "StorageManager::OnWriteMutableDHTEntry:\n  torrent valid? " << torrent_handle.is_valid() << " status: " <<
  //      status.name << " - " << torrent_state(status);
  //}

  //for (libtorrent::alert* alert : alerts) {
  //  if (libtorrent::alert_cast<libtorrent::dht_reply_alert>(alert)) {
  //    printf("[dht announce reply]: %s\n", alert->message().c_str());
  //  }
  //}
}

bool StorageManager::GetUUID(const std::string& disk_name, const std::string& name, base::UUID* id) {
  Storage* disk = GetStorage(disk_name);
  if (!disk) {
    return false;
  }
  return disk->GetUUID(name, id);
}

void StorageManager::OnTorrentFinished(const scoped_refptr<Torrent>& torrent) {
  //LOG(INFO) << "StorageManager::OnTorrentFinished";
}

void StorageManager::OnTorrentSeeding(const scoped_refptr<Torrent>& torrent) {
  LOG(INFO) << "StorageManager::OnTorrentSeeding";
  // the owner maybe dont give us the right heuristics
  // if we want/need the things in the list
  // but it will do for now.
  // Maybe the best way is to iterate over the torrents being
  // shared on the torrent manager and see if they are already there
  //if (torrent->is_tree() && !torrent->io_handler()->is_owner()) {
  if (torrent->is_root() && !torrent->io_handler()->is_owner()) {
    base::PostTaskWithTraits(
    FROM_HERE,
    {base::MayBlock(), base::WithBaseSyncPrimitives()},
    base::BindOnce(&StorageManager::CloneTorrentsFromRoot,
                   base::Unretained(this),
                   torrent));  
  } else {
    //LOG(INFO) << "OnTorrentSeeding: torrent " << torrent->storage_id() << " - '" << 
    //  torrent->id().to_string() << "' NOT of registry kind";
    ProcessScheduledTasks();
  }
}

void StorageManager::CloneTorrentsFromRoot(const scoped_refptr<Torrent>& torrent) {
  LOG(INFO) << "StorageManager::CloneTorrentsFromRoot";
  //if (torrent->io_handler()->is_owner()) {
  //  LOG(INFO) << "OnTorrentSeeding: '" << torrent->id().to_string() << "' is tree, but we are a owner of the disk, so no need to sync the other elements";
  //  ProcessScheduledTasks();
  //  return;
  //}
  IOHandler* handler = torrent->io_handler();
  if (!torrent->db_is_open()) {
    base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
    handler->OpenDatabase(
      torrent,
      base::Bind(&OnDatabaseOpen, base::Unretained(&waiter)));
    //LOG(INFO) << "OnTorrentSeeding: waiting for '" << torrent->id().to_string() << "' to open as a catalog..";
    waiter.Wait();
    //LOG(INFO) << "OnTorrentSeeding: ended waiting";
  }
  //Database* db = torrent->db();
  //if (!db) {
    //LOG(ERROR) << "OnTorrentSeeding: failed getting db from '" << torrent->id().to_string() << "'";
  //  ProcessScheduledTasks();
  //  return;
  //}
  std::vector<std::unique_ptr<storage_proto::Info>> infos = ScanInfos(torrent);
  if (HaveAllTorrentsInRoot(infos)) {
    //LOG(INFO) << "OnTorrentSeeding: torrent " << torrent->storage_id() << " - '" << 
    //  torrent->id().to_string() << "' we have all the items in the registry list. No need to download them";
    ProcessScheduledTasks();
    return;
  }
  //LOG(INFO) << "OnTorrentSeeding: torrent " << torrent->storage_id() << " - '" << 
  //  torrent->id().to_string() << "' IS of registry kind and we dont have the torrents on that list";
  // We are done downloading torrent and its the 'registry' type
  // we need to post another job that will iterate over its elements
  // and schedule the torrents found in the list
  //disk_frontend_task_runner_->PostTask(
  //  FROM_HERE,
  //  base::BindOnce(&StorageManager::AddTorrentsFromRegistry,
  //                 base::Unretained(this),
  //                 base::Unretained(disk),
  //                 base::Passed(std::move(infos))));
  AddTorrentsFromRoot(handler, std::move(infos));
}

bool StorageManager::HaveAllTorrentsInRoot(const std::vector<std::unique_ptr<storage_proto::Info>>& infos) {
  size_t iteration = 0;
  for (auto it = infos.begin(); it != infos.end(); ++it) {
    storage_proto::Info* info = it->get();
    if (!info) {
      LOG(ERROR) << "HaveAllTorrentsInRegistry: bad.. info at iteration " << iteration << " in null";
      continue;
    }
    // temporary..
    std::string text;
    if (google::protobuf::TextFormat::PrintToString(*info, &text)) {
      printf("---#---\n%s\n---#---\n", text.c_str());
    }
    base::UUID tid(reinterpret_cast<const uint8_t *>(info->id().data()));
    //LOG(INFO) << "HaveAllTorrentsInRegistry: checking if we already have " << tid.to_string() << " torrent";
    if (!torrent_manager_->HasTorrent(tid)) {
      return false;
    }
    iteration++;
  }
  return true;
}

std::vector<std::unique_ptr<storage_proto::Info>> StorageManager::ScanInfos(const scoped_refptr<Torrent>& torrent) {
  std::vector<std::unique_ptr<storage_proto::Info>> result;
  auto trans = torrent->db().BeginTransaction(false);
  auto cursor = torrent->db().CreateCursor(trans.get(), "inodes");
  if (!cursor) {
    LOG(ERROR) << "StorageManager::ScanInfos: could not create cursor for keyspace 'inodes'";
    return std::vector<std::unique_ptr<storage_proto::Info>>();
  }
  cursor->First();
  while (cursor->IsValid()) {
    std::unique_ptr<storage_proto::Info> info = std::make_unique<storage_proto::Info>();
    bool valid = false;
    KeyValuePair kv = DbDecodeKV(cursor->GetData(), &valid);
    if (!info->ParseFromArray(kv.second.data(), kv.second.size())) {
      DLOG(ERROR) << "oops. problem parsing row. raw data (" << kv.second.size() << "):\n'" << kv.second.as_string() << "'";
      cursor->Next();
      continue;
    }
    // temporary..
    std::string text;
    if (google::protobuf::TextFormat::PrintToString(*info, &text)) {
      printf("---*---\n%s\n---*---\n", text.c_str());
    }
    result.push_back(std::move(info));
    cursor->Next();
  }

  trans->Commit();
  
  return result;
}

void StorageManager::AddTorrentsFromRoot(IOHandler* handler, std::vector<std::unique_ptr<storage_proto::Info>> infos) {
  //LOG(INFO) << "StorageManager::AddTorrentsFromRegistry";
  //std::vector<std::unique_ptr<storage_proto::Info>> infos = catalog->ScanTableAll<storage_proto::Info>(torrent->id().to_string());
  //LOG(INFO) << "AddTorrentsFromRegistry: recovered " << infos.size() << " entries from the registry";
  for (auto it = infos.begin(); it != infos.end(); ++it) {
    //LOG(INFO) << "AddTorrentsFromRegistry: creating '" << (*it)->path() << "' torrent";
    torrent_manager_->NewTorrent(handler, std::move(*it));
  }
  if (!infos.size()) {
    ProcessScheduledTasks();
  }
}

void StorageManager::ProcessScheduledTasks() {
  task_list_mutex_.Acquire();
  if (scheduled_tasks_.size()) {
    for (auto it = scheduled_tasks_.begin(); it != scheduled_tasks_.end(); ++it) {
      main_runner_->PostTask(FROM_HERE, std::move(*it));
    }
    scheduled_tasks_.clear();
  }
  task_list_mutex_.Release();
}

void StorageManager::OnWriteImmutableDHTEntry(Storage* disk,
                                           libtorrent::sha1_hash target, 
                                           int num) {
  //DLOG(INFO) << "StorageManager::OnWriteImmutableDHTEntry:\n" << 
  // "  sha1: " << base::HexEncode(target.data(), 20) <<
  // "  num: " << num << "\n\n";
}

void StorageManager::OnCloneStorage(const base::Callback<void(int)>& cb, const libtorrent::entry& entry, const std::array<char, 32>& pk, const std::array<char, 64>& sig, const std::int64_t& seq, std::string const& salt, bool authoritative) {
  //LOG(INFO) << "StorageManager::OnCloneStorage";
  if (is_shutting_down_) {
    return;
  }

  auto pk_hex = base::HexEncode(pk.data(), 32);
  if (entry.type() == lt::entry::undefined_t) {
    LOG(ERROR) << "OnCloneStorage: error invalid entry payload received for " << pk_hex;
    cb.Run(net::ERR_FAILED);
    return;
  }

  storage_proto::StorageManifest manifest;
  if (!manifest.ParseFromString(entry.string())) {
    LOG(ERROR) << "OnCloneStorage: error while decoding entry '" << pk_hex << "':\n" << entry.to_string();
    cb.Run(net::ERR_FAILED);
    return;
  }

  //LOG(INFO) << "OnCloneStorage: creating disk " << manifest.name() << "...";

  Storage* disk = GetStorage(manifest.name());
  if (disk) {
    LOG(ERROR) << "OnCloneStorage: disk '" << manifest.name() << "' already created for " << pk_hex << 
    ". Why is this getting called more than once?";

    //std::vector<libtorrent::alert*> alerts;
    //torrent_manager_->session()->pop_alerts(&alerts);
    //for (libtorrent::alert* alert : alerts) {
    //  printf("[*] %s\n", alert->message().c_str());
    //}
    return;
  }

  std::unique_ptr<storage_proto::Info> registry_info = std::make_unique<storage_proto::Info>();
  for (int i = 0;i < manifest.record_size(); i++) {
    registry_info->CopyFrom(manifest.record(i));
  }

  disk = CloneStorageImpl(manifest.name(), registry_info->id(), pk.data());

  scoped_refptr<Torrent> torrent = torrent_manager_->NewTorrent(disk, std::move(registry_info));
  if (!torrent) {
    LOG(ERROR) << "OnCloneStorage: error while creating/adding torrent to torrent manager";
    cb.Run(net::ERR_FAILED);
    return;
  }

  // keep it til we know the files were transfered or cancelled
  task_list_mutex_.Acquire();
  scheduled_tasks_.push_back(base::Bind(cb, net::OK));
  task_list_mutex_.Release();

  // The code on the libtorrent side might be calling the callback
  // passed to 'GetMutableItem()' more than once
  // as a circumvent, we are using weak ptrs and once
  // theres a first dispatch we cancel the weak ptrs
  // so it should prevent another undesired call
  //main_runner_->PostTask(FROM_HERE, base::BindOnce(&StorageManager::InvalidateAllWeakPtrs, base::Unretained(this)));
}

}