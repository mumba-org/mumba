// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_LIB_STORAGE_STORAGE_H_
#define MUMBA_LIB_STORAGE_STORAGE_H_

#include <string>
#include <memory>
#include <vector>
#include <map>

#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/synchronization/waitable_event.h"
#include "base/single_thread_task_runner.h"
#include "base/uuid.h"
#include "base/atomic_sequence_num.h"
#include "storage/storage_resource.h"
#include "url/gurl.h"
#include "net/base/completion_callback.h"
#include "storage/storage_info.h"
#include "storage/storage_backend.h"
#include "storage/block.h"
#include "storage/io_handler.h"
#include "libtorrent/kademlia/ed25519.hpp"

namespace storage {
class Code;
class StorageFile;
class Catalog;

using CompletionCallback = base::Callback<void(int64_t)>;

// TODO: make Storage + StorageBackend into one
//       given the 'real' backend is already StorageBackend
class Storage : public StorageResource,
             public StorageBackend::Delegate,
             public IOHandler {
public:
 
  static std::unique_ptr<Storage> Create(const base::FilePath& dir,
                                      TorrentCache* torrent_cache,
                                      scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
                                      scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                      std::string id = std::string(),
                                      const char* pkey = nullptr,
                                      bool force = false);  
  // generic open
  static std::unique_ptr<Storage> Open(const base::FilePath& path,
                                    TorrentCache* torrent_cache,
                                    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
                                    scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner);
 
  static std::unique_ptr<Storage> Open(const base::FilePath& path,
                                    TorrentCache* torrent_cache,
                                    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
                                    scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                    std::unique_ptr<storage_proto::StorageState> state, bool first_run);

  ~Storage() override;
  
  void Start(base::Callback<void(Storage*, int)> callback = base::Callback<void(Storage*, int)>());
  void Stop(CompletionCallback callback = CompletionCallback());

  // StorageAsset overrides
  storage_proto::ResourceKind resource_type() const override;

  const base::FilePath& path() const override;
  size_t size() const;
  const std::string& address() const;
  bool is_signed() const;
  storage_proto::StorageStatus status() const;
  const storage_proto::StorageState* state() const {
    return state_.get();
  }

  scoped_refptr<Torrent> root_tree() const override;

  bool is_initializing() {
    return initializing_ || status() == storage_proto::STORAGE_STATUS_ONLINE;
  }

  StorageBackend* backend() const {
    return backend_.get();
  }

  bool is_owner() const override {
    return state_->owner();
  }

  bool sharing() const {
    return state_->sharing();
  }

  void set_sharing(bool sharing) {
    state_->set_sharing(sharing);
  }

  void CopyFile(
    const scoped_refptr<Torrent>& torrent,
    const base::FilePath& src,
    const CompletionCallback& callback);

  void CopyEntry(
    const scoped_refptr<Torrent>& torrent,
    const base::FilePath& dest,
    const CompletionCallback& callback);

  void InitEntry(const scoped_refptr<Torrent>& torrent,
                 const base::FilePath& src,
                 const CompletionCallback& callback);

  void InitEntry(const scoped_refptr<Torrent>& torrent,
                 const CompletionCallback& callback);

  void GetInfo(base::Callback<void(storage_proto::StorageState)> callback);

  void Query(const std::string& query_string,
             const std::string& catalog_name,
             base::Callback<void(std::unique_ptr<Block>, int64_t)> callback);
  
  void OpenDatabase(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb) override;
  void CreateDatabase(const scoped_refptr<Torrent>& torrent, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) override;

  void OpenFileset(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb);
  void CreateFileset(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb);
  
  void GetEntryInfo(const scoped_refptr<Torrent>& torrent, base::Callback<void(storage_proto::Info, int64_t)> cb);
  void ListEntries(base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb);

  std::vector<std::unique_ptr<storage_proto::Info>> GetAllEntriesInfos();
  
  // TODO: this api is not meant to leak as public
  //       we need to make a different interface
  //       so the internal consumer aka. the sqlite db
  //       and torrent file apis can reach this, but
  //       not the external consumer of this object interface
  const base::FilePath& GetPath() const override;
  bool ShouldSeed(const storage_proto::Info& info) override;
  Future<int> CreateTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> OpenTorrent(const scoped_refptr<Torrent>& torrent) override;
  Future<int> CloseTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> ReadTorrent(const scoped_refptr<Torrent>& torrent, void* buf, int64_t size, int64_t offset, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> WriteTorrent(const scoped_refptr<Torrent>& torrent, const void* buf, int64_t size, int64_t offset, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> DeleteTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal = false) override;
  int64_t GetTorrentSize(const scoped_refptr<Torrent>& torrent) override;
  Future<int> SyncTorrentMetadata(const scoped_refptr<Torrent>& torrent) override;

  scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner() const {
    return backend_task_runner_;
  }

private:
  class Context;

  Storage(TorrentCache* torrent_cache,
       const base::FilePath& path,
       scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
       scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
       std::unique_ptr<storage_proto::StorageState> state,
       std::string id,
       const char* pkey,
       bool first_run);

  void StopImpl();

  void OnBackendInit(base::Callback<void(Storage*, int)> callback, bool result);
  void ProcessScheduledIO();
  bool HasScheduledIO() const {
    return scheduled_io_.size() > 0;
  }

  void GetAllEntriesInfosImpl(std::vector<std::unique_ptr<storage_proto::Info>>* out);

  base::FilePath path_;

  std::unique_ptr<storage_proto::StorageState> state_;
 
  scoped_refptr<base::SingleThreadTaskRunner> frontend_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner_;

  std::unique_ptr<StorageBackend> backend_;

  base::AtomicSequenceNumber db_id_gen_;
  const char* given_pkey_if_cloned_ = nullptr;
  std::string given_id_if_cloned_;

  // ops called before a proper async initialization
  std::vector<base::OnceCallback<void()>> scheduled_io_;

  bool initialized_;
  bool first_run_;
  mutable bool initializing_;

  base::WaitableEvent init_event_;
  base::WaitableEvent event_wait_;

  DISALLOW_COPY_AND_ASSIGN(Storage);
};

}

#endif
