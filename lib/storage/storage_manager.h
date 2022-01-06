// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_NET_MUMBA_MUMBA_SESSION_H_
#define MUMBA_NET_MUMBA_MUMBA_SESSION_H_

#include "base/macros.h"
#include "base/callback.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/synchronization/waitable_event.h"
#include "base/single_thread_task_runner.h"
//#include "net/quic/quartc/quartc_factory.h"
//#include "net/tools/epoll_server/epoll_server.h"
#include "libtorrent/kademlia/node.hpp"
#include "libtorrent/torrent_info.hpp"
#include "libtorrent/torrent_delegate.hpp"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/ct_serialization.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/cert/x509_util.h"
#include "net/http/transport_security_state.h"
#include "net/quic/chromium/crypto/proof_source_chromium.h"
#include "net/quic/core/crypto/proof_verifier.h"
#include "storage/storage.h"
#include "storage/proto/storage.pb.h"
#include "storage/torrent_manager.h"
#include "libtorrent/io_context.hpp"
#include "storage/storage_export.h"

namespace storage {
class Storage;
class StorageEntry;
class Block;
class TreeCatalog;
//using CompletionCallback = base::Callback<void(int64_t)>;


// FIXME: We should automate the DHT "Bootstrap" process to retry
//        within a period of time and to respond when the network
//        change its status offline <-> online

class STORAGE_EXPORT StorageManager : public TorrentManager::Delegate {
public:
  StorageManager(const base::FilePath& path);
  ~StorageManager() override;

  TorrentManager* torrent_manager() const {
    return torrent_manager_.get();
  }

  bool has_dht() const;

  void AddBootstrapNode(const net::IPEndPoint& endpoint);
  void Init(const base::Callback<void(int)>& init_cb, bool batch_mode = false);
  void Shutdown();

  void CreateStorage(const std::string& name, base::Callback<void(Storage*, int)> cb);
  void OpenStorage(const std::string& name, base::Callback<void(Storage*, int)> cb);
  Storage* GetStorage(const std::string& name);
  Storage* GetStorageByDHTAddress(const std::string& name);
  bool AddStorage(const std::string& name, std::unique_ptr<Storage> disk);
  bool RemoveStorage(const std::string& name, std::unique_ptr<Storage>* disk);
  void ListStorages(base::Callback<void(std::vector<const storage_proto::StorageState*>, int64_t)> cb);
  void CloneStorage(const std::string& addr, base::Callback<void(int)> cb);
  void ShareStorage(Storage* disk);
  void UnshareStorage(Storage* disk, base::Callback<void(int)> cb = base::Callback<void(int)>());

  // TorrentManager::Delegate
  const base::FilePath& root_path() const override {
    return root_path_;
  }
  // disks ops
  //void CopyFile(
  //  const std::string& disk,
  //  const base::UUID& key,
  //  const base::FilePath& src,
  //  const CompletionCallback& callback);

  scoped_refptr<Torrent> CopyEntry(
    const std::string& disk,
    const base::UUID& src,
    const base::FilePath& dest,
    const CompletionCallback& callback);
  
  scoped_refptr<Torrent> AddEntry(
    const std::string& disk,
    const base::FilePath& src,
    const CompletionCallback& callback,
    std::string name = std::string());

  void AddEntry(
    scoped_refptr<Torrent> torrent,
    const std::string& disk,
    const base::FilePath& src,
    const CompletionCallback& callback,
    std::string name = std::string());
  
  void GetInfo(const std::string& disk, base::Callback<void(storage_proto::StorageState)> callback);
  
  //void Query(const std::string& disk,
  //           const std::string& query_string,
  //           const std::string& catalog_name,
  //           base::Callback<void(std::unique_ptr<Block>, int64_t)> callback);

  scoped_refptr<Torrent> NewTorrent(const std::string& disk);
  scoped_refptr<Torrent> NewTorrent(const std::string& disk, const base::UUID& id, bool is_root = false);
  scoped_refptr<Torrent> NewTorrent(const std::string& disk, std::unique_ptr<storage_proto::Info> info, bool is_root);
  scoped_refptr<Torrent> NewTorrent(Storage* disk, std::unique_ptr<storage_proto::Info> info, bool is_root);
  scoped_refptr<Torrent> NewTorrent(Storage* disk, const base::UUID& id, bool is_root = false);
  scoped_refptr<Torrent> GetTorrent(const std::string& disk, const std::string& name);
  scoped_refptr<Torrent> GetTorrent(const std::string& disk, const base::UUID& id);
  scoped_refptr<Torrent> GetTorrent(const base::UUID& id) const;

  scoped_refptr<Torrent> CreateTorrent(const std::string& disk, storage_proto::InfoKind type, const std::string& name, std::vector<std::string> keyspaces = std::vector<std::string>(), base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<Torrent> CreateTorrent(const std::string& disk, storage_proto::InfoKind type, const base::UUID& id, const std::string& name, std::vector<std::string> keyspaces = std::vector<std::string>(), base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<Torrent> CreateTorrentWithInfohash(const std::string& disk, storage_proto::InfoKind type, const base::UUID& id, const std::string& name, const std::string& infohash, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<Torrent> OpenTorrent(const std::string& disk, const base::UUID& id, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<Torrent> OpenTorrent(const std::string& disk, const std::string& name, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<Torrent> OpenTorrent(Storage* disk, const base::UUID& id, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  bool OpenTorrent(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  bool DeleteTorrent(const std::string& disk, const base::UUID& key);
  bool DeleteTorrent(const std::string& disk, const std::string& name);
  bool DeleteTorrent(const scoped_refptr<Torrent>& torrent);
  bool AddTorrentToSessionOrUpdate(const scoped_refptr<Torrent>& torrent);

  void OpenDatabase(const std::string& disk, const base::UUID& key, base::Callback<void(int64_t)> cb);
  void OpenDatabase(const std::string& disk, const std::string& name, base::Callback<void(int64_t)> cb);
  void OpenDatabase(Storage* disk, const base::UUID& key, base::Callback<void(int64_t)> cb);
  void CreateDatabase(const std::string& disk, const std::string& db_name, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb);
  void GetEntryInfo(const std::string& disk, const base::UUID& key, base::Callback<void(storage_proto::Info, int64_t)> cb);
  void ListEntries(const std::string& disk, base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb);
  void CloseDatabase(const std::string& disk, const std::string& name, base::Callback<void(int64_t)> cb);
  void CloseDatabase(const std::string& disk, const base::UUID& key, base::Callback<void(int64_t)> cb);
  void CloseDatabase(Storage* disk, const base::UUID& key, base::Callback<void(int64_t)> cb);

  bool HasUUID(const std::string& disk_name, const base::UUID& uuid);
  bool GetUUID(const std::string& disk_name, const std::string& name, base::UUID* id);

private:

  void InitImpl();
  void ShutdownImpl();

  Storage* CloneStorageImpl(const std::string& name, std::string id, const std::array<char, 32>& pkey, std::unique_ptr<storage_proto::Info> registry_info);
  void ShareStorageImpl(Storage* disk, std::vector<std::unique_ptr<storage_proto::Info>> infos, int64_t result);
  void DestroyTracker(base::WaitableEvent* stop_event);
  bool OpenStorageInternal(const std::string& name, const base::FilePath& path);

  void OnBootstrap(std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const& dht_nodes);
  
  void OnStorageStarted(base::Callback<void(Storage*, int)> cb, Storage* disk, int result);
  void WriteMutableDHTEntry(Storage* disk,
                            libtorrent::entry& entry, 
                            std::array<char, 64>& signature, 
                            std::int64_t& seq, 
                            std::string const& salt);
  void OnWriteMutableDHTEntry(Storage* disk,
                              libtorrent::dht::item const& item, 
                              int num);

  void OnWriteImmutableDHTEntry(Storage* disk,
                                libtorrent::sha1_hash target, 
                                int num);

  // TorrentManagerDelegate

  void OnTorrentFinished(const scoped_refptr<Torrent>& torrent) override;
  void OnTorrentSeeding(const scoped_refptr<Torrent>& torrent) override;

  void CloneStorageOnBootstrap(const std::string& addr, std::array<char, 32> pub_key, base::Callback<void(int)> cb);

  void OnCloneStorage(const std::string& addr, const libtorrent::entry& entry, const std::array<char, 32>& pk, const std::array<char, 64>& sig, const std::int64_t& seq, std::string const& salt, bool authoritative);
  void ProcessWaitingBootstrapTasks();
  void CloneTorrentsFromRoot(const scoped_refptr<Torrent>& torrent);
  void AddTorrentsFromRoot(IOHandler* handler, const scoped_refptr<Torrent>& torrent, std::vector<std::unique_ptr<storage_proto::Info>> infos);
  std::vector<std::unique_ptr<storage_proto::Info>> ScanInfos(const scoped_refptr<Torrent>& torrent);
  bool HaveAllTorrentsInRoot(const std::vector<std::unique_ptr<storage_proto::Info>>& infos);
  void OnRootIndexLoaded(const scoped_refptr<Torrent>& torrent, int64_t r);
  void RunCloneCallback(const std::string& addr, int code);
  void OnIndexAddedForCreateTorrentWithInfohash(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb, int64_t result);

  base::FilePath root_path_;
  std::vector<net::IPEndPoint> bootstrap_routers_;
  scoped_refptr<base::SingleThreadTaskRunner> main_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> frontend_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> net_io_runner_;
  //scoped_refptr<base::SingleThreadTaskRunner> disk_frontend_task_runner_;
  //scoped_refptr<base::SingleThreadTaskRunner> disk_backend_task_runner_;
//  scoped_refptr<base::SingleThreadTaskRunner> db_task_runner_;
  std::unique_ptr<TorrentManager> torrent_manager_;
  std::unordered_map<std::string, std::unique_ptr<storage::Storage>> disks_;
  mutable bool bootstrap_pending_;
  mutable bool bootstraped_;
  bool batch_mode_;
  //base::AtomicSequenceNumber storage_index_seq_;
  int disk_started_counter_;
  std::vector<Storage*> disk_share_list_;
  std::vector<base::OnceCallback<void()>> waiting_bootstrap_tasks_;
  std::unordered_map<std::string, base::OnceCallback<void(int)>> waiting_clone_tasks_;
  std::vector<scoped_refptr<Torrent>> pending_torrents_to_clone_;
  base::Callback<void(int)> init_callback_;
  base::Lock init_cb_mutex_;
  base::Lock disks_mutex_;
  base::Lock disk_list_mutex_;
  base::Lock task_list_mutex_;
  base::WaitableEvent init_event_;
  std::unique_ptr<base::WaitableEvent> shutdown_event_;
  bool is_shutting_down_;
  
  DISALLOW_COPY_AND_ASSIGN(StorageManager);
};

}

#endif
