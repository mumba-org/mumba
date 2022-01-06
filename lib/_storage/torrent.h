// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_TORRENT_H_
#define MUMBA_STORAGE_TORRENT_H_

#include <string>
#include <array>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/lock.h"
#include "storage/proto/storage.pb.h"
#include "storage/io_handler.h"
#include "storage/storage_export.h"
#include "libtorrent/torrent_handle.hpp"
#include "storage/db/db.h"
#include "storage/merkle_tree.h"

namespace storage {
class StorageEntry;
class TorrentObserver;
class TorrentManager;
class Storage;
class IOEntity;

class STORAGE_EXPORT Torrent : public base::RefCountedThreadSafe<Torrent> {
public:
  enum DbPolicy {
    kOPEN_CLOSE = 0,
    kKEEP_OPEN = 1
  };
  Torrent(TorrentManager* manager, scoped_refptr<Torrent> parent, std::unique_ptr<storage_proto::Info> info, int storage_id, IOHandler* io_handler, DbPolicy policy = kOPEN_CLOSE);
  Torrent(TorrentManager* manager, scoped_refptr<Torrent> parent, const base::UUID& id, int storage_id, IOHandler* io_handler, DbPolicy policy = kOPEN_CLOSE);

  storage_proto::InfoState state() const {
    return info_->state();
  }

  void set_state(storage_proto::InfoState state);

  bool valid() const {
    return valid_;
  }

  bool is_root() const {
    return parent_ == nullptr;
  }

  bool is_busy() const {
    //LOG(INFO) << "Torrent::is_busy: " << id_.to_string() << " busy_counter_ = " << busy_counter_;
    return busy_counter_ > 0;
  }

  // TODO: maybe a higher level BeginTransaction/EndTransaction
  // with the inc/dec inside of it would be better...

  // External 'transactions' know how/when this is desirable
  // the canonical one is the Context from StorageBackend
  void inc_busy_counter() {
    busy_counter_++; 
    //LOG(INFO) << "Torrent::inc_busy_counter: " << id_.to_string() << " busy_counter_ = " << busy_counter_;
  }

  // External 'transactions' know how/when this is desirable
  // the canonical one is the Context from StorageBackend
  void dec_busy_counter() {
    busy_counter_--;
    //LOG(INFO) << "Torrent::dec_busy_counter: " << id_.to_string() << " busy_counter_ = " << busy_counter_;
    if (busy_counter_ == 0 && waiting_pending_io_) {
//      LOG(INFO) << "" << id_.to_string() << " - busy_counter_ == 0 && wait_pending_io_event_ != nullptr. releasing pending io wait";
      wait_pending_io_event_.Signal();
      waiting_pending_io_ = false;
    }
  }

  const base::UUID& id() const {
    return id_;
  }

  int storage_id() const {
    return storage_id_;
  }

  const storage_proto::Info& info() const {
    return *info_;
  }

  storage_proto::Info* mutable_info() {
    return info_.get();
  }

  const libtorrent::torrent_handle& handle() const {
    return handle_;
  }

  void set_handle(libtorrent::torrent_handle&& handle) {
    handle_ = std::move(handle);
  }

  bool is_open() const {
    return opened_;
  }

  bool db_is_open() const;

  bool is_checked() const {
    return checked_;
  }

  bool is_published() const {
    return published_;
  }

  storage_proto::InfoKind type() const {
    return info_->kind();
  }

  scoped_refptr<Torrent> parent() const {
    return parent_;
  }

  //bool is_tree() const {
  //  return info_->kind() == storage_proto::INFO_TREE;
  //}

  bool is_raw() const {
    return info_->kind() == storage_proto::INFO_RAW;
  }

  bool is_data() const {
    return info_->kind() == storage_proto::INFO_DATA;
  }

  bool is_file() const {
    return info_->kind() == storage_proto::INFO_FILE;
  }

  //bool is_app() const {
//    return info_->kind() == storage_proto::INFO_APP;
 // }

  void set_checked(bool checked) {
    checked_ = checked;
  }

  void set_dirty(bool dirty);

  Database& db();

  DbPolicy db_policy() const {
    return policy_;
  }

  void set_db(Database* db);
  void set_owned_db(std::unique_ptr<Database> db);

  bool owns_db() const {
    return owned_db_ != nullptr;
  }

  bool is_downloading() const {
    return state() == storage_proto::STATE_DOWNLOADING; 
  }

  MerkleTree* merkle_tree() const {
    return merkle_tree_.get();
  }

  void set_merkle_tree(std::unique_ptr<MerkleTree> merkle_tree);

  IOEntity* entity() const {
    return entity_;
  }

  IOHandler* io_handler() const {
    return io_handler_;
  }

  void set_entity(IOEntity* entity) {
    entity_ = entity;
  }

  StorageEntry* entry() const {
    return entry_;
  }

  void set_entry(StorageEntry* entry) {
    entry_ = entry;
  }

  bool info_valid() const {
    return info_valid_;
  }

  bool merkle_valid() const {
    return merkle_valid_;
  }

  bool should_seed() const;

  const std::string& path() const;

  void AddObserver(TorrentObserver* observer);
  void RemoveObserver(TorrentObserver* observer);

  void WaitPendingIO();

  //const storage_proto::InfoPiece& GetPieceInfo(int index) const;
  //storage_proto::InfoPiece* GetPieceInfo(int index);
  //void AddPieceInfo(const storage_proto::InfoPiece& piece);
  //void SetPieceInfo(int index, const storage_proto::InfoPiece& piece);
  int piece_count() const;

  // TODO: We should create something like TorrentContent
  // or TorrentData, where we can instantiate and iterate
  // over contents of a torrent from 'raw' torrent data

  // also: we could distinguish this 'internal' interface
  // from something external.. this api get consumed by things
  // like db, but we could have a Open() for instance
  // where the 'user' or any consumer can use, that will
  // open the StorageEntry in the backend, but also make sure
  // the Database handle is also instantiated

  const char* GetHash(int offset);
  bool GetHashList(std::vector<const char *>* hashes);
  bool GetHashMap(std::map<int, const char *>* hashes);
  int Create(bool journal = false, int jrn_seq = -1);
  int Open();
  int Read(void* buf, int64_t size, int64_t offset, bool journal = false, int jrn_seq = -1);
  int Write(const void* buf, int64_t size, int64_t offset, bool journal = false, int jrn_seq = -1);
  int Close(bool journal = false, int jrn_seq = -1);
  int Delete(bool journal = false);
  bool UpdateDigest(lt::torrent_handle handle);
  int64_t GetSize();
  bool SyncMetadata();
  bool LoadInfoFromBytes(const char* data, size_t size);
  void LoadInfo(const storage_proto::Info& info);
  bool SerializeInfoToString(std::string* out);
  int NewJournalEntry();
  StorageEntry* GetJournalEntry(int seq);
  void SetJournalEntry(int seq, StorageEntry* fd);
  std::string GetJournalPath(int seq);
  void CloseJournal(int seq);
  std::pair<std::string, StorageEntry*> PopJournalFromDeleteList();
  bool CreateMerkleTreeTables(int table_count);
  bool CreateMerkleTreePieces(int piece_count);

  void Pause();
  void Resume();
  void Announce();

  void OnMetadataDone();

private:
  friend class TorrentManager;
  friend class Storage;
  friend class base::RefCountedThreadSafe<Torrent>;

  ~Torrent();

  struct JournalEntry {
    int seq;
    std::string path;
    StorageEntry* fd;
  };

  void OnMetadataLoaded(bool result);
  void OnTorrentAddedToSession();

  void OnDHTAnnounceReply(int peers);
  void OnMetadataReceived();
  void OnMetadataError(int error);
  void OnPieceReadError(int piece, int error);
  void OnPiecePass(int piece);
  void OnPieceFailed(int piece);
  void OnPieceRead(int piece, int64_t offset, int64_t size, int64_t block_size, int result);
  void OnPieceWrite(int piece, int64_t offset, int64_t size, int64_t block_size, int result);
  void OnPieceFinished(int piece);
  void OnPieceHashFailed(int piece);
  void OnFileCompleted(int piece);
  void OnFinished();
  void OnDownloading();
  void OnCheckingFiles();
  void OnDownloadingMetadata();
  void OnSeeding();
  void OnPaused();
  void OnResumed();
  void OnChecked();
  void OnDeleted();
  void OnDeletedError(int error);
  void OnFileRenamed(int file_offset, const std::string& name);
  void OnFileRenamedError(int index, int error);
  void ScheduleCheckpoint();
  void MaybeCheckpoint();
  
  TorrentManager* manager_;
  scoped_refptr<Torrent> parent_;
  base::UUID id_;
  int storage_id_;
  std::unique_ptr<storage_proto::Info> info_;
  libtorrent::torrent_handle handle_;
  std::unique_ptr<MerkleTree> merkle_tree_;
  IOHandler* io_handler_;
  StorageEntry* entry_;
  // when this is a database, there is a companion journal entry
  std::unordered_map<int, JournalEntry> journal_entries_;
  std::vector<JournalEntry> journals_to_delete_;
  std::vector<TorrentObserver *> observers_;
  base::Lock observer_list_mutex_;
  int last_journal_seq_;
  base::Lock journal_entry_mutex_;
  base::Lock journal_delete_mutex_;
  IOEntity* entity_;
  //TorrentState state_;
  // if this is a database type or a tree, and if it was opened
  // as a db, it will be cached here
  std::unique_ptr<Database> owned_db_;
  Database* db_;
  base::Lock db_mutex_;
  bool checked_;
  bool opened_;
  bool valid_;
  bool info_valid_;
  bool merkle_valid_;
  bool published_;
  bool is_dirty_;
  bool checkpoint_scheduled_;
  mutable int busy_counter_;
  DbPolicy policy_;
  mutable bool waiting_pending_io_;
  base::WaitableEvent wait_pending_io_event_;

  DISALLOW_COPY_AND_ASSIGN(Torrent);
};

}

#endif