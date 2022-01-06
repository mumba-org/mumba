// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/torrent.h"

#include "base/strings/string_number_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "storage/storage.h"
#include "storage/torrent_manager.h"
#include "storage/torrent_observer.h"
#include "storage/db/sqlite3.h"
#include "libtorrent/torrent.hpp"

namespace storage {

namespace {

constexpr size_t kBlockSize = 65536;
constexpr size_t kSqliteInitialBlocks = 2;

}

Torrent::Torrent(
  TorrentManager* manager,
  scoped_refptr<Torrent> parent,
  std::unique_ptr<storage_proto::Info> info, 
  int storage_id, 
  IOHandler* io_handler,
  DbPolicy policy):
 manager_(manager),
 parent_(parent),
 storage_id_(storage_id),
 info_(std::move(info)),
 io_handler_(io_handler),
 entry_(nullptr),
 last_journal_seq_(0),
 entity_(nullptr),
 db_(nullptr),
 checked_(false),
 opened_(false),
 valid_(true),
 info_valid_(true),
 merkle_valid_(false),
 published_(false),
 is_dirty_(false),
 checkpoint_scheduled_(false),
 busy_counter_(0),
 policy_(policy),
 waiting_pending_io_(false),
 wait_pending_io_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC, base::WaitableEvent::InitialState::NOT_SIGNALED) {

 id_ = base::UUID(reinterpret_cast<const uint8_t*>(info_->id().data()));
}

Torrent::Torrent(
  TorrentManager* manager,
  scoped_refptr<Torrent> parent, 
  const base::UUID& id, 
  int storage_id, 
  IOHandler* io_handler,
  DbPolicy policy):
 manager_(manager),
 parent_(parent),
 id_(id),
 storage_id_(storage_id),
 info_(new storage_proto::Info()),
 io_handler_(io_handler),
 entry_(nullptr),
 last_journal_seq_(0),
 entity_(nullptr),
 db_(nullptr),
 checked_(false),
 opened_(false),
 valid_(false),
 info_valid_(false),
 merkle_valid_(false),
 published_(false),
 is_dirty_(false),
 checkpoint_scheduled_(false),
 busy_counter_(0),
 policy_(policy),
 waiting_pending_io_(false),
 wait_pending_io_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC, base::WaitableEvent::InitialState::NOT_SIGNALED) {
  info_->set_id(std::string(reinterpret_cast<const char *>(id_.data), 16));
  info_->set_state(storage_proto::STATE_NONE);
  if (parent_) {
    info_->set_tree(std::string(reinterpret_cast<const char *>(parent_->id().data), 16));
  }
}

Torrent::~Torrent() {

}

void Torrent::set_state(storage_proto::InfoState state) {
  info_->set_state(state);
  //for (int i = 0; i < info_.piece_count(); i++) {
  //  auto piece = info_.mutable_piece(i);
  //  piece->set_state(state);
  //}
  // TODO: what about the side-effects on the torrent?
  // suppose the torrent is in 'download' state...
  // we need to force the change there too
}

void Torrent::set_db(Database* db) {
  db_ = db;
}

bool Torrent::db_is_open() const { 
  //if ((is_tree() && !is_root()) || is_file()) {
  if (is_file()) {
    DCHECK(parent_);
    return parent_->db_is_open();
  }
  // is database or the root tree
  return db_ != nullptr ? !db_->is_closed() : false;
}

Database& Torrent::db() {
  //if ((is_tree() && !is_root()) || is_file()) {
  if (is_file()) {
    DCHECK(parent_);
    return parent_->db(); 
  }
  DCHECK(db_);
  // if the reference is retained outside of the lock
  // scope, does it actually work? 
  // i dont think so, so this autolock is probably useless
  base::AutoLock lock(db_mutex_);
  return *db_;
}

void Torrent::set_owned_db(std::unique_ptr<Database> db) {
  owned_db_ = std::move(db);
  db_ = owned_db_.get();
  //ScheduleCheckpoint();
}

bool Torrent::should_seed() const {
  return io_handler_->ShouldSeed(*info_);
}

const std::string& Torrent::path() const {
  return info_->path();
}

void Torrent::WaitPendingIO() {
  DCHECK(is_busy());
  waiting_pending_io_ = true;
  wait_pending_io_event_.Wait();
}

const char* Torrent::GetHash(int offset) {
  int64_t size = GetSize();
  int leaf_offset = merkle_tree_->first_leaf_offset() + offset;
  if (leaf_offset >= merkle_tree_->node_count()) {
    DLOG(ERROR) << "GetHash: leaf_offset > merkle tree block_count: " << leaf_offset << " > " << merkle_tree_->block_count();
    return nullptr;
  }
  DLOG(INFO) << "GetHash: getting " << offset + 1 << " of " << merkle_tree_->leaf_count() << ". leaf offset: " << leaf_offset << " node count " << merkle_tree_->node_count() << " piece count(leafs) = " << piece_count() << " " << size << " / " << kBlockSize <<  " = " << (size/kBlockSize);
  return merkle_tree_->node(leaf_offset)->hash();
}

bool Torrent::GetHashList(std::vector<const char *>* hashes) {
  int leaf_offset = merkle_tree_->first_leaf_offset();
  for (int i = 0; i < merkle_tree_->leaf_count(); ++i) {
    hashes->push_back(merkle_tree_->node(i + leaf_offset)->hash());
  }
  return true;
}

bool Torrent::GetHashMap(std::map<int, const char *>* hashes) {
  if (!merkle_tree_) {
    return false;
  }
  for (int i = 0; i < merkle_tree_->node_count(); ++i) {
    hashes->emplace(std::make_pair(i, merkle_tree_->node(i)->hash()));
  }
  return true;
}

bool Torrent::UpdateDigest(lt::torrent_handle handle) {
  std::map<int, const char *> hashes;
  if (!GetHashMap(&hashes)) {
    return false;
  }
  std::map<int, lt::sha1_hash> sha1_leafs;
  for (auto n : hashes) {
    sha1_leafs.emplace(std::make_pair(n.first, lt::sha1_hash(n.second)));
  }
  handle.native_handle()->add_merkle_nodes(sha1_leafs);
  return true;
}

int Torrent::Create(bool journal, int jrn_seq) {
  Future<int> future = io_handler_->CreateTorrent(this, journal, jrn_seq);
  int r = future.get(); 
  if (!journal) {
    opened_ = r == 0 ? true : false;
  }
  return r;
}

int Torrent::Open() {
  Future<int> future = io_handler_->OpenTorrent(this);
  int r = future.get(); 
  opened_ = r == 0 ? true : false;
  return r;
}

int Torrent::Read(void* buf, int64_t size, int64_t offset, bool journal, int jrn_seq) {
  Future<int> future = io_handler_->ReadTorrent(this, buf, size, offset, journal, jrn_seq);
  return future.get();
}

int Torrent::Write(const void* buf, int64_t size, int64_t offset, bool journal, int jrn_seq) {
  // this flag is used mostly for checkpoints
  //set_dirty(true);
  Future<int> future = io_handler_->WriteTorrent(this, buf, size, offset, journal, jrn_seq);
  return future.get();
}

int Torrent::Close(bool journal, int jrn_seq) {
  Future<int> future = io_handler_->CloseTorrent(this, journal, jrn_seq);
  int r = future.get();
  // after that, the entry cannot be acted upon
  if (!journal && r == 0) {
    entry_ = nullptr;
    opened_ = false;
  } //else {
  //  journal_entry_ = nullptr;
  //}
  return r;
}

bool Torrent::SyncMetadata() {
  // theres no need..
  if (!merkle_valid_) {
    return true;
  }
  // Theres no need.. merkle tree wasnt changed
  // after it was recovered from disk and its in 
  // sync with it
  if (!merkle_tree_->is_dirty()) {
    return true;
  }
  Future<int> future = io_handler_->SyncTorrentMetadata(this);
  int r = future.get();
  return r == 0;
}

int Torrent::Delete(bool journal) {
  Future<int> future = io_handler_->DeleteTorrent(this, journal);
  return future.get(); 
}

int64_t Torrent::GetSize() {
  return io_handler_->GetTorrentSize(this);
}

//const storage_proto::InfoPiece& Torrent::GetPieceInfo(int index) const {
//  DCHECK(index < info_->piece_count());
//  return info_->pieces(index);
//}

//storage_proto::InfoPiece* Torrent::GetPieceInfo(int index) {
//  DCHECK(index < info_->piece_count());
//  return info_->mutable_pieces(index);
//}

//void Torrent::SetPieceInfo(int index, const storage_proto::InfoPiece& piece) {
//  DCHECK(index < info_->piece_count());
//  storage_proto::InfoPiece* cur_piece = info_->mutable_pieces(index);
//  cur_piece->CopyFrom(piece);
//}

//void Torrent::AddPieceInfo(const storage_proto::InfoPiece& piece) {
//  auto new_piece = info_->add_pieces();
//  new_piece->CopyFrom(piece);
//}

int Torrent::piece_count() const {
  return info_->piece_count();
}

void Torrent::set_merkle_tree(std::unique_ptr<MerkleTree> merkle_tree) {
  merkle_tree_ = std::move(merkle_tree); 
  merkle_valid_ = true;
  //OnMetadataDone();
}

bool Torrent::LoadInfoFromBytes(const char* data, size_t size) {
  bool ok = info_->ParseFromArray(data, size);
  return ok;
}

void Torrent::LoadInfo(const storage_proto::Info& info) {
  info_->MergeFrom(info);
}

void Torrent::OnMetadataDone() {
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &Torrent::OnMetadataLoaded,
      base::Unretained(this),
      true));
}

bool Torrent::CreateMerkleTreeTables(int table_count) {
  // TODO: this is just for databases. fix for blobs
  // this is a db (or root tree) only method for now, so we expect this to be here
  DLOG(INFO) << "merkle tree: recovered " << table_count << " initial tables, with total of " << kSqliteInitialBlocks + table_count << " leafs";
  std::unique_ptr<MerkleTree> merkle_tree(new MerkleTree(kSqliteInitialBlocks + table_count));
  merkle_tree->Init();
  set_merkle_tree(std::move(merkle_tree));
  //OnMetadataDone();
  return true;
}

bool Torrent::CreateMerkleTreePieces(int piece_count) {
  LOG(INFO) << "merkle tree: creating merkle tree with " << piece_count << " initial blocks";
  std::unique_ptr<MerkleTree> merkle_tree(new MerkleTree(piece_count));
  merkle_tree->Init();
  set_merkle_tree(std::move(merkle_tree));
  //OnMetadataDone();
  return true;
}

bool Torrent::SerializeInfoToString(std::string* out) {
  return info_->SerializeToString(out);
}

int Torrent::NewJournalEntry() {
  journal_entry_mutex_.Acquire();
  int seq = last_journal_seq_;
  journal_entries_.emplace(std::make_pair(
    seq,
    JournalEntry {
      seq, 
      std::string(id_.to_string() + "-journal" + base::NumberToString(seq)), 
      nullptr }));
  last_journal_seq_++;
  journal_entry_mutex_.Release();
  return seq;
}

StorageEntry* Torrent::GetJournalEntry(int seq) {
  StorageEntry* fd = nullptr;
  journal_entry_mutex_.Acquire();
  auto it = journal_entries_.find(seq);
  if (it == journal_entries_.end()) {
    LOG(ERROR) << "GetJournalEntry: journal entry with sequence " << seq << " not found";
    journal_entry_mutex_.Release();
    return nullptr;
  }
  fd = it->second.fd;
  journal_entry_mutex_.Release();
  return fd;
}

void Torrent::SetJournalEntry(int seq, StorageEntry* fd) {
  journal_entry_mutex_.Acquire();
  auto it = journal_entries_.find(seq);
  if (it == journal_entries_.end()) {
    LOG(ERROR) << "SetJournalEntry: journal entry with sequence " << seq << " not found";
    journal_entry_mutex_.Release();
    return;
  }
  it->second.fd = fd;
  journal_entry_mutex_.Release();
}

std::string Torrent::GetJournalPath(int seq) {
  std::string result;
  journal_entry_mutex_.Acquire();
  auto it = journal_entries_.find(seq);
  if (it == journal_entries_.end()) {
    LOG(ERROR) << "GetJournalPath: journal entry with sequence " << seq << " not found";
    journal_entry_mutex_.Release();
    return result;
  }
  result = std::string(it->second.path);
  journal_entry_mutex_.Release();
  return result;
}

void Torrent::CloseJournal(int seq) {
  journal_entry_mutex_.Acquire();
  auto it = journal_entries_.find(seq);
  if (it == journal_entries_.end()) {
    LOG(ERROR) << "CloseJournal: journal entry with sequence " << seq << " not found";
    journal_entry_mutex_.Release();
    return;
  }
  StorageEntry* fd = it->second.fd;
  fd->Close();

  // we do this trick because the Delete op dont pass the sequence back to us
  // so we just schedule this journal to deletion
  journals_to_delete_.push_back(std::move(it->second));
  journal_entries_.erase(it);
  journal_entry_mutex_.Release();
}

std::pair<std::string, StorageEntry*> Torrent::PopJournalFromDeleteList() {
  // it does not matter if really is the target journal
  // some other delete op will collect, and in the end it will be even
  // (we do this because the Delete op dont pass the sequence back to us)
  journal_delete_mutex_.Acquire();
  StorageEntry* fd_to_delete = nullptr;
  std::string key_to_delete;
  for (auto it = journals_to_delete_.begin(); it != journals_to_delete_.end(); it++) {
    fd_to_delete = it->fd;
    key_to_delete = it->path;
    // its safe to erase here, because the 'break'
    // after this will make sure we wont use 
    // the (now) invalid iterator
    journals_to_delete_.erase(it);
    break;
  }
  journal_delete_mutex_.Release();
  return std::make_pair(std::move(key_to_delete), fd_to_delete);
}

void Torrent::Pause() {
  handle_.pause();
}

void Torrent::Resume() {
  handle_.resume();
}

void Torrent::Announce() {
  handle_.force_reannounce(); 
  handle_.force_dht_announce(); 
}

void Torrent::AddObserver(TorrentObserver* observer) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  observers_.push_back(observer);
}

void Torrent::RemoveObserver(TorrentObserver* observer) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void Torrent::OnMetadataLoaded(bool result) {
  DLOG(INFO) << "Torrent::OnMetadataLoaded";
  bool last_info_valid = info_valid_;
  info_valid_ = result;
  // if the info was not in a valid state
  // ping back torrent manager, to do whatever it needs
  // eg. add it to the torrent session
  if (!last_info_valid && result) {
    manager_->OnTorrentInfoLoaded(this);
  }
}

void Torrent::OnTorrentAddedToSession() {
  DLOG(INFO) << "Torrent::OnTorrentAddedToSession: setting sequencial download to true";
  handle_.native_handle()->set_sequential_download(true);
  published_ = true;
}

void Torrent::OnDHTAnnounceReply(int peers) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnDHTAnnounceReply(this, peers);
  }
}

void Torrent::OnMetadataReceived() {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentMetadataReceived(this);
  }
}

void Torrent::OnMetadataError(int error) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentMetadataError(this, error);
  }
}

void Torrent::OnPieceReadError(int piece, int error) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceReadError(this, piece, error);
  }
}

void Torrent::OnPieceRead(int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceRead(this, piece, offset, size, block_size, result);
  } 
}

void Torrent::OnPieceWrite(int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceWrite(this, piece, offset, size, block_size, result);
  }
}

void Torrent::OnPiecePass(int piece) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPiecePass(this, piece);
  }
}

void Torrent::OnPieceFailed(int piece) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceFailed(this, piece);
  }
}

void Torrent::OnPieceFinished(int piece) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceFinished(this, piece);
  }
}

void Torrent::OnPieceHashFailed(int piece) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceHashFailed(this, piece);
  }
}

void Torrent::OnFileCompleted(int piece) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentFileCompleted(this, piece);
  }
}

void Torrent::OnFinished() {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentFinished(this);
  }
}

void Torrent::OnDownloading() {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentDownloading(this);
  }
}

void Torrent::OnCheckingFiles() {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentCheckingFiles(this);
  }
}

void Torrent::OnDownloadingMetadata() {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentDownloadingMetadata(this);
  }
}

void Torrent::OnSeeding() {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentSeeding(this);
  }
}

void Torrent::OnPaused() {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPaused(this);
  }
}

void Torrent::OnResumed() {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentResumed(this);
  }
}

void Torrent::OnChecked() {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentChecked(this);
  }
}

void Torrent::OnDeleted() {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentDeleted(this);
  }
}

void Torrent::OnDeletedError(int error) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentDeletedError(this, error);
  }
}

void Torrent::OnFileRenamed(int file_offset, const std::string& name) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentFileRenamed(this, file_offset, name);
  }
}

void Torrent::OnFileRenamedError(int index, int error) {
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentFileRenamedError(this, index, error);
  }
}

void Torrent::ScheduleCheckpoint() {
  if (db_ && !checkpoint_scheduled_) {
    checkpoint_scheduled_ = true;
    base::PostDelayedTaskWithTraits(
      FROM_HERE, 
      { base::MayBlock() },
      base::BindOnce(&Torrent::MaybeCheckpoint, 
                      base::Unretained(this)),
      base::TimeDelta::FromMicroseconds(1000 * 10));
  }
}

void Torrent::MaybeCheckpoint() {
  bool checkpointed = false;
  int reason = SQLITE_OK;
  if (db_ && is_dirty_) {
    DLOG(INFO) << "Checkpointing the database..";
    db_mutex_.Acquire();
    checkpointed = db_->Checkpoint(&reason);
    db_mutex_.Release();
    checkpoint_scheduled_ = false;
    if (!checkpointed && reason == SQLITE_LOCKED) {
      DLOG(INFO) << "checkpointing failed because there was a transaction going on. reescheduling..";
      // there was a transaction going on
      // so schedule again
      ScheduleCheckpoint();     
    }
  }
}

void Torrent::set_dirty(bool dirty) {
  is_dirty_ = dirty;
  ScheduleCheckpoint();
}

}