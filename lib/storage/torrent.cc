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
#include "libtorrent/peer_info.hpp"

namespace storage {

namespace {

constexpr size_t kBlockSize = 65536;
constexpr size_t kSqliteInitialBlocks = 2;

libtorrent::peer_source_flags_t ToPeerSourceFlags(Torrent::PeerSource source) {
  switch (source) {
    case Torrent::kPEER_SOURCE_TRACKER:
      return libtorrent::peer_info::tracker;
    case Torrent::kPEER_SOURCE_DHT:
      return libtorrent::peer_info::dht;
    case Torrent::kPEER_SOURCE_PEX:
      return libtorrent::peer_info::pex;
    case Torrent::kPEER_SOURCE_LSD:
      return libtorrent::peer_info::lsd;
  }
}

libtorrent::torrent_status::state_t ToLibTorrentState(Torrent::State state) {
  switch (state) {
    case Torrent::kCHECKING_FILES:
      return libtorrent::torrent_status::checking_files;
    case Torrent::kDOWNLOADING_METADATA:
      return libtorrent::torrent_status::downloading_metadata;
		case Torrent::kDOWNLOADING:
      return libtorrent::torrent_status::downloading;
		case Torrent::kFINISHED:
      return libtorrent::torrent_status::finished;
		case Torrent::kSEEDING:
      return libtorrent::torrent_status::seeding;
	  case Torrent::kALLOCATING:
      return libtorrent::torrent_status::allocating;
		case Torrent::kCHECKING_RESUME_DATA:
      return libtorrent::torrent_status::checking_resume_data;
  }
}

Torrent::State FromLibTorrentState(libtorrent::torrent_status::state_t state) {
  switch (state) {
    case libtorrent::torrent_status::checking_files:
      return Torrent::kCHECKING_FILES;
		case libtorrent::torrent_status::downloading_metadata:
      return Torrent::kDOWNLOADING_METADATA;
    case libtorrent::torrent_status::downloading:
      return Torrent::kDOWNLOADING;
    case libtorrent::torrent_status::finished:
      return Torrent::kFINISHED;
    case libtorrent::torrent_status::seeding:
      return Torrent::kSEEDING;
    case libtorrent::torrent_status::allocating:
      return Torrent::kALLOCATING;
    case libtorrent::torrent_status::checking_resume_data:
      return Torrent::kCHECKING_RESUME_DATA;
    default:
      NOTREACHED();
  }
}

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
 torrent_info_(std::make_shared<libtorrent::torrent_info>()),
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
 added_to_session_(false),
 published_on_dht_(false),
 is_cloning_(false),
 is_dirty_(false),
 io_locked_(false),
 in_sync_(false),
 checkpoint_scheduled_(false),
 is_opening_db_(false),
 busy_counter_(0),
 policy_(policy),
 waiting_pending_io_(false),
 metadata_loaded_(true),
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
 torrent_info_(std::make_shared<libtorrent::torrent_info>()),
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
 added_to_session_(false),
 published_on_dht_(false),
 is_dirty_(false),
 io_locked_(false),
 in_sync_(false),
 checkpoint_scheduled_(false),
 busy_counter_(0),
 policy_(policy),
 waiting_pending_io_(false),
 metadata_loaded_(false),
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
  if (db_->in_memory()) {
    opened_ = true;
  }
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
  is_opening_db_ = false;
  if (db_->in_memory()) {
    opened_ = true;
  }
  //ScheduleCheckpoint();
}

bool Torrent::should_seed() const {
  return have_metadata() ? io_handler_->ShouldSeed(*info_) : false;
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
  if (!merkle_tree_) {
    DLOG(ERROR) << "GetHash: trying to access a hash of a merkle that is unexistent";
    return nullptr;
  }
  int64_t size = GetSize();
  int leaf_offset = merkle_tree_->first_leaf_offset() + offset;
  //DLOG(INFO) << "Torrent::GetHash: " << id().to_string() << " offset: " << offset << " leaf_offset: " << leaf_offset << " first_leaf_offset: " << merkle_tree_->first_leaf_offset() << " node_count: " << merkle_tree_->node_count() << " block count: " << merkle_tree_->block_count();
  if (leaf_offset >= merkle_tree_->node_count()) {
    DLOG(ERROR) << "GetHash: leaf_offset > merkle tree node_count: " << leaf_offset << " > " << merkle_tree_->node_count();
    return nullptr;
  }
  //DLOG(INFO) << "GetHash: getting " << leaf_offset << " of " << merkle_tree_->node_count() << " piece count(leafs) = " << piece_count() << " " << size << " / " << kBlockSize <<  " = " << (size/kBlockSize);
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
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::UpdateDigest: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return false;
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
  // return future.get();
  int r = future.get();
  return r;
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
  int r = Sync();
  return r == 0;
}

int Torrent::Delete(bool journal) {
  Future<int> future = io_handler_->DeleteTorrent(this, journal);
  return future.get(); 
}

int Torrent::Sync() {
  if (is_syncing()) {
    return 0;
  }
  Future<int> future = io_handler_->SyncTorrent(this);
  return future.get();
}

int64_t Torrent::GetSize() {
  DCHECK(is_open());
  return io_handler_->GetTorrentSize(this);
}

void Torrent::BeginSync() {
  //DCHECK(!in_sync_);
  in_sync_ = true;
}

void Torrent::EndSync() {
  in_sync_ = false;
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
  return (info_->length() + info_->piece_length() - 1) / info_->piece_length();
  //return info_->piece_count();
}

int Torrent::piece_length() const {
  return info_->piece_length();
}

const libtorrent::sha1_hash& Torrent::info_hash() const {
  return torrent_info_->info_hash();
}

std::string Torrent::info_hash_hex() const {
  std::string ih_bytes = info_hash().to_string();
  return base::HexEncode(ih_bytes.data(), ih_bytes.size());
}

void Torrent::set_merkle_tree(std::unique_ptr<MerkleTree> merkle_tree) {
  merkle_tree_ = std::move(merkle_tree); 
  merkle_valid_ = true;
  //OnMetadataDone();
}

bool Torrent::LoadInfoFromBytes(const char* data, size_t size) {
  //DLOG(INFO) << "Torrent::LoadInfoFromBytes: " << id().to_string();
  bool ok = info_->ParseFromArray(data, size);
  return ok;
}

void Torrent::MergeInfo(const storage_proto::Info& info) {
  //DLOG(INFO) << "Torrent::MergeInfo: " << id().to_string();
  info_->MergeFrom(info);
}

void Torrent::CopyInfo(const storage_proto::Info& info) {
  //DLOG(INFO) << "Torrent::CopyInfo: " << id().to_string();
  info_->Clear();
  info_->MergeFrom(info);
}

void Torrent::OnMetadataDone() {
  //DLOG(INFO) << "Torrent::OnMetadataDone";
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &Torrent::OnMetadataLoaded,
      this,
      true));
}

bool Torrent::CreateMerkleTreeTables(int table_count) {
  // TODO: this is just for databases. fix for blobs
  // this is a db (or root tree) only method for now, so we expect this to be here
  //DLOG(INFO) << "merkle tree: recovered " << table_count << " initial tables, with total of " << kSqliteInitialBlocks + table_count << " leafs";
  std::unique_ptr<MerkleTree> merkle_tree(new MerkleTree(kSqliteInitialBlocks + table_count));
  merkle_tree->Init();
  set_merkle_tree(std::move(merkle_tree));
  //OnMetadataDone();
  return true;
}

bool Torrent::CreateMerkleTreeSQLTables(int table_count) {
  int new_blocks = table_count - 1;
  //DLOG(INFO) << "merkle tree: recovered " << table_count << " initial tables, with total of " << kSqliteInitialBlocks + new_blocks << " leafs";
  std::unique_ptr<MerkleTree> merkle_tree(new MerkleTree(kSqliteInitialBlocks + new_blocks));
  merkle_tree->Init();
  set_merkle_tree(std::move(merkle_tree));
  return true;
}

bool Torrent::CreateMerkleTreePieces(int piece_count) {
  //DLOG(INFO) << "merkle tree: creating merkle tree with " << piece_count << " initial blocks";
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
    journal_entry_mutex_.Release();
    return nullptr;
  }
  fd = it->second.fd;
  journal_entry_mutex_.Release();
  return fd;
}

bool Torrent::HaveJornalEntry(int seq) {
  base::AutoLock lock(journal_entry_mutex_);
  auto it = journal_entries_.find(seq);
  if (it != journal_entries_.end()) {
    return true;
  }
  return false;
}

void Torrent::SetJournalEntry(int seq, StorageEntry* fd) {
  journal_entry_mutex_.Acquire();
  auto it = journal_entries_.find(seq);
  if (it == journal_entries_.end()) {
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
    journal_entry_mutex_.Release();
    return;
  }
  StorageEntry* fd = it->second.fd;
  if (fd) {
    fd->Close();
  }

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

void Torrent::set_upload_mode(bool mode) {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::set_upload_mode: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  handle_.native_handle()->set_upload_mode(mode);
}

void Torrent::set_share_mode(bool mode) {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::set_share_mode: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  handle_.native_handle()->set_share_mode(mode);
}

void Torrent::set_announce_to_dht(bool announce) {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::set_announce_to_dht: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  handle_.native_handle()->set_announce_to_dht(announce);
}

void Torrent::set_announce_to_lsd(bool announce) {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::set_announce_to_lsd: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  handle_.native_handle()->set_announce_to_lsd(announce);
}

void Torrent::auto_managed(bool managed) {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::auto_managed: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  handle_.native_handle()->auto_managed(managed);
}

void Torrent::set_sequential_download(bool sequential) {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::set_sequential_download: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  handle_.native_handle()->set_sequential_download(sequential);
}

Torrent::State Torrent::torrent_state() const {
  return FromLibTorrentState(handle_.native_handle()->state());
}

void Torrent::set_torrent_state(Torrent::State state) {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::set_torrent_state: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  handle_.native_handle()->set_state(ToLibTorrentState(state));
}

void Torrent::Pause() {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::Pause: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  handle_.native_handle()->pause();
}

void Torrent::Resume() {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::Resume: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  handle_.native_handle()->resume();
}

void Torrent::Announce() {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::Announce: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  handle_.force_reannounce(); 
  handle_.force_dht_announce(); 
}

void Torrent::Seed() {
  set_torrent_state(kSEEDING);
  Resume();
}

void Torrent::AddPeer(const char* address, int port, PeerSource source) {
  if (!handle_.is_valid()) {
    DLOG(ERROR) << "Torrent::AddPeer: torrent handle for " << id().to_string() << " is not valid. cancelling";
    return;
  }
  libtorrent::tcp::endpoint peer(boost::asio::ip::make_address_v4(address), port);
  handle_.native_handle()->add_peer(peer, ToPeerSourceFlags(source));
}

bool Torrent::Lock() {
  if (!io_locked_) {
    io_locked_ = true;
    return true;
  }
  return false;
}

bool Torrent::Unlock() {
  if (io_locked_) {
    io_locked_ = false;
    return true;
  }
  return false;
}

void Torrent::retain(const scoped_refptr<StorageContext>& context) {
  base::AutoLock lock(retained_by_mutex_);
  retained_by_.emplace(std::make_pair(context->id, context));
  //base::PostDelayedTask(FROM_HERE, base::Bind(&PrintRetainedBy, context, scoped_refptr<Torrent>(this)), base::TimeDelta::FromMilliseconds(5 * 1000));
  busy_counter_++;
}

// External 'transactions' know how/when this is desirable
// the canonical one is the Context from StorageBackend
void Torrent::release(const scoped_refptr<StorageContext>& context) {
  base::AutoLock lock(retained_by_mutex_);
  auto it = retained_by_.find(context->id);
  retained_by_.erase(it);
  busy_counter_--;
  if (busy_counter_ == 0 && waiting_pending_io_) {
    wait_pending_io_event_.Signal();
    waiting_pending_io_ = false;
  }
}

void Torrent::DoomEntry() {
  //base::AutoLock lock(entry_mutex_);
  entry_->Doom();
}

void Torrent::CloseEntry(CompletionCallback callback) {
  //base::AutoLock lock(entry_mutex_);
  entry_->Close(std::move(callback));
}

std::string Torrent::GetEntryKey() {
  //base::AutoLock lock(entry_mutex_);
  return entry_->GetKey();
}

base::Time Torrent::GetEntryLastUsed() {
  //base::AutoLock lock(entry_mutex_);
  return entry_->GetLastUsed();
}

base::Time Torrent::GetEntryLastModified() {
  //base::AutoLock lock(entry_mutex_);
  return entry_->GetLastModified();
}

int64_t Torrent::GetEntryDataSize(int index) {
  //base::AutoLock lock(entry_mutex_);
  return entry_->GetDataSize(index);
}

int Torrent::ReadEntryData(int index,
                           int64_t offset,
                           net::IOBuffer* buf,
                           int64_t buf_len,
                           const CompletionCallback& callback) {
  //base::AutoLock lock(entry_mutex_);
  return entry_->ReadData(index, offset, buf, buf_len, callback);
}

int Torrent::WriteEntryData(int index,
                            int64_t offset,
                            net::IOBuffer* buf,
                            int64_t buf_len,
                            const CompletionCallback& callback,
                            bool truncate) {
  //base::AutoLock lock(entry_mutex_);
  return entry_->WriteData(index, offset, buf, buf_len, callback, truncate);
}

int Torrent::ReadEntrySparseData(int64_t offset,
                                 net::IOBuffer* buf,
                                 int64_t buf_len,
                                 const CompletionCallback& callback) {
  //base::AutoLock lock(entry_mutex_);
  return entry_->ReadSparseData(offset, buf, buf_len, callback);
}

int Torrent::WriteEntrySparseData(int64_t offset,
                                  net::IOBuffer* buf,
                                  int64_t buf_len,
                                  const CompletionCallback& callback) {
  //base::AutoLock lock(entry_mutex_);
  return entry_->WriteSparseData(offset, buf, buf_len, callback);
}

int Torrent::GetEntryAvailableRange(int64_t offset,
                                    int64_t len,
                                    int64_t* start,
                                    const CompletionCallback& callback) {
  //base::AutoLock lock(entry_mutex_);
  return entry_->GetAvailableRange(offset, len, start, callback);
}

bool Torrent::CouldEntryBeSparse() {
  //base::AutoLock lock(entry_mutex_);
  return entry_->CouldBeSparse();
}

void Torrent::CancelEntrySparseIO() {
  //base::AutoLock lock(entry_mutex_);
  entry_->CancelSparseIO();
}

int Torrent::ReadyEntryForSparseIO(const CompletionCallback& callback) {
  //base::AutoLock lock(entry_mutex_);
  return entry_->ReadyForSparseIO(callback);
}

bool Torrent::EntryIsModified() {
  //base::AutoLock lock(entry_mutex_);
  return entry_->is_modified();
}

bool Torrent::EntryIsNew() {
  //base::AutoLock lock(entry_mutex_);
  return entry_->is_new();
}

void Torrent::EntrySetIsNew(bool is_new) {
  //base::AutoLock lock(entry_mutex_);
  return entry_->set_is_new(is_new);
}

int Torrent::EntrySync(const CompletionCallback& callback) {
  //base::AutoLock lock(entry_mutex_);
  return entry_->Sync(callback);
}

void Torrent::EntrySetModified(bool is_modified) {
  //base::AutoLock lock(entry_mutex_);
  if (entry_) {
    entry_->set_modified(is_modified);
  }
}

int Torrent::ReadJournalEntryData(
    int journal_seq,
    int index,
    int64_t offset,
    net::IOBuffer* buf,
    int64_t buf_len,
    const CompletionCallback& callback) {
  StorageEntry* entry = GetJournalEntry(journal_seq);
  if (!entry) {
    return net::ERR_FAILED;
  }
  return entry->ReadData(index, offset, buf, buf_len, callback);
}
    
int Torrent::WriteJournalEntryData(
    int journal_seq,
    int index,
    int64_t offset,
    net::IOBuffer* buf,
    int64_t buf_len,
    const CompletionCallback& callback,
    bool truncate) {
  StorageEntry* entry = GetJournalEntry(journal_seq);
  if (!entry) {
    return net::ERR_FAILED;
  }
  return entry->WriteData(index, offset, buf, buf_len, callback, truncate);
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
  //DLOG(INFO) << "Torrent::OnMetadataLoaded: r = " << result << " last info valid? " << info_valid_;
  bool last_info_valid = info_valid_;
  info_valid_ = result;
  metadata_loaded_ = result;
  // if the info was not in a valid state
  // ping back torrent manager, to do whatever it needs
  // eg. add it to the torrent session
  if (result) {//(!last_info_valid && result) {
    manager_->OnTorrentInfoLoaded(this);
  }
}

void Torrent::OnTorrentAddedToSession() {
  //DLOG(INFO) << "Torrent::OnTorrentAddedToSession: sequencial download -> true. should_seed() ? " << should_seed();
  set_sequential_download(true);
  added_to_session_ = true;
  if (should_seed()) {
    Seed();
  }
}

void Torrent::OnDHTAnnounceReply(int peers) {
  //DLOG(INFO) << "Torrent::OnDHTAnnounceReply: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  published_on_dht_ = peers > 0 ? true : false;
  for (auto* observer : observers_) {
    observer->OnDHTAnnounceReply(this, peers);
  }
}

void Torrent::OnMetadataReceived() {
  //DLOG(INFO) << "Torrent::OnMetadataReceived: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentMetadataReceived(this);
  }
}

void Torrent::OnMetadataError(int error) {
  //DLOG(INFO) << "Torrent::OnMetadataError: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentMetadataError(this, error);
  }
}

void Torrent::OnPieceReadError(int piece, int error) {
  //DLOG(INFO) << "Torrent::OnPieceReadError: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceReadError(this, piece, error);
  }
}

void Torrent::OnPieceRead(int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  //DLOG(INFO) << "Torrent::OnPieceRead: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceRead(this, piece, offset, size, block_size, result);
  } 
}

void Torrent::OnPieceWrite(int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  //DLOG(INFO) << "Torrent::OnPieceWrite: " << info_hash_hex() << " piece: " << piece;
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceWrite(this, piece, offset, size, block_size, result);
  }
}

void Torrent::OnPiecePass(int piece) {
  //DLOG(INFO) << "Torrent::OnPiecePass: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPiecePass(this, piece);
  }
}

void Torrent::OnPieceFailed(int piece) {
  //DLOG(INFO) << "Torrent::OnPieceFailed: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceFailed(this, piece);
  }
}

void Torrent::OnPieceFinished(int piece) {
  //DLOG(INFO) << "Torrent::OnPieceFinished: " << info_hash_hex() << " piece: " << piece;
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceFinished(this, piece);
  }
}

void Torrent::OnPieceHashFailed(int piece) {
  //DLOG(INFO) << "Torrent::OnPieceHashFailed: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPieceHashFailed(this, piece);
  }
}

void Torrent::OnFileCompleted(int piece) {
  //DLOG(INFO) << "Torrent::OnFileCompleted: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentFileCompleted(this, piece);
  }
}

void Torrent::OnFinished() {
  //DLOG(INFO) << "Torrent::OnFinished: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentFinished(this);
  }
}

void Torrent::OnDownloading() {
  if (!have_metadata()) {
    // for magnet link torrents, once its on Downloading state, it means
    // it received the metadata. So we need to update this torrent state
    // with the data from it
    //DLOG(INFO) << "Torrent::OnDownloading: torrent with no metadata. updating";
    torrent_info_ = handle_.native_handle()->mutable_torrent_file();
    if (!torrent_info_->parse_to_protobuf(info_.get())) {
      DLOG(INFO) << "Torrent::OnDownloading: failed to update torrent protobuf info from torrent metadata";
    } else {
      //DLOG(INFO) << "Torrent::OnDownloading: update torrent protobuf info from torrent metadata ok";
      metadata_loaded_ = true;
    }
  }
  //DLOG(INFO) << "Torrent::OnDownloading: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentDownloading(this);
  }
}

void Torrent::OnCheckingFiles() {
  //DLOG(INFO) << "Torrent::OnCheckingFiles: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentCheckingFiles(this);
  }
}

void Torrent::OnDownloadingMetadata() {
  //DLOG(INFO) << "Torrent::OnDownloadingMetadata: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentDownloadingMetadata(this);
  }
}

void Torrent::OnSeeding() {
  //DLOG(INFO) << "Torrent::OnSeeding: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentSeeding(this);
  }
}

void Torrent::OnPaused() {
  //DLOG(INFO) << "Torrent::OnPaused: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentPaused(this);
  }
}

void Torrent::OnResumed() {
  //DLOG(INFO) << "Torrent::OnResumed: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentResumed(this);
  }
}

void Torrent::OnChecked() {
  //DLOG(INFO) << "Torrent::OnChecked: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentChecked(this);
  }
}

void Torrent::OnDeleted() {
  //DLOG(INFO) << "Torrent::OnDeleted: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentDeleted(this);
  }
}

void Torrent::OnDeletedError(int error) {
  //DLOG(INFO) << "Torrent::OnDeletedError: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentDeletedError(this, error);
  }
}

void Torrent::OnFileRenamed(int file_offset, const std::string& name) {
  //DLOG(INFO) << "Torrent::OnFileRenamed: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentFileRenamed(this, file_offset, name);
  }
}

void Torrent::OnFileRenamedError(int index, int error) {
  //DLOG(INFO) << "Torrent::OnFileRenamedError: " << info_hash_hex();
  base::AutoLock scoped_lock(observer_list_mutex_);
  for (auto* observer : observers_) {
    observer->OnTorrentFileRenamedError(this, index, error);
  }
}

void Torrent::ScheduleCheckpoint() {
  ScheduleCheckpoint(0);
}

void Torrent::ScheduleCheckpoint(int seconds) {
  if (db_ && !checkpoint_scheduled_) {
    checkpoint_scheduled_ = true;
    if (seconds > 0) {
      base::PostDelayedTaskWithTraits(
        FROM_HERE, 
        { base::MayBlock() },
        base::BindOnce(&Torrent::MaybeCheckpoint, 
                       this),
        base::TimeDelta::FromMicroseconds(1000 * seconds));
    } else {
      base::PostTaskWithTraits(
        FROM_HERE, 
        { base::MayBlock() },
        base::BindOnce(&Torrent::MaybeCheckpoint, 
                       this));
    }
  }
}

void Torrent::MaybeCheckpoint() {
  bool checkpointed = false;
  int reason = SQLITE_OK;
  if (db_ && is_dirty_) {
    //D//LOG(INFO) << "Checkpointing the database..";
    db_mutex_.Acquire();
    checkpointed = db_->Checkpoint(&reason);
    db_mutex_.Release();
    checkpoint_scheduled_ = false;
    if (!checkpointed && reason == SQLITE_LOCKED) {
      //D//LOG(INFO) << "checkpointing failed because there was a transaction going on. reescheduling..";
      // there was a transaction going on
      // so schedule again
      ScheduleCheckpoint(2);     
    }
    if (checkpointed) {
      Sync();
    }
  }
}

void Torrent::set_dirty(bool dirty) {
  is_dirty_ = dirty;
  //ScheduleCheckpoint();
}

}