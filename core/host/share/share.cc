// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/share/share.h"

#include "core/host/share/share_peer.h"
#include "core/host/share/share_database.h"
#include "core/host/share/share_manager.h"
#include "core/host/repo/repo.h"
#include "storage/storage.h"
#include "core/common/protocol/message_serialization.h"
#include "third_party/libtorrent/include/libtorrent/version.hpp"
#include "third_party/protobuf/src/google/protobuf/text_format.h"

namespace host {

char Share::kClassName[] = "share";

// static 
std::unique_ptr<Share> Share::Deserialize(ShareManager* manager, bool in_memory, net::IOBuffer* buffer, int size) {
  protocol::Share share_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  if (!share_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  std::vector<std::string> keyspaces;
  std::unique_ptr<Share> handle(new Share(manager, std::move(share_proto), keyspaces, in_memory));

  return handle;
} 

Share::Share(ShareManager* manager, protocol::Share share_proto, const std::vector<std::string>& keyspaces, bool in_memory): 
  id_(reinterpret_cast<const uint8_t *>(share_proto.uuid().data())),
  share_proto_(std::move(share_proto)),
  managed_(false),
  manager_(manager),
  db_(nullptr),
  keyspaces_(keyspaces),
  in_memory_(in_memory) {

}

Share::Share(ShareManager* manager, const std::string& domain, scoped_refptr<storage::Torrent> torrent, const std::vector<std::string>& keyspaces, bool in_memory): 
  domain_(domain),
  managed_(false),
  torrent_(torrent),
  manager_(manager),
  db_(nullptr),
  keyspaces_(keyspaces),
  in_memory_(in_memory) {
  DCHECK(torrent);
  torrent_->AddObserver(this);
  LoadInfoFromTorrent();
}

Share::~Share() {
  torrent_->RemoveObserver(this); 
}

bool Share::is_open() const {
  return torrent_->is_open();
} 

bool Share::db_is_open() const {
  return torrent_->db_is_open();
}

const storage_proto::Info& Share::info() {
  return torrent_->info(); 
}

protocol::Share::Kind Share::type() const {
  return share_proto_.kind(); 
}

void Share::set_type(protocol::Share::Kind type) {
  share_proto_.set_kind(type);
}

protocol::ShareState Share::state() const {
  return share_proto_.state();
}

void Share::set_state(protocol::ShareState state) {
  share_proto_.set_state(state);
}

protocol::ShareTransport Share::transport() const {
  return share_proto_.transport();
}

void Share::set_transport(protocol::ShareTransport transport) {
  share_proto_.mutable_transport()->CheckTypeAndMergeFrom(transport);
}

const std::string& Share::name() const {
  return share_proto_.name();
}

void Share::set_name(const std::string& name) {
  share_proto_.set_name(name);
}

const std::string& Share::manifest() const {
  return share_proto_.manifest();
}

void Share::set_manifest(const std::string& manifest) {
  share_proto_.set_manifest(manifest);
}

const std::string& Share::creator() const {
  return share_proto_.creator();
}

void Share::set_creator(const std::string& creator) {
  share_proto_.set_creator(creator);
}

const std::string& Share::domain() const {
  return share_proto_.domain();
}

void Share::set_domain(const std::string& domain) {
  share_proto_.set_domain(domain);
}

const std::string& Share::address() const {
  return share_proto_.address();
}

void Share::set_address(const std::string& url) {
  share_proto_.set_address(url);
}

protocol::AddressFormat Share::address_format() const {
  return share_proto_.address_format();
}

void Share::set_address_format(protocol::AddressFormat format) {
  share_proto_.set_address_format(format);
}

const std::string& Share::address_format_version() const {
  return share_proto_.address_format_version();
}

void Share::set_address_format_version(const std::string& address_format_version) {
  share_proto_.set_address_format_version(address_format_version);
}

const std::string& Share::root_hash() const {
  return share_proto_.root_hash();
}

void Share::set_root_hash(const std::string& root_hash) {
  share_proto_.set_root_hash(root_hash);
}

const std::string& Share::public_key() const {
  return share_proto_.pk_signature();
}

void Share::set_public_key(const std::string& key) {
  share_proto_.set_pk_signature(key);
  // update the underlying torrent dht key too
  std::array<char, 32> dht_public_key;
  std::copy(key.begin(), key.end(), dht_public_key.begin());
  //torrent_->set_dht_public_key(dht_public_key);
}

protocol::PKCryptoFormat Share::pk_crypto_format() const {
  return share_proto_.pk_crypto_format();
}

void Share::set_pk_crypto_format(protocol::PKCryptoFormat format) {
  share_proto_.set_pk_crypto_format(format);
}

int64_t Share::piece_count() const {
  return share_proto_.piece_count();
}

void Share::set_piece_count(int64_t piece_count) {
  share_proto_.set_piece_count(piece_count);
}

int64_t Share::piece_length() const {
  return share_proto_.piece_length();
}

void Share::set_piece_length(int64_t piece_length) {
  share_proto_.set_piece_length(piece_length);
}

int64_t Share::size() const {
  return share_proto_.size();
}

void Share::set_size(int64_t size) {
  share_proto_.set_size(size);
}

std::string Share::public_key_hex() const {
  if (pk_crypto_format() == protocol::PKCryptoFormat::ED25519 && public_key().size()) {
    return base::HexEncode(public_key().data(), 32);
  }
  return std::string();
}

scoped_refptr<ShareDatabase> Share::db() {
  if (!db_ && torrent_->is_data()) {  
    db_ = new ShareDatabase(this, torrent_->db_ref(), in_memory_);
  }
  DCHECK(db_);
  return db_;
}

void Share::Pause() {
  torrent_->Pause();
}

void Share::Resume() {
  torrent_->Resume(); 
}

void Share::Seed() {
  torrent_->Seed(); 
}

int Share::Read(void* buf, int64_t size, int64_t offset) {
  return torrent_->Read(buf, size, offset); 
}

void Share::ReadEntryFileAsSharedBuffer(
    const base::FilePath& file_path,       
    base::Callback<void(int64_t, mojo::ScopedSharedBufferHandle, int64_t)> callback) {
  storage::Storage* storage = manager_->GetStorage(domain());
  if (!storage) {
    DLOG(ERROR) << "Share::ReadEntryFileAsSharedBuffer: no storage found for domain " << domain();
    std::move(callback).Run(-1, mojo::ScopedSharedBufferHandle(), net::ERR_FAILED);
    return;
  }
  storage->ReadEntryFileAsSharedBuffer(torrent_, file_path, std::move(callback));
}

void Share::WriteEntryFile(
  const base::FilePath& file_path,
  int offset,
  int size,
  const std::vector<uint8_t>& data,       
  base::Callback<void(int64_t)> callback) {
  storage::Storage* storage = manager_->GetStorage(domain());
  if (!storage) {
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }
  storage->WriteEntryFile(torrent_, file_path, offset, size, data, std::move(callback)); 
}

int Share::Write(const void* buf, int64_t size, int64_t offset) {
  return torrent_->Write(buf, size, offset); 
}

int Share::Close() {
  return torrent_->Close();
}

void Share::AddObserver(ShareObserver* observer) {
  base::AutoLock lock(observers_lock_);
  observers_.push_back(observer);
}

void Share::RemoveObserver(ShareObserver* observer) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (*it == observer) {
      observers_.erase(it);
      return;
    }
  }
}

scoped_refptr<net::IOBufferWithSize> Share::Serialize() const {
  return protocol::SerializeMessage(share_proto_);
}

void Share::OnDHTAnnounceReply(scoped_refptr<storage::Torrent> torrent, int peers) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnDHTAnnounceReply(this, peers);
  } 
}

void Share::OnTorrentMetadataReceived(scoped_refptr<storage::Torrent> torrent) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareMetadataReceived(this);
  } 
}

void Share::OnTorrentMetadataError(scoped_refptr<storage::Torrent> torrent, int error) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareMetadataError(this, error);
  }
}

void Share::OnTorrentPieceReadError(scoped_refptr<storage::Torrent> torrent, int piece_offset, int error) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnSharePieceReadError(this, piece_offset, error);
  }
}

void Share::OnTorrentPiecePass(scoped_refptr<storage::Torrent> torrent, int piece_offset) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnSharePiecePass(this, piece_offset);
  }
}

void Share::OnTorrentPieceFailed(scoped_refptr<storage::Torrent> torrent, int piece_offset) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnSharePieceFailed(this, piece_offset);
  }
}

void Share::OnTorrentPieceRead(scoped_refptr<storage::Torrent> torrent, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnSharePieceRead(this, piece, offset, size, block_size, result);
  }
}

void Share::OnTorrentPieceWrite(scoped_refptr<storage::Torrent> torrent, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnSharePieceWrite(this, piece, offset, size, block_size, result);
  }
}

void Share::OnTorrentPieceFinished(scoped_refptr<storage::Torrent> torrent, int piece_offset) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnSharePieceFinished(this, piece_offset);
  }
}

void Share::OnTorrentPieceHashFailed(scoped_refptr<storage::Torrent> torrent, int piece_offset) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnSharePieceHashFailed(this, piece_offset);
  }
}

void Share::OnTorrentFileCompleted(scoped_refptr<storage::Torrent> torrent, int piece_offset) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareFileCompleted(this, piece_offset);
  }
}

void Share::OnTorrentFinished(scoped_refptr<storage::Torrent> torrent) {
  base::AutoLock lock(observers_lock_);
  set_state(protocol::kFINISHED);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareFinished(this);
  }
}

void Share::OnTorrentDownloading(scoped_refptr<storage::Torrent> torrent) {
  base::AutoLock lock(observers_lock_);
  set_state(protocol::kDOWNLOADING);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareDownloading(this);
  }
}

void Share::OnTorrentCheckingFiles(scoped_refptr<storage::Torrent> torrent) {
  base::AutoLock lock(observers_lock_);
  set_state(protocol::kCHECKING_FILES);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareCheckingFiles(this);
  }
}

void Share::OnTorrentDownloadingMetadata(scoped_refptr<storage::Torrent> torrent) {
  base::AutoLock lock(observers_lock_);
  set_state(protocol::kDOWNLOADING_METADATA);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareDownloadingMetadata(this);
  }
}

void Share::OnTorrentSeeding(scoped_refptr<storage::Torrent> torrent) {
  base::AutoLock lock(observers_lock_);
  set_state(protocol::kSEEDING);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareSeeding(this);
  }
}

void Share::OnTorrentPaused(scoped_refptr<storage::Torrent> torrent) {
  base::AutoLock lock(observers_lock_);
  set_state(protocol::kPAUSED);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnSharePaused(this);
  }
}

void Share::OnTorrentResumed(scoped_refptr<storage::Torrent> torrent) {
  base::AutoLock lock(observers_lock_);
  set_state(protocol::kRESUMED);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareResumed(this);
  }
}

void Share::OnTorrentChecked(scoped_refptr<storage::Torrent> torrent) {
  base::AutoLock lock(observers_lock_);
  set_state(protocol::kCHECKED);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareChecked(this);
  }
}

void Share::OnTorrentDeleted(scoped_refptr<storage::Torrent> torrent) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareDeleted(this);
  } 
}

void Share::OnTorrentDeletedError(scoped_refptr<storage::Torrent> torrent, int error) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareDeletedError(this, error);
  }  
}

void Share::OnTorrentFileRenamed(scoped_refptr<storage::Torrent> torrent, int file_offset, const std::string& name) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareFileRenamed(this, file_offset, name);
  } 
}

void Share::OnTorrentFileRenamedError(scoped_refptr<storage::Torrent> torrent, int index, int error) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnShareFileRenamedError(this, index, error);
  }  
}

void Share::OpenDatabaseSync(bool key_value) {
  storage::Database::Open(torrent_, key_value);
}

void Share::LoadInfoFromTorrent() {
  // a share is basically a torrent wrapper, so we reuse the uuid
  // to have a natural 1-1 mapping
  id_ = torrent_->id();
  share_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));

  set_domain(domain_);
  set_name(torrent_->info().path());
  set_type(static_cast<protocol::Share::Kind>(torrent_->info().kind()));
  set_state(static_cast<protocol::ShareState>(torrent_->info().state()));

  protocol::ShareTransport tr;
  tr.set_type(protocol::ShareTransportType::TORRENT);
  tr.set_name("torrent");
  tr.set_vendor("libtorrent");
  tr.set_version(libtorrent::version());

  set_transport(std::move(tr));
  set_creator(torrent_->info().created_by());

  set_piece_length(torrent_->info().piece_length());
  set_piece_count(torrent_->info().piece_count());
  set_size(torrent_->info().length());
  set_address(torrent_->info().magnet_url());
  set_address_format(protocol::AddressFormat::TORRENT_MAGNET);
  set_address_format_version("0.1");
  set_root_hash(torrent_->info().root_hash());
  set_pk_crypto_format(protocol::PKCryptoFormat::ED25519);
  if (torrent_->dht_public_key().size()) {
    set_public_key(torrent_->dht_public_key().data());
  }
  
  // std::string json_output;
  // google::protobuf::TextFormat::PrintToString(share_proto_, &json_output);
  // printf("%s\n", json_output.c_str());  
  // TODO: manifest
}

}
