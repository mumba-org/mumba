// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SHARE_SHARE_H_
#define MUMBA_HOST_SHARE_SHARE_H_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"
#include "storage/torrent.h"
#include "storage/torrent_observer.h"
#include "core/host/share/share_observer.h"
#include "core/host/share/share_database.h"

namespace host {
class Repo;
class SharePeer;
class ShareManager;

class Share : public ShareDatabase::Delegate,
              public Serializable,
              public storage::TorrentObserver {
public:
  static char kClassName[];
  static std::unique_ptr<Share> Deserialize(ShareManager* manager, bool in_memory, net::IOBuffer* buffer, int size);

  Share(ShareManager* manager, const std::string& domain, scoped_refptr<storage::Torrent> torrent, const std::vector<std::string>& keyspaces, bool in_memory);
  Share(ShareManager* manager, protocol::Share share_proto, const std::vector<std::string>& keyspaces, bool in_memory);
  ~Share() override;

  const base::UUID& id() const {
    return id_;
  }

  bool in_memory() const {
    return in_memory_;
  }

  const scoped_refptr<storage::Torrent>& torrent() const override {
    return torrent_;
  }

  void set_torrent(scoped_refptr<storage::Torrent> torrent) {
    torrent_ = std::move(torrent);
    torrent_->AddObserver(this);
  }

  protocol::Share::Kind type() const;
  void set_type(protocol::Share::Kind type);

  protocol::ShareState state() const;
  void set_state(protocol::ShareState state);

  protocol::ShareTransport transport() const;
  void set_transport(protocol::ShareTransport transport);

  const std::string& name() const override;
  void set_name(const std::string& name);
  const std::string& manifest() const;
  void set_manifest(const std::string& manifest);
  const std::string& creator() const;
  void set_creator(const std::string& creator);
  const std::string& domain() const;
  void set_domain(const std::string& domain);
  const std::string& address() const;
  void set_address(const std::string& url);
  protocol::AddressFormat address_format() const;
  void set_address_format(protocol::AddressFormat format);
  const std::string& address_format_version() const;
  void set_address_format_version(const std::string& address_format_version);
  const std::string& root_hash() const;
  void set_root_hash(const std::string& root_hash);
  const std::string& public_key() const;
  void set_public_key(const std::string& key);
  protocol::PKCryptoFormat pk_crypto_format() const;
  void set_pk_crypto_format(protocol::PKCryptoFormat format);
  int64_t piece_count() const;
  void set_piece_count(int64_t piece_count);
  int64_t piece_length() const;
  void set_piece_length(int64_t piece_length);
  int64_t size() const;
  void set_size(int64_t size);

  std::string public_key_hex() const;

  Repo* repo() const {
    return repo_;
  }

  const std::vector<SharePeer*>& peers() const {
    return peers_;
  }

  std::vector<SharePeer*>& peers() {
    return peers_;
  }

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  bool is_open() const;
  bool db_is_open() const;
  const storage_proto::Info& info();

  scoped_refptr<ShareDatabase> db();

  void Pause();
  void Resume();
  void Seed();

  int Read(void* buf, int64_t size, int64_t offset);
  void ReadEntryFileAsSharedBuffer(
    const base::FilePath& file_path,       
    base::Callback<void(int64_t, mojo::ScopedSharedBufferHandle, int64_t)> callback);
  int Write(const void* buf, int64_t size, int64_t offset);
  void WriteEntryFile(
    const base::FilePath& file_path,
    int offset,
    int size,
    const std::vector<uint8_t>& data,       
    base::Callback<void(int64_t)> callback);
  int Close();

  void AddObserver(ShareObserver* observer);
  void RemoveObserver(ShareObserver* observer);

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

private:

  void OnDHTAnnounceReply(scoped_refptr<storage::Torrent> torrent, int peers) override;
  void OnTorrentMetadataReceived(scoped_refptr<storage::Torrent> torrent) override;
  void OnTorrentMetadataError(scoped_refptr<storage::Torrent> torrent, int error) override;
  void OnTorrentPieceReadError(scoped_refptr<storage::Torrent> torrent, int piece_offset, int error) override;
  void OnTorrentPiecePass(scoped_refptr<storage::Torrent> torrent, int piece_offset) override;
  void OnTorrentPieceFailed(scoped_refptr<storage::Torrent> torrent, int piece_offset) override;
  void OnTorrentPieceRead(scoped_refptr<storage::Torrent> torrent, int piece, int64_t offset, int64_t size, int64_t block_size, int result) override;
  void OnTorrentPieceWrite(scoped_refptr<storage::Torrent> torrent, int piece, int64_t offset, int64_t size, int64_t block_size, int result) override;
  void OnTorrentPieceFinished(scoped_refptr<storage::Torrent> torrent, int piece_offset) override;
  void OnTorrentPieceHashFailed(scoped_refptr<storage::Torrent> torrent, int piece_offset) override;
  void OnTorrentFileCompleted(scoped_refptr<storage::Torrent> torrent, int piece_offset) override;
  void OnTorrentFinished(scoped_refptr<storage::Torrent> torrent) override;
  void OnTorrentDownloading(scoped_refptr<storage::Torrent> torrent) override;
  void OnTorrentCheckingFiles(scoped_refptr<storage::Torrent> torrent) override;
  void OnTorrentDownloadingMetadata(scoped_refptr<storage::Torrent> torrent) override;
  void OnTorrentSeeding(scoped_refptr<storage::Torrent> torrent) override;
  void OnTorrentPaused(scoped_refptr<storage::Torrent> torrent) override;
  void OnTorrentResumed(scoped_refptr<storage::Torrent> torrent) override;
  void OnTorrentChecked(scoped_refptr<storage::Torrent> torrent) override;
  void OnTorrentDeleted(scoped_refptr<storage::Torrent> torrent) override;
  void OnTorrentDeletedError(scoped_refptr<storage::Torrent> torrent, int error) override;
  void OnTorrentFileRenamed(scoped_refptr<storage::Torrent> torrent, int file_offset, const std::string& name) override;
  void OnTorrentFileRenamedError(scoped_refptr<storage::Torrent> torrent, int index, int error) override;

  void OpenDatabaseSync() override;

  void LoadInfoFromTorrent();
  
  base::UUID id_;

  std::string domain_;

  protocol::Share share_proto_;

  bool managed_;

  base::Lock observers_lock_;

  scoped_refptr<storage::Torrent> torrent_;

  std::vector<SharePeer*> peers_;
  std::vector<ShareObserver*> observers_;

  Repo* repo_;

  ShareManager* manager_;

  scoped_refptr<ShareDatabase> db_;
  std::vector<std::string> keyspaces_;
  
  bool in_memory_;
  
  DISALLOW_COPY_AND_ASSIGN(Share);
};

}

#endif
