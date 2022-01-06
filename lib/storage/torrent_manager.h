// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_TORRENT_MANAGER_H_
#define MUMBA_STORAGE_TORRENT_MANAGER_H_

#include <memory>
#include <vector>

#include "base/macros.h"
#include "base/callback.h"
#include "base/single_thread_task_runner.h"
#include "base/memory/weak_ptr.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/synchronization/waitable_event.h"
#include "net/base/ip_endpoint.h"
#include "storage/storage_export.h"
#include "libtorrent/flags.hpp"
#include "libtorrent/torrent_delegate.hpp"
#include "libtorrent/add_torrent_params.hpp"
#include "libtorrent/session.hpp"
#include "libtorrent/ip_voter.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/socket.hpp"
#include "libtorrent/peer_id.hpp"
#include "libtorrent/tracker_manager.hpp"
#include "libtorrent/debug.hpp"
#include "libtorrent/piece_block_progress.hpp"
#include "libtorrent/ip_filter.hpp"
#include "libtorrent/aux_/ip_notifier.hpp"
#include "libtorrent/session_status.hpp"
#include "libtorrent/add_torrent_params.hpp"
#include "libtorrent/stat.hpp"
#include "libtorrent/bandwidth_manager.hpp"
#include "libtorrent/disk_io_thread.hpp"
#include "libtorrent/udp_socket.hpp"
#include "libtorrent/assert.hpp"
#include "libtorrent/alert_manager.hpp"
#include "libtorrent/deadline_timer.hpp"
#include "libtorrent/socket_io.hpp"
#include "libtorrent/aux_/socket_type.hpp"
#include "libtorrent/aux_/session_udp_sockets.hpp"
#include "libtorrent/aux_/session_impl.hpp"
#include "libtorrent/address.hpp"
#include "libtorrent/utp_socket_manager.hpp"
#include "libtorrent/bloom_filter.hpp"
#include "libtorrent/peer_class.hpp"
#include "libtorrent/peer_class_type_filter.hpp"
#include "libtorrent/kademlia/dht_observer.hpp"
#include "libtorrent/kademlia/dht_state.hpp"
#include "libtorrent/kademlia/dht_storage.hpp"
#include "libtorrent/kademlia/announce_flags.hpp"
#include "libtorrent/kademlia/dht_settings.hpp"
#include "libtorrent/kademlia/item.hpp"
#include "libtorrent/resolver.hpp"
#include "libtorrent/invariant_check.hpp"
#include "libtorrent/extensions.hpp"
#include "libtorrent/aux_/portmap.hpp"
#include "libtorrent/aux_/lsd.hpp"
#include "libtorrent/io_context.hpp"
#include "libtorrent/peer_connection.hpp"
#include "storage/proto/storage.pb.h"
#include "storage/torrent_cache.h"

namespace libtorrent {
namespace dht {
struct dht_tracker;
class alert;
}  
}

namespace storage {
class Storage;
class Torrent;
class TorrentManager;

class TorrentManagerContext : public libtorrent::TorrentStorageDelegate,
                              public base::RefCountedThreadSafe<TorrentManagerContext> {
public:
  TorrentManagerContext(TorrentManager* manager);

  bool OpenEntry(lt::storage_index_t storage) override;
  bool CreateEntry(lt::storage_index_t storage) override;
  bool EntryChecked(lt::storage_index_t storage) override;
  void SetEntryChecked(lt::storage_index_t storage, bool checked) override;
  const char* GetEntryHash(lt::storage_index_t storage, lt::piece_index_t piece) override;
  std::vector<const char *> GetEntryBlockHashes(lt::storage_index_t storage) override;
  void UpdateMerkleTree(lt::storage_index_t storage, const std::vector<const char *>& block_hashes) override;
  void ReadEntry(lt::storage_index_t storage, lt::span<lt::iovec_t const> bufs, lt::piece_index_t const piece, int const offset, lt::storage_error& error) override;
  void WriteEntry(lt::storage_index_t storage, lt::span<lt::iovec_t const> bufs, lt::piece_index_t const piece, int const offset, lt::storage_error& error) override;
  void OnReleaseFiles(lt::storage_index_t storage) override;

private:
  friend class base::RefCountedThreadSafe<TorrentManagerContext>;
  ~TorrentManagerContext() override;
  
  TorrentManager* manager_;

  DISALLOW_COPY_AND_ASSIGN(TorrentManagerContext);
};

class STORAGE_EXPORT TorrentManager : public libtorrent::dht::dht_observer,
                                      public libtorrent::TorrentDelegate,
                                      public libtorrent::SessionDelegate,
                                      public TorrentCache {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual const base::FilePath& root_path() const = 0;
    virtual void OnTorrentFinished(const scoped_refptr<Torrent>& torrent) = 0;
    virtual void OnTorrentSeeding(const scoped_refptr<Torrent>& torrent) = 0;
  };

  TorrentManager(Delegate* delegate, scoped_refptr<base::SingleThreadTaskRunner> backend_io_runner);
  ~TorrentManager() override;

  bool has_dht() const;

  bool started() const {
    return started_;
  }

  libtorrent::aux::session_impl* session() const {
    return session_.get();
  }

  // TorrentCache
  scoped_refptr<Torrent> NewTorrent(IOHandler* io_handler, std::unique_ptr<storage_proto::Info> info, bool is_root = false) override;
  scoped_refptr<Torrent> NewTorrent(IOHandler* io_handler, const base::UUID& id, bool is_root = false) override;
  scoped_refptr<Torrent> GetTorrent(int index) const override {
    auto it = torrent_list_.find(index);
    return (it == torrent_list_.end()) ? scoped_refptr<Torrent>() : it->second;
  }
  scoped_refptr<Torrent> GetTorrent(const base::UUID& id) const override;
  void AddTorrent(int index, scoped_refptr<Torrent> torrent) override;
  void RemoveTorrent(int index) override;
  size_t TorrentCount() const override {
    return torrent_list_.size();
  }

  bool HasTorrent(int index) const override {
    auto it = torrent_list_.find(index);
    return it == torrent_list_.end() ? false : true;
  }

  bool HasTorrent(const base::UUID& id) const override;

  scoped_refptr<Torrent> GetOrCreateTorrent(IOHandler* io_handler, const base::UUID& id);

  scoped_refptr<Torrent> GetTorrentSafe(int index) {
    torrent_list_mutex_.Acquire();
    auto it = torrent_list_.find(index);
    bool found = it != torrent_list_.end();
    torrent_list_mutex_.Release();
    return found ? it->second : scoped_refptr<Torrent>();
  }

  void Start(base::Callback<void(std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const&)> bootstrap_cb);
  void Stop();
  void Shutdown();

  void Update(base::Callback<void(std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const&)> bootstrap_cb);

  void AddNode(const net::IPEndPoint& endpoint);
  void AddRouterNode(const net::IPEndPoint& endpoint);
  void AddBootstrapNode(const net::IPEndPoint& endpoint);

  void GetImmutableItemSha1Hex(const std::string& sha1_hex, base::Callback<void(libtorrent::sha1_hash target, libtorrent::dht::item const& i)> cb);
  void GetImmutableItem(libtorrent::sha1_hash const& target, base::Callback<void(libtorrent::sha1_hash target, libtorrent::dht::item const& i)> cb);
  void GetMutableItem(std::array<char, 32> key, const base::Callback<void(const libtorrent::entry&, const std::array<char, 32>&, const std::array<char, 64>&, const std::int64_t&, std::string const&, bool)>& get_cb, std::string salt = std::string());

  void GetAlerts(std::vector<libtorrent::alert*>* alerts);

  //void WaitForAlert(libtorrent::alert alert);

  void PutImmutableItem(libtorrent::entry const& data, libtorrent::sha1_hash target, base::Callback<void(libtorrent::sha1_hash, int)> result_cb);

  void PutMutableItem(std::array<char, 32> key,
                      base::Callback<void(libtorrent::entry&, std::array<char, 64>&, std::int64_t&, std::string const&)> cb, 
                      base::Callback<void(libtorrent::dht::item const&, int)> result_cb,
                      std::string salt = std::string());

  void GetPeers(libtorrent::sha1_hash const& info_hash, base::Callback<void(std::vector<libtorrent::tcp::endpoint>)> cb);
  void Announce(libtorrent::sha1_hash const& info_hash, base::Callback<void(std::vector<libtorrent::tcp::endpoint>)> cb, int port = 0, libtorrent::dht::announce_flags_t flags = {});

  void LiveNodes(libtorrent::sha1_hash const& nid);
  void SampleInfohashes(libtorrent::udp::endpoint const& ep, libtorrent::sha1_hash const& target);

  void DirectRequest(libtorrent::udp::endpoint const& ep, libtorrent::entry& e, void* userdata = nullptr);

  //void Dispose();

  void OnTorrentInfoLoaded(const scoped_refptr<Torrent>& torrent);

  scoped_refptr<TorrentManagerContext> CreateStorageContext();

  bool AddTorrentToSessionOrUpdate(const scoped_refptr<Torrent>& torrent) override;

private:
  friend class StorageManager;
  friend class TorrentManagerContext;

  void UpdateBootstrapNodes();

  void RunBackendIO();
  void ProcessFinalShutdown();
  void ProcessShutdownEvents();
  void ReleaseTorrents();
  void OnSessionStart(
    base::Callback<void(std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const&)> bootstrap_cb,
    std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const& dht_nodes);

  // dht_observer
  
  void set_external_address(libtorrent::aux::listen_socket_handle const& iface
			, libtorrent::address const& addr, libtorrent::address const& source) override;
  int get_listen_port(libtorrent::aux::transport ssl, libtorrent::aux::listen_socket_handle const& s) override;
  void get_peers(libtorrent::sha1_hash const& ih) override;
  void outgoing_get_peers(libtorrent::sha1_hash const& target
			, libtorrent::sha1_hash const& sent_target, libtorrent::udp::endpoint const& ep) override;
  void announce(libtorrent::sha1_hash const& ih, libtorrent::address const& addr, int port) override;
  bool on_dht_request(libtorrent::string_view query, libtorrent::dht::msg const& request, libtorrent::entry& response) override;

#ifndef TORRENT_DISABLE_LOGGING
  bool should_log(libtorrent::dht::dht_logger::module_t m) const override;
  void log(libtorrent::dht::dht_logger::module_t m, char const* fmt, ...) override;  
	void log_packet(libtorrent::dht::dht_logger::message_direction_t dir, libtorrent::span<char const> pkt, libtorrent::udp::endpoint const& node) override;
#endif

  void SendUdpPacket(std::weak_ptr<libtorrent::utp_socket_interface> sock, 
    libtorrent::udp::endpoint const& ep, 
    libtorrent::span<char const> p, 
    libtorrent::error_code& ec, 
    libtorrent::udp_send_flags_t flags);

  void SendUdpPacketListen(libtorrent::aux::listen_socket_handle const& sock, 
    libtorrent::udp::endpoint const& ep, 
    libtorrent::span<char const> p, 
    libtorrent::error_code& ec, 
    libtorrent::udp_send_flags_t const flags);

  void OnUDPPacket(
    std::weak_ptr<libtorrent::aux::session_udp_socket> s, 
    std::weak_ptr<libtorrent::aux::listen_socket_t> ls, 
    libtorrent::aux::transport ssl, 
    libtorrent::error_code const& ec);

  void OnAcceptConnection(
    std::shared_ptr<libtorrent::aux::socket_type> const& s, 
    std::weak_ptr<libtorrent::tcp::acceptor> listen_socket, 
    libtorrent::error_code const& e, 
    libtorrent::aux::transport const ssl);

  void OnUdpWriteable(std::weak_ptr<libtorrent::aux::session_udp_socket> sock, libtorrent::error_code const& ec);
  void IncomingConnection(std::shared_ptr<libtorrent::aux::socket_type> const& s);

  void OnGetImmutableItem(libtorrent::sha1_hash target, libtorrent::dht::item const& i, base::Callback<void(libtorrent::sha1_hash target, libtorrent::dht::item const& i)> cb);
  void OnGetPeers(libtorrent::sha1_hash info_hash, base::Callback<void(std::vector<libtorrent::tcp::endpoint>)> cb, std::vector<libtorrent::tcp::endpoint> const& peers);
  void OnAnnounce(libtorrent::sha1_hash info_hash, base::Callback<void(std::vector<libtorrent::tcp::endpoint>)> cb, std::vector<libtorrent::tcp::endpoint> const& peers);
  void OnPutImmutableItem(libtorrent::sha1_hash target, int num, base::Callback<void(libtorrent::sha1_hash, int)> result_cb);
  void OnPutMutableItem(libtorrent::dht::item const& i, int num, base::Callback<void(libtorrent::dht::item const&, int)> result_cb);
  void OnGetMutableItem(const base::Callback<void(const libtorrent::entry&, const std::array<char, 32>&, const std::array<char, 64>&, const std::int64_t&, std::string const&, bool)>& get_cb, libtorrent::dht::item const& i, bool authoritative);
  void PutMutableCallback(
    libtorrent::dht::item& i, 
    base::Callback<void(libtorrent::entry&, std::array<char, 64>&, std::int64_t&, std::string const&)> cb
    //std::function<void(libtorrent::entry&, std::array<char, 64>&, std::int64_t&, std::string const&)> cb
    );

  void OnDirectResponse(void* userdata, libtorrent::dht::msg const& msg);

  // TorrentDelegate
  void OnTorrentPaused(lt::torrent_handle handle) override;
  void OnTorrentResumed(lt::torrent_handle handle) override;
  void OnTorrentChecked(lt::torrent_handle handle) override;
  void OnTorrentDeleted(lt::torrent_handle handle, lt::sha1_hash const& ih) override;
  void OnTorrentDeletedError(lt::torrent_handle handle, 
                             lt::error_code const& ec, 
                             lt::sha1_hash const& ih) override;
  void OnTorrentFileRenamed(lt::torrent_handle handle, 
                            lt::string_view name, 
                            lt::file_index_t index) override;

  void OnTorrentFileRenamedError(lt::torrent_handle handle, 
                                 lt::file_index_t index, 
                                 lt::error_code const& ec) override;

  void OnTorrentStateChanged(lt::torrent_handle const& h, 
                             lt::torrent_status::state_t st, 
                             lt::torrent_status::state_t prev_st) override;
  void OnDHTAnnounceReply(libtorrent::torrent_handle handle, int peers) override;
  void OnBlockFinished(lt::torrent_handle h, 
                       lt::tcp::endpoint const& ep, 
                       lt::peer_id const& peer_id, 
                       int block_num, 
                       lt::piece_index_t piece_num) override;
  void OnPieceHashedError(lt::error_code const& ec, 
                          lt::string_view file, 
                          lt::operation_t op, 
                          lt::torrent_handle const& h) override;
  void OnMetadataReceived(lt::torrent_handle const& handle) override;
  void OnMetadataError(lt::torrent_handle const& handle,
                       lt::error_code const& ec) override;

  void OnPieceReadError(lt::torrent_handle const& handle, 
                        lt::piece_index_t piece_num,
                        lt::error_code const& ec) override;

  void OnPiecePass(lt::torrent_handle const& handle, 
                   lt::piece_index_t piece_num) override;

  void OnPieceFailed(lt::torrent_handle const& handle, 
                     lt::piece_index_t piece_num) override;

  void OnPieceFinished(lt::torrent_handle const& handle, 
                       lt::piece_index_t piece_num) override;

  void OnFileCompleted(lt::torrent_handle const& handle, lt::file_index_t idx) override;

  void OnTrackerWarning(lt::torrent_handle const& handle, 
                        lt::tcp::endpoint const& endpoint, 
                        lt::string_view url, 
                        lt::string_view message) override;

  void OnTrackerScrapeReply(lt::torrent_handle const& handle, 
                            lt::tcp::endpoint const& endpoint,
                            int incomplete, 
                            int complete, 
                            lt::string_view url) override;

  void OnTrackerReply(lt::torrent_handle const& handle, 
                      lt::tcp::endpoint const& endpoint, 
                      int num_peers, 
                      lt::string_view url) override;

  void OnTrackerRequestError(lt::torrent_handle const& handle,
                             lt::tcp::endpoint const& ep, 
                             int times,
                             lt::string_view url, 
                             lt::error_code const& err, 
                             lt::string_view message) override;

  void OnPeerBlocked(lt::torrent_handle const& handle, 
                     lt::tcp::endpoint const& endpoint, 
                     int result) override;

  void OnPieceHashCheckFailed(lt::torrent_handle const& handle, lt::piece_index_t piece_num) override;

  void OnTrackerScrapeError(lt::torrent_handle const& h, 
                            lt::tcp::endpoint const& ep, 
                            lt::string_view u, 
                            lt::error_code const& e) override;

  // SessionDelegate
  void OnTick() override;

  //state changes
  void OnTorrentFinished(const scoped_refptr<Torrent>& torrent);
  void OnTorrentDownloading(const scoped_refptr<Torrent>& torrent);
  void OnTorrentCheckingFiles(const scoped_refptr<Torrent>& torrent);
  void OnTorrentDownloadingMetadata(const scoped_refptr<Torrent>& torrent);
  void OnTorrentSeeding(const scoped_refptr<Torrent>& torrent);
  void OnTorrentCheckingResumeData(const scoped_refptr<Torrent>& torrent);

  // TorrentStorageDelegate
  bool OpenEntry(lt::storage_index_t storage);
  bool CreateEntry(lt::storage_index_t storage);
  bool EntryChecked(lt::storage_index_t storage);
  void SetEntryChecked(lt::storage_index_t storage, bool checked);
  const char* GetEntryHash(lt::storage_index_t storage, lt::piece_index_t piece);
  std::vector<const char *> GetEntryBlockHashes(lt::storage_index_t storage);
  void UpdateMerkleTree(lt::storage_index_t storage, const std::vector<const char *>& block_hashes);
  void ReadEntry(lt::storage_index_t storage, lt::span<lt::iovec_t const> bufs, lt::piece_index_t const piece, int const offset, lt::storage_error& error);
  void WriteEntry(lt::storage_index_t storage, lt::span<lt::iovec_t const> bufs, lt::piece_index_t const piece, int const offset, lt::storage_error& error);
  void OnReleaseFiles(lt::storage_index_t storage);

  void OnTorrentAdded(const scoped_refptr<Torrent>& torrent, libtorrent::torrent_handle torrent_handle);

  void PrintManagedTorrentList();
  void SchedulePrintManagedTorrentList();
  void TimedForceDHTAnnouncement();
  void ScheduleForceDHTAnnouncement();
  void PrintRetainedByList();
  
  //std::shared_ptr<libtorrent::dht::dht_tracker> tracker_;

  libtorrent::dht::dht_tracker* dht() const {
    return session_->dht();
  }

  Delegate* delegate_;
  std::shared_ptr<libtorrent::aux::session_impl> session_;
  std::unique_ptr<libtorrent::dht::dht_storage_interface> dht_storage_;
	libtorrent::dht::dht_settings dht_settings_;
	libtorrent::dht::dht_storage_constructor_type dht_storage_constructor_;
  libtorrent::counters stats_counters_;
  libtorrent::dht::dht_state dht_state_;
  mutable libtorrent::alert_manager alerts_;

  std::vector<libtorrent::udp::endpoint> dht_bootstrap_nodes_;
	std::vector<libtorrent::udp::endpoint> dht_router_nodes_;
	std::vector<libtorrent::udp::endpoint> dht_nodes_;

  std::shared_ptr<libtorrent::io_context> io_context_;

  std::unique_ptr<libtorrent::disk_interface> disk_thread_;

  std::unique_ptr<libtorrent::utp_socket_manager> utp_socket_manager_;

  std::vector<std::shared_ptr<libtorrent::aux::listen_socket_t>> listen_sockets_;

  libtorrent::aux::session_settings settings_;

  std::vector<std::unique_ptr<libtorrent::peer_connection>> connections_;

  scoped_refptr<base::SingleThreadTaskRunner> backend_io_runner_;

  //base::WaitableEvent* shutdown_event_;
  bool started_;
  bool starting_;
  int tick_counter = 0;

  bool is_shutting_down_;
  mutable bool is_really_shutting_down_;
  mutable bool force_announcement_scheduled_;
  base::WaitableEvent shutdown_event_;
  base::WaitableEvent started_event_;

  std::unordered_map<int, scoped_refptr<Torrent>> torrent_list_;
  base::Lock torrent_list_mutex_;
  base::AtomicSequenceNumber storage_index_seq_;
  base::WeakPtrFactory<TorrentManager> weak_factory_;
  std::unique_ptr<base::WeakPtrFactory<TorrentManager>> weak_factory_for_io_;
  

  DISALLOW_COPY_AND_ASSIGN(TorrentManager);
};

}

#endif
