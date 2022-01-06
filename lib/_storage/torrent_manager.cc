// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/torrent_manager.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/lazy_instance.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/strings/string_number_conversions.h"
#include "storage/torrent_storage.h"
#include "storage/torrent.h"
#include "storage/storage.h"
#include "libtorrent/kademlia/dht_tracker.hpp"
#include "libtorrent/aux_/listen_socket_handle.hpp"
#include "libtorrent/aux_/session_impl.hpp"
#include "libtorrent/aux_/generate_peer_id.hpp"
#include "libtorrent/bt_peer_connection.hpp"
#include "libtorrent/hex.hpp"
#include "libtorrent/disk_interface.hpp"
#include "libtorrent/aux_/storage_utils.hpp" // for iovec_t
#include "libtorrent/fwd.hpp"
#include "google/protobuf/text_format.h"

using namespace std::placeholders;

namespace storage {

// Unfortunatelly We need this for the torrent storage constructor
// to get the TorrentManager instance at contruction, where
// we cant pass the reference as a parameter, because its called
// on libtorrent

static TorrentManager* g_torrent_manager = nullptr;

namespace {

constexpr size_t kBlockSize = 65536;

std::string GetModuleName(libtorrent::dht::dht_logger::module_t m) {
  switch(m) {
    case libtorrent::dht::dht_logger::tracker:
      return "tracker";
    case libtorrent::dht::dht_logger::node:
      return "node";
    case libtorrent::dht::dht_logger::routing_table:
      return "routing table";
    case libtorrent::dht::dht_logger::rpc_manager:
      return "rpc manager";
    case libtorrent::dht::dht_logger::traversal:
      return "traversal";
  }
  return "";
}


//std::string get_torrent_state(lt::torrent_status::state_t const& s) {
//  static char const* state_str[] =
//    {"queued for checking", "checking", "downloading metadata"
//    , "downloading", "finished", "seeding", "allocating", "checking resume data"};

//  return state_str[s];
//}

//std::string PrintTorrentState(storage_proto::InfoState state) {
//  static char const* tstate_str[] =
//    {"NONE", "CHECKING", "DOWNLOADING_META"
//    , "DOWNLOADING", "FINISHED", "SEEDING", "ERROR"};

//  return tstate_str[static_cast<int>(state)];
//}

std::unique_ptr<lt::disk_interface> TorrentStorageConstructor(lt::io_context& ioc, lt::counters&) {
  DCHECK(g_torrent_manager);
  return std::make_unique<TorrentStorage>(g_torrent_manager->CreateStorageContext(), ioc);
}

}

TorrentManagerContext::TorrentManagerContext(TorrentManager* manager): manager_(manager) {}
TorrentManagerContext::~TorrentManagerContext() {}

bool TorrentManagerContext::OpenEntry(lt::storage_index_t storage) {
  return manager_->OpenEntry(storage);
}

bool TorrentManagerContext::CreateEntry(lt::storage_index_t storage) {
  return manager_->CreateEntry(storage); 
}

bool TorrentManagerContext::EntryChecked(lt::storage_index_t storage) {
  return manager_->EntryChecked(storage);
}

void TorrentManagerContext::SetEntryChecked(lt::storage_index_t storage, bool checked) {
  manager_->SetEntryChecked(storage, checked);
}

const char* TorrentManagerContext::GetEntryHash(lt::storage_index_t storage, lt::piece_index_t piece) {
  return manager_->GetEntryHash(storage, piece);
}

std::vector<const char *> TorrentManagerContext::GetEntryBlockHashes(lt::storage_index_t storage) {
  return manager_->GetEntryBlockHashes(storage); 
}

void TorrentManagerContext::UpdateMerkleTree(lt::storage_index_t storage, const std::vector<const char *>& block_hashes) {
  manager_->UpdateMerkleTree(storage, block_hashes);  
}

void TorrentManagerContext::ReadEntry(lt::storage_index_t storage, lt::span<lt::iovec_t const> bufs, lt::piece_index_t const piece, int const offset, lt::storage_error& error) {
  manager_->ReadEntry(storage, bufs, piece, offset, error);   
}

void TorrentManagerContext::WriteEntry(lt::storage_index_t storage, lt::span<lt::iovec_t const> bufs, lt::piece_index_t const piece, int const offset, lt::storage_error& error) {
  manager_->WriteEntry(storage, bufs, piece, offset, error);   
}

void TorrentManagerContext::OnReleaseFiles(lt::storage_index_t storage) {
  manager_->OnReleaseFiles(storage);   
}

TorrentManager::TorrentManager(
  Delegate* delegate,
  std::shared_ptr<libtorrent::io_context> io_context, 
  scoped_refptr<base::SingleThreadTaskRunner> backend_io_runner):
 delegate_(delegate),
 dht_storage_constructor_(libtorrent::dht::dht_default_storage_constructor),
 alerts_(1000, libtorrent::alert_category_t::all()),
 io_context_(io_context),
 utp_socket_manager_(
			std::bind(&TorrentManager::SendUdpPacket, this, _1, _2, _3, _4, _5),
			std::bind(&TorrentManager::IncomingConnection, this, _1),
			*io_context_,
			settings_, 
      stats_counters_, 
      nullptr),
 backend_io_runner_(backend_io_runner),
 //shutdown_event_(nullptr),
 started_(false),
 starting_(false),
 is_shutting_down_(false),
 is_really_shutting_down_(false),
 shutdown_event_(nullptr),
 started_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED),
 weak_factory_(this) {
  
  g_torrent_manager = this;
}

TorrentManager::~TorrentManager() {
  //if (session_) {
  //  session_->dispose();
  //  if (session_->dht()) {
  //    session_->dht()->dispose();
  //  }
  //}
  io_context_ = nullptr;
  //session_ = nullptr;
  g_torrent_manager = nullptr;
}

bool TorrentManager::has_dht() const {
  if (!session_) {
    return false;
  }
  return session_->has_dht();
}

void TorrentManager::GetAlerts(std::vector<libtorrent::alert*>* alerts) {
  session_->pop_alerts(alerts);
}

//void TorrentManager::WaitForAlert(libtorrent::alert alert) {
//  session_->wait_for_alert(alert);
//}

void TorrentManager::Start(base::Callback<void(std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const&)> bootstrap_cb) {
  starting_ = true;
  libtorrent::settings_pack settings = libtorrent::default_settings();
  settings.set_int(libtorrent::settings_pack::alert_mask, 
                   lt::alert::torrent_log_notification | 
                   lt::alert::session_log_notification | 
                   lt::alert::stats_notification | 
                   lt::alert::picker_log_notification | 
                   lt::alert::piece_progress_notification | 
                   lt::alert::file_progress_notification | 
                   lt::alert::upload_notification);

  //settings.set_bool(libtorrent::settings_pack::enable_lsd, false);
  settings.set_bool(libtorrent::settings_pack::allow_multiple_connections_per_ip, true);
  settings.set_bool(libtorrent::settings_pack::prioritize_partial_pieces, true);
  //settings.set_str(libtorrent::settings_pack::outgoing_interfaces, "wlp1s0,  192.168.1.100, 127.0.0.1");
  // should be temporary
  settings.set_bool(libtorrent::settings_pack::disable_hash_checks, true);
  
  //libtorrent::disk_io_constructor_type disk_io;
  libtorrent::disk_io_constructor_type disk_io = TorrentStorageConstructor;
  session_ = std::make_shared<libtorrent::aux::session_impl>(std::ref(*io_context_.get()), std::move(settings), std::move(disk_io));
  
  libtorrent::dht::dht_settings dht_settings;
  libtorrent::dht::dht_state dht_state;
  libtorrent::dht::dht_storage_constructor_type dht_storage_constructor = libtorrent::dht::dht_default_storage_constructor;

  for (auto it = dht_bootstrap_nodes_.begin(); it != dht_bootstrap_nodes_.end(); it++) {
    dht_state.nodes.push_back(*it);
  }

  session_->set_dht_settings(std::move(dht_settings));
	session_->set_dht_state(std::move(dht_state));
	session_->set_dht_storage(std::move(dht_storage_constructor));

	session_->start_session(
    base::Bind(&TorrentManager::OnSessionStart, base::Unretained(this), base::Passed(std::move(bootstrap_cb))));
  
  backend_io_runner_->PostTask(
    FROM_HERE, 
    base::Bind(&TorrentManager::RunBackendIO, base::Unretained(this)));
}

void TorrentManager::Stop(base::WaitableEvent* shutdown_event) {
  //LOG(INFO) << "TorrentManager::Stop";
  session_->alerts().set_notify_function({});
  session_->call_abort();//->abort();
  ProcessShutdownEvents(shutdown_event);
}

void TorrentManager::Shutdown(base::WaitableEvent* shutdown_event) {
  // wait until started
  is_shutting_down_ = true;
  //if (starting_ && !started_) {
  //  LOG(INFO) << "not bootstraped yet. just waiting..";
  //  started_event_.Wait();
  //  started_event_.Reset();
  //  LOG(INFO) << "ok.. ended waiting";
  //}
  Stop(shutdown_event);
}

void TorrentManager::ProcessShutdownEvents(base::WaitableEvent* shutdown_event) {
  //LOG(INFO) << "TorrentManager::ProcessShutdownEvents";
  if (is_really_shutting_down_) {
    ProcessFinalShutdown(shutdown_event);
    return;
  }
  //std::vector<libtorrent::alert*> alerts;
  //session_->pop_alerts(&alerts);
  //GetAlerts(&alerts);
  //for (lt::alert const* a : alerts) {
    //std::cout << a->message() << std::endl;
    // if we receive the finished alert or an error, we're done
    //if (lt::alert_cast<lt::torrent_finished_alert>(a)) {
    //  DLOG(INFO) << "finished alert received: should exit..";
    //  //break 2;
    //  //goto done;
    //  ProcessFinalShutdown(shutdown_event);
    //  return;
    //} else if (lt::alert_cast<lt::torrent_error_alert>(a)) {
    //  DLOG(INFO) << "error alert received: should exit..";
      //break 2;
      //goto done;
    //  ProcessFinalShutdown(shutdown_event);
    //  return;
    //}
  //}
  base::PostDelayedTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(&TorrentManager::ProcessShutdownEvents, base::Unretained(this), base::Unretained(shutdown_event)),
    base::TimeDelta::FromMilliseconds(200));
}

void TorrentManager::ProcessFinalShutdown(base::WaitableEvent* shutdown_event) {
  //LOG(INFO) << "TorrentManager::ProcessFinalShutdown";
  shutdown_event_ = shutdown_event;
  io_context_->stop();
  if (session_) {
    session_->dispose();
    if (session_->dht()) {
      session_->dht()->stop();
      session_->dht()->dispose();
    }
  }
  ReleaseTorrents();  
  session_ = nullptr;
  if (shutdown_event) {
    shutdown_event->Signal();
  }
  //LOG(INFO) << "TorrentManager::ProcessFinalShutdown end";
}

void TorrentManager::ReleaseTorrents() {
  for (auto it = torrent_list_.begin(); it != torrent_list_.end(); ++it) {
    Torrent* torrent = it->second.get();
    if (torrent->is_open()) {
      //LOG(INFO) << "TorrentManager::ProcessFinalShutdown: is open";
      //if ((torrent->is_tree() &&  torrent->is_root())|| torrent->is_database()) {
      if (torrent->is_root() || torrent->is_data()) {
        // root can have "side effects" as it might be writing

        if (torrent->is_busy()) {
          //LOG(INFO) << "TorrentManager::ProcessFinalShutdown: is open and is busy: waiting..";
          torrent->WaitPendingIO();
          //LOG(INFO) << "TorrentManager::ProcessFinalShutdown: ended waiting";
        }
        //LOG(INFO) << "TorrentManager::ProcessFinalShutdown: is open and tree or db: closing database..";
        if (torrent->db_is_open()) {
          torrent->db().Close();
        } else {
          torrent->Close(false);
        }
      } else {
        //LOG(INFO) << "TorrentManager::ProcessFinalShutdown: is open and files: closing entry..";
        torrent->Close(false);
      }
    } else {
      //LOG(INFO) << "TorrentManager::ProcessFinalShutdown: is not open";
    }
    //it->second.reset();
  }
  //torrent_list_.clear();
}

void TorrentManager::OnSessionStart(
  base::Callback<void(std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const&)> bootstrap_cb,
  std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const& dht_nodes) {
  started_ = true;
  starting_ = false;
  if (!is_shutting_down_) {
    std::move(bootstrap_cb).Run(dht_nodes);
  }
  started_event_.Signal();
}

scoped_refptr<Torrent> TorrentManager::NewTorrent(IOHandler* io_handler, std::unique_ptr<storage_proto::Info> info) {
  lt::storage_index_t index = storage_index_seq_.GetNext() + 1;
  scoped_refptr<Torrent> parent = nullptr;
  
  if (info->tree().size() > 0) {
    base::UUID tree(reinterpret_cast<const uint8_t *>(info->tree().data()));
    parent = GetTorrent(tree);
    DCHECK(parent);
  }
  scoped_refptr<Torrent> torrent(new Torrent(this, parent, std::move(info), index, io_handler));
  AddTorrent(index, torrent);
  //if (session()) {
  //  AddTorrentToSession(torrent);
  //}
  return torrent;
}

scoped_refptr<Torrent> TorrentManager::NewTorrent(IOHandler* io_handler, const base::UUID& id, bool is_root) {
  lt::storage_index_t index = storage_index_seq_.GetNext() + 1;
  scoped_refptr<Torrent> parent;
  if (!is_root) {
    parent = io_handler->root_tree();
    DCHECK(parent);
  }
  scoped_refptr<Torrent> torrent(new Torrent(this, parent, id, index, io_handler));
  AddTorrent(index, torrent);
  return torrent;
}

bool TorrentManager::AddTorrentToSession(const scoped_refptr<Torrent>& torrent) {
  IOHandler* io_handler = torrent->io_handler();

  libtorrent::error_code ec;
  libtorrent::add_torrent_params params;
  params.ti = std::make_shared<libtorrent::torrent_info>();
  if (torrent->should_seed()) {
    params.flags = libtorrent::torrent_flags::seed_mode;
  }
  params.torrent_delegate = this;
  // not necessary as this should be the same for all torrents
  // and not per-torrent

  // params.storage_delegate = this;
  params.save_path = io_handler->GetPath().value() + "/" + torrent->path();
  params.storage = torrent->storage_id();

  if (!params.ti->parse_protobuf(torrent->info(), ec)) {
    LOG(ERROR) << "TorrentManager::CreateTorrent: error while creating torrent info from protobuf info";
    return false;
  }

  auto torrent_handle = session()->add_torrent(std::move(params), ec);
  if (ec.value() != 0) {
    LOG(ERROR) << "TorrentManager::CreateTorrent: error while adding torrent info to session: " << ec.message();
    return false;
  }
  //LOG(INFO) << "TorrentManager::CreateTorrent: valid? " << torrent_handle.is_valid();
  torrent->set_handle(std::move(torrent_handle));
  torrent->OnTorrentAddedToSession();

  return true;
}

scoped_refptr<Torrent> TorrentManager::GetOrCreateTorrent(IOHandler* io_handler, const base::UUID& id) {
  scoped_refptr<Torrent> handle = GetTorrent(id);
  if (!handle) {
    handle = NewTorrent(io_handler, id, false);
  }
  return handle;
}

scoped_refptr<Torrent> TorrentManager::GetTorrent(const base::UUID& id) const {
  for (auto it = torrent_list_.begin(); it != torrent_list_.end(); it++) {
    if (it->second->id() == id) {
      return it->second;
    }
  }
  return nullptr;
}

bool TorrentManager::HasTorrent(const base::UUID& id) const {
  for (auto it = torrent_list_.begin(); it != torrent_list_.end(); it++) {
    if (it->second->id() == id) {
      return true;
    }
  }
  return false;
}

void TorrentManager::AddTorrent(int index, scoped_refptr<Torrent> torrent) {
  torrent_list_mutex_.Acquire();
  //LOG(INFO) << "adding torrent " << torrent.get() << " - '" << torrent->id().to_string() << "' storage_id: " << index;
  torrent_list_.emplace(index, torrent);
  torrent_list_mutex_.Release();
}

void TorrentManager::RemoveTorrent(int index) {
  torrent_list_mutex_.Acquire();
  auto it = torrent_list_.find(index);
  if (it != torrent_list_.end()) {
    it->second = nullptr;
    torrent_list_.erase(it);
  }
  torrent_list_mutex_.Release();
}

void TorrentManager::Update(base::Callback<void(std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const&)> bootstrap_cb) {
  if (!dht_bootstrap_nodes_.empty() && dht_router_nodes_.empty()) {
    UpdateBootstrapNodes();
  } else {
    Start(std::move(bootstrap_cb));
  }
}

void TorrentManager::AddNode(const net::IPEndPoint& endpoint) {
  boost::asio::ip::address_v4 addr = boost::asio::ip::address_v4::from_string(endpoint.address().ToString());
  libtorrent::udp::endpoint dht_endpoint(addr, endpoint.port());
  dht()->add_node(dht_endpoint);
  dht_nodes_.push_back(dht_endpoint);
}

void TorrentManager::AddRouterNode(const net::IPEndPoint& endpoint) {
  boost::asio::ip::address_v4 addr = boost::asio::ip::address_v4::from_string(endpoint.address().ToString());
  libtorrent::udp::endpoint dht_endpoint(addr, endpoint.port());
  dht()->add_router_node(dht_endpoint);
  dht_router_nodes_.push_back(dht_endpoint);
}

void TorrentManager::AddBootstrapNode(const net::IPEndPoint& endpoint) {
  boost::asio::ip::address_v4 addr = boost::asio::ip::address_v4::from_string(endpoint.address().ToString());
  libtorrent::udp::endpoint dht_endpoint(addr, endpoint.port());
  dht_bootstrap_nodes_.push_back(dht_endpoint);
}
void TorrentManager::GetImmutableItemSha1Hex(const std::string& sha1_hex, base::Callback<void(libtorrent::sha1_hash target, libtorrent::dht::item const& i)> cb) {
  char hash_data[20] = {0};
  libtorrent::aux::from_hex({sha1_hex.data(), sha1_hex.size()}, hash_data);
  libtorrent::sha1_hash item = libtorrent::sha1_hash(hash_data);
  dht()->get_item(item, std::bind(&TorrentManager::OnGetImmutableItem, this, item, _1, std::move(cb)));
}

void TorrentManager::GetImmutableItem(libtorrent::sha1_hash const& target, base::Callback<void(libtorrent::sha1_hash target, libtorrent::dht::item const& i)> cb) {
  dht()->get_item(target, std::bind(&TorrentManager::OnGetImmutableItem, this, target, _1, std::move(cb)));
}

void TorrentManager::OnGetImmutableItem(libtorrent::sha1_hash target, libtorrent::dht::item const& i, base::Callback<void(libtorrent::sha1_hash target, libtorrent::dht::item const& i)> cb) {
  //LOG(INFO) << "GetImmutableItem got:\n'" << i.value().to_string() << "'";
  //alerts_.emplace_alert<libtorrent::dht_immutable_item_alert>(target, i.value());
  std::move(cb).Run(std::move(target), i);
}

void TorrentManager::GetMutableItem(std::array<char, 32> key, const base::Callback<void(const libtorrent::entry&, const std::array<char, 32>&, const std::array<char, 64>&, const std::int64_t&, std::string const&, bool)>& get_cb, std::string salt) {
  dht()->get_item(libtorrent::dht::public_key(key.data()), std::bind(&TorrentManager::OnGetMutableItem
			, this, get_cb, _1, _2), std::move(salt));
}

void TorrentManager::OnGetMutableItem(const base::Callback<void(const libtorrent::entry&, const std::array<char, 32>&, const std::array<char, 64>&, const std::int64_t&, std::string const&, bool)>& get_cb, libtorrent::dht::item const& i, bool authoritative) {
  //libtorrent::entry value = i.value();

  //LOG(INFO) << "OnGetMutableItem:\n" << value.to_string();

  //alerts_.emplace_alert<libtorrent::dht_mutable_item_alert>(i.pk().bytes, 
//    i.sig().bytes, 
 //   i.seq().value, 
  //  i.salt(), 
  //  i.value(), 
  //  authoritative);
  if (get_cb.is_null()) {
    LOG(ERROR) << "TorrentManager::OnGetMutableItem: something is wrong.. i was calling the user callback, but its actually null.\nmaybe its being called more than once?";
    return;
  }
  get_cb.Run(i.value(), i.pk().bytes, i.sig().bytes, i.seq().value, i.salt(), authoritative);
}

void TorrentManager::PutImmutableItem(libtorrent::entry const& data, libtorrent::sha1_hash target, base::Callback<void(libtorrent::sha1_hash, int)> result_cb) {
  dht()->put_item(data, std::bind(&TorrentManager::OnPutImmutableItem, this, target, _1, std::move(result_cb)));
}

void TorrentManager::PutMutableItem(std::array<char, 32> key, 
   // std::function<void(libtorrent::entry&, std::array<char,64>&, std::int64_t&, std::string const&)> cb, 
    base::Callback<void(libtorrent::entry&, std::array<char, 64>&, std::int64_t&, std::string const&)> cb,
    base::Callback<void(libtorrent::dht::item const&, int)> result_cb,
    std::string salt) {
  dht()->put_item(libtorrent::dht::public_key(key.data())
			, std::bind(&TorrentManager::OnPutMutableItem, this, _1, _2, std::move(result_cb))
			, std::bind(&TorrentManager::PutMutableCallback, this, _1, std::move(cb)), salt);
}

void TorrentManager::GetPeers(libtorrent::sha1_hash const& info_hash, base::Callback<void(std::vector<libtorrent::tcp::endpoint>)> cb) {
  dht()->get_peers(info_hash, std::bind(&TorrentManager::OnGetPeers, this, info_hash, std::move(cb), _1));
}

void TorrentManager::Announce(libtorrent::sha1_hash const& info_hash, base::Callback<void(std::vector<libtorrent::tcp::endpoint>)> cb, int port, libtorrent::dht::announce_flags_t flags) {
  dht()->announce(info_hash, port, flags, std::bind(&TorrentManager::OnAnnounce, this, info_hash, std::move(cb), _1));
}

void TorrentManager::LiveNodes(libtorrent::sha1_hash const& nid) {
  auto nodes = dht()->live_nodes(nid);
	alerts_.emplace_alert<libtorrent::dht_live_nodes_alert>(nid, nodes);
}

void TorrentManager::SampleInfohashes(libtorrent::udp::endpoint const& ep, libtorrent::sha1_hash const& target) {
  dht()->sample_infohashes(ep, target, [this, &ep](
    libtorrent::time_duration interval, 
    int num, 
    std::vector<libtorrent::sha1_hash> samples, 
    std::vector<std::pair<libtorrent::sha1_hash, libtorrent::udp::endpoint>> nodes) {
			alerts_.emplace_alert<libtorrent::dht_sample_infohashes_alert>(ep, interval, num, samples, nodes);
		});
}

void TorrentManager::DirectRequest(libtorrent::udp::endpoint const& ep, libtorrent::entry& e, void* userdata) {
  dht()->direct_request(ep, e, std::bind(&TorrentManager::OnDirectResponse, this, userdata, _1));
}

void TorrentManager::OnDirectResponse(void* userdata, libtorrent::dht::msg const& msg) {
  //LOG(INFO) << "TorrentManager::OnDirectResponse";
 	//if (msg.message.type() == libtorrent::bdecode_node::none_t)
	//  alerts_.emplace_alert<libtorrent::dht_direct_response_alert>(userdata, msg.addr);
	//else
 //		alerts_.emplace_alert<libtorrent::dht_direct_response_alert>(userdata, msg.addr, msg.message);
}

void TorrentManager::RunBackendIO() {
  //LOG(INFO) << "TorrentManager::RunBackendIO: io_context_->run()";
  io_context_->run();
  //weak_factory_.InvalidateWeakPtrs();
  is_really_shutting_down_ = true;
  //if (shutdown_event_) {
  //  shutdown_event_->Signal();
  //}
  //LOG(INFO) << "TorrentManager::RunBackendIO: io_context_->run() end";
}

void TorrentManager::UpdateBootstrapNodes() {
  for (auto it = dht_bootstrap_nodes_.begin(); it != dht_bootstrap_nodes_.end(); it++) {
    if (session_) {
      dht()->add_router_node(*it);
    }
    dht_router_nodes_.push_back(*it);
  }
}

void TorrentManager::set_external_address(
  libtorrent::aux::listen_socket_handle const& iface,
  libtorrent::address const& addr, 
  libtorrent::address const& source) {

  libtorrent::tcp::endpoint local_endpoint;

  for (auto& i : listen_sockets_) {
    local_endpoint = i->local_endpoint;
		break;
	}

  auto sock = std::find_if(listen_sockets_.begin(), listen_sockets_.end()
			, [&](std::shared_ptr<libtorrent::aux::listen_socket_t> const& v) { 
        return v->local_endpoint == local_endpoint; });

	if (sock != listen_sockets_.end()) {
    dht()->update_node_id(*sock);
  }
}

int TorrentManager::get_listen_port(libtorrent::aux::transport ssl, libtorrent::aux::listen_socket_handle const& s) {
  return s.get()->udp_external_port();;
}

void TorrentManager::get_peers(libtorrent::sha1_hash const& ih) {
  //GetPeers(ih);
}

void TorrentManager::outgoing_get_peers(
  libtorrent::sha1_hash const& target, 
  libtorrent::sha1_hash const& sent_target, libtorrent::udp::endpoint const& ep) {
  //alerts_.emplace_alert<libtorrent::dht_outgoing_get_peers_alert>(target, sent_target, ep);
}

void TorrentManager::announce(
  libtorrent::sha1_hash const& ih, 
  libtorrent::address const& addr, 
  int port) {
  alerts_.emplace_alert<libtorrent::dht_announce_alert>(addr, port, ih);
}

bool TorrentManager::on_dht_request(
  libtorrent::string_view query, 
  libtorrent::dht::msg const& request, 
  libtorrent::entry& response) {
  //LOG(INFO) << "TorrentManager::on_dht_request";
  return false;
}

bool TorrentManager::should_log(libtorrent::dht::dht_logger::module_t m) const {
  switch(m) {
    case libtorrent::dht::dht_logger::tracker:
      return true;
    case libtorrent::dht::dht_logger::node:
      return true;
    case libtorrent::dht::dht_logger::routing_table:
      return true;
    case libtorrent::dht::dht_logger::rpc_manager:
      return true;
    case libtorrent::dht::dht_logger::traversal:
      return true;
  }
  return true;
}

void TorrentManager::log(libtorrent::dht::dht_logger::module_t m, char const* fmt, ...) {
  std::string module_type = GetModuleName(m);
  std::ostringstream str;
  
  str << module_type << " > ";
  va_list v;
	va_start(v, fmt);
	alerts_.emplace_alert<libtorrent::log_alert>(fmt, v);
  while (*fmt) {
    if (*fmt == 's') {
      str << " string: " << va_arg(v, char *);
    } else if (*fmt == 'i') {
      str << " int: " << libtorrent::error_code(va_arg(v, int), libtorrent::system_category()).message();
    } else if (*fmt == 'c') {
      str << " char: " << (char)va_arg(v, int);
    }
    va_end(v);
    fmt++;
  }
  printf("%s\n", str.str().c_str());
}

void TorrentManager::log_packet(libtorrent::dht::dht_logger::message_direction_t dir, libtorrent::span<char const> pkt, libtorrent::udp::endpoint const& node) {
  //LOG(INFO) << "TorrentManager::log_packet";
}

void TorrentManager::SendUdpPacket(
    std::weak_ptr<libtorrent::utp_socket_interface> sock, 
    libtorrent::udp::endpoint const& ep, 
    libtorrent::span<char const> p, 
    libtorrent::error_code& ec, 
    libtorrent::udp_send_flags_t flags) {
  auto m = sock.lock();
  if (!m) {
    ec = boost::asio::error::bad_descriptor;
    return;
  }

  auto s = std::static_pointer_cast<libtorrent::aux::session_udp_socket>(m);

  DCHECK(s->sock.is_closed() || s->sock.local_endpoint().protocol() == ep.protocol());

  s->sock.send(ep, p, ec, flags);

  if ((ec == boost::asio::error::would_block || ec == boost::asio::error::try_again) && !s->write_blocked) {
    s->write_blocked = true;
    s->sock.async_write(std::bind(&TorrentManager::OnUdpWriteable, this, s, _1));
  }
}

void TorrentManager::SendUdpPacketListen(
  libtorrent::aux::listen_socket_handle const& sock, 
  libtorrent::udp::endpoint const& ep, 
  libtorrent::span<char const> p, 
  libtorrent::error_code& ec, 
  libtorrent::udp_send_flags_t const flags) {
  
  libtorrent::aux::listen_socket_t* s = sock.get();
  if (!s) {
    ec = boost::asio::error::bad_descriptor;
    return;
  }
  SendUdpPacket(s->udp_sock, ep, p, ec, flags);
}

void TorrentManager::OnUDPPacket(
  std::weak_ptr<libtorrent::aux::session_udp_socket> s, 
  std::weak_ptr<libtorrent::aux::listen_socket_t> ls, 
  libtorrent::aux::transport ssl, 
  libtorrent::error_code const& ec) {

}

void TorrentManager::OnAcceptConnection(
  std::shared_ptr<libtorrent::aux::socket_type> const& s, 
  std::weak_ptr<libtorrent::tcp::acceptor> listen_socket, 
  libtorrent::error_code const& e, 
  libtorrent::aux::transport const ssl) {

}

void TorrentManager::OnUdpWriteable(std::weak_ptr<libtorrent::aux::session_udp_socket> sock, libtorrent::error_code const& ec) {
  if (ec) {
    return;
  }

	auto m = sock.lock();
	if (!m) {
    return;
  }

	m->write_blocked = false;

	utp_socket_manager_.writable();
}

void TorrentManager::IncomingConnection(std::shared_ptr<libtorrent::aux::socket_type> const& s) {
  libtorrent::error_code ec;
  libtorrent::tcp::endpoint endp = s->remote_endpoint(ec);

  if (ec) {
    // TODO get the ec error message
    LOG(ERROR) << "error on incoming connection";
    return;
  }

  //stats_counters_.set_value(counters::has_incoming_connections, 1);
  //stats_counters_.inc_stats_counter(counters::incoming_connections);

  libtorrent::peer_connection_args pack{
    //this,
    nullptr,
    &settings_,
    &stats_counters_,
    disk_thread_.get(),
    io_context_.get(),
    std::weak_ptr<libtorrent::torrent>(),
    s,
    endp,
    nullptr,
    libtorrent::aux::generate_peer_id(settings_)
  };

  std::unique_ptr<libtorrent::peer_connection> c
    = std::make_unique<libtorrent::bt_peer_connection>(std::move(pack));

  if (!c->is_disconnecting()) {
    connections_.push_back(std::move(c));
    c->start();
  }
}

void TorrentManager::OnGetPeers(libtorrent::sha1_hash info_hash, base::Callback<void(std::vector<libtorrent::tcp::endpoint>)> cb, std::vector<libtorrent::tcp::endpoint> const& peers) {
	//if (alerts.should_post<dht_get_peers_reply_alert>())
  //alerts_.emplace_alert<libtorrent::dht_get_peers_reply_alert>(info_hash, peers);
  std::move(cb).Run(std::move(peers));
}

void TorrentManager::OnAnnounce(libtorrent::sha1_hash info_hash, base::Callback<void(std::vector<libtorrent::tcp::endpoint>)> cb, std::vector<libtorrent::tcp::endpoint> const& peers) {
  //alerts_.emplace_alert<libtorrent::dht_announce_alert>(info_hash, peers);
  std::move(cb).Run(std::move(peers));
}

void TorrentManager::OnPutImmutableItem(libtorrent::sha1_hash target, int num, base::Callback<void(libtorrent::sha1_hash, int)> result_cb) {
	//alerts_.emplace_alert<libtorrent::dht_put_alert>(target, num);
  std::move(result_cb).Run(std::move(target), num);
}

void TorrentManager::OnPutMutableItem(libtorrent::dht::item const& i, int num, base::Callback<void(libtorrent::dht::item const&, int)> result_cb) {
  std::move(result_cb).Run(i, num);
}

void TorrentManager::PutMutableCallback(
  libtorrent::dht::item& i, 
  base::Callback<void(libtorrent::entry&, std::array<char, 64>&, std::int64_t&, std::string const&)> cb
  ){
			libtorrent::entry value = i.value();
			libtorrent::dht::signature sig = i.sig();
			libtorrent::dht::public_key pk = i.pk();
			libtorrent::dht::sequence_number seq = i.seq();
			std::string salt = i.salt();
			//cb(value, sig.bytes, seq.value, salt);
      std::move(cb).Run(value, sig.bytes, seq.value, salt);
			i.assign(std::move(value), salt, seq, pk, sig);
}

void TorrentManager::OnTorrentChecked(lt::torrent_handle handle) {
  lt::storage_index_t storage_id = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage_id);
  if (!torrent) {
    LOG(ERROR) << "TorrentManager::OnTorrentChecked: torrent with id " << (int)storage_id << " not found";
    return;
  }
  ////DLOG(INFO) << "TorrentManager::OnTorrentChecked: setting torrent " << storage_id << " as checked";
  //it->second->checked = true;
  //DLOG(INFO) << "TorrentManager::OnTorrentChecked: setting merkle leafs for torrent " << storage_id;
  torrent->UpdateDigest(handle);
  torrent->OnChecked();
}

void TorrentManager::OnTorrentResumed(lt::torrent_handle handle) {
  //DLOG(INFO) << "TorrentManager::OnTorrentResumed";
  lt::storage_index_t storage_id = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage_id);
  if (!torrent) {
    LOG(ERROR) << "TorrentManager::OnTorrentResumed: torrent with id " << (int)storage_id << " not found";
    return;
  }
  //for (int i = 0; i < torrent->info().pieces_size(); i++) {
  //  auto piece = torrent->mutable_info()->mutable_pieces(i);
  //  piece->set_state(storage_proto::STATE_DOWNLOADING);
  //}
  torrent->OnResumed();
}

void TorrentManager::OnTorrentPaused(lt::torrent_handle handle) {
  //DLOG(INFO) << "TorrentManager::OnTorrentPaused";
lt::storage_index_t storage_id = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage_id);
  if (!torrent) {
    LOG(ERROR) << "TorrentManager::OnTorrentPaused: torrent with id " << (int)storage_id << " not found";
    return;
  }
  torrent->OnPaused();
}

void TorrentManager::OnTorrentDeleted(lt::torrent_handle handle, lt::sha1_hash const& ih) {
  //DLOG(INFO) << "TorrentManager::OnTorrentDeleted";
  lt::storage_index_t storage_id = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage_id);
  if (!torrent) {
    LOG(ERROR) << "TorrentManager::OnTorrentDeleted: torrent with id " << (int)storage_id << " not found";
    return;
  }
  torrent->OnDeleted(); 
}

void TorrentManager::OnTorrentDeletedError(lt::torrent_handle handle, 
                                     lt::error_code const& ec, 
                                     lt::sha1_hash const& ih) {
  //DLOG(INFO) << "TorrentManager::OnTorrentDeletedError";
  lt::storage_index_t storage_id = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage_id);
  if (!torrent) {
    LOG(ERROR) << "TorrentManager::OnTorrentDeletedError: torrent with id " << (int)storage_id << " not found";
    return;
  }
  torrent->OnDeletedError(ec.value()); 
}

void TorrentManager::OnTorrentFileRenamed(lt::torrent_handle handle, 
                                    lt::string_view name, 
                                    lt::file_index_t index) {
  //DLOG(INFO) << "TorrentManager::OnTorrentFileRenamed";
  lt::storage_index_t storage_id = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage_id);
  if (!torrent) {
    LOG(ERROR) << "TorrentManager::OnTorrentFileRenamed: torrent with id " << (int)storage_id << " not found";
    return;
  }
  torrent->OnFileRenamed(index, name.to_string());
}

void TorrentManager::OnTorrentFileRenamedError(lt::torrent_handle handle, 
                                         lt::file_index_t index, 
                                         lt::error_code const& ec) {
  //DLOG(INFO) << "TorrentManager::OnTorrentFileRenamedError";
  lt::storage_index_t storage_id = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage_id);
  if (!torrent) {
    LOG(ERROR) << "TorrentManager::OnTorrentFileRenamed: torrent with id " << (int)storage_id << " not found";
    return;
  }
  torrent->OnFileRenamedError(index, ec.value());
}

void TorrentManager::OnTrackerRequestError(lt::torrent_handle const& handle,
                                     lt::tcp::endpoint const& ep, 
                                     int times,
                                     lt::string_view url, 
                                     lt::error_code const& err, 
                                     lt::string_view message) {
  //DLOG(INFO) << "TorrentManager::OnTrackerRequestError";
}

void TorrentManager::OnTrackerScrapeError(lt::torrent_handle const& h, 
                                    lt::tcp::endpoint const& ep, 
                                    lt::string_view u, 
                                    lt::error_code const& e) {
  //DLOG(INFO) << "TorrentManager::OnTrackerScrapeError";
}

void TorrentManager::OnTorrentFinished(const scoped_refptr<Torrent>& torrent) {
  //DLOG(INFO) << "TorrentManager::OnTorrentFinished: state = " << PrintTorrentState(torrent->state());

  // if (torrent->state() == storage_proto::STATE_DOWNLOADING || 
  //     torrent->state() == storage_proto::STATE_FINISHED || 
  //     torrent->state() == storage_proto::STATE_SEEDING) {
  //   DLOG(INFO) << "TorrentManager::OnTorrentFinished: closing torrent " << torrent->id();
  //   int r = torrent->Close();
  //   if (r != 0) {
  //     LOG(ERROR) << "TorrentManager::TorrentFinished: failed to close torrent with id " << (int)storage;
  //   }
  // }
  if (delegate_) {
    delegate_->OnTorrentFinished(torrent);
  }
  torrent->OnFinished();
}


void TorrentManager::OnTorrentDownloading(const scoped_refptr<Torrent>& torrent) {
  //DLOG(INFO) << "TorrentManager::OnTorrentDownloading";
  torrent->OnDownloading();
}

void TorrentManager::OnTorrentCheckingFiles(const scoped_refptr<Torrent>& torrent) {
  //DLOG(INFO) << "TorrentManager::OnTorrentCheckingFiles"; 
  torrent->OnCheckingFiles();
}

void TorrentManager::OnTorrentDownloadingMetadata(const scoped_refptr<Torrent>& torrent) {
  //DLOG(INFO) << "TorrentManager::OnTorrentDownloadingMetadata";
  torrent->OnDownloadingMetadata();
}

void TorrentManager::OnTorrentSeeding(const scoped_refptr<Torrent>& torrent) {
  //DLOG(INFO) << "TorrentManager::OnTorrentSeeding";
  //std::string text;
  //if (google::protobuf::TextFormat::PrintToString(torrent->info(), &text)) {
  //  printf("%s\n", text.c_str());
  //}

  if (delegate_) {
    delegate_->OnTorrentSeeding(torrent);
  }
  torrent->OnSeeding();
}

void TorrentManager::OnTorrentCheckingResumeData(const scoped_refptr<Torrent>& torrent) {
  //DLOG(INFO) << "TorrentManager::OnTorrentCheckingResumeData"; 
}

void TorrentManager::OnTorrentStateChanged(lt::torrent_handle const& h, 
                                           lt::torrent_status::state_t state, 
                                           lt::torrent_status::state_t prev_state) {
  //DLOG(INFO) << "TorrentManager::OnTorrentStateChanged: " << get_torrent_state(state) << " was " << get_torrent_state(prev_state);
  auto storage = h.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    //DLOG(INFO) << "TorrentManager::OnTorrentStateChanged: torrent " << (int)storage << " not found";
    return;
  }  
  switch (state) {
    case lt::torrent_status::checking_files:
      torrent->set_state(storage_proto::STATE_CHECKING);
      OnTorrentCheckingFiles(torrent);
      break;
    case lt::torrent_status::downloading_metadata:
      torrent->set_state(storage_proto::STATE_DOWNLOADING_META);
      OnTorrentDownloadingMetadata(torrent);
      break;
    case lt::torrent_status::downloading:
      torrent->set_state(storage_proto::STATE_DOWNLOADING);
      OnTorrentDownloading(torrent);
      break;
    case lt::torrent_status::finished:
      torrent->set_state(storage_proto::STATE_FINISHED);
      OnTorrentFinished(torrent);
      break;
    case lt::torrent_status::seeding:
      torrent->set_state(storage_proto::STATE_SEEDING);
      OnTorrentSeeding(torrent);
      break;
    case lt::torrent_status::checking_resume_data:
      torrent->set_state(storage_proto::STATE_CHECKING);
      OnTorrentCheckingResumeData(torrent);
      break;
    case lt::torrent_status::allocating:
    default:
      return;
  }

}

void TorrentManager::OnDHTAnnounceReply(libtorrent::torrent_handle thandle, int peer_count) {
  std::vector<libtorrent::peer_info> peers;
  std::shared_ptr<libtorrent::torrent> lt_torrent = thandle.native_handle();
  std::string peers_str;

  lt_torrent->get_peer_info(&peers);
  for (auto it = peers.begin(); it != peers.end(); ++it) {
    peers_str += "  " + (*it).ip.address().to_string() + ":" + base::IntToString((*it).ip.port()) + "\n";
  }

  //DLOG(INFO) << "TorrentManager::OnDHTAnnounceReply: peers count = " << peer_count << "\n" << peers_str;
  std::vector<libtorrent::alert*> alerts;
  GetAlerts(&alerts);
  for (libtorrent::alert* alert : alerts) {
    printf("[*] %s\n", alert->message().c_str());
  }

  auto storage = thandle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  torrent->OnDHTAnnounceReply(peer_count);
}

void TorrentManager::OnBlockFinished(lt::torrent_handle h, 
                                     lt::tcp::endpoint const& ep, 
                                     lt::peer_id const& peer_id, 
                                     int block_num, 
                                     lt::piece_index_t piece_num) {
  //DLOG(INFO) << "TorrentManager::OnBlockFinished";
}

void TorrentManager::OnPieceHashedError(lt::error_code const& ec, 
                                        lt::string_view file, 
                                        lt::operation_t op, 
                                        lt::torrent_handle const& handle) {
  DLOG(INFO) << "TorrentManager::OnPieceHashedError"; 
}

void TorrentManager::OnPieceReadError(lt::torrent_handle const& handle, 
                                      lt::piece_index_t piece_num,
                                      lt::error_code const& ec) {
  DLOG(INFO) << "TorrentManager::OnPieceReadError: piece = " << (int)piece_num;
  //auto storage = handle.native_handle()->storage();
  //Torrent* t = GetTorrent(storage);
  //if (!t) {
  //  return;
  //}
  //storage_proto::InfoPiece* piece = t->GetPieceInfo(piece_num);
  //piece->set_state(storage_proto::STATE_ERROR);
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  torrent->OnPieceReadError(piece_num, ec.value()); 
}

void TorrentManager::OnMetadataReceived(lt::torrent_handle const& handle) {
  //DLOG(INFO) << "TorrentManager::OnMetadataReceived";
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  torrent->OnMetadataReceived();
}

void TorrentManager::OnMetadataError(lt::torrent_handle const& handle,
                                     lt::error_code const& ec) {
  DLOG(INFO) << "TorrentManager::OnMetadataError";
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  torrent->OnMetadataError(ec.value());
}

void TorrentManager::OnPiecePass(lt::torrent_handle const& handle, 
                                 lt::piece_index_t piece_num) {
  //DLOG(INFO) << "TorrentManager::OnPiecePass: piece = " << (int)piece_num;
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  torrent->OnPiecePass(piece_num);
}

void TorrentManager::OnPieceFailed(lt::torrent_handle const& handle, 
                                   lt::piece_index_t piece_num) {
  DLOG(INFO) << "TorrentManager::OnPieceFailed: piece = " << (int)piece_num;
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  torrent->OnPieceFailed(piece_num);
}

void TorrentManager::OnPieceFinished(lt::torrent_handle const& handle, 
                                     lt::piece_index_t piece_num) {
  //DLOG(INFO) << "TorrentManager::OnPieceFinished: piece = " << (int)piece_num;
  //auto storage = handle.native_handle()->storage();
  //Torrent* t = GetTorrent(storage);
  //if (!t) {
   // return;
  //}
  //storage_proto::InfoPiece* piece = t->GetPieceInfo(piece_num);
  //piece->set_state(storage_proto::STATE_FINISHED);
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  torrent->OnPieceFinished(piece_num);
}

void TorrentManager::OnPieceHashCheckFailed(lt::torrent_handle const& handle, lt::piece_index_t piece_num) {
  DLOG(INFO) << "TorrentManager::OnPieceHashCheckFailed: piece = " << (int)piece_num;
  //auto storage = handle.native_handle()->storage();
  //Torrent* t = GetTorrent(storage);
  //if (!t) {
  //  return;
  //}
  //storage_proto::InfoPiece* piece = t->GetPieceInfo(piece_num);
  //piece->set_state(storage_proto::STATE_ERROR);
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  torrent->OnPieceHashFailed(piece_num);
}

void TorrentManager::OnFileCompleted(lt::torrent_handle const& handle, lt::file_index_t idx) {
  //DLOG(INFO) << "TorrentManager::OnFileCompleted: file index = " << (int)idx;
  // we need to Close
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  torrent->OnFileCompleted(idx);
}

void TorrentManager::OnTrackerWarning(lt::torrent_handle const& handle, 
                        lt::tcp::endpoint const& endpoint, 
                        lt::string_view url, 
                        lt::string_view message) {
  //DLOG(INFO) << "TorrentManager::OnTrackerWarning";
}

void TorrentManager::OnTrackerScrapeReply(lt::torrent_handle const& handle, 
                                    lt::tcp::endpoint const& endpoint,
                                    int incomplete, 
                                    int complete, 
                                    lt::string_view url) {
  //DLOG(INFO) << "TorrentManager::OnTrackerScrapeReply";
}

void TorrentManager::OnTrackerReply(lt::torrent_handle const& handle, 
                              lt::tcp::endpoint const& endpoint, 
                              int num_peers, 
                              lt::string_view url) {
  //DLOG(INFO) << "TorrentManager::OnTrackerReply";
}

void TorrentManager::OnPeerBlocked(lt::torrent_handle const& handle, 
                             lt::tcp::endpoint const& endpoint, 
                             int result) {
  //DLOG(INFO) << "TorrentManager::OnPeerBlocked";
}

bool TorrentManager::OpenEntry(lt::storage_index_t storage) {
  scoped_refptr<Torrent> t = GetTorrent(storage);
  if (!t) {
    LOG(ERROR) << "TorrentManager::OpenEntry: torrent with id " << (int)storage << " not found";
    return false;
  }
  int r = t->Open();
  return r == 0 ? true : false;
}

bool TorrentManager::EntryChecked(lt::storage_index_t storage) {
  scoped_refptr<Torrent> t = GetTorrent(storage);
  if (!t) {
    LOG(ERROR) << "TorrentManager::EntryChecked: torrent with id " << (int)storage << " not found";
    return false;
  }
  return t->is_checked();
}

void TorrentManager::SetEntryChecked(lt::storage_index_t storage, bool checked) {
  scoped_refptr<Torrent> t = GetTorrent(storage);
  if (!t) {
    LOG(ERROR) << "TorrentManager::SetEntryChecked: torrent with id " << (int)storage << " not found";
    return;
  }
  t->set_checked(checked);
}

bool TorrentManager::CreateEntry(lt::storage_index_t storage) {
  scoped_refptr<Torrent> t = GetTorrent(storage);
  if (!t) {
    LOG(ERROR) << "TorrentManager::OpenEntry: torrent with id " << (int)storage << " not found";
    return false;
  }
  int r = t->Create();
  return r == 0 ? true : false;
}

const char* TorrentManager::GetEntryHash(lt::storage_index_t storage, lt::piece_index_t piece) {
  scoped_refptr<Torrent> t = GetTorrent(storage);
  if (!t) {
    LOG(ERROR) << "TorrentManager::GetEntryHash: torrent with id " << (int)storage << " not found";
    return nullptr;
  }
  return t->GetHash(piece);
}

std::vector<const char *> TorrentManager::GetEntryBlockHashes(lt::storage_index_t storage) {
  std::vector<const char *> result;
  scoped_refptr<Torrent> t = GetTorrent(storage);
  if (!t) {
    LOG(ERROR) << "TorrentManager::GetEntryBlockHashes: torrent with id " << (int)storage << " not found";
    return result;
  }
  if (!t->GetHashList(&result)) {
    LOG(ERROR) << "TorrentManager::GetEntryBlockHashes: error while getting entry hashes from the backend"; 
  }
  return result;
}

void TorrentManager::OnReleaseFiles(lt::storage_index_t storage) {
  if (is_shutting_down_) {
    return;
  }
  auto it = torrent_list_.find((int)storage);
  if (it == torrent_list_.end()) {
    return;
  }
  scoped_refptr<Torrent> torrent = it->second.get();
  if (torrent->state() == storage_proto::STATE_DOWNLOADING || 
      torrent->state() == storage_proto::STATE_FINISHED || 
      torrent->state() == storage_proto::STATE_SEEDING) {
    //DLOG(INFO) << "TorrentManager::OnReleaseFiles: syncing metadata for torrent " << torrent->id().to_string();
    int r = torrent->SyncMetadata();
    if (r != 0) {
      LOG(ERROR) << "TorrentManager::OnReleaseFiles: failed to sync metadata for torrent " << (int)storage;
    }
  }
  //it->second.reset();
  //torrent_list_.erase(it);
}

void TorrentManager::UpdateMerkleTree(lt::storage_index_t storage, const std::vector<const char *>& block_hashes) {
  // auto it = share_list_.find((int)storage);
  // if (it == share_list_.end()) {
  //   LOG(ERROR) << "TorrentManager::UpdateMerkleTree: torrent with id " << (int)storage << " not found";
  //   return;
  // }
  // Inode* inode = it->second.get();
  // std::shared_ptr<lt::torrent_info> info = inode->handle.mutable_torrent_file();
  // if (!info) {
  //   LOG(ERROR) << "TorrentManager::UpdateMerkleTree: update merkle for torrent " << (int)storage << " failed. torrent info reference is null";
  //   return; 
  // }
  // info->update_merkle_blocks(block_hashes);
}

void TorrentManager::ReadEntry(
  lt::storage_index_t storage, 
  lt::span<lt::iovec_t const> bufs, 
  lt::piece_index_t const piece, 
  int const offset, 
  lt::storage_error& error) {

  scoped_refptr<Torrent> t = GetTorrent(storage);
  if (!t) {
    LOG(ERROR) << "TorrentManager::ReadEntry: torrent with id " << (int)storage << " not found";
    error.ec.assign(1, lt::generic_category());
    error.file((lt::file_index_t)piece);
    error.operation = lt::operation_t::partfile_read;
    return;
  }
  
  lt::iovec_t const buf = bufs[0];
  size_t block_size = t->info().piece_length();
  int file_offset = piece == 0 ? 0 : (piece * block_size);
  DLOG(INFO) << "Read: piece: " << piece << " file_offset: " << file_offset << " size: " << buf.size() << " offset: " << offset;
  int r = t->Read(buf.data(), buf.size(), file_offset);
  if (r != 0) {
    LOG(ERROR) << "TorrentManager::ReadEntry: error reading '" << t->id().to_string() << "'";
    error.ec.assign(1, lt::generic_category());
    error.file((lt::file_index_t)piece);
    error.operation = lt::operation_t::partfile_read;
  }
  t->OnPieceRead(piece, file_offset, buf.size(), block_size, r);
}

void TorrentManager::WriteEntry(lt::storage_index_t storage, lt::span<lt::iovec_t const> bufs, lt::piece_index_t const piece, int const offset, lt::storage_error& error) {
  scoped_refptr<Torrent> t = GetTorrent(storage);
  if (!t) {
    LOG(ERROR) << "TorrentManager::WriteEntry: torrent with id " << (int)storage << " not found";
    error.ec.assign(1, lt::generic_category());
    error.file((lt::file_index_t)piece);
    error.operation = lt::operation_t::partfile_write;
    return;
  }
  
  //lt::iovec_t const buf = bufs[0];
  size_t block_size = t->info().piece_length();
  int file_offset = piece == 0 ? 0 : (piece * block_size);
  
  for (lt::iovec_t const buf: bufs) {
    DLOG(INFO) << "Write: piece: " << piece << " file_offset: " << file_offset << " size: " << buf.size() << " offset: " << offset;
    int r = t->Write(buf.data(), buf.size(), file_offset);
    if (r != 0) {
      LOG(ERROR) << "TorrentManager::WriteEntry: error writing '" << t->id().to_string() << "'";
      error.ec.assign(1, lt::generic_category());
      error.file((lt::file_index_t)piece);
      error.operation = lt::operation_t::partfile_write;
      return;
    }
    file_offset += buf.size();
    t->OnPieceWrite(piece, file_offset, buf.size(), block_size, r);
  }
}

void TorrentManager::OnTorrentInfoLoaded(const scoped_refptr<Torrent>& torrent) {
  LOG(INFO) << "TorrentManager::OnTorrentInfoLoaded";
  if (session()) {
    AddTorrentToSession(torrent);
  }
}

scoped_refptr<TorrentManagerContext> TorrentManager::CreateStorageContext() {
  return scoped_refptr<TorrentManagerContext>(new TorrentManagerContext(this));
}


}
