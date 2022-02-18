// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/torrent_manager.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/lazy_instance.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/strings/utf_string_conversions.h"
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
#include "libtorrent/flags.hpp"
#include "libtorrent/magnet_uri.hpp"
#include "libtorrent/extensions/ut_pex.hpp"
#include "libtorrent/extensions/ut_metadata.hpp"
#include "libtorrent/extensions/smart_ban.hpp"
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

#ifndef TORRENT_DISABLE_LOGGING
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
#endif

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

std::string TorrentStateToString(libtorrent::torrent_status::state_t state) {
  switch (state) {
    case libtorrent::torrent_status::checking_files:
      return "CHECKING_FILES";
		case libtorrent::torrent_status::downloading_metadata:
      return "DOWNLOADING_METADATA";
    case libtorrent::torrent_status::downloading:
      return "DOWNLOADING";
    case libtorrent::torrent_status::finished:
      return "FINISHED";
    case libtorrent::torrent_status::seeding:
      return "SEEDING";
    case libtorrent::torrent_status::allocating:
      return "ALLOCATING";
    case libtorrent::torrent_status::checking_resume_data:
      return "CHECKING_RESUME_DATA";
    default:
      return "INVALID";
  }
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
  scoped_refptr<base::SingleThreadTaskRunner> backend_io_runner):
 delegate_(delegate),
 dht_storage_constructor_(libtorrent::dht::dht_default_storage_constructor),
 alerts_(1000, libtorrent::alert_category_t::all()),
 backend_io_runner_(backend_io_runner),
 started_(false),
 starting_(false),
 is_shutting_down_(false),
 is_really_shutting_down_(false),
 force_announcement_scheduled_(false),
 shutdown_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED),
 started_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED),
 weak_factory_(this),
 weak_factory_for_io_(new base::WeakPtrFactory<TorrentManager>(this)) {
  
  g_torrent_manager = this;
}

TorrentManager::~TorrentManager() {
  auto* ptr = weak_factory_for_io_.release();
  backend_io_runner_->DeleteSoon(FROM_HERE, ptr);
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
  if (starting_) {
    DLOG(INFO) << "TorrentManager::Start: called twice. cancelling the second start";
    return;
  }
  starting_ = true;
  libtorrent::settings_pack settings = libtorrent::default_settings();
  
  settings.set_int(libtorrent::settings_pack::alert_mask, 
                   lt::alert::torrent_log_notification | 
                   lt::alert::session_log_notification | 
                   lt::alert::stats_notification | 
                   lt::alert::status_notification |
                   lt::alert::picker_log_notification | 
                   lt::alert::piece_progress_notification | 
                   lt::alert::file_progress_notification | 
                   lt::alert::upload_notification);

  settings.set_bool(libtorrent::settings_pack::enable_lsd, true);
  settings.set_bool(libtorrent::settings_pack::enable_outgoing_utp, true);
	settings.set_bool(libtorrent::settings_pack::enable_incoming_utp, true);
	settings.set_bool(libtorrent::settings_pack::enable_outgoing_tcp, true);
	settings.set_bool(libtorrent::settings_pack::enable_incoming_tcp, true);
  settings.set_bool(libtorrent::settings_pack::allow_multiple_connections_per_ip, true);
  settings.set_bool(libtorrent::settings_pack::prioritize_partial_pieces, true);
  //settings.set_str(libtorrent::settings_pack::outgoing_interfaces, "wlp2s0, lo, 192.168.1.68, 127.0.0.1");
  
  // should be temporary
  settings.set_bool(libtorrent::settings_pack::disable_hash_checks, true);
  
  
  //settings.set_str(libtorrent::settings_pack::listen_interfaces, "0.0.0.0:6881,[::]:6881");

  io_context_ = std::make_shared<libtorrent::io_context>();

  //libtorrent::disk_io_constructor_type disk_io;
  libtorrent::disk_io_constructor_type disk_io = TorrentStorageConstructor;
  session_ = std::make_shared<libtorrent::aux::session_impl>(this, std::ref(*io_context_.get()), std::move(settings), std::move(disk_io));
  session_->add_ses_extension(std::make_shared<libtorrent::aux::session_impl::session_plugin_wrapper>(libtorrent::create_ut_pex_plugin));
  session_->add_ses_extension(std::make_shared<libtorrent::aux::session_impl::session_plugin_wrapper>(libtorrent::create_ut_metadata_plugin));
  session_->add_ses_extension(std::make_shared<libtorrent::aux::session_impl::session_plugin_wrapper>(libtorrent::create_smart_ban_plugin));
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
    base::Bind(&TorrentManager::RunBackendIO, weak_factory_for_io_->GetWeakPtr()));

  //SchedulePrintManagedTorrentList();
  //ScheduleForceDHTAnnouncement();
  //base::PostDelayedTask(FROM_HERE, base::Bind(&TorrentManager::PrintRetainedByList, base::Unretained(this)), base::TimeDelta::FromMilliseconds(5 * 1000));
}

void TorrentManager::Stop() {
  session_->alerts().set_notify_function({});
  session_->call_abort();//->abort();
  ProcessShutdownEvents();
}

void TorrentManager::Shutdown() {
  // wait until started
  is_shutting_down_ = true;
  //if (starting_ && !started_) {
  //  //LOG(INFO) << "not bootstraped yet. just waiting..";
  //  started_event_.Wait();
  //  started_event_.Reset();
  //  //LOG(INFO) << "ok.. ended waiting";
  //}
  Stop();
}

void TorrentManager::ProcessShutdownEvents() {
  //if (is_really_shutting_down_) {
  shutdown_event_.Wait();  
  ProcessFinalShutdown();
  //  return;
  //}
  //std::vector<libtorrent::alert*> alerts;
  //session_->pop_alerts(&alerts);
  //GetAlerts(&alerts);
  //for (lt::alert const* a : alerts) {
    //std::cout << a->message() << std::endl;
    // if we receive the finished alert or an error, we're done
    //if (lt::alert_cast<lt::torrent_finished_alert>(a)) {
    //  //D//LOG(INFO) << "finished alert received: should exit..";
    //  //break 2;
    //  //goto done;
    //  ProcessFinalShutdown(shutdown_event);
    //  return;
    //} else if (lt::alert_cast<lt::torrent_error_alert>(a)) {
    //  //D//LOG(INFO) << "error alert received: should exit..";
      //break 2;
      //goto done;
    //  ProcessFinalShutdown(shutdown_event);
    //  return;
    //}
  //}
  // base::PostDelayedTaskWithTraits(
  //   FROM_HERE,
  //   { base::WithBaseSyncPrimitives(), base::MayBlock() },
  //   base::BindOnce(&TorrentManager::ProcessShutdownEvents, base::Unretained(this), base::Unretained(shutdown_event)),
  //   base::TimeDelta::FromMilliseconds(200));
}

void TorrentManager::ProcessFinalShutdown() {
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
  //weak_factory_for_io_.InvalidateWeakPtrs();
  // torrent_list_.clear();
  session_ = nullptr;
}

void TorrentManager::ReleaseTorrents() {
  for (auto it = torrent_list_.begin(); it != torrent_list_.end(); ++it) {
    Torrent* torrent = it->second.get();
    if (torrent->is_open()) {
      ////LOG(INFO) << "TorrentManager::ProcessFinalShutdown: is open";
      //if ((torrent->is_tree() &&  torrent->is_root())|| torrent->is_database()) {
      if (torrent->is_root() || torrent->is_data()) {
        // root can have "side effects" as it might be writing

        // if (torrent->is_busy()) {
        //   ////LOG(INFO) << "TorrentManager::ProcessFinalShutdown: is open and is busy: waiting..";
        //   torrent->WaitPendingIO();
        //   ////LOG(INFO) << "TorrentManager::ProcessFinalShutdown: ended waiting";
        // }
        ////LOG(INFO) << "TorrentManager::ProcessFinalShutdown: is open and tree or db: closing database..";
        if (torrent->db_is_open()) {
          torrent->db().Close();
        } else {
          torrent->Close(false);
        }
      } else {
        ////LOG(INFO) << "TorrentManager::ProcessFinalShutdown: is open and files: closing entry..";
        torrent->Close(false);
      }
    } else {
      ////LOG(INFO) << "TorrentManager::ProcessFinalShutdown: is not open";
    }
    //it->second.reset();
  }
  torrent_list_.clear();
}

void TorrentManager::RunBackendIO() {
  utp_socket_manager_.reset(
    new libtorrent::utp_socket_manager(
      std::bind(&TorrentManager::SendUdpPacket, this, _1, _2, _3, _4, _5),
      std::bind(&TorrentManager::IncomingConnection, this, _1),
      *io_context_,
      settings_, 
      stats_counters_, 
      nullptr));
  io_context_->run();
  weak_factory_for_io_->InvalidateWeakPtrs();
  //weak_factory_for_io_.reset();
  is_really_shutting_down_ = true;
  //if (shutdown_event_) {
  //  shutdown_event_->Signal();
  //}
  shutdown_event_.Signal();
}

void TorrentManager::OnSessionStart(
  base::Callback<void(std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const&)> bootstrap_cb,
  std::vector<std::pair<libtorrent::dht::node_entry, std::string>> const& dht_nodes) {
  started_ = true;
  starting_ = false;
  if (!is_shutting_down_) {
    std::move(bootstrap_cb).Run(dht_nodes);
  }
  // backend_io_runner_->PostTask(
  //   FROM_HERE, 
  //   base::Bind(&TorrentManager::RunBackendIO, weak_factory_for_io_->GetWeakPtr()));
  started_event_.Signal();
}

scoped_refptr<Torrent> TorrentManager::NewTorrent(IOHandler* io_handler, std::unique_ptr<storage_proto::Info> info, bool is_root) {
  lt::storage_index_t index = storage_index_seq_.GetNext() + 1;
  scoped_refptr<Torrent> parent = nullptr;
  if (!is_root) {
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
    //DCHECK(parent);
  }
  scoped_refptr<Torrent> torrent(new Torrent(this, parent, id, index, io_handler));
  AddTorrent(index, torrent);
  //if (session()) {
  //  AddTorrentToSession(torrent);
  //}
  return torrent;
}

bool TorrentManager::AddTorrentToSessionOrUpdate(const scoped_refptr<Torrent>& torrent) {
  //LOG(INFO) << "TorrentManager::AddTorrentToSessionOrUpdate: " << torrent->id().to_string();
  // if (!torrent->metadata_loaded()) {
  //   DLOG(INFO) << "TorrentManager::AddTorrentToSession: torrent metadata is not loaded yet. cancelling";
  //   return false;
  // }
  libtorrent::error_code ec;
  libtorrent::torrent_handle torrent_handle;
 
  IOHandler* io_handler = torrent->io_handler();
  libtorrent::add_torrent_params params;
  
  if (!torrent->have_metadata()) {
    libtorrent::error_code parse_magnet_uri_ec;
    params = libtorrent::parse_magnet_uri(torrent->info().magnet_url(), parse_magnet_uri_ec);
    if (parse_magnet_uri_ec.value() != 0) {
      LOG(ERROR) << "TorrentManager::AddTorrentToSession: error while parsing magnet url: " << parse_magnet_uri_ec.message() << " url: " << torrent->info().magnet_url();
      return false;
    }
    // force only downloading metadata first.
    // once the metadata is full, we properly initiate
    // this torrent
    //params.flags = params.flags | lt::torrent_flags::upload_mode;
    params.flags = params.flags | lt::torrent_flags::auto_managed;
  }
  
  params.torrent_delegate = this;
#if defined (OS_WIN)
  params.save_path = base::UTF16ToASCII(io_handler->GetPath().value()) + "/" + torrent->path();
#else
  params.save_path = io_handler->GetPath().value() + "/" + torrent->path();
#endif
  params.storage = torrent->storage_id();

  if (torrent->have_metadata()) {
    if (torrent->should_seed()) {
      params.flags = libtorrent::torrent_flags::seed_mode;
    }
    params.ti = torrent->torrent_info();
    if (!params.ti->parse_protobuf(torrent->info(), ec, torrent->added_to_session())) {
      LOG(ERROR) << "TorrentManager::AddTorrentToSession: error while creating torrent info from protobuf info";
      return false;
    }
  }
  // FIXME: this is a hack. If we just add to the session on the first time
  //        the torrent is not properly shared (even if the other side find it on DHT)
  //        so in this case we are removing and adding it again.
  //        before we were just not adding it again (as it should be), 
  //        but then it was not sharing properly
  if (!torrent->added_to_session()) {
    session()->async_add_torrent_cb(std::move(params), base::BindOnce(&TorrentManager::OnTorrentAdded, base::Unretained(this), torrent));
  } //else {
  //  session()->remove_torrent(torrent->handle(), libtorrent::remove_flags_t());
  //  session()->async_add_torrent(&params, base::BindOnce(&TorrentManager::OnTorrentAdded, base::Unretained(this), torrent));
  //}

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
  //LOG(INFO) << "TorrentManager::AddTorrent: adding torrent " << torrent->id().to_string() << "' storage_id: " << index;
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
  LOG(INFO) << "GetImmutableItem got:\n'" << i.value().to_string() << "'";
  //alerts_.emplace_alert<libtorrent::dht_immutable_item_alert>(target, i.value());
  std::move(cb).Run(std::move(target), i);
}

void TorrentManager::GetMutableItem(std::array<char, 32> key, const base::Callback<void(const libtorrent::entry&, const std::array<char, 32>&, const std::array<char, 64>&, const std::int64_t&, std::string const&, bool)>& get_cb, std::string salt) {
  dht()->get_item(libtorrent::dht::public_key(key.data()), std::bind(&TorrentManager::OnGetMutableItem
			, this, get_cb, _1, _2), std::move(salt));
}

void TorrentManager::OnGetMutableItem(const base::Callback<void(const libtorrent::entry&, const std::array<char, 32>&, const std::array<char, 64>&, const std::int64_t&, std::string const&, bool)>& get_cb, libtorrent::dht::item const& i, bool authoritative) {
  libtorrent::entry value = i.value();

  LOG(INFO) << "OnGetMutableItem:\n" << value.to_string();

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
  LOG(ERROR) << "TorrentManager::LiveNodes: live nodes disabled til we replace the alert system with callbacks";
  DCHECK(false);
  //auto nodes = dht()->live_nodes(nid);
	//alerts_.emplace_alert<libtorrent::dht_live_nodes_alert>(nid, nodes);
}

void TorrentManager::SampleInfohashes(libtorrent::udp::endpoint const& ep, libtorrent::sha1_hash const& target) {
  LOG(ERROR) << "TorrentManager::SampleInfohashes: sample infohashes disabled til we replace the alert system with callbacks";
  DCHECK(false);
  // dht()->sample_infohashes(ep, target, [this, &ep](
  //   libtorrent::time_duration interval, 
  //   int num, 
  //   std::vector<libtorrent::sha1_hash> samples, 
  //   std::vector<std::pair<libtorrent::sha1_hash, libtorrent::udp::endpoint>> nodes) {
		// 	alerts_.emplace_alert<libtorrent::dht_sample_infohashes_alert>(ep, interval, num, samples, nodes);
		// });
}

void TorrentManager::DirectRequest(libtorrent::udp::endpoint const& ep, libtorrent::entry& e, void* userdata) {
  //DLOG(INFO) << "TorrentManager::DirectRequest";
  dht()->direct_request(ep, e, std::bind(&TorrentManager::OnDirectResponse, this, userdata, _1));
}

void TorrentManager::OnDirectResponse(void* userdata, libtorrent::dht::msg const& msg) {
  //DLOG(INFO) << "TorrentManager::OnDirectResponse";
 	//if (msg.message.type() == libtorrent::bdecode_node::none_t)
	//  alerts_.emplace_alert<libtorrent::dht_direct_response_alert>(userdata, msg.addr);
	//else
 //		alerts_.emplace_alert<libtorrent::dht_direct_response_alert>(userdata, msg.addr, msg.message);
}

void TorrentManager::UpdateBootstrapNodes() {
  //DLOG(INFO) << "TorrentManager::UpdateBootstrapNodes";
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
  //DLOG(INFO) << "TorrentManager::set_external_address";
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
  //DLOG(INFO) << "TorrentManager::get_listen_port: ";
  return s.get()->udp_external_port();;
}

void TorrentManager::get_peers(libtorrent::sha1_hash const& ih) {
  //DLOG(INFO) << "TorrentManager::get_peers: nothing here";
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
  //alerts_.emplace_alert<libtorrent::dht_announce_alert>(addr, port, ih);
  LOG(ERROR) << "TorrentManager::announce: live nodes disabled til we replace the alert system with callbacks";
  DCHECK(false);
}

bool TorrentManager::on_dht_request(
  libtorrent::string_view query, 
  libtorrent::dht::msg const& request, 
  libtorrent::entry& response) {
  LOG(INFO) << "TorrentManager::on_dht_request: nothing here. returning false";
  return false;
}

#ifndef TORRENT_DISABLE_LOGGING
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
  ////LOG(INFO) << "TorrentManager::log_packet";
}

#endif

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
  // DLOG(INFO) << "TorrentManager::OnUDPPacket";
}

void TorrentManager::OnAcceptConnection(
  std::shared_ptr<libtorrent::aux::socket_type> const& s, 
  std::weak_ptr<libtorrent::tcp::acceptor> listen_socket, 
  libtorrent::error_code const& e, 
  libtorrent::aux::transport const ssl) {
  DLOG(INFO) << "TorrentManager::OnAcceptConnection";
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

	utp_socket_manager_->writable();
}

void TorrentManager::IncomingConnection(std::shared_ptr<libtorrent::aux::socket_type> const& s) {
  // DLOG(INFO) << "TorrentManager::IncomingConnection";
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
	//DLOG(INFO) << "TorrentManager::OnGetPeers";
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
  //DLOG(INFO) << "TorrentManager::OnTorrentChecked: '" << torrent->id().to_string() << "' setting torrent " << storage_id << " as checked";
  //it->second->checked = true;
  //DLOG(INFO) << "TorrentManager::OnTorrentChecked: setting merkle leafs for torrent " << storage_id;
  torrent->UpdateDigest(handle);
  torrent->OnChecked();
}

void TorrentManager::OnTorrentResumed(lt::torrent_handle handle) {
  lt::storage_index_t storage_id = handle.native_handle()->storage();
  LOG(ERROR) << "TorrentManager::OnTorrentResumed (" << storage_id << ")";
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage_id);
  if (!torrent) {
    LOG(ERROR) << "TorrentManager::OnTorrentResumed: torrent with id " << (int)storage_id << " not found";
    return;
  }
  //DLOG(INFO) << "TorrentManager::OnTorrentResumed: " << torrent->id().to_string();
  //for (int i = 0; i < torrent->info().pieces_size(); i++) {
  //  auto piece = torrent->mutable_info()->mutable_pieces(i);
  //  piece->set_state(storage_proto::STATE_DOWNLOADING);
  //}
  torrent->OnResumed();
}

void TorrentManager::OnTorrentPaused(lt::torrent_handle handle) {
  lt::storage_index_t storage_id = handle.native_handle()->storage();
  // DLOG(INFO) << "TorrentManager::OnTorrentPaused (" << storage_id << ")";
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage_id);
  if (!torrent) {
    //LOG(ERROR) << "TorrentManager::OnTorrentPaused: torrent with id " << (int)storage_id << " not found";
    return;
  }
  //DLOG(INFO) << "TorrentManager::OnTorrentPaused: " << torrent->id().to_string();
  torrent->OnPaused();
}

void TorrentManager::OnTorrentDeleted(lt::torrent_handle handle, lt::sha1_hash const& ih) {
  // DLOG(INFO) << "TorrentManager::OnTorrentDeleted";
  lt::storage_index_t storage_id = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage_id);
  if (!torrent) {
    LOG(ERROR) << "TorrentManager::OnTorrentDeleted: torrent with id " << (int)storage_id << " not found";
    return;
  }
  //DLOG(INFO) << "TorrentManager::OnTorrentDeleted: " << torrent->id().to_string();
  torrent->OnDeleted(); 
}

void TorrentManager::OnTorrentDeletedError(lt::torrent_handle handle, 
                                     lt::error_code const& ec, 
                                     lt::sha1_hash const& ih) {
  // DLOG(INFO) << "TorrentManager::OnTorrentDeletedError";
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
  // DLOG(INFO) << "TorrentManager::OnTorrentFileRenamed";
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
  // DLOG(INFO) << "TorrentManager::OnTorrentFileRenamedError";
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
  //// DLOG(INFO) << "TorrentManager::OnTrackerRequestError";
}

void TorrentManager::OnTrackerScrapeError(lt::torrent_handle const& h, 
                                    lt::tcp::endpoint const& ep, 
                                    lt::string_view u, 
                                    lt::error_code const& e) {
  //// DLOG(INFO) << "TorrentManager::OnTrackerScrapeError";
}

void TorrentManager::OnTorrentFinished(const scoped_refptr<Torrent>& torrent) {
  // DLOG(INFO) << "TorrentManager::OnTorrentFinished: " << torrent->id().to_string();//: state = " << get_torrent_state(torrent->state());

  // if (torrent->state() == storage_proto::STATE_DOWNLOADING || 
  //     torrent->state() == storage_proto::STATE_FINISHED || 
  //     torrent->state() == storage_proto::STATE_SEEDING) {
  //   //D//LOG(INFO) << "TorrentManager::OnTorrentFinished: closing torrent " << torrent->id();
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
  // DLOG(INFO) << "TorrentManager::OnTorrentDownloading: " << torrent->id().to_string();
  torrent->OnDownloading();
}

void TorrentManager::OnTorrentCheckingFiles(const scoped_refptr<Torrent>& torrent) {
  // DLOG(INFO) << "TorrentManager::OnTorrentCheckingFiles: "  << torrent->id().to_string(); 
  torrent->OnCheckingFiles();
}

void TorrentManager::OnTorrentDownloadingMetadata(const scoped_refptr<Torrent>& torrent) {
  // DLOG(INFO) << "TorrentManager::OnTorrentDownloadingMetadata: " << torrent->id().to_string();
  torrent->OnDownloadingMetadata();
}

void TorrentManager::OnTorrentSeeding(const scoped_refptr<Torrent>& torrent) {
  // DLOG(INFO) << "TorrentManager::OnTorrentSeeding: "  << torrent->id().to_string();
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
  //// DLOG(INFO) << "TorrentManager::OnTorrentCheckingResumeData: "  << torrent->id().to_string(); 
}

void TorrentManager::OnTorrentStateChanged(lt::torrent_handle const& h, 
                                           lt::torrent_status::state_t state, 
                                           lt::torrent_status::state_t prev_state) {
  //: " << get_torrent_state(state) << " was " << get_torrent_state(prev_state);
  auto storage = h.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    ////D//LOG(INFO) << "TorrentManager::OnTorrentStateChanged: torrent " << (int)storage << " not found";
    return;
  }
  //// DLOG(INFO) << "TorrentManager::OnTorrentStateChanged: " << torrent->id().to_string();
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
  int port = 6882;

  lt_torrent->get_peer_info(&peers);
  for (auto it = peers.begin(); it != peers.end(); ++it) {
    peers_str += "  " + (*it).ip.address().to_string() + ":" + base::IntToString((*it).ip.port()) + "\n";
    port = (*it).ip.port();
  }

  std::vector<libtorrent::alert*> alerts;
  GetAlerts(&alerts);
  //for (libtorrent::alert* alert : alerts) {
  //  printf("[*] %s\n", alert->message().c_str());
  //}

  auto storage = thandle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  // DLOG(INFO) << "TorrentManager::OnDHTAnnounceReply: " << torrent->id().to_string() << " peers count = " << peer_count << "\n" << peers_str;
  torrent->OnDHTAnnounceReply(peer_count);
}

void TorrentManager::OnBlockFinished(lt::torrent_handle h, 
                                     lt::tcp::endpoint const& ep, 
                                     lt::peer_id const& peer_id, 
                                     int block_num, 
                                     lt::piece_index_t piece_num) {
  auto storage = h.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  // DLOG(INFO) << "TorrentManager::OnBlockFinished: " << torrent->id().to_string();
}

void TorrentManager::OnPieceHashedError(lt::error_code const& ec, 
                                        lt::string_view file, 
                                        lt::operation_t op, 
                                        lt::torrent_handle const& handle) {
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  // DLOG(INFO) << "TorrentManager::OnPieceHashedError: " << torrent->id().to_string();
}

void TorrentManager::OnPieceReadError(lt::torrent_handle const& handle, 
                                      lt::piece_index_t piece_num,
                                      lt::error_code const& ec) {
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
  // DLOG(INFO) << "TorrentManager::OnPieceReadError: " << torrent->id().to_string() << " piece = " << (int)piece_num;
  torrent->OnPieceReadError(piece_num, ec.value()); 
}

void TorrentManager::OnMetadataReceived(lt::torrent_handle const& handle) {
  // DLOG(INFO) << "TorrentManager::OnMetadataReceived: storage = " << (int)handle.native_handle()->storage();
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    //// DLOG(INFO) << "TorrentManager::OnMetadataReceived: torrent for " << handle.native_handle()->storage() << " not found. cancelling";
    return;
  }
  // // DLOG(INFO) << "TorrentManager::OnMetadataReceived: " << torrent->id().to_string();
  torrent->OnMetadataReceived();
}

void TorrentManager::OnMetadataError(lt::torrent_handle const& handle,
                                     lt::error_code const& ec) {
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  // DLOG(INFO) << "TorrentManager::OnMetadataError: " << torrent->id().to_string();
  torrent->OnMetadataError(ec.value());
}

void TorrentManager::OnPiecePass(lt::torrent_handle const& handle, 
                                 lt::piece_index_t piece_num) {
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  // DLOG(INFO) << "TorrentManager::OnPiecePass: " << torrent->id().to_string() << " piece = " << (int)piece_num;
  torrent->OnPiecePass(piece_num);
}

void TorrentManager::OnPieceFailed(lt::torrent_handle const& handle, 
                                   lt::piece_index_t piece_num) {
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  // DLOG(INFO) << "TorrentManager::OnPieceFailed: " << torrent->id().to_string() << " piece = " << (int)piece_num;
  torrent->OnPieceFailed(piece_num);
}

void TorrentManager::OnPieceFinished(lt::torrent_handle const& handle, 
                                     lt::piece_index_t piece_num) {
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
  // DLOG(INFO) << "TorrentManager::OnPieceFinished: " << torrent->id().to_string() << " piece = " << (int)piece_num;
  torrent->OnPieceFinished(piece_num);
}

void TorrentManager::OnPieceHashCheckFailed(lt::torrent_handle const& handle, lt::piece_index_t piece_num) {
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
  // DLOG(INFO) << "TorrentManager::OnPieceHashCheckFailed: " << torrent->id().to_string() << " piece = " << (int)piece_num;
  torrent->OnPieceHashFailed(piece_num);
}

void TorrentManager::OnFileCompleted(lt::torrent_handle const& handle, lt::file_index_t idx) {
  // we need to Close
  auto storage = handle.native_handle()->storage();
  scoped_refptr<Torrent> torrent = GetTorrent((int)storage);
  if (!torrent) {
    return;
  }
  // DLOG(INFO) << "TorrentManager::OnFileCompleted: " << torrent->id().to_string() << " file index = " << (int)idx;
  torrent->OnFileCompleted(idx);
}

void TorrentManager::OnTrackerWarning(lt::torrent_handle const& handle, 
                        lt::tcp::endpoint const& endpoint, 
                        lt::string_view url, 
                        lt::string_view message) {
  ////D//LOG(INFO) << "TorrentManager::OnTrackerWarning";
}

void TorrentManager::OnTrackerScrapeReply(lt::torrent_handle const& handle, 
                                    lt::tcp::endpoint const& endpoint,
                                    int incomplete, 
                                    int complete, 
                                    lt::string_view url) {
  ////D//LOG(INFO) << "TorrentManager::OnTrackerScrapeReply";
}

void TorrentManager::OnTrackerReply(lt::torrent_handle const& handle, 
                              lt::tcp::endpoint const& endpoint, 
                              int num_peers, 
                              lt::string_view url) {
  //// DLOG(INFO) << "TorrentManager::OnTrackerReply";
}

void TorrentManager::OnPeerBlocked(lt::torrent_handle const& handle, 
                             lt::tcp::endpoint const& endpoint, 
                             int result) {
 // // DLOG(INFO) << "TorrentManager::OnPeerBlocked";
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
  if (!t->is_open()) {
    t->Open();
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
    if (!torrent->SyncMetadata()) {
      DLOG(ERROR) << "TorrentManager::OnReleaseFiles: failed to sync metadata for torrent " << (int)storage;
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
  //D//LOG(INFO) << "Read: piece: " << piece << " file_offset: " << file_offset << " size: " << buf.size() << " offset: " << offset;
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
    // DLOG(INFO) << "Write(" << (int)storage << "): piece: " << piece << " file_offset: " << file_offset << " size: " << buf.size() << " offset: " << offset;
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
  //LOG(INFO) << "TorrentManager::OnTorrentInfoLoaded: " << torrent->id().to_string();
  if (session()) {
    AddTorrentToSessionOrUpdate(torrent);
  }
}

scoped_refptr<TorrentManagerContext> TorrentManager::CreateStorageContext() {
  return scoped_refptr<TorrentManagerContext>(new TorrentManagerContext(this));
}

void TorrentManager::OnTorrentAdded(const scoped_refptr<Torrent>& torrent, libtorrent::torrent_handle torrent_handle) {
  //LOG(INFO) << "TorrentManager::OnTorrentAdded: valid? " << torrent_handle.is_valid() << " storage: " << torrent_handle.native_handle()->storage();
  if (torrent_handle.native_handle()->storage() == 0) {
    //LOG(INFO) << "TorrentManager::OnTorrentAdded: storage is 0. forcing the real number"; 
  }
  torrent->set_handle(std::move(torrent_handle));
  torrent->OnTorrentAddedToSession();
  torrent->set_announce_to_dht(true);
	torrent->set_announce_to_lsd(true);
  if (!torrent->have_metadata()) {
    torrent->auto_managed(true);
  }
  if (torrent->should_seed()) {
    //LOG(INFO) << "TorrentManager::OnTorrentAdded: " << torrent->id().to_string() << " should_seed() = true. calling Seed()";
    torrent->set_upload_mode(true);
    torrent->set_share_mode(true);
    torrent->Seed();
  }
}

void TorrentManager::PrintManagedTorrentList() {
  //LOG(INFO) << "TorrentManager::PrintManagedTorrentList";
  std::vector<libtorrent::torrent_handle> torrents = session_->get_torrents();
  printf("%s - total torrents = %ld\n\n", delegate_->root_path().BaseName().value().c_str(), torrents.size());
  int i = 0;
  for (auto& t : torrents) {
    std::vector<std::int64_t> files;
    auto storage = t.native_handle()->storage();
    // magnet torrents without metadata often have 0 as index
    if (storage == 0) {
      auto status = t.status();
      std::string ih_bytes = status.info_hash.to_string();
      std::string ifh = base::HexEncode(ih_bytes.data(), ih_bytes.size());
      printf("  torrent [%d] (no metadata): %s => %s peers: %d list_peers: %d list_seeds: %d\n", i, ifh.c_str(), TorrentStateToString(status.state).c_str(), status.num_peers, status.list_peers, status.list_seeds);
      continue;
    }
    scoped_refptr<Torrent> tor = GetTorrent((int)storage);
    std::string type(tor->is_data() ? "DATABASE" : "FILEBASE");
    printf("  torrent [%d]: %s '%s' [%s] => %s dht: %s\n", i, tor->info_hash_hex().c_str(), t.name().c_str(), type.c_str(), TorrentStateToString(t.native_handle()->state()).c_str(), (tor->published_on_dht() ? "yes" : "no"));
    t.file_progress(files);
    for (int x = 0; x < files.size(); ++x) {
      printf("      +- file[%d] => %ld\n", x, files[x]);
    }
    ++i;
  }

  std::vector<libtorrent::alert*> alerts;
	session_->pop_alerts(&alerts);
	for (libtorrent::alert const* a : alerts) {
		//printf("[a] %s\n", a->message().c_str());
    if (auto st = lt::alert_cast<lt::state_update_alert>(a)) {
      if (st->status.empty()) continue;
      for (int i = 0; i < st->status.size(); ++i) {
        lt::torrent_status const& s = st->status[i];
        DLOG(INFO) << "\r" << TorrentStateToString(s.state) << " "
          << (s.download_payload_rate / 1000) << " kB/s "
          << (s.total_done / 1000) << " kB ("
          << (s.progress_ppm / 10000) << "%) downloaded\x1b[K";
      }
  	}
  }
  //SchedulePrintManagedTorrentList();
}

void TorrentManager::SchedulePrintManagedTorrentList() {
  // should be temporary, so no problem with the strong ref
  // base::PostDelayedTask(
  //   FROM_HERE, 
  //   base::BindOnce(&TorrentManager::PrintManagedTorrentList, 
  //   //weak_factory_.GetWeakPtr()),
  //   base::Unretained(this)),
  //   base::TimeDelta::FromMilliseconds(20 * 1000));
}

void TorrentManager::TimedForceDHTAnnouncement() {
  //DLOG(INFO) << "TorrentManager::TimedForceDHTAnnouncement";
  force_announcement_scheduled_ = false;
  bool unpublished_torrents = false;
  for (const auto& item : torrent_list_) {
    if (!item.second->published_on_dht() && item.second->have_metadata()) {
      DLOG(INFO) << " " << item.second->info_hash_hex() << " not published on dht. forcing reannounce";
      item.second->Announce();
      unpublished_torrents = true;
    }
  }
  if (unpublished_torrents) {
    //ScheduleForceDHTAnnouncement();
    force_announcement_scheduled_ = true;
  }
}

void TorrentManager::ScheduleForceDHTAnnouncement() {
  // this guard is to avoid scheduling this more than once
  if (force_announcement_scheduled_) {
    return;
  }
  base::PostDelayedTask(
    FROM_HERE, 
    base::BindOnce(&TorrentManager::TimedForceDHTAnnouncement, 
    // FIXME: this is bound to crash. turn it into a safe weak_ptr or something
    base::Unretained(this)), 
    //weak_factory_.GetWeakPtr()),
    base::TimeDelta::FromMilliseconds(30 * 1000));
}

void TorrentManager::OnTick() {
  //TimedForceDHTAnnouncement();
  // if (tick_counter % 10 == 0) {
  //   PrintManagedTorrentList();
  // }
  // tick_counter++;
}

void TorrentManager::PrintRetainedByList() {
  // for (auto it = torrent_list_.begin(); it != torrent_list_.end(); ++it) {
  //   const auto& torrent = it->second;
  //   if (torrent->retained_by_.size() > 0) {
  //     std::string id_str = torrent->id().to_string();
  //     printf("io's retained on torrent '%s': %ld\n", id_str.c_str(), torrent->retained_by_.size());
  //     for (auto rit = torrent->retained_by_.begin(); rit != torrent->retained_by_.end(); ++rit) { 
  //       printf("torrent %s retained by context: %d\n", id_str.c_str(), rit->first);
  //     }
  //   }
  // }
  // base::PostDelayedTask(FROM_HERE, 
  //   base::Bind(&TorrentManager::PrintRetainedByList, 
  //     base::Unretained(this)),
  //     //weak_factory_.GetWeakPtr()), 
  //   base::TimeDelta::FromMilliseconds(5 * 1000));
}

}
