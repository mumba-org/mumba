// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/torrent_storage.h"

#include "base/strings/string_number_conversions.h"
#include "storage/backend/storage_entry.h"
#include "storage/storage.h"
#include "storage/torrent_manager.h"
#include "libtorrent/file_storage.hpp"
#include "libtorrent/add_torrent_params.hpp"
#include "libtorrent/flags.hpp"

namespace storage {

TorrentStorage::TorrentStorage(scoped_refptr<TorrentManagerContext> manager, lt::io_context& io_context): 
  manager_(manager),
  buffer_pool_(io_context),
  io_context_(io_context) {

}

TorrentStorage::~TorrentStorage() {

}

void TorrentStorage::set_settings(lt::settings_pack const* pack) {
  //D//LOG(INFO) << "TorrentStorage::set_settings";
  apply_pack(pack, settings_);
}

lt::storage_holder TorrentStorage::new_torrent(
    lt::storage_params params, 
    std::shared_ptr<void> const&) {
  //D//LOG(INFO) << "TorrentStorage::new_torrent: index = " << (int)params.storage_index;
  return lt::storage_holder(params.storage_index, *this);
}

void TorrentStorage::remove_torrent(lt::storage_index_t const idx) {
  //D//LOG(INFO) << "TorrentStorage::remove_torrent";
}

void TorrentStorage::abort(bool) {
  //D//LOG(INFO) << "TorrentStorage::abort";
}

void TorrentStorage::async_read(
    lt::storage_index_t storage, 
    lt::peer_request const& r, 
    std::function<void(lt::disk_buffer_holder block, 
    lt::storage_error const& se)> handler, 
    lt::disk_job_flags_t) {
  //D//LOG(INFO) << "TorrentStorage::async_read";

  // TODO: see how/if we can reuse the same buffer
  // mmaped to the file from the backstore
  // so we skip this allocation + copy
  lt::disk_buffer_holder buffer = lt::disk_buffer_holder(*this, buffer_pool_.allocate_buffer("send buffer"), lt::default_block_size);
  lt::storage_error error;
  if (!buffer){
    error.ec = lt::errors::no_memory;
    error.operation = lt::operation_t::alloc_cache_piece;
    post(io_context_, [=, h = std::move(handler)]{ h(lt::disk_buffer_holder(*this, nullptr, 0), error); });
    return;
  }

  //lt::time_point const start_time = lt::clock_type::now();
  lt::iovec_t buf = {buffer.data(), r.length};

  //m_torrents[storage]->readv(m_settings, buf, r.piece, r.start, error);
  manager_->ReadEntry(storage, buf, r.piece, r.start, error);

  // if (!error.ec){
  //   std::int64_t const read_time = total_microseconds(clock_type::now() - start_time);

  //   m_stats_counters.inc_stats_counter(counters::num_read_back);
  //   m_stats_counters.inc_stats_counter(counters::num_blocks_read);
  //   m_stats_counters.inc_stats_counter(counters::num_read_ops);
  //   m_stats_counters.inc_stats_counter(counters::disk_read_time, read_time);
  //   m_stats_counters.inc_stats_counter(counters::disk_job_time, read_time);
  // }

  post(io_context_, [h = std::move(handler), b = std::move(buffer), error] () mutable
    { h(std::move(b), error); });
}

bool TorrentStorage::async_write(lt::storage_index_t storage, 
    lt::peer_request const& r, 
    char const* buf, std::shared_ptr<lt::disk_observer>, 
    std::function<void(lt::storage_error const&)> handler,
     lt::disk_job_flags_t) {
  //D//LOG(INFO) << "TorrentStorage::async_write";

  lt::iovec_t const b = { const_cast<char*>(buf), r.length };

  //lt::time_point const start_time = clock_type::now();

  lt::storage_error error;
  manager_->WriteEntry(storage, b, r.piece, r.start, error);
  
  post(io_context_, [=, h = std::move(handler)]{ h(error); });
  return false;
}

void TorrentStorage::async_hash(
    lt::storage_index_t storage, 
    lt::piece_index_t const piece, lt::disk_job_flags_t,
    std::function<void(lt::piece_index_t, lt::sha1_hash const&, 
    lt::storage_error const&)> handler) {
  //D//LOG(INFO) << "TorrentStorage::async_hash";
  lt::storage_error error;

  const char* hash_data = manager_->GetEntryHash(storage, piece);
  if (!hash_data) {
    //DLOG(ERROR) << "TorrentStorage::async_hash: we failed, and need to set the error accordingly";
    error.ec.assign(lt::errors::invalid_piece_index, lt::libtorrent_category());
    post(io_context_, [=]{ handler(piece,  lt::sha1_hash{}, error); });
    return;
  }
  //D//LOG(INFO) << "TorrentStorage::async_hash: hash for " << piece << " = " << base::HexEncode(hash_data, 20);
  
  lt::sha1_hash hash(hash_data);
  post(io_context_, [=]{ handler(piece, hash, error); });
}

void TorrentStorage::async_move_storage(
    lt::storage_index_t, 
    std::string p, lt::move_flags_t, 
    std::function<void(lt::status_t, 
    std::string const&, lt::storage_error const&)> handler) {
  //D//LOG(INFO) << "TorrentStorage::async_move_storage";
}

void TorrentStorage::async_release_files(
    lt::storage_index_t storage, 
    std::function<void()> handler) {
  //D//LOG(INFO) << "TorrentStorage::async_release_files";
  manager_->OnReleaseFiles(storage);
  post(io_context_, std::move(handler));
}

void TorrentStorage::async_delete_files(lt::storage_index_t, 
    lt::remove_flags_t, 
    std::function<void(lt::storage_error const&)> handler) {
  //D//LOG(INFO) << "TorrentStorage::async_delete_files";
}

void TorrentStorage::async_check_files(
    lt::storage_index_t index, 
    lt::add_torrent_params const* resume_data, 
    lt::aux::vector<std::string, lt::file_index_t> links, 
    std::function<void(lt::status_t, lt::storage_error const&)> handler) {

  lt::storage_error error;
  //lt::status_t ret = lt::status_t::need_full_check;
  lt::status_t ret = lt::status_t::no_error;

  lt::add_torrent_params tmp;
  lt::add_torrent_params const* rd = resume_data ? resume_data : &tmp;

  //D//LOG(INFO) << "TorrentStorage::async_check_files: opening entry '" << index << "' in sync mode..";
  if (!manager_->OpenEntry(index)) {
    if (!manager_->CreateEntry(index)) {
      //D//LOG(INFO) << "TorrentStorage::async_check_files: failed while creating entry";
      ret = lt::status_t::fatal_disk_error;
    } else {// else {
    //  ret = lt::status_t::file_exist;//no_error;
    //}
      //D//LOG(INFO) << "TorrentStorage::async_check_files: entry was created now. returning no_error";  
      ret = lt::status_t::no_error;
    }
  } else if (manager_->EntryChecked(index)) {
    //D//LOG(INFO) << "TorrentStorage::async_check_files: entry already checked. returning no_error";  
    ret = lt::status_t::no_error;//file_exist;
  } else {
    //D//LOG(INFO) << "TorrentStorage::async_check_files: entry exists, but not checked. returning need_full_check";  
    //std::vector<const char *> hashes = delegate_->GetEntryBlockHashes(index);
    //if (hashes.size() > 0) {
    //  //D//LOG(INFO) << "TorrentStorage::async_check_files: updating torrent info merkle tree piece values";
    //  delegate_->UpdateMerkleTree(index, hashes);
    //}
    ret = lt::status_t::need_full_check;
  }
  //for (auto file : links) {
  //  //D//LOG(INFO) << "file -- name: " << file;//.first << " index: " << file.second;
  //}

  post(io_context_, [error, ret, h = std::move(handler)]{ h(ret, error); });
}

void TorrentStorage::async_rename_file(
    lt::storage_index_t, 
    lt::file_index_t const idx, 
    std::string const name, 
    std::function<void(std::string const&, lt::file_index_t, lt::storage_error const&)> handler) {
  //D//LOG(INFO) << "TorrentStorage::async_rename_file";
}

void TorrentStorage::async_stop_torrent(lt::storage_index_t, std::function<void()> handler) {
  //D//LOG(INFO) << "TorrentStorage::async_stop_torrent";
  if (!handler) {
    return;
  }
  post(io_context_, std::move(handler));
}

void TorrentStorage::async_set_file_priority(
    lt::storage_index_t, 
    lt::aux::vector<lt::download_priority_t, lt::file_index_t> prio, 
    std::function<void(lt::storage_error const&, 
    lt::aux::vector<lt::download_priority_t, lt::file_index_t>)> handler) {
  //D//LOG(INFO) << "TorrentStorage::async_set_file_priority";
}

void TorrentStorage::async_clear_piece(
   lt::storage_index_t, 
   lt::piece_index_t index, 
   std::function<void(lt::piece_index_t)> handler) {
  //D//LOG(INFO) << "TorrentStorage::async_clear_piece";
}

void TorrentStorage::free_disk_buffer(char* b) {
  //D//LOG(INFO) << "TorrentStorage::free_disk_buffer";
  buffer_pool_.free_buffer(b);
}

void TorrentStorage::update_stats_counters(lt::counters&) const {
  //D//LOG(INFO) << "TorrentStorage::update_stats_counters";
}

std::vector<lt::open_file_state> TorrentStorage::get_status(lt::storage_index_t) const {
  //D//LOG(INFO) << "TorrentStorage::get_status";
  return {};
}

void TorrentStorage::submit_jobs() {
  ////D//LOG(INFO) << "TorrentStorage::submit_jobs";
}

}