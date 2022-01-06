// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_TORRENT_STORAGE_H_
#define MUMBA_STORAGE_TORRENT_STORAGE_H_

#include <unordered_map>

#include "base/macros.h"
#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/atomic_sequence_num.h"
#include "base/files/file_path.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner.h"
#include "storage/storage_export.h"
#include "third_party/libtorrent/include/libtorrent/torrent_delegate.hpp"
#include "third_party/libtorrent/include/libtorrent/aux_/session_settings.hpp"
#include "third_party/libtorrent/include/libtorrent/io_context.hpp"
#include "third_party/libtorrent/include/libtorrent/disk_interface.hpp"
#include "third_party/libtorrent/include/libtorrent/aux_/storage_utils.hpp"
#include "third_party/libtorrent/include/libtorrent/disk_buffer_pool.hpp"

namespace storage {
class StorageEntry;
class TorrentManagerContext;
/*
 * A torrent storage over a blob storage (cache filesystem)
 */
class TorrentStorage : public lt::disk_interface, 
                       public lt::buffer_allocator_interface {
public:
  TorrentStorage(scoped_refptr<TorrentManagerContext> manager, lt::io_context& io_context);
  ~TorrentStorage() override;

  void set_settings(lt::settings_pack const*) override;

  lt::storage_holder new_torrent(lt::storage_params params, std::shared_ptr<void> const&) override;

  void remove_torrent(lt::storage_index_t const idx) override;
  void abort(bool) override;
  void async_read(lt::storage_index_t storage, lt::peer_request const& r
    , std::function<void(lt::disk_buffer_holder block, lt::storage_error const& se)> handler
    , lt::disk_job_flags_t) override;

  bool async_write(lt::storage_index_t storage, lt::peer_request const& r
    , char const* buf, std::shared_ptr<lt::disk_observer>
    , std::function<void(lt::storage_error const&)> handler
    , lt::disk_job_flags_t) override;

  void async_hash(lt::storage_index_t storage, lt::piece_index_t const piece, lt::disk_job_flags_t
    , std::function<void(lt::piece_index_t, lt::sha1_hash const&, lt::storage_error const&)> handler) override;

  void async_move_storage(lt::storage_index_t, std::string p, lt::move_flags_t
    , std::function<void(lt::status_t, std::string const&, lt::storage_error const&)> handler) override;

  void async_release_files(lt::storage_index_t, std::function<void()>) override;

  void async_delete_files(lt::storage_index_t, lt::remove_flags_t
    , std::function<void(lt::storage_error const&)> handler) override;

  void async_check_files(lt::storage_index_t
    , lt::add_torrent_params const*
    , lt::aux::vector<std::string, lt::file_index_t>
    , std::function<void(lt::status_t, lt::storage_error const&)> handler) override;

  void async_rename_file(lt::storage_index_t
    , lt::file_index_t const idx
    , std::string const name
    , std::function<void(std::string const&, lt::file_index_t, lt::storage_error const&)> handler) override;

  void async_stop_torrent(lt::storage_index_t, std::function<void()> handler) override;

  void async_set_file_priority(lt::storage_index_t
    , lt::aux::vector<lt::download_priority_t, lt::file_index_t> prio
    , std::function<void(lt::storage_error const&
        , lt::aux::vector<lt::download_priority_t, lt::file_index_t>)> handler) override;

  void async_clear_piece(lt::storage_index_t, lt::piece_index_t index
    , std::function<void(lt::piece_index_t)> handler) override;

 // implements buffer_allocator_interface
  void free_disk_buffer(char*) override;
  void update_stats_counters(lt::counters&) const override;
  std::vector<lt::open_file_state> get_status(lt::storage_index_t) const override;
  void submit_jobs() override;

private:
  // struct Inode {
  //   std::string key;
  //   StorageBackend* backend;
  //   StorageEntry* entry;

  //   Inode(std::string key): key(std::move(key)), backend(nullptr), entry(nullptr) {}
  // };
  //base::AtomicSequenceNumber storage_index_seq_;
  //base::AtomicSequenceNumber disk_seq_;
  scoped_refptr<TorrentManagerContext> manager_;
  lt::aux::session_settings settings_;
  lt::disk_buffer_pool buffer_pool_;
  lt::io_context& io_context_;

  //std::unordered_map<lt::storage_index_t, std::unique_ptr<Inode>> entries_; 

  DISALLOW_COPY_AND_ASSIGN(TorrentStorage);
};

}

#endif