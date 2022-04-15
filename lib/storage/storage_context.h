// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_STORAGE_CONTEXT_H_
#define MUMBA_STORAGE_STORAGE_CONTEXT_H_

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <map>

#include "base/macros.h"
#include "base/callback.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner.h"
#include "base/files/file_path.h"
#include "base/sha1.h"
#include "base/files/file.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/atomic_sequence_num.h"
#include "base/single_thread_task_runner.h"
#include "base/memory/weak_ptr.h"
#include "storage/io_entity.h"
#include "storage/storage_export.h"
#include "storage/storage_info.h"
#include "storage/file_set.h"
#include "storage/backend/storage_entry.h"
#include "storage/backend/storage_backend.h"
#include "storage/merkle_tree.h"
#include "storage/db/db.h"
#include "storage/io_handler.h"
#include "storage/proto/storage.pb.h"
#include "mojo/public/cpp/system/buffer.h"
#include "net/base/io_buffer.h"
#include "net/disk_cache/disk_cache.h"
#include "net/log/net_log.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "url/gurl.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wignored-qualifiers"
#include "third_party/zetasql/parser/parse_tree.h"
#include "third_party/zetasql/parser/ast_node_kind.h"
#include "third_party/zetasql/parser/parser.h"
#include "third_party/zetasql/public/parse_resume_location.h"
#include "third_party/zetasql/base/status.h"
#pragma clang diagnostic pop


namespace storage {
class Torrent;

constexpr size_t kBufSize = 1024 * 1024;

class IOBufferWrapper : public net::IOBuffer {
public:
  IOBufferWrapper(void* data, int64_t size);
  IOBufferWrapper(const void* data, int64_t size);
  ~IOBufferWrapper() override; 
  int64_t size() const {
    return size_;
  } 
private:
  void* real_data_;
  int64_t size_;
};

struct CreateDbParams {
  storage_proto::InfoKind type = storage_proto::InfoKind::INFO_KVDB;
  std::vector<std::string> keyspaces;
  std::vector<std::string> create_table_stmts;
  std::vector<std::string> insert_table_stmts;
  bool in_memory = false;
};

// A shared-over-threads context to hold important handles both in Read and Write scenarios
// (we have to pass a lot of params in async-mode here)
// the idea is also to make ownership semantics more simple

// this is the sole holder of state among read and write methods

struct StorageContext : public base::RefCountedThreadSafe<StorageContext> {
public:
  enum Opcode {
    kUNDEFINED = 0,
    // IO OPS (run on io task runner)
    //kCOPY_FILE = 1,      
    kCOPY_ENTRY = 2,
    kREAD_ENTRY_FILE = 3,
    kWRITE_ENTRY_FILE = 4,
    kADD_ENTRY = 5,
    kADD_ENTRY_EMPTY = 6,
    kCREATE_TORRENT = 7,
    kOPEN_TORRENT = 8,     
    kREAD_TORRENT = 9,
    kWRITE_TORRENT = 10,
    kCLOSE_TORRENT = 11,
    kDELETE_TORRENT = 12,
    kSYNC_TORRENT = 13,
    kGET_ENTRY_INFO = 14,
    kLIST_ENTRIES = 15,
    kSYNC_METADATA = 16,
    kADD_INDEX = 17,
    // DATA OPS (run on db task runner/ actually, unlike IO, any task runner)
    kOPEN_DATABASE = 18,
    kCREATE_DATABASE = 19
  };
  
  // TODO: we need to take things out of the global
  // context, and put them in the inner structs
  // later, instead of having the data for all ops
  // the context can have only the struct it needs
  // according to its opcode

  Opcode op;
  scoped_refptr<Torrent> torrent;
  int id = -1;
  int parent_id = -1;
  base::UUID key;
  int file;
  storage_proto::Info info;
  std::string encoded_header;
  FileSet files;
  bool is_journal = false;
  bool should_close = false;
  bool was_open = false;
  bool is_sync = false;
  int jrn_seq = -1;
  StorageEntry* journal_fd = nullptr;
  scoped_refptr<net::IOBufferWithSize> computed_hash;
  scoped_refptr<net::IOBufferWithSize> header_data;
  scoped_refptr<net::IOBufferWithSize> buffer;
  scoped_refptr<net::IOBufferWithSize> hash_buffer;
  scoped_refptr<IOBufferWrapper> iobuf;
  scoped_refptr<StorageContext> parent;
  //SHA256_CTX sha2_ctx;
  CreateDbParams create_db_params;
  CreateDbParams open_db_params;
  IOHandler* storage;
  std::unique_ptr<StorageIterator> iterator;
  scoped_refptr<WaitableEvent<int>> sync_event;
  scoped_refptr<base::SingleThreadTaskRunner> original_task_runner;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner;
  base::Lock storage_mutex_;
  
  int64_t bytes_total = 0;
  struct {
    int64_t bytes = 0;
    int64_t offset = 0;
    int64_t status = 0;
  } header;

  struct {
    int64_t bytes = 0;
    int64_t offset = 0;
    int64_t status = 0;
  } read;

  struct {
    int64_t bytes = 0;
    int64_t offset = 0;
    int64_t status = 0;
  } write;

  struct {
    base::FilePath src;
    std::string name;
    int64_t content_len = 0;
    int64_t hash_header_len = 0;
    int64_t hash_content_len = 0;
    int64_t block_count = 0;
    int64_t block_size = 0;
    int64_t file_count = 0;
  } add_entry;

  struct {
    base::FilePath dest;
    base::FilePath file_path;
    int64_t bytes_total = 0;
    storage_proto::Info entry_header;
    std::vector<base::File> files;
    mojo::ScopedSharedBufferHandle file_data;
    bool output_as_shared_buffer = false;
    int inode_index = -1;
  } copy_entry;

  struct {
    base::FilePath file_path;
    int64_t bytes_total = 0;
    storage_proto::Info entry_header;
    int offset = -1;
    int size = -1;
    int inode_index = -1;
    //scoped_refptr<net::WrappedIOBuffer> data;
    scoped_refptr<net::IOBuffer> data;
  } write_entry;

  struct {
    std::vector<std::unique_ptr<storage_proto::Info>> entries;
  } list_entries;

  struct {
    int64_t size;
    int64_t offset;
    void* buf;
  } read_torrent;

  struct {
    int64_t size;
    int64_t offset;
    const void* buf;
  } write_torrent;

  CompletionCallback next_callback;
  CompletionCallback exit_callback;
//  base::Callback<void(std::unique_ptr<Block>, int64_t)> list_exit_callback;
  base::Callback<void(storage_proto::Info, int64_t)> info_exit_callback;
  base::Callback<void(int64_t, mojo::ScopedSharedBufferHandle, int64_t)> sharedbuf_exit_callback;

  StorageContext(IOHandler* storage):
    op(kUNDEFINED),
    computed_hash(new net::IOBufferWithSize(base::kSHA1Length)),
    buffer(new net::IOBufferWithSize(kBufSize)),
    storage(storage),
    sync_event(new WaitableEvent<int>()) {
      //SHA256_Init(&sha2_ctx);
    }

  StorageContext(Opcode opcode, IOHandler* storage): 
    op(opcode),
    computed_hash(new net::IOBufferWithSize(base::kSHA1Length)),
    buffer(new net::IOBufferWithSize(kBufSize)),
    storage(storage),
    sync_event(new WaitableEvent<int>()) {
      //SHA256_Init(&sha2_ctx);
  }
      
  template <typename Functor, typename State> void BindNext(Functor&& functor, base::WeakPtr<State> state) {
    next_callback = base::Bind(std::forward<Functor>(functor), state, scoped_refptr<StorageContext>(this));
  }

  template <typename Functor, typename State> void BindExit(Functor&& functor, base::WeakPtr<State> state, CompletionCallback user_callback) {
    exit_callback = base::Bind(std::forward<Functor>(functor), state, scoped_refptr<StorageContext>(this), base::Passed(std::move(user_callback)));
  }

  //template <typename Functor> void BindExit(Functor&& functor, base::Callback<void(std::unique_ptr<Block>, int64_t)> user_callback) {
  //  list_exit_callback = base::Bind(functor, base::Unretained(storage), scoped_refptr<StorageContext>(this), base::Passed(std::move(user_callback)));
  //}

  template <typename Functor, typename State> void BindExit(Functor&& functor, base::WeakPtr<State> state, base::Callback<void(storage_proto::Info, int64_t)> user_callback) {
    info_exit_callback = base::Bind(std::forward<Functor>(functor), state, scoped_refptr<StorageContext>(this), base::Passed(std::move(user_callback)));
  }

  template <typename Functor, typename State> void BindExit(Functor&& functor, base::WeakPtr<State> state, base::Callback<void(int64_t, mojo::ScopedSharedBufferHandle, int64_t)> user_callback) {
    sharedbuf_exit_callback = base::Bind(std::forward<Functor>(functor), state, scoped_refptr<StorageContext>(this), base::Passed(std::move(user_callback)));
  }

  void Next(int64_t result) {
    // should be a 'one shot' callback anyway
    if (!next_callback.is_null())
      std::move(next_callback).Run(result);
  }

  void Exit(int64_t result) {
    Dispose();
    if (!exit_callback.is_null())
      std::move(exit_callback).Run(result);
  }

  void Exit(storage_proto::Info info, int64_t result) {
    Dispose();
    if (!info_exit_callback.is_null())
      std::move(info_exit_callback).Run(std::move(info), result);
  }

  void Exit(int64_t readed, mojo::ScopedSharedBufferHandle data, int64_t result) {
    Dispose();
    if (!sharedbuf_exit_callback.is_null())
      std::move(sharedbuf_exit_callback).Run(readed, std::move(data), result);
  }

  //void Exit(std::unique_ptr<Block> block, int64_t result) {
  //  Dispose();
  //  std::move(list_exit_callback).Run(std::move(block), result);
  //}

  void Dispose() {
    //if (ptr) {
    //  ptr->Close();
    //  ptr = nullptr;
    //}
    //OPENSSL_cleanse(&sha2_ctx, sizeof(sha2_ctx));
  }

  void Signal(int result) {
    sync_event->Signal(result);
  }

private:
  friend class base::RefCountedThreadSafe<StorageContext>;

  ~StorageContext() {
    //CHECK(!ptr);
  }

  DISALLOW_COPY_AND_ASSIGN(StorageContext);
};

}

#endif