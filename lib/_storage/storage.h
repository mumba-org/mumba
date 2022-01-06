// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_STORAGE_H_
#define MUMBA_STORAGE_STORAGE_H_

#include <string>
#include <memory>
#include <unordered_map>
#include <map>

#include "base/macros.h"
#include "base/callback.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner.h"
#include "base/files/file_path.h"
#include "base/files/file.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/atomic_sequence_num.h"
#include "base/single_thread_task_runner.h"
#include "base/memory/weak_ptr.h"
#include "storage/backend/storage_backend.h"
#include "storage/backend/addr.h"
#include "storage/io_entity.h"
#include "storage/storage_export.h"
#include "storage/storage_info.h"
#include "storage/file_set.h"
#include "storage/backend/storage_entry.h"
#include "storage/merkle_tree.h"
#include "storage/torrent.h"
//#include "storage/block.h"
#include "storage/db/db.h"
#include "storage/io_handler.h"
#include "net/base/io_buffer.h"
#include "net/disk_cache/disk_cache.h"
#include "net/log/net_log.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "url/gurl.h"
//#include "third_party/zetasql/public/analyzer.h"
//#include "third_party/zetasql/resolved_ast/resolved_ast.h"
//#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/sha.h"

namespace storage {
class Database;
//class Catalog;
//class Application;
//class RegistryCatalog;
class Manifest;
class TorrentCache;

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

class STORAGE_EXPORT Storage : public IOHandler {
public:
  struct CreateDbParams {
    std::vector<std::string> keyspaces;
  };

  // A shared-over-threads context to hold important handles both in Read and Write scenarios
  // (we have to pass a lot of params in async-mode here)
  // the idea is also to make ownership semantics more simple

  // this is the sole holder of state among read and write methods

  struct StorageContext : public base::RefCountedThreadSafe<Storage::StorageContext> {
  public:
    enum Opcode {
      kUNDEFINED = 0,
      // IO OPS (they run on io task runner)
      kCOPY_FILE = 1,
      kCOPY_ENTRY = 2,
      kMANIFEST_GET = 3,
      kINIT_ENTRY = 4,
      kCREATE_BLOB = 8,
      kOPEN_BLOB = 9,     
      kREAD_BLOB = 10,
      kWRITE_BLOB = 11,
      kCLOSE_BLOB = 12,
      kDELETE_BLOB = 13,
      kGET_ENTRY_INFO = 16,
      kLIST_ENTRIES = 17,
      kSYNC_METADATA = 18,
      
      // DATA OPS (they run on db task runner)
      kOPEN_CATALOG = 6,
      kCREATE_CATALOG = 7,
    };
    // this is meant to work more in a struct fashion
    // by exposing its guts and being about data
    Opcode op;
    scoped_refptr<Torrent> torrent;
    int id = -1;
    int parent_id = -1;
    base::UUID key;
    base::FilePath src;
    base::FilePath dest;
    int file;
    storage_proto::Info info;
    std::string encoded_header;
    FileSet files;
    bool is_journal = false;
    bool should_close = false;
    bool was_open = false;
    int jrn_seq = -1;
    StorageEntry* journal_fd = nullptr;
    scoped_refptr<net::IOBufferWithSize> computed_hash;
    scoped_refptr<net::IOBufferWithSize> header_data;
    scoped_refptr<net::IOBufferWithSize> buffer;
    scoped_refptr<net::IOBufferWithSize> hash_buffer;
    scoped_refptr<IOBufferWrapper> iobuf;
    scoped_refptr<StorageContext> parent;
    //SHA256_CTX sha2_ctx;
    base::File copy_file;
    CreateDbParams create_db_params;
    Storage* storage;
    std::unique_ptr<StorageIterator> iterator;
    scoped_refptr<WaitableEvent<int>> sync_event_;
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
      int64_t content_len = 0;
      int64_t hash_header_len = 0;
      int64_t hash_content_len = 0;
      int64_t block_count = 0;
      int64_t block_size = 0;
      int64_t file_count = 0;
      //std::unique_ptr<MerkleTree> entry_merkle;
    } init;

    CompletionCallback next_callback;
    CompletionCallback exit_callback;
  //  base::Callback<void(std::unique_ptr<Block>, int64_t)> list_exit_callback;
    base::Callback<void(storage_proto::Info, int64_t)> info_exit_callback;

    StorageContext(Storage* storage):
      op(kUNDEFINED),
      computed_hash(new net::IOBufferWithSize(SHA_DIGEST_LENGTH)),
      buffer(new net::IOBufferWithSize(kBufSize)),
      storage(storage),
      sync_event_(new WaitableEvent<int>()) {
        //SHA256_Init(&sha2_ctx);
      }

    StorageContext(Opcode opcode, Storage* storage): 
      op(opcode),
      computed_hash(new net::IOBufferWithSize(SHA_DIGEST_LENGTH)),
      buffer(new net::IOBufferWithSize(kBufSize)),
      storage(storage),
      sync_event_(new WaitableEvent<int>()) {
        //SHA256_Init(&sha2_ctx);
    }
    
    std::string src_string() const {
      return src.value();
    }

    std::string dest_string() const {
      return dest.value();
    }
    
    template <typename Functor> void BindNext(Functor&& functor) {
      next_callback = base::Bind(functor, base::Unretained(storage), scoped_refptr<StorageContext>(this));
    }

    template <typename Functor> void BindExit(Functor&& functor, CompletionCallback user_callback) {
      exit_callback = base::Bind(functor, base::Unretained(storage), scoped_refptr<StorageContext>(this), base::Passed(std::move(user_callback)));
    }

    //template <typename Functor> void BindExit(Functor&& functor, base::Callback<void(std::unique_ptr<Block>, int64_t)> user_callback) {
    //  list_exit_callback = base::Bind(functor, base::Unretained(storage), scoped_refptr<StorageContext>(this), base::Passed(std::move(user_callback)));
    //}

    template <typename Functor> void BindExit(Functor&& functor, base::Callback<void(storage_proto::Info, int64_t)> user_callback) {
      info_exit_callback = base::Bind(functor, base::Unretained(storage), scoped_refptr<StorageContext>(this), base::Passed(std::move(user_callback)));
    }

    void Next(int64_t result) {
      // should be a 'one shot' callback anyway
      std::move(next_callback).Run(result);
    }

    void Exit(int64_t result) {
      Dispose();
      std::move(exit_callback).Run(result);
    }

    void Exit(storage_proto::Info info, int64_t result) {
      Dispose();
      std::move(info_exit_callback).Run(std::move(info), result);
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
      sync_event_->Signal(result);
    }

  private:
    friend class base::RefCountedThreadSafe<StorageContext>;

    ~StorageContext() {
      //CHECK(!ptr);
    }

    DISALLOW_COPY_AND_ASSIGN(StorageContext);
  };

  static std::unique_ptr<Storage> Create(const base::FilePath& dir,
                                         TorrentCache* torrent_cache,
                                         scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
                                         scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                         bool force = false);
  static std::unique_ptr<Storage> Clone(const base::FilePath& dir,
                                        TorrentCache* torrent_cache,
                                        scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
                                        scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                        std::string id = std::string(),
                                        const char* pkey = nullptr,
                                        bool force = false); 
  // generic open
  static std::unique_ptr<Storage> Open(const base::FilePath& path,
                                       TorrentCache* torrent_cache,
                                       scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
                                       scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner);
 
  static std::unique_ptr<Storage> Open(const base::FilePath& path,
                                       TorrentCache* torrent_cache,
                                       scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
                                       scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                       std::unique_ptr<storage_proto::StorageState> state, bool first_run);

  Storage(TorrentCache* torrent_cache,
       const base::FilePath& path,
       scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
       scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
       std::unique_ptr<storage_proto::StorageState> state,
       bool first_run,
       std::string id,
       const char* pkey);


  ~Storage() override;

  // Storage
  void Start(base::Callback<void(Storage*, int)> callback = base::Callback<void(Storage*, int)>());
  void Stop(CompletionCallback callback = CompletionCallback());

  // Storage
  const base::FilePath& path() const;
  size_t size() const;
  const std::string& address() const;
  bool is_signed() const;
  storage_proto::StorageStatus status() const;
  const storage_proto::StorageState* state() const {
    return state_.get();
  }

  bool is_initializing() {
    return initializing_ || status() == storage_proto::STORAGE_STATUS_ONLINE;
  }

  bool is_owner() const override {
    return is_owner_;
  }

  bool sharing() const {
    return state_->sharing();
  }

  void set_sharing(bool sharing) {
    state_->set_sharing(sharing);
  }

  scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner() const {
    return backend_task_runner_;
  }

  // Storage
  scoped_refptr<Torrent> root_tree() const override {
    return root_tree_;
  }

  const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner() const {
    return main_task_runner_;
  }

  std::unique_ptr<StorageIterator> CreateIterator();

  bool shutting_down() const {
    return shutdown_;
  }

  const Manifest* GetManifest() const;
  bool being_cloned() const;

  int64_t GetEntryCount() const;
  int64_t GetAllocatedSize() const;  

  void GetInfo(base::Callback<void(storage_proto::StorageState)> callback); 
  void GetEntryInfo(const scoped_refptr<Torrent>& torrent, base::Callback<void(storage_proto::Info, int64_t)> cb);
  void ListEntries(base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb);
  void ListAllEntriesInfo(std::vector<std::unique_ptr<storage_proto::Info>>* out, base::WaitableEvent* event);  
  std::vector<std::unique_ptr<storage_proto::Info>> GetAllEntriesInfos();

  void CopyFile(const scoped_refptr<Torrent>& torrent,
                const base::FilePath& from,
                CompletionCallback callback);

  void CopyEntry(const scoped_refptr<Torrent>& torrent,
                 const base::FilePath& to,
                 CompletionCallback callback);
  
  void InitEntry(const scoped_refptr<Torrent>& torrent,
                 const base::FilePath& from,
                 CompletionCallback callback);

  void InitEntry(const scoped_refptr<Torrent>& torrent,
                 CompletionCallback callback);

  //void Query(const std::string& query_string,
  //           const std::string& catalog_name,
  //           base::Callback<void(std::unique_ptr<Block>, int64_t)> callback);

  const base::FilePath& GetPath() const override;
  bool ShouldSeed(const storage_proto::Info& info) override;
  void OpenDatabase(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb) override;
  void CreateDatabase(const scoped_refptr<Torrent>& torrent, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) override;
  void OpenFileset(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb);
  void CreateFileset(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb);
  Future<int> CreateTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> OpenTorrent(const scoped_refptr<Torrent>& torrent) override;
  Future<int> CloseTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> ReadTorrent(const scoped_refptr<Torrent>& torrent, void* buf, int64_t size, int64_t offset, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> WriteTorrent(const scoped_refptr<Torrent>& torrent, const void* buf, int64_t size, int64_t offset, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> DeleteTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal = false) override;
  int64_t GetTorrentSize(const scoped_refptr<Torrent>& torrent) override;
  Future<int> SyncTorrentMetadata(const scoped_refptr<Torrent>& torrent) override;

  bool GetUUID(const std::string& name, base::UUID* id);

private: 
  
  // StorageBackend
  void StartImpl(Manifest::InitParams params, base::Callback<void(Storage*, int)> callback);
  void OnBackendInit(base::Callback<void(Storage*, int)> callback, int64_t code);
  void OnInit(base::Callback<void(Storage*, int)> callback, bool result);
  void OpenRootTreeOnInit(scoped_refptr<Storage::StorageContext> context, bool create, base::Callback<void(Storage*, int)> callback);
  
  void StopImpl(base::WaitableEvent* shutdown_event);
  void StopSecondPhase(base::WaitableEvent* shutdown_event);

  void GetInfoImpl(base::Callback<void(storage_proto::StorageState)> callback) const; 
  
  void CopyFileImpl(scoped_refptr<Storage::StorageContext> context);
  void CopyEntryImpl(scoped_refptr<Storage::StorageContext> context);

  void InitEntryImpl(scoped_refptr<Storage::StorageContext> context);
  void InitEmptyEntry(scoped_refptr<Storage::StorageContext> context);
  void GetEntryInfoImpl(scoped_refptr<Storage::StorageContext> context);

  //void QueryImpl(const std::string& query,
  //               Catalog* catalog,
  //               base::Callback<void(std::unique_ptr<Block>, int64_t)> callback);

  void OpenDatabaseImpl(scoped_refptr<Storage::StorageContext> context);
  void CreateDatabaseImpl(scoped_refptr<Storage::StorageContext> context);
  
  void CreateTorrentImpl(scoped_refptr<Storage::StorageContext> context);
  void OpenTorrentImpl(scoped_refptr<Storage::StorageContext> context);
  void UpdateTorrentMetadataImpl(scoped_refptr<Storage::StorageContext> context);
  void ReadTorrentImpl(scoped_refptr<Storage::StorageContext> context, void* buf, int64_t size, int64_t offset);
  void WriteTorrentImpl(scoped_refptr<Storage::StorageContext> context, const void* buf, int64_t size, int64_t offset);
  void WriteTorrentMerkleImpl(scoped_refptr<Storage::StorageContext> context);
  void DeleteTorrentImpl(scoped_refptr<Storage::StorageContext> context);
  int AddIndexOnTree(scoped_refptr<StorageContext> context);
  void AddIndexOnTreeOnDbThread(scoped_refptr<StorageContext> context);

  void CreateSQLiteDatabase(scoped_refptr<StorageContext> context);
  void OpenSQLiteDatabase(scoped_refptr<StorageContext> context);
  void ListAllEntriesInfoImpl(std::vector<std::unique_ptr<storage_proto::Info>>* out, base::WaitableEvent* event);
  
  void OnDeleteTorrent(scoped_refptr<Storage::StorageContext> context, int64_t result);
  void OnCreateTorrent(scoped_refptr<StorageContext> context, int64_t result);
  void OnOpenTorrent(scoped_refptr<StorageContext> context, int64_t result);
  void OnCreateTorrentWriteManifest(scoped_refptr<StorageContext> context, int64_t expected, int64_t bytes_written);
  void OnOpenTorrentReadManifest(scoped_refptr<StorageContext> context, int64_t expected, int64_t bytes_read);
  void OnOpenTorrentReadMerkle(scoped_refptr<StorageContext> context, int64_t expected, int64_t bytes_read);

  void OnReadTorrent(scoped_refptr<StorageContext> context, int64_t expected, int64_t result);
  void OnWriteTorrent(scoped_refptr<StorageContext> context, int64_t expected, int64_t result);
  void OnWriteTorrentMerkle(scoped_refptr<StorageContext> context, int64_t expected, int64_t result);
  void OnWriteTorrentHeaderResult(scoped_refptr<StorageContext> context, int64_t expected, int64_t result);
  void OnWriteTorrentIndex(scoped_refptr<StorageContext> context, int64_t result);
  void OnCreateDatabase(scoped_refptr<StorageContext> context, int64_t result);
  void OnOpenDatabase(scoped_refptr<StorageContext> context, int64_t result);
  
  void OnOpenDatabaseReadManifest(scoped_refptr<StorageContext> context, int64_t bytes_readed);
  void OnCreateDatabaseWriteManifest(scoped_refptr<StorageContext> context, int64_t bytes_written);

  void OnCopyFile(scoped_refptr<StorageContext> context, int64_t result);
  void OnCopyEntry(scoped_refptr<StorageContext> context, int64_t result);
  void OnGetEntryInfo(scoped_refptr<StorageContext> context, int64_t result);
  void DecodeEntryInfo(scoped_refptr<StorageContext> context, int64_t result);
  
  void OnInitEntry(scoped_refptr<StorageContext> context, int64_t result);
  //void OnQuery(scoped_refptr<StorageContext> context, Catalog* catalog, std::unique_ptr<const zetasql::AnalyzerOutput> output, int64_t result);
 
  void OnInitEntryWriteContent(scoped_refptr<StorageContext> context, int file_offset, int64_t expected, int64_t result);
  void OnInitEntryWriteHashes(scoped_refptr<StorageContext> context, int64_t result);
  void OnInitEntryWriteManifest(scoped_refptr<StorageContext> context, int64_t result);
  void OnInitEntryWriteHeader(scoped_refptr<StorageContext> context, int64_t result);
  void OnInitEntryWriteIndex(scoped_refptr<StorageContext> context, int64_t result);

  void ReadFile(scoped_refptr<StorageContext> context, int64_t bytes_written);
  void ReadEntry(scoped_refptr<StorageContext> context, int64_t result);
 
  void WriteEntryContent(scoped_refptr<StorageContext> context, int64_t bytes_readed);
  void WriteEntryManifest(scoped_refptr<StorageContext> context, int64_t result);

  void ReadEntryContent(scoped_refptr<StorageContext> context, int64_t result);
  void OnReadHeaderData(scoped_refptr<StorageContext> context, int64_t result);
  void OnReadEntryManifest(scoped_refptr<StorageContext> context, int64_t result);
  void OnReadEntryContent(scoped_refptr<StorageContext> context, int64_t readed);
  // TODO: we should move this to catalog
  //int64_t WriteDatabaseMetadata(scoped_refptr<StorageContext> context, Database* db);

  bool GetInfoForEntry(StorageEntry* entry, net::IOBuffer* buffer, size_t read_size, storage_proto::Info* info);

  void ReplyCopyFile(
    scoped_refptr<StorageContext> context, 
    CompletionCallback user_callback, 
    int64_t result);

  void ReplyCopyEntry(
    scoped_refptr<StorageContext> context,
    CompletionCallback user_callback,
    int64_t result);

  void ReplyGetEntryInfo(
    scoped_refptr<StorageContext> context,
    base::Callback<void(storage_proto::Info, int64_t)> callback,
    storage_proto::Info info,
    int64_t result);

  void ReplyInitEntry(
    scoped_refptr<StorageContext> context,
    CompletionCallback user_callback,
    int64_t result);

  //void ReplyQuery(
  //  scoped_refptr<StorageContext> context,
  //  base::Callback<void(std::unique_ptr<Block>, int64_t)> callback,
  //  std::unique_ptr<Block> block,
  //  int64_t result);

  void ReplyOpenDatabase(
    //std::unique_ptr<Catalog> catalog,
    base::Callback<void(int64_t)> callback,
    int64_t result);

  void ReplyCreateDatabase(
   // std::unique_ptr<Catalog> catalog,
    base::Callback<void(int64_t)> callback,
    int64_t result);

  int GetContextId(StorageContext::Opcode code, const base::UUID& key);
  scoped_refptr<StorageContext> GetContext(StorageContext::Opcode code, const base::UUID& key);
  scoped_refptr<StorageContext> GetContext(int id);
  scoped_refptr<StorageContext> CreateContext(StorageContext::Opcode code, const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb);
  void TerminateContext(scoped_refptr<StorageContext> context, CompletionCallback* user_callback);
  void TerminateContext(scoped_refptr<StorageContext> context) {
    CompletionCallback callback;
    TerminateContext(context, &callback);
  }

  void RunIO(scoped_refptr<StorageContext> context);
  void RunIOImpl(scoped_refptr<StorageContext> context);

  /* Storage */
  void ProcessScheduledIO();
  bool HasScheduledIO() const {
    return scheduled_io_.size() > 0;
  }

  void GetAllEntriesInfosImpl(std::vector<std::unique_ptr<storage_proto::Info>>* out);

  bool ResolveUUID(const std::string& name, base::UUID* out);


  TorrentCache* torrent_cache_;
  base::FilePath path_;
  std::unique_ptr<StorageBackend> backend_;
  std::unique_ptr<storage_proto::StorageState> state_;
  scoped_refptr<Torrent> root_tree_;
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> frontend_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner_;
  //scoped_refptr<base::SingleThreadTaskRunner> db_task_runner_;
  scoped_refptr<disk_cache::BackendCleanupTracker> cleanup_tracker_;
  base::Lock name_index_lock_;
  std::unordered_map<std::string, base::UUID> name_index_;
  net::NetLog log_;
  const char* given_pkey_if_cloned_ = nullptr;
  std::string given_id_if_cloned_;
  bool initialized_;
  mutable bool initializing_;
  mutable bool shutdown_;
  bool first_run_;
  bool is_owner_;
 
  base::Lock contexts_lock_;
  std::map<int, scoped_refptr<StorageContext>> contexts_;
  std::vector<std::pair<scoped_refptr<StorageContext>, base::OnceCallback<void()>>> scheduled_io_;

  base::AtomicSequenceNumber context_id_gen_;
  base::AtomicSequenceNumber db_id_gen_;

  base::WaitableEvent init_event_;
  base::WaitableEvent event_wait_;
   
  DISALLOW_COPY_AND_ASSIGN(Storage);
};

}

#endif
