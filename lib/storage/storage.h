// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_STORAGE_H_
#define MUMBA_STORAGE_STORAGE_H_

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
#include "storage/backend/storage_backend.h"
#include "storage/backend/addr.h"
#include "storage/io_entity.h"
#include "storage/storage_export.h"
#include "storage/storage_info.h"
#include "storage/storage_context.h"
#include "storage/file_set.h"
#include "storage/backend/storage_entry.h"
#include "storage/merkle_tree.h"
#include "storage/torrent.h"
//#include "storage/block.h"
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
class Database;
//class Catalog;
//class Application;
//class RegistryCatalog;
class Manifest;
class StorageManager;

class STORAGE_EXPORT Storage : public IOHandler {
public:

  static std::unique_ptr<Storage> Create(const std::string& name,
                                         const base::FilePath& dir,
                                         StorageManager* manager,
                                         const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
                                         const scoped_refptr<base::SingleThreadTaskRunner>& frontend_task_runner,
                                         scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                         bool force = false);

  static std::unique_ptr<Storage> Clone(const std::string& name,
                                        const base::FilePath& dir,
                                        StorageManager* manager,
                                        const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
                                        const scoped_refptr<base::SingleThreadTaskRunner>& frontend_task_runner,
                                        scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                        const std::string& id,
                                        const std::array<char, 32>& pkey,
                                        std::unique_ptr<storage_proto::Info> registry_info,
                                        bool force = false); 
  // generic open
  static std::unique_ptr<Storage> Open(const std::string& name,
                                       const base::FilePath& path,
                                       StorageManager* manager,
                                       const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
                                       const scoped_refptr<base::SingleThreadTaskRunner>& frontend_task_runner,
                                       scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner);
 
  static std::unique_ptr<Storage> Open(const std::string& name,
                                       const base::FilePath& path,
                                       StorageManager* manager,
                                       const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
                                       const scoped_refptr<base::SingleThreadTaskRunner>& frontend_task_runner,
                                       scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                       std::unique_ptr<storage_proto::StorageState> state, bool first_run);

  Storage(
    StorageManager* manager,
    const std::string& name,
    const base::FilePath& path,
    const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
    const scoped_refptr<base::SingleThreadTaskRunner>& frontend_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
    std::unique_ptr<storage_proto::StorageState> state,
    bool first_run,
    bool being_cloned,
    const std::string& id,
    const std::array<char, 32>& pkey,
    std::unique_ptr<storage_proto::Info> root_info = std::unique_ptr<storage_proto::Info>());


  ~Storage() override;

  // Storage
  void Start(base::Callback<void(Storage*, int)> callback = base::Callback<void(Storage*, int)>());
  void Stop(CompletionCallback callback = CompletionCallback());

  // Storage
  const std::string& name() const;
  const base::FilePath& path() const;
  size_t size() const;
  const std::string& address() const;
  bool is_signed() const;
  storage_proto::StorageStatus status() const;
  const storage_proto::StorageState* state() const {
    return state_.get();
  }

  StorageManager* manager() const {
    return manager_;
  }

  bool is_initializing() {
    return initializing_ || status() == storage_proto::STORAGE_STATUS_ONLINE;
  }

  bool is_owner() const override;
  
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
  bool being_cloned() const override;

  int64_t GetEntryCount() const override;
  int64_t GetAllocatedSize() const override;  

  void GetInfo(base::Callback<void(storage_proto::StorageState)> callback); 
  void GetEntryInfo(const scoped_refptr<Torrent>& torrent, base::Callback<void(storage_proto::Info, int64_t)> cb);
  //std::vector<std::unique_ptr<storage_proto::Info>> GetEntryList();
  void ListEntries(base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb);
  void ListAllEntriesInfo(scoped_refptr<StorageContext> context, base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb);  
  void GetAllEntriesInfos(scoped_refptr<StorageContext> context, base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb);

  //void CopyFile(const scoped_refptr<Torrent>& torrent,
  //              const base::FilePath& from,
  //              CompletionCallback callback);

  void CopyEntry(const scoped_refptr<Torrent>& torrent,
                 const base::FilePath& to,
                 CompletionCallback callback);

  void CopyEntryFile(const scoped_refptr<Torrent>& torrent,
                     const base::FilePath& file_path,       
                     const base::FilePath& to,
                     CompletionCallback callback);

  void ReadEntryFileAsSharedBuffer(
    const scoped_refptr<Torrent>& torrent,
    const base::FilePath& file_path,       
    base::Callback<void(int64_t, mojo::ScopedSharedBufferHandle, int64_t)> callback);
  
  void WriteEntryFile(
    const scoped_refptr<Torrent>& torrent,
    const base::FilePath& file_path,
    int offset,
    int size,
    const std::vector<uint8_t>& data,       
    base::Callback<void(int64_t)> callback);


  void AddEntry(const scoped_refptr<Torrent>& torrent,
                 const base::FilePath& from,
                 std::string name,
                 CompletionCallback callback);

  void AddEntry(const scoped_refptr<Torrent>& torrent,
                CompletionCallback callback);

  void AddIndex(const scoped_refptr<Torrent>& torrent,
                const std::string& name,
                CompletionCallback callback);

  //void Query(const std::string& query_string,
  //           const std::string& catalog_name,
  //           base::Callback<void(std::unique_ptr<Block>, int64_t)> callback);

  const base::FilePath& GetPath() const override;
  const std::string& GetName() const override;
  
  base::WeakPtr<IOHandler> GetWeakPtrForContext() const override {
    return weak_this_for_task_;
  }

  bool ShouldSeed(const storage_proto::Info& info) override;
  void OpenDatabase(scoped_refptr<Torrent> torrent, bool key_value, base::Callback<void(int64_t)> cb, bool sync = false) override;
  void CreateDatabase(scoped_refptr<Torrent> torrent, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) override;
  void CreateDatabase(scoped_refptr<Torrent> torrent, const std::vector<std::string>& create_table_stmts, const std::vector<std::string>& insert_table_stmts, bool key_value, base::Callback<void(int64_t)> cb) override;
  Future<int> CreateTorrent(scoped_refptr<Torrent> torrent, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> OpenTorrent(scoped_refptr<Torrent> torrent) override;
  Future<int> CloseTorrent(scoped_refptr<Torrent> torrent, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> ReadTorrent(scoped_refptr<Torrent> torrent, void* buf, int64_t size, int64_t offset, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> WriteTorrent(scoped_refptr<Torrent> torrent, const void* buf, int64_t size, int64_t offset, bool is_journal = false, int jrn_seq = -1) override;
  Future<int> DeleteTorrent(scoped_refptr<Torrent> torrent, bool is_journal = false) override;
  Future<int> SyncTorrent(scoped_refptr<Torrent> torrent) override;
  int64_t GetTorrentSize(scoped_refptr<Torrent> torrent) override;
  Future<int> SyncTorrentMetadata(scoped_refptr<Torrent> torrent) override;
  void LoadRootIndex(base::Callback<void(int64_t)> cb) override;

  bool GetUUID(const std::string& name, base::UUID* id);
  bool HasUUID(const base::UUID& uuid);
  bool HasEntryNamed(const std::string& name);

private: 
  // for weak_this_
  friend struct StorageContext;

  // StorageBackend
  void StartImpl(Manifest::InitParams params, base::Callback<void(Storage*, int)> callback);
  void OnBackendInit(base::Callback<void(Storage*, int)> callback, int64_t code);
  void OnInit(base::Callback<void(Storage*, int)> callback, bool result);
  void OpenRootTreeOnInit(scoped_refptr<StorageContext> context, bool create, base::Callback<void(Storage*, int)> callback);
  void OpenRootTreeOnClone(scoped_refptr<StorageContext> context, base::Callback<void(int64_t)> callback);

  void StopImpl(base::WaitableEvent* shutdown_event);
  void StopSecondPhase(base::WaitableEvent* shutdown_event);

  void GetInfoImpl(base::Callback<void(storage_proto::StorageState)> callback) const; 

  void AddIndexImpl(scoped_refptr<StorageContext> context);
  
  //void CopyFileImpl(scoped_refptr<StorageContext> context);
  void CopyEntryImpl(scoped_refptr<StorageContext> context);
  void ReadEntryFileImpl(scoped_refptr<StorageContext> context);
  void WriteEntryFileImpl(scoped_refptr<StorageContext> context);

  void AddEntryImpl(scoped_refptr<StorageContext> context);
  void AddEmptyEntry(scoped_refptr<StorageContext> context);
  void GetEntryInfoImpl(scoped_refptr<StorageContext> context);

  void SyncTorrentAfterMetadataSync(scoped_refptr<StorageContext> context, int64_t r);
  void OnSyncTorrent(scoped_refptr<StorageContext> context, int64_t result);
  //void OnSyncTorrent(scoped_refptr<StorageContext> context, int64_t result);
  //void SyncOpenEntry(scoped_refptr<StorageContext> context);
  //void QueryImpl(const std::string& query,
  //               Catalog* catalog,
  //               base::Callback<void(std::unique_ptr<Block>, int64_t)> callback);

  void OpenDatabaseImpl(scoped_refptr<StorageContext> context);
  void CreateDatabaseImpl(scoped_refptr<StorageContext> context);
  
  void CreateTorrentImpl(scoped_refptr<StorageContext> context);
  void OpenTorrentImpl(scoped_refptr<StorageContext> context);
  void UpdateTorrentMetadataImpl(scoped_refptr<StorageContext> context);
  void ReadTorrentImpl(scoped_refptr<StorageContext> context);
  void WriteTorrentImpl(scoped_refptr<StorageContext> context);
  void WriteTorrentMerkleImpl(scoped_refptr<StorageContext> context);
  void DeleteTorrentImpl(scoped_refptr<StorageContext> context);
  void SyncTorrentImpl(scoped_refptr<StorageContext> context);
  int AddIndexOnTree(scoped_refptr<StorageContext> context);
  void AddIndexOnTreeOnDbThread(scoped_refptr<StorageContext> context);

  void CreateSQLiteDatabase(scoped_refptr<StorageContext> context);
  void OpenSQLiteDatabase(scoped_refptr<StorageContext> context);
  void GetAllEntriesInfosImpl(scoped_refptr<StorageContext> context, base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb);
  void ListAllEntriesInfoImpl(scoped_refptr<StorageContext> context, base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb);
  
  void OnDeleteTorrent(scoped_refptr<StorageContext> context, int64_t result);
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

  //void OnCopyFile(scoped_refptr<StorageContext> context, int64_t result);
  void OnCopyEntry(scoped_refptr<StorageContext> context, int64_t result);
  void OnReadEntryFile(scoped_refptr<StorageContext> context, int64_t result);
  void OnGetEntryInfo(scoped_refptr<StorageContext> context, int64_t result);
  void DecodeEntryInfo(scoped_refptr<StorageContext> context, int64_t result);
  
  void OnAddEntry(scoped_refptr<StorageContext> context, int64_t result);
  //void OnQuery(scoped_refptr<StorageContext> context, Catalog* catalog, std::unique_ptr<const zetasql::AnalyzerOutput> output, int64_t result);
 
  void OnAddEntryWriteContent(scoped_refptr<StorageContext> context, int file_offset, int64_t expected, int64_t result);
  void OnAddEntryWriteHashes(scoped_refptr<StorageContext> context, int64_t result);
  void OnAddEntryWriteManifest(scoped_refptr<StorageContext> context, int64_t result);
  void OnAddEntryWriteHeader(scoped_refptr<StorageContext> context, int64_t result);
  void OnAddEntryWriteIndex(scoped_refptr<StorageContext> context, int64_t result);

  void ReadEntry(scoped_refptr<StorageContext> context, int64_t result); 
  void OnReadEntryManifest(scoped_refptr<StorageContext> context, int64_t result);
  void ReadEntryContent(scoped_refptr<StorageContext> context, int file_offset, int64_t result);
  void OnReadEntryContent(scoped_refptr<StorageContext> context, int file_offset, int64_t readed);
  void OnReadHeaderData(scoped_refptr<StorageContext> context, int64_t result);
  
  void ReadEntryForFile(scoped_refptr<StorageContext> context, int64_t result);
  void OnReadEntryManifestForFileRead(scoped_refptr<StorageContext> context, int64_t result);
  void ReadEntryContentForFile(scoped_refptr<StorageContext> context, int64_t result);
  void OnReadEntryContentForFile(scoped_refptr<StorageContext> context, int64_t readed);

  void OnReadEntryManifestForFileWrite(scoped_refptr<StorageContext> context, int64_t result);
  void WriteEntryContentForFile(scoped_refptr<StorageContext> context, int64_t result);
  void OnWriteEntryContentForFile(scoped_refptr<StorageContext> context, int64_t readed);

  bool GetInfoForEntry(StorageEntry* entry, net::IOBuffer* buffer, size_t read_size, storage_proto::Info* info);

  void OnRootTreeDatabaseReady(base::Callback<void(Storage*, int)> callback, Storage*, int);

  void ReplyCopyFile(
    scoped_refptr<StorageContext> context, 
    CompletionCallback user_callback, 
    int64_t result);

  void ReplyCopyEntry(
    scoped_refptr<StorageContext> context,
    CompletionCallback user_callback,
    int64_t result);

   void ReplyCopyEntryFile(
    scoped_refptr<StorageContext> context,
    CompletionCallback user_callback,
    int64_t result);

   void ReplyReadEntryFileWithBuffer(
    scoped_refptr<StorageContext> context, 
    base::Callback<void(int64_t, mojo::ScopedSharedBufferHandle, int64_t)> user_callback, 
    int64_t file_size,
    mojo::ScopedSharedBufferHandle file_data,
    int64_t result);

   void ReplyWriteEntryFile(
    scoped_refptr<StorageContext> context, 
    base::Callback<void(int64_t)> user_callback, 
    int64_t result);

  void ReplyGetEntryInfo(
    scoped_refptr<StorageContext> context,
    base::Callback<void(storage_proto::Info, int64_t)> callback,
    storage_proto::Info info,
    int64_t result);

  void ReplyAddEntry(
    scoped_refptr<StorageContext> context,
    CompletionCallback user_callback,
    int64_t result);

  void ReplyAddIndex(
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
  scoped_refptr<StorageContext> CreateContext(StorageContext::Opcode code, scoped_refptr<Torrent> torrent, base::Callback<void(int64_t)> cb);
  scoped_refptr<StorageContext> CreateContext(StorageContext::Opcode code, base::Callback<void(int64_t)> cb);
  void TerminateContext(scoped_refptr<StorageContext> context, CompletionCallback* user_callback);
  void TerminateContext(scoped_refptr<StorageContext> context) {
    CompletionCallback callback;
    TerminateContext(context, &callback);
  }

  /* Storage */
  void ProcessScheduledIO();
  bool HasScheduledIO() const {
    return scheduled_io_.size() > 0;
  }

  bool ResolveUUID(const std::string& name, base::UUID* out);

  void RunIO(scoped_refptr<StorageContext> context);

  StorageManager* manager_;
  std::string name_;
  base::FilePath path_;
  std::unique_ptr<StorageBackend> backend_;
  std::unique_ptr<storage_proto::StorageState> state_;
  base::Lock open_root_tree_lock_;
  scoped_refptr<Torrent> root_tree_;
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> frontend_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> db_task_runner_;
  scoped_refptr<disk_cache::BackendCleanupTracker> cleanup_tracker_;
  base::Lock name_index_lock_;
  std::unordered_map<std::string, base::UUID> name_index_;
  net::NetLog log_;
  std::array<char, 32> given_pkey_if_cloned_;
  std::string given_id_if_cloned_;
  std::unique_ptr<storage_proto::Info> root_info_if_cloned_;
  bool initialized_;
  mutable bool initializing_;
  mutable bool shutdown_;
  mutable bool root_tree_opened_;
  bool first_run_;
  bool being_cloned_;
 
  base::Lock contexts_lock_;
  std::map<int, scoped_refptr<StorageContext>> contexts_;
  std::vector<std::pair<scoped_refptr<StorageContext>, base::OnceCallback<void()>>> scheduled_io_;

  base::AtomicSequenceNumber context_id_gen_;
  base::AtomicSequenceNumber db_id_gen_;

  base::WaitableEvent init_event_;
  base::WaitableEvent event_wait_;

  base::WeakPtr<Storage> weak_this_;
  base::WeakPtr<Storage> weak_this_for_task_;

  base::WeakPtrFactory<Storage> weak_factory_;
  base::WeakPtrFactory<Storage> weak_factory_for_task_;
    
  DISALLOW_COPY_AND_ASSIGN(Storage);
};

}

#endif
