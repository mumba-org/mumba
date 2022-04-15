// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/storage.h"

#include "base/macros.h"
#include "base/logging.h"
#include "base/base64url.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/files/file_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/files/file.h"
#include "base/bind.h"
#include "base/sequenced_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/files/file_enumerator.h"
#include "components/base32/base32.h"
#include "base/uuid.h"
#include "base/strings/string_number_conversions.h"
#include "storage/storage_constants.h"
#include "storage/storage_manager.h"
#include "storage/hash.h"
#include "storage/storage_context.h"
#include "storage/io_completion_callback.h"
#include "storage/db/sqliteInt.h"
#include "net/base/net_errors.h"
#include "net/base/io_buffer.h"
#include "net/base/mime_util.h"
#include "storage/backend/addr.h"
#include "storage/torrent.h"
#include "storage/torrent_cache.h"
#include "third_party/protobuf/src/google/protobuf/util/json_util.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"
#include "third_party/boringssl/src/include/openssl/sha.h"

namespace storage {

namespace {

constexpr size_t kBlockSize = 65536;
// the mininal number of blocks a sqlite database starts with
constexpr size_t kSqliteInitialBlocks = 2;

constexpr int kDefaultHashSize = SHA_DIGEST_LENGTH;

constexpr int kHEADER_VERSION_MAJOR = 0;
constexpr int kHEADER_VERSION_MINOR = 1;

void CleanupTrackerResult() {
  //// //D//LOG(INFO) << "BackendCleanupTracker::TryCreate callback called";
}

base::StringPiece FormatFilePath(base::StringPiece name, base::StringPiece input) {
  size_t offset = input.find(name);
  if (offset == base::StringPiece::npos) {
    return input;
  }
  input.remove_prefix(offset);

  offset = input.find("/");
  if (offset == base::StringPiece::npos) {
    return input;
  }
  input.remove_prefix(offset + 1);

  return input;
}

base::StringPiece FormatFileName(base::StringPiece input) {
  size_t offset = input.rfind("/");
  if (offset == base::StringPiece::npos) {
    return input;
  }
  input.remove_prefix(offset + 1);
  return input;
}


std::unique_ptr<MerkleTree> GenerateMerkleTreeForFiles(FileSet* fileset) {
  std::unique_ptr<MerkleTree> merkle = MerkleTree::CreateAndBuild(fileset);
  return merkle;
}

// Used to leak a strong reference to an StorageEntry to the user of disk_cache.
// StorageEntry* LeakStorageEntry(scoped_refptr<StorageEntry> entry) {
//    // Balanced on OP_CLOSE_ENTRY handling in BackendIO::ExecuteBackendOperation.
//    if (entry) {
//      entry->AddRef();
//    }
//    return entry.get();
// }

}


std::unique_ptr<Storage> Storage::Create(const std::string& name,
                                         const base::FilePath& input_dir,
                                         StorageManager* manager,
                                         const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
                                         const scoped_refptr<base::SingleThreadTaskRunner>& frontend_task_runner,
                                         scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                         bool force) {
  bool first_run = true; 
  if (!base::DirectoryExists(input_dir)) {
    //first_run = true;
    if (!base::CreateDirectory(input_dir)) {
      return {};
    }
  } else {
    if (!force) {
      DLOG(ERROR) << "Directory alredy exists and no force was specified";
      return {};
    }
    if (!base::DeleteFile(input_dir, true)) {
      DLOG(ERROR) << "Unable to delete path " << input_dir;       
      return {};
    }
    //first_run = true;
    if (!base::CreateDirectory(input_dir)) {
      DLOG(ERROR) << "Unable to create dir";
      return {};
    }
  }
  std::unique_ptr<storage_proto::StorageState> disk_state = std::make_unique<storage_proto::StorageState>();
  
  return std::unique_ptr<Storage>(new Storage(
        manager,
        name,
        input_dir,
        main_task_runner,
        frontend_task_runner,
        backend_task_runner,
        std::move(disk_state),
        first_run,
        false,
        std::string(), 
        std::array<char, 32>(),
        std::unique_ptr<storage_proto::Info>()));
}

std::unique_ptr<Storage> Storage::Clone(const std::string& name,
                                        const base::FilePath& input_dir,
                                        StorageManager* manager,
                                        const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
                                        const scoped_refptr<base::SingleThreadTaskRunner>& frontend_task_runner,
                                        scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                        const std::string& id,
                                        const std::array<char, 32>& pkey,
                                        std::unique_ptr<storage_proto::Info> registry_info,
                                        bool force) {
  bool first_run = true; 
  if (!base::DirectoryExists(input_dir)) {
    //first_run = true;
    if (!base::CreateDirectory(input_dir)) {
      return {};
    }
  } else {
    if (!force) {
      DLOG(ERROR) << "Directory alredy exists and no force was specified";
      return {};
    }
    if (!base::DeleteFile(input_dir, true)) {
      DLOG(ERROR) << "Unable to delete path " << input_dir;       
      return {};
    }
    //first_run = true;
    if (!base::CreateDirectory(input_dir)) {
      DLOG(ERROR) << "Unable to create dir";
      return {};
    }
  }
  std::unique_ptr<storage_proto::StorageState> disk_state = std::make_unique<storage_proto::StorageState>();
  
  return std::unique_ptr<Storage>(new Storage(
        manager,
        name,
        input_dir,
        main_task_runner,
        frontend_task_runner,
        backend_task_runner,
        std::move(disk_state),
        first_run,
        true,
        id,
        pkey,
        std::move(registry_info)));
}

// static 
std::unique_ptr<Storage> Storage::Open(const std::string& name,
                                       const base::FilePath& path,
                                       StorageManager* manager,
                                       const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
                                       const scoped_refptr<base::SingleThreadTaskRunner>& frontend_task_runner,
                                       scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner) {//,
   std::unique_ptr<storage_proto::StorageState> state(new storage_proto::StorageState());
   return Storage::Open(
    name,
    path, 
    manager, 
    main_task_runner,
    frontend_task_runner,
    backend_task_runner, 
    std::move(state),
    false);
}

// static 
std::unique_ptr<Storage> Storage::Open(
  const std::string& name,
  const base::FilePath& path,
  StorageManager* manager,
  const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
  const scoped_refptr<base::SingleThreadTaskRunner>& frontend_task_runner,
  scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
  std::unique_ptr<storage_proto::StorageState> state,
  bool first_run) {
  base::FilePath dir_path = path;
  if (path.MatchesExtension(kStorageFileExtensionWithDot)) {
    dir_path = dir_path.RemoveExtension();
  }
  
  return std::unique_ptr<Storage>(new Storage(
        manager,
        name,
        dir_path,
        main_task_runner,
        frontend_task_runner,
        backend_task_runner,
        std::move(state),
        first_run,
        false,
        std::string(),
        std::array<char, 32>(),
        std::unique_ptr<storage_proto::Info>()));
}

Storage::Storage(
    StorageManager* manager,
    const std::string& name,
    const base::FilePath& path,
    const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
    const scoped_refptr<base::SingleThreadTaskRunner>& frontend_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner, 
    std::unique_ptr<storage_proto::StorageState> disk_state,
    bool first_run,
    bool being_cloned,
    const std::string& id,
    const std::array<char, 32>& pkey,
    std::unique_ptr<storage_proto::Info> root_info):
  manager_(manager),
  name_(name),
  path_(path),
  state_(std::move(disk_state)),
  main_task_runner_(main_task_runner),
  // frontend_task_runner_(
  //   base::CreateSingleThreadTaskRunnerWithTraits(
  //      { base::MayBlock(),
  //        base::WithBaseSyncPrimitives() },
  //      base::SingleThreadTaskRunnerThreadMode::DEDICATED)
  // ),
  frontend_task_runner_(frontend_task_runner),
  backend_task_runner_(std::move(backend_task_runner)),
  //db_task_runner_(
  //  base::CreateSingleThreadTaskRunnerWithTraits(
  //     { base::MayBlock(),
  //      base::WithBaseSyncPrimitives() },
  //     base::SingleThreadTaskRunnerThreadMode::DEDICATED)
  //),
  given_pkey_if_cloned_(pkey),
  given_id_if_cloned_(id),
  root_info_if_cloned_(std::move(root_info)),
  initialized_(false),
  initializing_(false),
  shutdown_(false),
  root_tree_opened_(false),
  first_run_(first_run),
  being_cloned_(being_cloned),
  init_event_(
    base::WaitableEvent::ResetPolicy::MANUAL, 
    base::WaitableEvent::InitialState::NOT_SIGNALED),
  event_wait_(
    base::WaitableEvent::ResetPolicy::MANUAL, 
    base::WaitableEvent::InitialState::NOT_SIGNALED),
  weak_factory_(this),
  weak_factory_for_task_(this) {

  weak_this_ = weak_factory_.GetWeakPtr();

  DCHECK(state_.get());
  // sanitize state
  state_->set_status(storage_proto::STORAGE_STATUS_NONE);
 #if defined(OS_WIN)
  state_->set_local_path(base::UTF16ToASCII(path_.value()));
 #else
  state_->set_local_path(path_.value());
 #endif 
  state_->set_started_time(-1);
  state_->set_size(-1);
  state_->set_sharing(false);
  state_->set_owner(false);
  state_->set_dirty(false);
}

Storage::~Storage() {
  frontend_task_runner_ = nullptr;
  backend_task_runner_ = nullptr;
}

void Storage::Start(base::Callback<void(Storage*, int)> callback) {
  if (state_->status() == storage_proto::STORAGE_STATUS_ONLINE || initializing_) {
    if (!callback.is_null()) {
      //DLOG(INFO) << "Storage::Start: storage_proto::STORAGE_STATUS_ONLINE || initializing_. calling callback";
      callback.Run(this, net::OK);
    }
    return;
  }
  initializing_ = true;
  Manifest::InitParams params;
  if (first_run_) {
    if (being_cloned_) {
      //DLOG(INFO) << "Storage::Start: being_cloned = true";
      params.public_key.bytes = given_pkey_if_cloned_;
      params.is_owner = false;
      params.root_tree = base::UUID(reinterpret_cast<const uint8_t *>(given_id_if_cloned_.data()));
      //DLOG(INFO) << "Storage::Start: setting root tree to " << params.root_tree.to_string() << ". CLONED storage version";
    } else {
      //DLOG(INFO) << "Storage::Start: being_clone = false => is_owner_ = true";
      std::array<char, 32> seed = libtorrent::dht::ed25519_create_seed();
      std::tuple<libtorrent::dht::public_key, libtorrent::dht::secret_key> keys = libtorrent::dht::ed25519_create_keypair(seed);
      params.public_key = std::move(std::get<0>(keys));
      params.private_key = std::move(std::get<1>(keys));
      params.root_tree = base::UUID::generate();
      //DLOG(INFO) << "setting root tree to " << params.root_tree.to_string() << ". NEW storage version";
      params.is_owner = true;
    }
#if defined(OS_WIN)
    params.base32_address = base::UTF16ToASCII(path_.BaseName().value());
#else
    params.base32_address = path_.BaseName().value();
#endif
    params.creator = "Donald Duck";
    //printf("address: %s\nroot: %s\npublic key: %s\n", params.base32_address.c_str(), params.root_tree.to_string().c_str(), base::HexEncode(params.public_key.bytes.data(), 32).c_str());
    
  }
 
  frontend_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(
      &Storage::StartImpl, 
       weak_this_,
       base::Passed(std::move(params)),
       base::Passed(std::move(callback))));
  
  //init_event_.Wait();
}

bool Storage::is_owner() const {
  const Manifest* manifest = GetManifest();
  return manifest->GetSize(Manifest::PRIVKEY) > 0;
}

void Storage::StartImpl(Manifest::InitParams params, base::Callback<void(Storage*, int)> callback) {
  base::AutoLock lock(open_root_tree_lock_);

  int result = -1;
  weak_this_for_task_ = weak_factory_for_task_.GetWeakPtr();

  cleanup_tracker_ = disk_cache::BackendCleanupTracker::TryCreate(
    path_, base::BindOnce(&CleanupTrackerResult));

  StorageBackend* block_cache =
      new StorageBackend(path_, 
                      cleanup_tracker_.get(),
                      backend_task_runner_, 
                      &log_);
  
  backend_.reset(block_cache);
  result = block_cache->Init(
    std::move(params), 
    base::BindOnce(&Storage::OnBackendInit, weak_this_for_task_, base::Passed(std::move(callback))));
}

void Storage::OnBackendInit(base::Callback<void(Storage*, int)> callback, int64_t code) {
  if (code == 0) {
    if (being_cloned()) {
      DCHECK(root_info_if_cloned_);
      // FIXME: ok, on clone we dont have the root database yet
      // but we need to load it as soon as it arrives
      //OnInit(std::move(callback), true);
      root_tree_ = manager_->NewTorrent(this, std::move(root_info_if_cloned_), true /* is_root*/);
      //DLOG(INFO) << "Storage::OnBackendInit: root_tree_ = " << root_tree_->id().to_string();
      root_tree_->set_dht_public_key(given_pkey_if_cloned_);

      // force adding to the session, given this is a empty torrent
      // that need to be downloaded and metadata will never load
      // and trigger the add to session that full torrents do
      //manager_->AddTorrentToSessionOrUpdate(root_tree_);
      OnInit(std::move(callback), true);
    } else {
      scoped_refptr<StorageContext> context;
      const Manifest* manifest = backend_->manifest();
      base::StringPiece root_tree_str = manifest->GetProperty(Manifest::TREE);
      base::StringPiece public_key_str = manifest->GetProperty(Manifest::PUBKEY);
      //D//LOG(INFO) << "Storage::OnBackendInit: manifest = " << manifest <<
      // "\n root tree size = " << root_tree_str.size();
      base::UUID root_tree(reinterpret_cast<const uint8_t*>(root_tree_str.data()));
      //LOG(INFO) << "Storage::OpenRootTreeOnInit: received root uuid " << root_tree.to_string();
      root_tree_ = manager_->NewTorrent(this, std::move(root_tree), true /* is_root*/);
      std::array<char, 32> key;
      memcpy(key.data(), public_key_str.data(), 32);
      root_tree_->set_dht_public_key(key);
      //DLOG(INFO) << "Storage::OnBackendInit: root_tree_ = " << root_tree_->id().to_string();
      if (first_run_) {
        context = CreateContext(StorageContext::kCREATE_DATABASE, root_tree_, CompletionCallback());
        // the path of the root tree = the disk's 'name'
        //root_tree_->mutable_info()->set_path(path_.BaseName().value());
        root_tree_->mutable_info()->set_path("root");
        root_tree_->mutable_info()->set_kind(storage_proto::INFO_KVDB);
        context->create_db_params.keyspaces.push_back("keyspaces");
        context->create_db_params.keyspaces.push_back("inodes");
        context->create_db_params.keyspaces.push_back("index");
      } else {
        context = CreateContext(StorageContext::kOPEN_DATABASE, root_tree_, CompletionCallback());
      }
      context->task_runner->PostTask(FROM_HERE,
        base::BindOnce(
          &Storage::OpenRootTreeOnInit,
          base::Unretained(this),
          context,
          first_run_,
          base::Bind(&Storage::OnRootTreeDatabaseReady, 
            base::Unretained(this), 
            base::Passed(std::move(callback)))));
    }
    initialized_ = true;
  } else {
    OnInit(std::move(callback), false);
  }
}

void Storage::OnRootTreeDatabaseReady(base::Callback<void(Storage*, int)> callback, Storage*, int) {
  // context->task_runner->PostTask(
  //   FROM_HERE,
  //   base::BindOnce(
  //     &Storage::OpenRootTreeOnInit,
  //     base::Unretained(this),
  //     context,
  //     first_run_,
  //     base::Passed(std::move(callback))));
  OnInit(std::move(callback), true);
}

void Storage::LoadRootIndex(base::Callback<void(int64_t)> cb) {
  //DLOG(INFO) << "Storage::LoadRootIndex";
  // const Manifest* manifest = backend_->manifest();
  // base::StringPiece root_tree_str = manifest->GetProperty(Manifest::TREE);
  // base::UUID root_tree(reinterpret_cast<const uint8_t*>(root_tree_str.data()));
  // root_tree_ = manager_->NewTorrent(this, std::move(root_tree), true /* is_root*/);
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kOPEN_DATABASE, root_tree_, CompletionCallback());
  context->task_runner->PostTask(FROM_HERE,
    base::BindOnce(
      &Storage::OpenRootTreeOnClone,
      // FIXME
      base::Unretained(this), 
      context,
      base::Passed(std::move(cb))));
}

void Storage::OnInit(base::Callback<void(Storage*, int)> callback, bool result) {
  if (result) {
    bool manifest_error = false;
    initialized_ = true;
    if (HasScheduledIO()) {
      ProcessScheduledIO();
    }

    const Manifest* manifest = GetManifest();
    int version_size = manifest->GetSize(storage::Manifest::VERSION);
    int addr_size = manifest->GetSize(storage::Manifest::ADDRESS);
    int pubkey_size = manifest->GetSize(storage::Manifest::PUBKEY);
    int privkey_size = manifest->GetSize(storage::Manifest::PRIVKEY);
    int creator_size = manifest->GetSize(storage::Manifest::CREATOR);

    if (version_size > 0 && addr_size > 0 && pubkey_size >= 32 && creator_size > 0) {
      state_->set_version(std::string(manifest->GetProperty(storage::Manifest::VERSION).data(), version_size));
      state_->set_address(std::string(manifest->GetProperty(storage::Manifest::ADDRESS).data(), addr_size));
      state_->set_pubkey(std::string(manifest->GetProperty(storage::Manifest::PUBKEY).data(), pubkey_size));
      state_->set_creator(std::string(manifest->GetProperty(storage::Manifest::CREATOR).data(), creator_size));
    } else {
      LOG(ERROR) << "reading manifest from disk error: some required properties were not set properly";
      manifest_error = true;
    }
    if (privkey_size >= 64) {
      state_->set_privkey(std::string(manifest->GetProperty(storage::Manifest::PRIVKEY).data(), pubkey_size));
    }
    state_->set_status(manifest_error ? storage_proto::STORAGE_STATUS_ERROR : storage_proto::STORAGE_STATUS_ONLINE);
    state_->set_started_time(base::Time::Now().ToInternalValue());
    state_->set_size(GetAllocatedSize());
    state_->set_entry_count(GetEntryCount());
    state_->set_owner(privkey_size == 64);
  } else {
    state_->set_status(storage_proto::STORAGE_STATUS_ERROR);
  }
  //init_event_.Signal();
  if (!callback.is_null()) {
    main_task_runner_->PostTask(FROM_HERE, base::Bind(callback, base::Unretained(this), result ? 0 : 2));
  }
  //initializing_ = false;
}

void Storage::OpenRootTreeOnInit(scoped_refptr<StorageContext> context, bool create, base::Callback<void(Storage*, int)> callback) {
   //DLOG(INFO) << "Storage::OpenRootTreeOnInit";
   //base::AutoLock lock(open_root_tree_lock_);
   if (root_tree_opened_){
     return;
   }
   Database* db = create ? 
     Database::Create(root_tree_, context->create_db_params.keyspaces, true, false) : 
     Database::Open(root_tree_, true);

   if (!db) {
     LOG(ERROR) << "Storage::OpenRootTreeOnInit: failed to open/create root tree db";
   }

   //if (create) {
   // db->Close();
   //}

   TerminateContext(context);
   OnInit(std::move(callback), true);
   root_tree_opened_ = true;
}

void Storage::OpenRootTreeOnClone(scoped_refptr<StorageContext> context, base::Callback<void(int64_t)> callback) {
  //DLOG(INFO) << "Storage::OpenRootTreeOnClone";
   int64_t r = 0;
   Database* db = Database::Open(root_tree_, true);
   if (!db) {
     LOG(ERROR) << "Storage::OpenRootTreeOnClone: failed to open/create root tree db";
     r = -2;
   }
   TerminateContext(context);
   std::move(callback).Run(r);
}

void Storage::Stop(CompletionCallback callback) {
  frontend_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&Storage::StopImpl, 
      weak_this_, 
      base::Unretained(&event_wait_)));
  event_wait_.Wait();
  state_->set_status(storage_proto::STORAGE_STATUS_OFFLINE);
  weak_this_.reset();
 
  
  if (!callback.is_null()) {
    callback.Run(0);
  }
}

void Storage::StopImpl(base::WaitableEvent* shutdown_event) {
  shutdown_ = true;
  StopSecondPhase(shutdown_event);
}

void Storage::StopSecondPhase(base::WaitableEvent* shutdown_event) {
  contexts_lock_.Acquire();
  
  for (auto it = contexts_.begin(); it != contexts_.end(); ++it) {
    it->second = nullptr;
  }

  contexts_.clear();
  contexts_lock_.Release();

  backend_.reset();

  main_task_runner_ = nullptr;
  backend_task_runner_ = nullptr;
  cleanup_tracker_ = nullptr;

  weak_factory_for_task_.InvalidateWeakPtrs();
  weak_factory_.InvalidateWeakPtrs();

  if (shutdown_event) {
    shutdown_event->Signal();
  }
}

bool Storage::being_cloned() const {
  return backend_->manifest()->GetSize(storage::Manifest::PRIVKEY) == 0 && first_run_;
}

int64_t Storage::GetEntryCount() const {
  return backend_->GetEntryCount();
}

int64_t Storage::GetAllocatedSize() const {
  return backend_->SyncCalculateSizeOfAllEntries();
}

const Manifest* Storage::GetManifest() const {
  return backend_->manifest();
}

std::unique_ptr<StorageIterator> Storage::CreateIterator() {
  return backend_->CreateIterator();
}

void Storage::ListEntries(base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb) {
  //DLOG(INFO) << "Storage::ListEntries";
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kLIST_ENTRIES, CompletionCallback());
  GetAllEntriesInfos(context, std::move(cb));
  //TerminateContext(context); 
  //std::move(cb).Run(std::move(infos), net::OK);
}

// std::vector<std::unique_ptr<storage_proto::Info>> Storage::GetEntryList() {
//   //DLOG(INFO) << "Storage::GetEntryList";
//   scoped_refptr<StorageContext> context = CreateContext(StorageContext::kLIST_ENTRIES, CompletionCallback());
//   std::vector<std::unique_ptr<storage_proto::Info>> infos = GetAllEntriesInfos(context);
//   TerminateContext(context);
//   return infos;
// }

void Storage::GetAllEntriesInfos(scoped_refptr<StorageContext> context, base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb) {
  //DLOG(INFO) << "Storage::GetAllEntriesInfo";
  context->task_runner->PostTask(
      FROM_HERE,
      base::Bind(
        &Storage::GetAllEntriesInfosImpl,
        weak_this_, 
        context, 
        base::Passed(std::move(cb)))
  );
}

void Storage::GetAllEntriesInfosImpl(scoped_refptr<StorageContext> context, base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb) {
  //DLOG(INFO) << "Storage::GetAllEntriesInfoImpl";
  ListAllEntriesInfo(context, std::move(cb));
}

void Storage::ListAllEntriesInfo(scoped_refptr<StorageContext> context, base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb) {
  //DLOG(INFO) << "Storage::ListAllEntriesInfo";
  backend_task_runner_->PostTask(FROM_HERE, 
    base::Bind(&Storage::ListAllEntriesInfoImpl, 
        // FIXME
        base::Unretained(this),
        //weak_this_,
        context,
        base::Passed(std::move(cb))));
}

void Storage::ListAllEntriesInfoImpl(scoped_refptr<StorageContext> context, base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb) {
  //DLOG(INFO) << "Storage::ListAllEntriesInfoImpl";
  scoped_refptr<StorageEntry> node;
  std::unique_ptr<Rankings::Iterator> iterator(new Rankings::Iterator());
  int rv = backend_->SyncOpenNextEntry(iterator.get(), &node);
  while (rv == net::OK) {
    size_t size = static_cast<size_t>(node->GetDataSize(kDATA_MANIFEST)); 
    //LOG(ERROR) << "ListAllEntriesInfo: reading node " << node->GetKey() << " manifest size = " << size << " ..";
    std::unique_ptr<storage_proto::Info> info = std::make_unique<storage_proto::Info>();
    scoped_refptr<net::IOBufferWithSize> header_data = new net::IOBufferWithSize(size);
    int r = node->ReadDataImpl(kDATA_MANIFEST, 
                               0,
                               header_data.get(),
                               size,
                               CompletionCallback());
    if (r > 0) {
      if (info->ParseFromArray(header_data->data(), r)) {
        //bool ok = false;
        //base::UUID uuid = base::UUID::from_string(info->id(), &ok);
        //DLOG(INFO) << "Storage::ListAllEntriesInfoImpl: " << info->path() << " - " << uuid.to_string();
        context->list_entries.entries.push_back(std::move(info));
      } else {
        LOG(ERROR) << "ListAllEntriesInfo: failed to decode info header for entry '" << node->GetKey() << "'. size " << size << " bytes. readed " << r << " bytes";
      }
    } else {
      LOG(ERROR) << "ListAllEntriesInfo: failed to read header data for torrent '" << node->GetKey() << "' with MANIFEST section size of " << size << ". r = " << r;
    }
    //node->Close();
    rv = backend_->SyncOpenNextEntry(iterator.get(), &node);
  }
  iterator->Reset();
  if (!cb.is_null()) {
    std::move(cb).Run(std::move(context->list_entries.entries), net::OK);
  }

  //context->sync_event->Signal(rv);
  //DLOG(INFO) << "Storage::ListAllEntriesInfoImpl: END";
}


void Storage::OpenDatabase(scoped_refptr<Torrent> torrent, bool key_value, base::Callback<void(int64_t)> cb, bool sync) {
  //DLOG(INFO) << "Storage::OpenDatabase";
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kOPEN_DATABASE, torrent, std::move(cb));
  context->open_db_params.type = key_value ? storage_proto::InfoKind::INFO_KVDB : storage_proto::InfoKind::INFO_SQLDB;
  context->is_sync = sync;
  RunIO(context);
}

void Storage::OpenDatabaseImpl(scoped_refptr<StorageContext> context) {
  //DLOG(INFO) << "Storage::OpenDatabaseImpl";
  OpenSQLiteDatabase(context);
}

void Storage::CreateDatabase(scoped_refptr<Torrent> torrent, std::vector<std::string> keyspaces, bool in_memory, base::Callback<void(int64_t)> cb) {
  //DLOG(INFO) << "Storage::CreateDatabase";
  // bug check: sometimes theres a empty uuid string getting called
  // to create the database. make a check
  std::string uuid_str = torrent->id().to_string();
  DCHECK(!uuid_str.empty());
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCREATE_DATABASE, torrent, std::move(cb));
  context->create_db_params.keyspaces = std::move(keyspaces);
  context->create_db_params.keyspaces.push_back(".global");
  context->create_db_params.in_memory = in_memory;
  RunIO(context);
}

void Storage::CreateDatabase(scoped_refptr<Torrent> torrent, const std::vector<std::string>& create_table_stmts, const std::vector<std::string>& insert_table_stmts, bool key_value, bool in_memory, base::Callback<void(int64_t)> cb) {
  std::string uuid_str = torrent->id().to_string();
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCREATE_DATABASE, torrent, std::move(cb));
  context->create_db_params.type = key_value ? storage_proto::InfoKind::INFO_KVDB : storage_proto::InfoKind::INFO_SQLDB;
  context->create_db_params.create_table_stmts = create_table_stmts;
  context->create_db_params.insert_table_stmts = insert_table_stmts;
  if (key_value) {
    context->create_db_params.keyspaces = create_table_stmts;
    context->create_db_params.keyspaces.push_back(".global");
  }
  context->create_db_params.in_memory = in_memory;
  RunIO(context);
}

void Storage::CreateDatabaseImpl(scoped_refptr<StorageContext> context) {
  //DLOG(INFO) << "Storage::CreateDatabaseImpl";
  CreateSQLiteDatabase(context);
}

void Storage::GetInfo(base::Callback<void(storage_proto::StorageState)> callback) {
  //DLOG(INFO) << "Storage::GetInfo";
  callback.Run(*state_.get());
}

void Storage::GetInfoImpl(base::Callback<void(storage_proto::StorageState)> callback) const {
  //DLOG(INFO) << "Storage::GetInfoImpl";
  storage_proto::StorageState info;
  const Manifest* manifest = backend_->manifest();
  
  info.set_entry_count(backend_->GetEntryCount());
  info.set_size(backend_->SyncCalculateSizeOfAllEntries());

  int version_size = manifest->GetSize(storage::Manifest::VERSION);
  int addr_size = manifest->GetSize(storage::Manifest::ADDRESS);
  int pubkey_size = manifest->GetSize(storage::Manifest::PUBKEY);
  int privkey_size = manifest->GetSize(storage::Manifest::PRIVKEY);
  int creator_size = manifest->GetSize(storage::Manifest::CREATOR);

  if (version_size > 0 && addr_size > 0 && pubkey_size >= 32 && creator_size > 0) {
    info.set_version(std::string(manifest->GetProperty(storage::Manifest::VERSION).data(), version_size));
    info.set_address(std::string(manifest->GetProperty(storage::Manifest::ADDRESS).data(), addr_size));
    info.set_pubkey(std::string(manifest->GetProperty(storage::Manifest::PUBKEY).data(), pubkey_size));
    info.set_creator(std::string(manifest->GetProperty(storage::Manifest::CREATOR).data(), creator_size));
  }
  if (privkey_size >= 64) {
    info.set_privkey(std::string(manifest->GetProperty(storage::Manifest::PRIVKEY).data(), pubkey_size));
  }

  std::move(callback).Run(std::move(info));
}

void Storage::CopyEntry(
    const scoped_refptr<Torrent>& torrent,
    const base::FilePath& dest,
    CompletionCallback callback) {
  //DLOG(INFO) << "Storage::CopyEntry";   
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCOPY_ENTRY, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyCopyEntry, weak_this_for_task_, std::move(callback));
  context->copy_entry.dest = dest;
  RunIO(context);
}

void Storage::CopyEntryImpl(scoped_refptr<StorageContext> context) {
  //DLOG(INFO) << "Storage::CopyEntryImpl";   
  context->BindNext(&Storage::OnCopyEntry, weak_this_for_task_);
  int result = backend_->OpenEntry(
    context->key,
    &context->torrent->entry_,
    context->next_callback);

  if (result != net::ERR_IO_PENDING) {
    context->Next(result);
  }
}

void Storage::OnCopyEntry(scoped_refptr<StorageContext> context, int64_t result) {
  //DLOG(INFO) << "Storage::OnCopyEntry";   
  const scoped_refptr<Torrent>& torrent = context->torrent;
  if (result == net::OK) {
    context->BindNext(&Storage::ReadEntry, weak_this_for_task_);
    context->bytes_total = torrent->GetEntryDataSize(kDATA_CONTENT);
    // now write the data from the input file
    context->Next(0);
  } else {
    //printf("blob storage entry open error. code = %ld\n", result);
    context->Exit(result);
  }
}

void Storage::ReadEntry(scoped_refptr<StorageContext> context, int64_t result) {
  //DLOG(INFO) << "Storage::ReadEntry";   
  const scoped_refptr<Torrent>& torrent = context->torrent;
  context->BindNext(&Storage::OnReadEntryManifest, weak_this_for_task_);
  
  // we dont know the real size, so we try to make enough room
  size_t manifest_size = torrent->GetEntryDataSize(kDATA_MANIFEST);
  context->header_data = new net::IOBufferWithSize(manifest_size);

  context->header.bytes = torrent->ReadEntryData(
    kDATA_MANIFEST, // slot offset:  0 = header
    context->header.offset, // byte offset
    context->header_data.get(),
    context->header_data->size(),
    context->next_callback);

  if (context->header.bytes != net::ERR_IO_PENDING) {
    context->Next(context->header.bytes);
  }
}

void Storage::OnReadEntryManifest(scoped_refptr<StorageContext> context, int64_t result) {
  bool should_create_dirs = false;
  // first.. check if the reading the header succeeded.
  if (result < 0) { 
    DLOG(ERROR) << "error while reading the entry header";
    context->Exit(result);
    return;
  }

  context->header.status = net::OK;

  if (!context->copy_entry.entry_header.ParseFromArray(context->header_data->data(), result)) {
    DLOG(ERROR) << "error while decoding entry header/manifest. encoded size: " << result;
    context->Exit(net::ERR_FAILED);
    return; 
  }

  // Change here
  if (context->copy_entry.entry_header.inodes().size() > 1) {
    should_create_dirs = true;
    // create dest as a dir
    // NOTE: its unfortunate that the Backend(cache fs) needs the same frontend thread
    //       to deal with it, as this is expensive, and other ops on this storage
    //       will block waiting for this and other expensive IO ops we have around here. 
    if (!base::PathExists(context->copy_entry.dest)) {
      if (!base::CreateDirectory(context->copy_entry.dest)) {
        DLOG(ERROR) << "error while creating directory " << context->copy_entry.dest;
        context->Exit(net::ERR_FAILED);
        return;
      }
    }
  } 
  // open the output files
  for (int i = 0; i < context->copy_entry.entry_header.inodes().size(); i++) {
    storage_proto::InfoInode inode = context->copy_entry.entry_header.inodes(i);
    if (inode.path().empty()) {
      DLOG(ERROR) << "OnReadEntryManifest: inode " << i << " - '" << inode.name() << "' has empty path";
      continue;
    }
    base::FilePath file_path = should_create_dirs ?  
      context->copy_entry.dest.AppendASCII(inode.path()) :
      context->copy_entry.dest;
    if (should_create_dirs) {
      base::FilePath dir_path = file_path.DirName();
      if (!base::PathExists(dir_path)) {
        if (!base::CreateDirectory(dir_path)) {
          DLOG(ERROR) << "error while creating directory " << dir_path;
          context->Exit(net::ERR_FAILED);
          return;
        }
      }
    }
    base::File file(file_path, base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_READ | base::File::FLAG_WRITE);
    if (!file.IsValid()) {
#if defined (OS_WIN)
      printf("error: could not create/open output file '%ls'\n", file_path.value().c_str());
#else
      printf("error: could not create/open output file '%s'\n", file_path.value().c_str());
#endif
      context->Exit(net::ERR_FAILED);
      return;
    }
#if defined(OS_POSIX)
    int attr_mode = inode.posix_attr();
    if (attr_mode != -1)
      DCHECK(base::SetPosixFilePermissions(file_path, attr_mode));
#endif
    context->copy_entry.files.push_back(std::move(file));
  }

  ReadEntryContent(context, 0, 0);
}

void Storage::ReadEntryContent(scoped_refptr<StorageContext> context, int file_offset, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //context->BindNext(&Storage::OnReadEntryContent);

  if (context->read.offset == 0 && context->header.status != net::OK) { 
    DLOG(ERROR) << "ReadEntryContent: read.offset == 0 && header.status != net::OK";
    context->Exit(context->header.status);
    return;
  }

  CompletionCallback cb = base::Bind(&Storage::OnReadEntryContent, weak_this_for_task_, context, file_offset);

  context->read.bytes = torrent->ReadEntryData(
    kDATA_CONTENT,
    context->read.offset, 
    context->buffer.get(), 
    context->buffer->size(),
    cb);

  if (context->read.bytes != net::ERR_IO_PENDING) {
    std::move(cb).Run(context->read.bytes);
  }
}

void Storage::OnReadEntryContent(scoped_refptr<StorageContext> context, int file_offset, int64_t readed) {
  
  if (readed < 0 ) {
#if defined (OS_WIN)
    printf("read error at offset %lld: %lld", context->read.offset, readed);
#else
    printf("read error at offset %ld: %ld", context->read.offset, readed);
#endif
    for (int i = 0; i < context->copy_entry.files.size(); ++i) {
      context->copy_entry.files[i].Close();  
    }
    SyncTorrentImpl(context);
    context->torrent->CloseEntry();
    context->Exit(readed);
    return;
  }

  int64_t former_files_sum_size = 0;
  for (int i = 0; i < file_offset; i++) {
    former_files_sum_size += context->copy_entry.entry_header.inodes(i).length();
  }

  int64_t current_file_size = context->copy_entry.entry_header.inodes(file_offset).length();
  // calculate the file byte offset
  int64_t file_start_byte_offset = context->read.offset - former_files_sum_size;
  int64_t rest = current_file_size - file_start_byte_offset;
  int64_t file_ammount_to_write = readed < rest ? readed : rest;
  
  // this is EOF. we are done
  if (readed == 0) {
    for (int i = 0; i < context->copy_entry.files.size(); ++i) {
      context->copy_entry.files[i].Close();  
    }
    SyncTorrentImpl(context);
    context->torrent->CloseEntry();
    context->Exit(readed);
    return;
  }
  
  int wr = 0;
  if ((wr = context->copy_entry.files[file_offset].Write(file_start_byte_offset, context->buffer->data(), file_ammount_to_write)) == -1) {
    LOG(ERROR) << "file.Write error ("<< wr << ") at offset " << file_start_byte_offset << 
      " while trying to write " << file_ammount_to_write << " bytes";
    for (int i = 0; i < context->copy_entry.files.size(); ++i) {
      context->copy_entry.files[i].Close();  
    }
    SyncTorrentImpl(context);
    context->torrent->CloseEntry();
    context->Exit(-2);
    return;
  }

  context->write.bytes = wr;

  if (context->write.bytes != file_ammount_to_write) {
    LOG(ERROR) << "write != file_ammount_to_write " << context->write.bytes << " vs. " << file_ammount_to_write;
    for (int i = 0; i < context->copy_entry.files.size(); ++i) {
      context->copy_entry.files[i].Close();  
    }
    SyncTorrentImpl(context);
    context->torrent->entry_->Close();
    context->torrent->entry_ = nullptr;
    context->Exit(-2);
  }

  context->read.offset += context->write.bytes;
  
  int next_file_offset = file_start_byte_offset == current_file_size ? file_offset + 1 : file_offset;
  ReadEntryContent(context, next_file_offset, context->write.bytes);
}

void Storage::CopyEntryFile(const scoped_refptr<Torrent>& torrent,
                            const base::FilePath& file_path,       
                            const base::FilePath& dest,
                            CompletionCallback callback) {
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kREAD_ENTRY_FILE, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyCopyEntryFile, weak_this_for_task_, std::move(callback));
  context->copy_entry.file_path = file_path;
  context->copy_entry.dest = dest;
  RunIO(context);
}

void Storage::ReadEntryFileAsSharedBuffer(
  const scoped_refptr<Torrent>& torrent,
  const base::FilePath& file_path,       
  base::Callback<void(int64_t, mojo::ScopedSharedBufferHandle, int64_t)> callback) {
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kREAD_ENTRY_FILE, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyReadEntryFileWithBuffer, weak_this_for_task_, std::move(callback));
  context->copy_entry.file_path = file_path;
  context->copy_entry.output_as_shared_buffer = true;
  RunIO(context);
}

void Storage::WriteEntryFile(
    const scoped_refptr<Torrent>& torrent,
    const base::FilePath& file_path,
    int offset,
    int size,
    const std::vector<uint8_t>& data,       
    base::Callback<void(int64_t)> callback) {
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kWRITE_ENTRY_FILE, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyWriteEntryFile, weak_this_for_task_, std::move(callback));
  context->write_entry.file_path = file_path;
  context->write_entry.offset = offset;
  context->write_entry.size = size;
  context->write_entry.data = new net::IOBuffer(data.size());
  memcpy(context->write_entry.data->data(), reinterpret_cast<const char *>(data.data()), data.size());
  //context->write_entry.data = new net::WrappedIOBuffer(reinterpret_cast<const char *>(data.data()));
  RunIO(context);  
}

void Storage::ReadEntryFileImpl(scoped_refptr<StorageContext> context) {
  context->BindNext(&Storage::OnReadEntryFile, weak_this_for_task_);
  int result = backend_->OpenEntry(
    context->key,
    &context->torrent->entry_,
    context->next_callback);

  if (result != net::ERR_IO_PENDING) {
    context->Next(result);
  }
}

void Storage::OnReadEntryFile(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  if (result == net::OK) {
    context->BindNext(&Storage::ReadEntryForFile, weak_this_for_task_);
    context->bytes_total = torrent->GetEntryDataSize(kDATA_CONTENT);
    // now write the data from the input file
    context->Next(0);
  } else {
    //printf("blob storage entry open error. code = %ld\n", result);
    context->Exit(result);
  }
}

void Storage::ReadEntryForFile(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  if (context->op == StorageContext::kWRITE_ENTRY_FILE) {
    context->BindNext(&Storage::OnReadEntryManifestForFileWrite, weak_this_for_task_);
  } else {
    context->BindNext(&Storage::OnReadEntryManifestForFileRead, weak_this_for_task_);
  }
  
  // we dont know the real size, so we try to make enough room
  size_t manifest_size = torrent->GetEntryDataSize(kDATA_MANIFEST);
  context->header_data = new net::IOBufferWithSize(manifest_size);

  context->header.bytes = torrent->ReadEntryData(
    kDATA_MANIFEST, // slot offset:  0 = header
    context->header.offset, // byte offset
    context->header_data.get(),
    context->header_data->size(),
    context->next_callback);

  if (context->header.bytes != net::ERR_IO_PENDING) {
    context->Next(context->header.bytes);
  }
}

void Storage::OnReadEntryManifestForFileRead(scoped_refptr<StorageContext> context, int64_t result) {
  bool should_create_dirs = false;
  bool found = false;
  int read_offset = 0;
  // first.. check if the reading the header succeeded.
  if (result < 0) { 
    DLOG(ERROR) << "error while reading the entry header";
    context->Exit(result);
    return;
  }

  context->header.status = net::OK;

  if (!context->copy_entry.entry_header.ParseFromArray(context->header_data->data(), result)) {
    DLOG(ERROR) << "error while decoding entry header/manifest. encoded size: " << result;
    context->Exit(net::ERR_FAILED);
    return; 
  }

  // Change here
  //if (context->copy_entry.entry_header.inodes().size() > 1 && !context->copy_entry.output_as_shared_buffer) {
  if (!context->copy_entry.output_as_shared_buffer) {
    if (!base::PathExists(context->copy_entry.dest)) {
      should_create_dirs = true;
      if (!base::CreateDirectory(context->copy_entry.dest)) {
        DLOG(ERROR) << "error while creating directory " << context->copy_entry.dest;
        context->Exit(net::ERR_FAILED);
        return;
      }
    }
  } 
#if defined(OS_WIN)
  std::string output_file_str = base::UTF16ToASCII(context->copy_entry.file_path.value());
#else
  std::string output_file_str = context->copy_entry.file_path.value();
#endif
    
  if (!context->copy_entry.output_as_shared_buffer) {
    // open the output file
    for (int i = 0; i < context->copy_entry.entry_header.inodes().size(); i++) {
      storage_proto::InfoInode inode = context->copy_entry.entry_header.inodes(i);
      if (inode.path() != output_file_str) {
        read_offset += inode.length();
        continue;      
      } else {
        found = true;
        context->copy_entry.inode_index = i;
        break;
      }
      base::FilePath file_path = should_create_dirs ?  
        context->copy_entry.dest.AppendASCII(inode.path()) :
        context->copy_entry.dest;
      if (should_create_dirs) {
        base::FilePath dir_path = file_path.DirName();
        if (!base::PathExists(dir_path)) {
          if (!base::CreateDirectory(dir_path)) {
            DLOG(ERROR) << "error while creating directory " << dir_path;
            context->Exit(net::ERR_FAILED);
            return;
          }
        }
      }
      base::File file(file_path, base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_READ | base::File::FLAG_WRITE);
      if (!file.IsValid()) {
#if defined (OS_WIN)
        printf("error: could not create/open output file '%ls'\n", file_path.value().c_str());
#else
        printf("error: could not create/open output file '%s'\n", file_path.value().c_str());
#endif
        context->Exit(net::ERR_FAILED);
        return;
      }
#if defined(OS_POSIX)
      int attr_mode = inode.posix_attr();
      if (attr_mode != -1)
        DCHECK(base::SetPosixFilePermissions(file_path, attr_mode));
#endif
      context->copy_entry.files.push_back(std::move(file));
    }

  } else { // !output_as_shared_buffer
    for (int i = 0; i < context->copy_entry.entry_header.inodes().size(); i++) {
      storage_proto::InfoInode inode = context->copy_entry.entry_header.inodes(i);
      if (inode.path() != output_file_str) {
        read_offset += inode.length();
        continue;      
      } else {
        found = true;
        context->copy_entry.inode_index = i;
        // create the shared buffer here
        context->copy_entry.file_data = mojo::SharedBufferHandle::Create(inode.length());
        break;
      }
    }
  }

  if (!found) {
    printf("error: could not find file '%s' as a inode of entry\n", output_file_str.c_str());
    context->Exit(net::ERR_FAILED);
    return;
  }

  context->read.offset = read_offset;

  base::ThreadTaskRunnerHandle::Get()->PostTask(
    FROM_HERE,
    base::BindOnce(&Storage::ReadEntryContentForFile, 
      weak_this_for_task_, 
      context, 
      0));
}

void Storage::OnReadEntryManifestForFileWrite(scoped_refptr<StorageContext> context, int64_t result) {
  bool should_create_dirs = false;
  bool found = false;
  int write_offset = 0;
  if (result < 0) { 
    DLOG(ERROR) << "error while reading the entry header";
    context->Exit(result);
    return;
  }

  context->header.status = net::OK;

  if (!context->write_entry.entry_header.ParseFromArray(context->header_data->data(), result)) {
    DLOG(ERROR) << "error while decoding entry header/manifest. encoded size: " << result;
    context->Exit(net::ERR_FAILED);
    return; 
  }

#if defined(OS_WIN)
  std::string output_file_str = base::UTF16ToASCII(context->write_entry.file_path.value());
#else
  std::string output_file_str = context->write_entry.file_path.value();
#endif

  for (int i = 0; i < context->write_entry.entry_header.inodes().size(); i++) {
    storage_proto::InfoInode inode = context->write_entry.entry_header.inodes(i);
    if (inode.path() != output_file_str) {
      write_offset += inode.length();
      continue;      
    } else {
      found = true;
      context->write_entry.inode_index = i;
      break;
    }
  }

  if (!found) {
    printf("error: could not find file '%s' as a inode of entry\n", output_file_str.c_str());
    context->Exit(net::ERR_FAILED);
    return;
  }

  context->write.offset = write_offset;

  base::ThreadTaskRunnerHandle::Get()->PostTask(
    FROM_HERE,
    base::BindOnce(&Storage::WriteEntryContentForFile, 
      weak_this_for_task_, 
      context, 
      0));
}

void Storage::ReadEntryContentForFile(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //context->BindNext(&Storage::OnReadEntryContent);

  if (context->read.offset == 0 && context->header.status != net::OK) { 
    DLOG(ERROR) << "Storage::ReadEntryContentForFile: read.offset == 0 && header.status != net::OK";
    context->Exit(context->header.status);
    return;
  }

  CompletionCallback cb = base::Bind(&Storage::OnReadEntryContentForFile, weak_this_for_task_, context);
 
  context->read.bytes = torrent->ReadEntryData(
    kDATA_CONTENT,
    context->read.offset, 
    context->buffer.get(), 
    context->buffer->size(),
    cb);

  if (context->read.bytes != net::ERR_IO_PENDING) {
    std::move(cb).Run(context->read.bytes);
  }
}

void Storage::OnReadEntryContentForFile(scoped_refptr<StorageContext> context, int64_t readed) {
  if (readed < 0 ) {
#if defined (OS_WIN)
    printf("read error at offset %lld: %lld", context->read.offset, readed);
#else
    printf("read error at offset %ld: %ld", context->read.offset, readed);
#endif
    if (!context->copy_entry.output_as_shared_buffer) {
      context->copy_entry.files[0].Close();  
    }
    SyncTorrentImpl(context);
    context->torrent->CloseEntry();
    context->Exit(readed);
    return;
  }

  int inode_index = context->copy_entry.inode_index;
  // use this to calculate what we should skip
  int64_t former_files_sum_size = 0;
  for (int i = 0; i < inode_index; i++) {
    former_files_sum_size += context->copy_entry.entry_header.inodes(i).length();
  }
  int64_t current_file_size = context->copy_entry.entry_header.inodes(inode_index).length();
  // calculate the file byte offset
  int64_t file_start_byte_offset = context->read.offset - former_files_sum_size;
  int64_t rest = current_file_size - file_start_byte_offset;
  int64_t file_ammount_to_write = readed < rest ? readed : rest;
  
  // this is EOF. we are done
  if (file_ammount_to_write == 0) {
    if (!context->copy_entry.output_as_shared_buffer) {
      context->copy_entry.files[0].Close();  
    }
    SyncTorrentImpl(context);
    context->torrent->CloseEntry();
    if (context->copy_entry.output_as_shared_buffer) {
      // if we get here, we wrote all the data to the selected file
      // so just pass the total size
      context->Exit(current_file_size, std::move(context->copy_entry.file_data), net::OK);
    } else {
      context->Exit(readed);
    }
    return;
  }
  
  int wr = 0;
  if (!context->copy_entry.output_as_shared_buffer) {  
    if ((wr = context->copy_entry.files[0].Write(file_start_byte_offset, context->buffer->data(), file_ammount_to_write)) == -1) {
      LOG(ERROR) << "file.Write error ("<< wr << ") at offset " << file_start_byte_offset << 
        " while trying to write " << file_ammount_to_write << " bytes";
      context->copy_entry.files[0].Close();  
      SyncTorrentImpl(context);
      context->torrent->CloseEntry();
      context->Exit(-2);
      return;
    }
  } else {
    mojo::ScopedSharedBufferMapping mapping = context->copy_entry.file_data->Map(current_file_size);
    char* pos = reinterpret_cast<char *>(mapping.get());
    // advance the pointer to the right offset
    pos += file_start_byte_offset;
    // copy to the shared mem
    //DCHECK(file_ammount_to_write == current_file_size);
    
    // see how we can avoid this copy here at least on Linux
    // by using 'tee' directly on the mmap'ed file that the torrent
    // entry can point to us 
    memcpy(pos, context->buffer->data(), file_ammount_to_write);
    wr = file_ammount_to_write;
  }

  context->write.bytes = wr;

  if (context->write.bytes != file_ammount_to_write) {
    LOG(ERROR) << "write != file_ammount_to_write " << context->write.bytes << " vs. " << file_ammount_to_write;
    if (!context->copy_entry.output_as_shared_buffer) {  
      context->copy_entry.files[0].Close();  
    }
    SyncTorrentImpl(context);
    context->torrent->entry_->Close();
    context->torrent->entry_ = nullptr;
    context->Exit(-2);
  }

  context->read.offset += context->write.bytes;
  
  ReadEntryContentForFile(context, context->write.bytes);
}

void Storage::WriteEntryContentForFile(scoped_refptr<StorageContext> context, int64_t result) {
  CompletionCallback cb = base::Bind(&Storage::OnWriteEntryContentForFile, weak_this_for_task_, context);
  //char* data = reinterpret_cast<char *>(context->write_entry.data.dat());
  //scoped_refptr<net::WrappedIOBuffer> buffer = new net::WrappedIOBuffer(data);
  int r = context->torrent->WriteEntryData(
    kDATA_CONTENT,
    // context->write.offset = start offset for the file
    // context->write_entry.offset = user provided offset (within the file)
    context->write.offset + context->write_entry.offset,
    context->write_entry.data.get(),
    //buffer.get(),
    context->write_entry.size,
    cb,
    false);

  if (r != net::ERR_IO_PENDING) {
    std::move(cb).Run(r);
  }    
}

void Storage::OnWriteEntryContentForFile(scoped_refptr<StorageContext> context, int64_t readed) {
  SyncTorrentImpl(context);
  // TODO: see if we really want this.. as open()/close() might be controlled
  //       by the user
  ////DLOG(INFO) << "OnWriteEntryContentForFile: closing entry";
  //context->torrent->CloseEntry();
  context->Exit(readed);  
}

void Storage::AddEntry(const scoped_refptr<Torrent>& torrent,
                        CompletionCallback callback) {
  //DLOG(INFO) << "StorageManager::AddEntry";
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kADD_ENTRY_EMPTY, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyAddEntry, weak_this_for_task_, std::move(callback));
  context->add_entry.file_count = 0;
  RunIO(context);
}

void Storage::AddEntry(const scoped_refptr<Torrent>& torrent,
                        const base::FilePath& src,
                        std::string name,
                        CompletionCallback callback) {
  //DLOG(INFO) << "Storage::AddEntry: " << torrent->id().to_string() << " src = " << src << " name = " << name;
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kADD_ENTRY, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyAddEntry, weak_this_for_task_, std::move(callback));
  context->add_entry.src = src;
  context->add_entry.name = std::move(name);
  RunIO(context);
}

void Storage::AddIndex(const scoped_refptr<Torrent>& torrent,
                       const std::string& name,
                       CompletionCallback callback) {
  //DLOG(INFO) << "Storage::AddIndex: " << torrent->id().to_string() << " name = " << name;
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kADD_INDEX, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyAddIndex, weak_this_for_task_, std::move(callback));
  context->add_entry.name = name;
  RunIO(context);
}

void Storage::AddIndexImpl(scoped_refptr<StorageContext> context) {
  //context->BindNext(&Storage::ReplyAddIndex);
  int r = AddIndexOnTree(context);
  if (r != net::ERR_IO_PENDING) {
    context->Next(r);
  }
}

void Storage::AddEmptyEntry(scoped_refptr<StorageContext> context) {
  context->BindNext(&Storage::OnAddEntry, weak_this_for_task_); 

  int result = backend_->CreateEntry(
    context->torrent->id(),
    &context->torrent->entry_,
    context->next_callback);

  if (result != net::ERR_IO_PENDING) {
    context->Next(result);
  }
}

void Storage::AddEntryImpl(scoped_refptr<StorageContext> context) {
  //DLOG(INFO) << "Storage::AddEntryImpl: " << context->torrent->id().to_string();
  context->BindNext(&Storage::OnAddEntry, weak_this_for_task_);

  base::FileEnumerator files_to_add(context->add_entry.src, true, base::FileEnumerator::FILES);
  for (base::FilePath file = files_to_add.Next(); !file.empty(); file = files_to_add.Next()) {
    int id = context->files.Load(file);
    if (id == -1) {
      DLOG(ERROR) << "failed while trying to open mmap file " << file << " for " << context->key.to_string();
      context->Exit(net::ERR_FAILED);
      return;
    }
  }
  
  // check if no file was added, and exit early if true
  if (context->files.file_count() == 0) {
    context->Exit(net::ERR_FAILED);
    return;
  }

  context->add_entry.file_count = context->files.file_count();

  ////DLOG(INFO) << "Storage::AddEntryImpl: " << context->add_entry.file_count << " files loaded";

  int result = backend_->CreateEntry(
    context->torrent->id(),
    &context->torrent->entry_,
    context->next_callback);

  if (result != net::ERR_IO_PENDING) {
    context->Next(result);
  }
}

void Storage::OnAddEntry(scoped_refptr<StorageContext> context, int64_t result) {
  //DLOG(INFO) << "Storage::OnAddEntry: " << context->torrent->id().to_string() << " r = " << result;
  if (result != 0) {
    context->Exit(net::ERR_FAILED);
    return;
  }
   
  OnAddEntryWriteContent(context, 0, 0, 0);
}

void Storage::OnAddEntryWriteContent(scoped_refptr<StorageContext> context, int file_offset, int64_t expected, int64_t result) { 
  //DLOG(INFO) << "Storage::OnAddEntryWriteContent: " << context->torrent->id().to_string() << " file_offset = " << file_offset << " expected = " << expected << " wrote = " << result;

  const scoped_refptr<Torrent>& torrent = context->torrent;

  if (result != expected) {
    DLOG(ERROR) << "write content failed: expected " << expected << " wrote " << result;
    context->Exit(net::ERR_FAILED);
    return;
  }

  // check if we are done
  if (file_offset >= int(context->files.file_count())) {
    context->BindNext(&Storage::OnAddEntryWriteHashes, weak_this_for_task_);
    context->Next(net::OK);
    return;
  }
  
  size_t size = context->files.GetLength(file_offset);
  
  CompletionCallback cb = base::Bind(&Storage::OnAddEntryWriteContent, weak_this_for_task_, context, file_offset + 1, size); //GetWeakPtr(), context, file_offset + 1, size);

  size_t offset = 0;
  for (int i = 0; i < file_offset; ++i) {
    offset += context->files.GetLength(i);
  }
  
  char* data = reinterpret_cast<char *>(context->files.Map(file_offset));
  DCHECK(data);
  scoped_refptr<net::WrappedIOBuffer> buffer = new net::WrappedIOBuffer(data);

  //DLOG(INFO) << "writing file " << file_offset << " with size " << size << " from " << offset  << " to " << offset + size << " on CONTENT sector";

  int r = torrent->WriteEntryData(
    kDATA_CONTENT,
    offset,
    buffer.get(),
    size,
    cb,
    false);

  if (r != net::ERR_IO_PENDING) {
    std::move(cb).Run(r);
  }

}

void Storage::OnAddEntryWriteHashes(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  
  //DLOG(INFO) << "Storage::OnAddEntryWriteHashes: " << torrent->id().to_string() << " r = " << result << "\ntotal blob content size = " << 
  //  torrent->GetEntryDataSize(kDATA_CONTENT) << "\ntotal input files size = " << context->files.GetTotalLength();

  storage_proto::EntryMerkleHeader merkle_header;
  
  context->BindNext(&Storage::OnAddEntryWriteManifest, weak_this_for_task_);

  size_t total_len = context->files.GetTotalLength();
  int block_count = (total_len + kBlockSize - 1) / kBlockSize;//context->files.GetTotalBlockCount();
    
  context->add_entry.block_count = block_count;
  context->add_entry.content_len = total_len;
  context->add_entry.block_size = torrent->piece_length() > 0 ? torrent->piece_length() : kBlockSize;

  merkle_header.set_count(1);//context->files.file_count() + 1);

  // create the merkle tree for all the files
  std::unique_ptr<MerkleTree> merkle = GenerateMerkleTreeForFiles(&context->files);
  if (!merkle) {
    DLOG(ERROR) << "error while generating merkle tree for blobs";
    context->Exit(net::ERR_FAILED);
    return;
  }

  torrent->set_merkle_tree(std::move(merkle));

  MerkleTree* entry_merkle = torrent->merkle_tree();//context->add_entry.entry_merkle.get();

  //entry_merkle->Print();

  size_t header_content_size = 0;

  // and the node into the header for the entry node
  auto* node = merkle_header.add_node();
  node->set_content_size(entry_merkle->digest_size());
  node->set_node_count(entry_merkle->node_count());
  node->set_leaf_count(entry_merkle->leaf_count());
  node->set_block_count(entry_merkle->block_count());
  node->set_first_leaf(entry_merkle->first_leaf_offset());

  header_content_size += entry_merkle->digest_size();
   
  merkle_header.set_content_size(header_content_size);

  std::string encoded_header;
  merkle_header.SerializeToString(&encoded_header);

  int header_size = encoded_header.size();
  
  size_t allocated_size = csqliteVarintLen(header_size) + header_size + header_content_size;

  context->add_entry.hash_header_len = csqliteVarintLen(header_size) + encoded_header.size();
  context->add_entry.hash_content_len = header_content_size;

  // //DLOG(INFO) << "Storage::OnAddEntryWriteHashes:\n content_size: " << entry_merkle->digest_size() << 
  // "\n node_count: " << entry_merkle->node_count() <<
  // "\n leaf_count: " << entry_merkle->leaf_count() <<
  // "\n block_count: " << entry_merkle->block_count() <<
  // "\n first_leaf_offset: " << entry_merkle->first_leaf_offset() <<
  // "\n encoded_header_size: " << encoded_header.size() <<
  // "\n allocated_size (encoded_header + content_size): " << allocated_size;

  // NOTE: we need to have a better way here, If the files are big
  // we might end with big merkle payload.. we already have to make
  // room for the payload in the tree itself.. here we are allocating
  // almost the same ammount of memory + header size to accomodate them
  // besides if we found a better way, we can skip the expensive memcpy
  // we are doing below
  // (not much of a problem if the files are not that big (40 bytes * (filelen / 65536)))
  context->hash_buffer = new net::IOBufferWithSize(allocated_size);

  // TODO: this is a really dumb copy, se if we can make it better
  // by providing the buffer to all of them
  char* current_buf = context->hash_buffer->data();

  // write the header size
  current_buf += csqlitePutVarint(reinterpret_cast<unsigned char *>(current_buf), header_size);

  // write the header
  memcpy(current_buf, encoded_header.data(), encoded_header.size());
  current_buf += encoded_header.size();

  // write the merkle tree for the entry into the buffer
  entry_merkle->Encode(current_buf);

  // now persist into the entry 'DATA_MERKLE' sector
  int r = torrent->WriteEntryData(
    kDATA_MERKLE,
    0,
    context->hash_buffer.get(),
    allocated_size,
    context->next_callback,
    false);

  if (r != net::ERR_IO_PENDING) {
    context->Next(r);
  }
}

void Storage::OnAddEntryWriteManifest(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //DLOG(INFO) << "Storage::OnAddEntryWriteManifest: " << torrent->id().to_string() << " r = " << result;
  //storage_proto::Info header;
  // if error exit early
  if (result < 0) {
    context->Exit(net::ERR_FAILED);
    return;
  }

  context->BindNext(&Storage::OnAddEntryWriteHeader, weak_this_for_task_);

  base::Time creation_time = base::Time::Now();
  
  MerkleTree* entry_merkle = torrent->merkle_tree();

  std::string entry_root_hash = entry_merkle->root_hash();
#if defined(OS_WIN)
  std::string file_name = context->add_entry.name.empty() ? base::UTF16ToASCII(context->add_entry.src.BaseName().value()) : context->add_entry.name;
#else
  std::string file_name = context->add_entry.name.empty() ? context->add_entry.src.BaseName().value() : context->add_entry.name;
#endif

  storage_proto::Info header;
  header.set_kind(storage_proto::INFO_FILE);
  header.set_state(storage_proto::STATE_FINISHED);
  header.set_id(torrent->id().string());
  header.set_path(file_name);
  header.set_root_hash(entry_root_hash);
  header.set_inode_count(context->add_entry.file_count);
  header.set_piece_length(context->add_entry.block_size);
  header.set_piece_count(context->add_entry.block_count);
  header.set_length(context->add_entry.content_len);
  header.set_hash_header_length(context->add_entry.hash_header_len);
  header.set_hash_content_length(context->add_entry.hash_content_len);
  header.set_creation_date(creation_time.ToInternalValue());
  header.set_mtime(creation_time.ToInternalValue());
  
  //  printf("id: %s\n  name: %s\n root hash: %s\n  piece_length: %ld\n  piece_count: %ld\n  length: %ld\n  hashes size: %d\n  files: %ld\n", 
  //    torrent->id().to_string().c_str(),
  //    header.path().c_str(),
  //    //description.c_str(),
  //    base::HexEncode(entry_root_hash.data(), entry_root_hash.size()).c_str(),
  //    context->add_entry.block_size,
  //    context->add_entry.block_count,
  //    context->add_entry.content_len,
  //    context->hash_buffer->size(),
  //    context->add_entry.file_count);
  
  int block_start = 1;
  for (int i = 0; i < context->add_entry.file_count; i++) {
    int posix_file_permissions = -1;
    std::string content_type;
    base::Time time = base::Time::Now();
    base::StringPiece file_fullpath = context->files.GetPath(i);
#if defined(OS_WIN)
    base::FilePath file_fullpath_path(base::ASCIIToUTF16(file_fullpath));
#else
    base::FilePath file_fullpath_path(file_fullpath);
#endif
    base::StringPiece file_name = FormatFileName(file_fullpath);
    base::StringPiece file_path = FormatFilePath(context->add_entry.src.BaseName().value(), file_fullpath);
    size_t file_size = context->files.GetLength(i);
    int block_count = context->files.GetBlockCount(i);

    net::GetMimeTypeFromFile(file_fullpath_path, &content_type);

    if (content_type.empty()) {
      base::FilePath::StringType file_ext = file_fullpath_path.Extension();
      base::StringPiece sample = context->files.GetFirstBytes(i);
      // check if this is a unix executable (no extension + executable bit)
      if (file_ext.empty()) { 
        if (!base::IsStringUTF8(sample)) { // assume binary
          content_type = "application/octet-stream";
        } else { 
          content_type = "text/plain";
        }
      }
    }

#if defined(OS_POSIX)
  DCHECK(GetPosixFilePermissions(file_fullpath_path, &posix_file_permissions));
#endif

    int block_end = block_start + block_count - 1;
    //std::string blob_root_hash = context->files.GetMerkleRoot(i);
    //MerkleTree* merkle_tree = context->files.GetMerkleTree(i);
    
    // add it
    //printf(" file[%d] - name: %s path: %s size: %ld\n", i, file_name.as_string().c_str(), file_fullpath_path.value().c_str(), file_size);

    auto* inode = header.add_inodes();
    inode->set_parent(context->key.string());
    inode->set_name(file_name.as_string());
    inode->set_path(file_path.as_string());
    inode->set_length(file_size);
    inode->set_offset(i + 1);
    inode->set_root_hash(entry_root_hash);//blob_root_hash);
    inode->set_piece_count(block_count);
    inode->set_piece_start(block_start);
    inode->set_piece_end(block_end);
    inode->set_content_type(content_type);
    inode->set_creation_date(time.ToInternalValue());
    inode->set_mtime(time.ToInternalValue());
    inode->set_posix_attr(posix_file_permissions);

    //std::string json_str;
    //google::protobuf::util::JsonPrintOptions options;
    //options.add_whitespace = true;
    //options.always_print_primitive_fields = true;
    //options.preserve_proto_field_names = true;
    //google::protobuf::util::MessageToJsonString(*inode, &json_str, options);

    //printf("%s\n", json_str.c_str());
    block_start += block_count;
  }

  torrent->MergeInfo(header);
  
  if (!torrent->SerializeInfoToString(&context->encoded_header)) {
    LOG(ERROR) << "init: serializing protobuf header to string failed";
    context->Exit(net::ERR_FAILED);
    TerminateContext(context);
    return;
  }

  scoped_refptr<net::StringIOBuffer> manifest_buf = new net::StringIOBuffer(context->encoded_header);
  // write the manifest
  int r = torrent->WriteEntryData(
    kDATA_MANIFEST,
    0,
    manifest_buf.get(),
    manifest_buf->size(),
    context->next_callback,
    false);

  if (r != net::ERR_IO_PENDING) {
    context->Next(r);
  }
}

void Storage::OnAddEntryWriteHeader(scoped_refptr<StorageContext> context, int64_t result) {
  //DLOG(INFO) << "Storage::OnAddEntryWriteHeader:" << context->torrent->id().to_string() << " r = " << result;
  const scoped_refptr<Torrent>& torrent = context->torrent;
  
  if (result < 0) {
    context->Exit(net::ERR_FAILED);
    TerminateContext(context);
    return;
  }

  // for safety we close the entry now
  //torrent->CloseEntry();

  context->BindNext(&Storage::OnAddEntryWriteIndex, weak_this_for_task_);
  int r = AddIndexOnTree(context);
  if (r != net::ERR_IO_PENDING) {
    context->Next(r);
  }
}
 
void Storage::OnAddEntryWriteIndex(scoped_refptr<StorageContext> context, int64_t result) {
  //DLOG(INFO) << "Storage::OnAddEntryWriteIndex:" << context->torrent->id().to_string() << " r = " << result;
  if (result == net::OK) {
    SyncTorrentImpl(context);
    context->Exit(result);
  } else {
    context->Exit(result);
    TerminateContext(context);
  }
}


void Storage::GetEntryInfo(const scoped_refptr<Torrent>& torrent, base::Callback<void(storage_proto::Info, int64_t)> cb) {
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kGET_ENTRY_INFO, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyGetEntryInfo, weak_this_for_task_, std::move(cb));
  RunIO(context);  
}

void Storage::GetEntryInfoImpl(scoped_refptr<StorageContext> context) {
  context->BindNext(&Storage::OnGetEntryInfo, weak_this_for_task_);

  int result = backend_->OpenEntry(
    context->torrent->id(),
    &context->torrent->entry_,
    context->next_callback);

  if (result != net::ERR_IO_PENDING) {
    context->Next(result);
  }
}

//void Storage::Query(const std::string& query_string,
//                 const std::string& catalog_name,
//                 base::Callback<void(std::unique_ptr<Block>, int64_t)> callback) {
//  std::move(callback).Run({}, -1);
//}



//void Storage::QueryImpl(const std::string& query,
//                     Catalog* catalog,
//                     base::Callback<void(std::unique_ptr<Block>, int64_t)> callback) {
  // scoped_refptr<StorageContext> context = CreateContext(StorageContext::kQUERY, catalog->FullName(), CompletionCallback());
  // context->BindExit(&Storage::ReplyQuery, std::move(callback));
  
  // std::unique_ptr<const zetasql::AnalyzerOutput> output;
  // zetasql::AnalyzerOptions options;
  // options.mutable_language()->SetSupportsAllStatementKinds(); 
  // zetasql_base::Status status = zetasql::AnalyzeStatement(
  //                                 query,
  //                                 options,
  //                                 catalog, 
  //                                 catalog->type_factory(),
  //                                 &output);

  // if (status.ok()) {
  //   db_task_runner_->PostTask(FROM_HERE, 
  //     base::BindOnce(
  //       &Storage::OnQuery, 
  //       base::Unretained(this),
  //       context,
  //       base::Unretained(catalog),
  //       base::Passed(std::move(output)),
  //       0));
  // } else {
  //   DLOG(ERROR) << "query result error: " << status.message();
  //   std::unique_ptr<Block> block;
  //   context->Exit(std::move(block), -1);
  //   TerminateContext(context);
  // }
//}

//void Storage::OnQuery(
//  scoped_refptr<StorageContext> context,
//  Catalog* catalog,
//  std::unique_ptr<const zetasql::AnalyzerOutput> output, 
//  int64_t result) {
  
//  if (result == net::OK) {
//      const zetasql::ResolvedStatement* stmt = output->resolved_statement();
//      const zetasql::ResolvedQueryStmt* query_stmt = static_cast<const zetasql::ResolvedQueryStmt*>(stmt);
//      auto block = catalog->Scan(query_stmt);
//      int result = block ? net::OK : net::ERR_FAILED;
      //frontend_task_runner_->PostTask(FROM_HERE, 
//      frontend_task_runner_->PostTask(FROM_HERE, 
//        base::Bind(context->list_exit_callback, 
//          base::Passed(std::move(block)), 
//          result));
//  } else {
//      std::unique_ptr<Block> block;
      //frontend_task_runner_->PostTask(FROM_HERE, 
//      frontend_task_runner_->PostTask(FROM_HERE, 
//        base::Bind(context->list_exit_callback, 
//          base::Passed(std::move(block)), 
//          -1));
//  }
  
//}


void Storage::OpenSQLiteDatabase(scoped_refptr<StorageContext> context) {
  int64_t result = net::OK;
  const scoped_refptr<Torrent>& torrent = context->torrent;//manager_->NewTorrent(this, context->key);
  torrent->set_is_opening_db(true);
  Database* db = Database::Open(torrent, context->open_db_params.type == storage_proto::INFO_KVDB);

  if (!db) {
    // //D//LOG(INFO) << "Storage::OpenSQLiteDatabase: open sqlite db failed";
    result = net::ERR_FAILED;
    //context->op == StorageContext::kOPEN_CATALOG ?
    ReplyOpenDatabase(std::move(context->exit_callback), result); //:
      //ReplyOpenApplication({}, std::move(context->exit_callback), result);
    TerminateContext(context);
    return;
  }

  ReplyOpenDatabase(std::move(context->exit_callback), result);
  TerminateContext(context);
}

void Storage::CreateSQLiteDatabase(scoped_refptr<StorageContext> context) {
  //Torrent* torrent = manager_->NewTorrent(this, context->key);
  const scoped_refptr<Torrent>& torrent = context->torrent;
  torrent->mutable_info()->set_kind(context->create_db_params.type);
  torrent->set_is_opening_db(true);
  Database* db = nullptr;
  if (context->create_db_params.type == storage_proto::INFO_KVDB) {
    db = Database::Create(torrent, context->create_db_params.keyspaces, true, context->create_db_params.in_memory);
  } else {
    db = Database::Create(torrent, context->create_db_params.create_table_stmts, context->create_db_params.insert_table_stmts, false, context->create_db_params.in_memory);
  }
  int64_t result = net::OK;
  
  if (!db) { // return early
    result = net::ERR_FAILED;
    ReplyCreateDatabase(std::move(context->exit_callback), result);
    TerminateContext(context);
    return;
  }
  
  if (context->op == StorageContext::kCREATE_DATABASE) {
    if (!torrent->is_root()) {   
      ////LOG(INFO) << "Storage::OnWriteTorrentHeaderResult: AddIndexOnRegistry " << torrent->id().to_string();
      if (being_cloned()) {
        //D//LOG(INFO) << "Storage::CreateSQLiteDatabase: being cloned. cancelling adding index";
        return;
      }
      AddIndexOnTreeOnDbThread(context);
    }
    ReplyCreateDatabase(std::move(context->exit_callback), result);
  }
  TerminateContext(context);
}

const std::string& Storage::name() const {
  return name_;
}

const base::FilePath& Storage::path() const {
  return path_;
}

const std::string& Storage::address() const {
  return state_->address();
}

size_t Storage::size() const {
  return static_cast<size_t>(GetAllocatedSize());
}

bool Storage::is_signed() const {
  return false;
}

storage_proto::StorageStatus Storage::status() const {
  return state_->status(); 
}

const base::FilePath& Storage::GetPath() const {
  return path_;
}

const std::string& Storage::GetName() const {
  return name_;
}

bool Storage::ShouldSeed(const storage_proto::Info& info) {
  // for now is just this
  return is_owner();
}

Future<int> Storage::ReadTorrent(scoped_refptr<Torrent> torrent, void* buf, int64_t size, int64_t offset, bool is_journal, int jrn_seq) {
  bool sync = false;
  DCHECK(torrent);
  DCHECK(torrent->entry_);

  if (is_journal && !torrent->HaveJornalEntry(jrn_seq)) {
    return Future<int>(net::ERR_FAILED);
  }

  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kREAD_TORRENT, torrent, CompletionCallback());
  context->is_journal = is_journal;
  context->jrn_seq = jrn_seq;
  context->read_torrent.size = size;
  context->read_torrent.offset = offset;
  context->read_torrent.buf = buf;
  RunIO(context);
  return Future<int>(context->sync_event, sync);
}

void Storage::ReadTorrentImpl(scoped_refptr<StorageContext> context) {
  //Inode* inode = GetInode(key);
  //if (inode) {
  scoped_refptr<Torrent> torrent = context->torrent;
  DCHECK(torrent);
  // //D//LOG(INFO) << "Storage::ReadTorrentImpl: " << torrent->id().to_string() << " journal? " << context->is_journal;
  CompletionCallback callback = base::Bind(&Storage::OnReadTorrent, weak_this_for_task_, context, context->read_torrent.size);//GetWeakPtr(), context, size);
  context->iobuf = new IOBufferWrapper(context->read_torrent.buf, context->read_torrent.size);
  
//  // //D//LOG(INFO) << "reading blob content";
  if (context->is_journal) {
    context->read.bytes = torrent->ReadJournalEntryData(
      context->jrn_seq,
      kDATA_CONTENT, 
      context->read_torrent.offset,
      context->iobuf.get(),
      context->read_torrent.size,
      callback);
  } else {
    context->read.bytes = torrent->ReadEntryData(
      kDATA_CONTENT, 
      context->read_torrent.offset,
      context->iobuf.get(),
      context->read_torrent.size,
      callback);
  }

  if (context->read.bytes != net::ERR_IO_PENDING) {
    callback.Run(context->read.bytes);
  }

}

void Storage::OnReadTorrent(scoped_refptr<StorageContext> context, int64_t expected, int64_t result) {
  //// //D//LOG(INFO) << "Storage::OnReadBlob: " << context->key << " r = " << result;
  context->read.bytes = result;
  context->Signal(0);
  
  TerminateContext(context);
}

Future<int> Storage::WriteTorrent(scoped_refptr<Torrent> torrent, const void* buf, int64_t size, int64_t offset, bool is_journal, int jrn_seq) {
  ////DLOG(INFO) << "Storage::WriteTorrent: " << torrent->id().to_string() << " offset = " << offset << " size = " << size << " journal? " << is_journal;
  bool sync = false;
  DCHECK(torrent->entry_);
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kWRITE_TORRENT, torrent, CompletionCallback());
  context->is_journal = is_journal;
  context->jrn_seq = jrn_seq;
  context->write_torrent.size = size;
  context->write_torrent.offset = offset;
  context->write_torrent.buf = buf;

  // if we are coming from a create catalog, get some useful parameters from the parent context
  // who will still be alive
  scoped_refptr<StorageContext> parent_context = GetContext(StorageContext::kCREATE_DATABASE, torrent->id());
  if (parent_context) {
    context->create_db_params.keyspaces = parent_context->create_db_params.keyspaces;
    context->create_db_params.create_table_stmts = parent_context->create_db_params.create_table_stmts;
    context->parent = parent_context;
  }
  RunIO(context);
  return Future<int>(context->sync_event, sync);
}

void Storage::WriteTorrentImpl(scoped_refptr<StorageContext> context) {
  //DLOG(INFO) << "Storage::WriteTorrentImpl: " << context->torrent->id().to_string() << " offset = " << context->write_torrent.offset << " size = " << context->write_torrent.size << " piece_length: " << context->torrent->piece_length();
  CompletionCallback callback = base::Bind(&Storage::OnWriteTorrent, weak_this_for_task_, context, context->write_torrent.size);
  const scoped_refptr<Torrent>& torrent = context->torrent;
  context->iobuf = new IOBufferWrapper(context->write_torrent.buf, context->write_torrent.size);
  if (!context->is_journal) {
    MerkleTree* merkle_tree = torrent->merkle_tree();
    if (!merkle_tree) {
      int table_count = context->create_db_params.keyspaces.size() > 0 ? context->create_db_params.keyspaces.size() : context->create_db_params.create_table_stmts.size();
      bool ok = false;
      int piece_count = torrent->piece_count();
      //DLOG(INFO) << " table count: " << table_count << " piece count: " << piece_count << " create_table_stmts: " << context->create_db_params.create_table_stmts.size();
      if (table_count && context->create_db_params.keyspaces.size()) {
        ok = torrent->CreateMerkleTreeTables(table_count);
      } else if (table_count && context->create_db_params.create_table_stmts.size()) {
        ok = torrent->CreateMerkleTreeSQLTables(table_count);
      } else if (piece_count > 0) {
        ok = torrent->CreateMerkleTreePieces(piece_count);
      }
      if (!ok) {
        //DLOG(ERROR) << "error while creating merkle tree for torrent " << context->key.to_string();
        context->Signal(-1);
        TerminateContext(context);
        return;
      }
    }
    merkle_tree = torrent->merkle_tree();
    int64_t block_offset = context->write_torrent.offset / torrent->piece_length();//kBlockSize;
    int64_t leaf_offset = merkle_tree->first_leaf_offset() + block_offset;
    // get the block offset
    if (!merkle_tree->NodeIsSet(leaf_offset)) {
      //DLOG(INFO) << "adding leaf: leaf_offset = " << leaf_offset << " context->write_torrent.offset = " << context->write_torrent.offset << " block offset = " << block_offset << " adding leaf = " << leaf_offset << " blocks: " << merkle_tree->block_count() << " nodes: "  << merkle_tree->node_count();
      merkle_tree->AddLeaf(leaf_offset, context->write_torrent.buf, context->write_torrent.size);
    } else {
      //DLOG(INFO) << "updating leaf: offset = " << leaf_offset << " block offset = " << block_offset << " updating leaf = " << leaf_offset<< " blocks: " << merkle_tree->block_count() << " nodes: "  << merkle_tree->node_count();
      merkle_tree->UpdateLeaf(leaf_offset, context->write_torrent.buf, context->write_torrent.size);
    }
  }
  if (context->is_journal) {
    context->write.bytes = torrent->WriteJournalEntryData(
      context->jrn_seq,
      kDATA_CONTENT, 
      context->write_torrent.offset,
      context->iobuf.get(),
      context->write_torrent.size,
      callback,
      false);
  } else {
    context->write.bytes = torrent->WriteEntryData(
      kDATA_CONTENT, 
      context->write_torrent.offset,
      context->iobuf.get(),
      context->write_torrent.size,
      callback,
      false);
  }
  
  if (context->write.bytes != net::ERR_IO_PENDING) {
    callback.Run(context->write.bytes);
  }
}

void Storage::WriteTorrentMerkleImpl(scoped_refptr<StorageContext> context) {
    const scoped_refptr<Torrent>& torrent = context->torrent;  
    //D//LOG(INFO) << "Storage::WriteTorrentMerkleImpl: " << torrent->id().to_string() << " journal? " << context->is_journal;
    size_t header_content_size = 0;  
   
    storage_proto::EntryMerkleHeader merkle_header;
    merkle_header.set_count(1);
  
    MerkleTree* merkle_tree = torrent->merkle_tree();//merkle_tree_list_.find(key)->second.get();

    auto* node = merkle_header.add_node();
    node->set_content_size(merkle_tree->digest_size());
    node->set_node_count(merkle_tree->node_count());
    node->set_leaf_count(merkle_tree->leaf_count());
    node->set_block_count(merkle_tree->block_count());
    node->set_first_leaf(merkle_tree->first_leaf_offset());  
    
    header_content_size += merkle_tree->digest_size();

    merkle_header.set_content_size(header_content_size);

    std::string encoded_header;
    merkle_header.SerializeToString(&encoded_header);
    
    int header_size = encoded_header.size();
  
    size_t allocated_size = csqliteVarintLen(header_size) + header_size + header_content_size;
    context->hash_buffer = new net::IOBufferWithSize(allocated_size);

    CompletionCallback callback = base::Bind(&Storage::OnWriteTorrentMerkle, weak_this_for_task_, context, allocated_size);

    // TODO: this is a really dumb copy, se if we can make it better
    // by providing the buffer to all of them
    char* current_buf = context->hash_buffer->data();

    // write the header size
    current_buf += csqlitePutVarint(reinterpret_cast<unsigned char *>(current_buf), header_size);

    // write the header
    memcpy(current_buf, encoded_header.data(), encoded_header.size());
    current_buf += encoded_header.size();

    // write the merkle tree for the entry into the buffer
    merkle_tree->Encode(current_buf);

    //LOG(INFO) << "Storage::WriteTorrentMerkleImpl: " << torrent->id().to_string() << ". writing entry kDATA_MERKLE";
    
    context->write.bytes = torrent->WriteEntryData(
      kDATA_MERKLE, 
      0,
      context->hash_buffer.get(),
      allocated_size,
      callback,
      false);
    
    if (context->write.bytes != net::ERR_IO_PENDING) {
      callback.Run(context->write.bytes);
    }
}

int64_t Storage::GetTorrentSize(scoped_refptr<Torrent> torrent) {
  // //D//LOG(INFO) << "Storage::GetTorrentSize: " << torrent->id().to_string();
  return torrent->GetEntryDataSize(kDATA_CONTENT);
}

Future<int> Storage::SyncTorrentMetadata(scoped_refptr<Torrent> torrent) {
  // //D//LOG(INFO) << "Storage::SyncTorrentMetadata: " << torrent->id().to_string();
  bool sync = false;
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kSYNC_METADATA, torrent, CompletionCallback());
  context->is_journal = false;
  context->should_close = false;
  RunIO(context);
  return Future<int>(context->sync_event, sync);
}

Future<int> Storage::CreateTorrent(scoped_refptr<Torrent> torrent, bool is_journal, int jrn_seq) {
  // dont call this from the "storage" thread
  // //D//LOG(INFO) << "Storage::CreateTorrent: " << torrent->id().to_string() << " journal? " << is_journal;
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCREATE_TORRENT, torrent, CompletionCallback());
  scoped_refptr<StorageContext> parent_context = GetContext(StorageContext::kCREATE_DATABASE, torrent->id());
  if (parent_context) {
    context->create_db_params.keyspaces = parent_context->create_db_params.keyspaces;
    context->parent = parent_context;
  }
  context->is_journal = is_journal;
  context->jrn_seq = jrn_seq;
  bool sync = false;
  RunIO(context);  
  return Future<int>(context->sync_event, sync);
}

void Storage::CreateTorrentImpl(scoped_refptr<StorageContext> context) {

  int result = net::ERR_FAILED;
  
  context->next_callback = base::Bind(&Storage::OnCreateTorrent, weak_this_for_task_, context); //GetWeakPtr(), context);
  const scoped_refptr<Torrent>& torrent = context->torrent;

  // //D//LOG(INFO) << "Storage::CreateTorrentImpl: key = " << torrent->id().to_string() << " journal ? " << context->is_journal;

  if (context->is_journal) {
    std::string key = torrent->GetJournalPath(context->jrn_seq);
    result = backend_->CreateEntry(
      key,
      &context->journal_fd,
      context->next_callback);
  } else {
    result = backend_->CreateEntry(
      torrent->id(),
      &torrent->entry_,
      context->next_callback);
  }

  if (result != net::ERR_IO_PENDING) {
    context->next_callback.Run(result);
  }
}

void Storage::OnCreateTorrent(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //DLOG(INFO) << "Storage::OnCreateTorrent: " << torrent->id().to_string() << " journal? " << context->is_journal << " r = " << result;
  if (result == 0) {
    if (context->is_journal) {
      torrent->SetJournalEntry(context->jrn_seq, context->journal_fd);
      context->Signal(0);
      TerminateContext(context);
    } else {
      std::string tid = torrent->id().to_string();
      // TODO: now that we have torrent as a state, use it instead of the entry
      torrent->EntrySetIsNew(true);
      
      base::Time creation_time = base::Time::Now();
      std::string content_type;

      // form the header
      storage_proto::Info header;
      header.set_state(is_owner() ? storage_proto::STATE_FINISHED : storage_proto::STATE_NONE);
      header.set_creation_date(creation_time.ToInternalValue());
      header.set_mtime(creation_time.ToInternalValue());
      header.set_id(torrent->id().string());
      header.set_piece_length(kBlockSize);
      header.set_readonly(false);

      // one for each keyspace in the database
      // as we start with at least one
      auto* inode = header.add_inodes();
      inode->set_name(tid);
      inode->set_offset(1);
      inode->set_path(torrent->info().path() + "/" + tid);
      inode->set_creation_date(creation_time.ToInternalValue());
      inode->set_mtime(creation_time.ToInternalValue());
#if defined(OS_WIN)
      net::GetMimeTypeFromExtension(L"db", &content_type);
#else
      net::GetMimeTypeFromExtension("db", &content_type);
#endif      
      inode->set_content_type(content_type.empty() ? "application/octet-stream" : content_type);
      //inode->set_type(storage_proto::INODE_DATABASE);
      //  offset++;
      //}

      // When a torrent is created from a manifest, it shoud not merge/ be modified
      // as the data is already there, before local storage creation on the torrent
      // (via Torrent constructor that receives a storage_proto::Info protobuf metadata)
      if (!torrent->metadata_loaded()) {
        torrent->MergeInfo(header);
      }

      // write it
      if (!torrent->SerializeInfoToString(&context->encoded_header)) {
        //context->Exit(net::ERR_FAILED);
        LOG(ERROR) << "Error while encoding header for blob";
        context->Signal(-1);
        TerminateContext(context);
        return;
      }
  
      scoped_refptr<net::StringIOBuffer> header_data = new net::StringIOBuffer(context->encoded_header);

      CompletionCallback callback = base::Bind(&Storage::OnCreateTorrentWriteManifest, 
          weak_this_for_task_, 
          context, 
          context->encoded_header.size());

      context->header.bytes = torrent->WriteEntryData(//context->WriteEntryData(
        kDATA_MANIFEST,
        0,
        header_data.get(),
        context->encoded_header.size(),
        callback,
        false);

      if (context->header.bytes != net::ERR_IO_PENDING) {
        callback.Run(context->header.bytes);
      }
    }
  } else {
    context->read.bytes = result;
    context->Signal(-1);
    TerminateContext(context);
  }
}

int Storage::AddIndexOnTree(scoped_refptr<StorageContext> context) {
  //DLOG(INFO) << "Storage::AddIndexOnTree: " << context->torrent->id().to_string();
  if (being_cloned()) {
    //DLOG(INFO) << "Storage::AddIndexOnTree: being cloned returning OK instead of PENDING";
    return net::OK;
  }

  base::PostTaskWithTraits(
    FROM_HERE,
    { base::MayBlock(),
      base::WithBaseSyncPrimitives() },
    base::BindOnce(&Storage::AddIndexOnTreeOnDbThread, 
      //weak_this_, 
      base::Unretained(this),
      //weak_this_for_task_,
      context)
  );

  // backend_task_runner_->PostTask(
  //   FROM_HERE,
  //   base::BindOnce(&Storage::AddIndexOnTreeOnDbThread, 
  //     // FIXME
  //     base::Unretained(this),//weak_this_, 
  //     context));

  return net::ERR_IO_PENDING;
}

void Storage::AddIndexOnTreeOnDbThread(scoped_refptr<StorageContext> context) {
  //DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread: " << context->torrent->id().to_string();
  scoped_refptr<Torrent> torrent = context->torrent;
  DCHECK(torrent);
  std::string uuid_str = context->key.to_string();
  DCHECK(root_tree_);
  if (!root_tree_->db_is_open()) {
    Database::Open(root_tree_, true);
  }
  Transaction* tr = root_tree_->db().Begin(true);
  bool result = root_tree_->db().Put(tr, "inodes", base::StringPiece(uuid_str), context->encoded_header);
  if (result) {
    //DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread: " << context->torrent->id().to_string() << " db.put('inodes') = ok";
    result = root_tree_->db().Put(tr, "index", torrent->info().path(), base::StringPiece(uuid_str));
    if (result) {
      //DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread: " << context->torrent->id().to_string() << " db.put('index') = ok";
      name_index_lock_.Acquire();
      name_index_.emplace(std::make_pair(torrent->info().path(), context->key));
      name_index_lock_.Release();
    }
  }
  result ? tr->Commit() : tr->Rollback();
  //root_tree_->db().Close();

  // init(adding blobs) entry also adds a index, but have a different exit path
  // as it is async (unlike db ops where its already inside the consumer db task runner)
  if (context->op == StorageContext::kADD_ENTRY) {
    //DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread: StorageContext::kADD_ENTRY = true. caling next callback";
    context->task_runner->PostTask(  
      FROM_HERE,
      base::BindOnce(
        std::move(context->next_callback),
        result ? net::OK : net::ERR_FAILED)
    );
  } else if (context->op == StorageContext::kADD_INDEX) {
    //DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread: StorageContext::kADD_INDEX = true. caling exit callback";
    context->task_runner->PostTask(  
      FROM_HERE,
      base::BindOnce(
        std::move(context->exit_callback),
        result ? net::OK : net::ERR_FAILED));
  }
}

void Storage::OnCreateTorrentWriteManifest(scoped_refptr<StorageContext> context, int64_t expected, int64_t bytes_written) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //// //D//LOG(INFO) << "Storage::OnCreateBlobWriteManifest: " << context->key;
  int r = 0;
  if (bytes_written < 0) {
    DLOG(ERROR) << "Error while writing manifest for blob";
    r = -1;
  } else {
    if (context->parent) {
      context->parent->encoded_header = context->encoded_header;
    }
  }
  context->Signal(r);
  TerminateContext(context);
}

Future<int> Storage::OpenTorrent(scoped_refptr<Torrent> torrent) {
  // //D//LOG(INFO) << "Storage::OpenTorrent: key = " << torrent->id().to_string();
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kOPEN_TORRENT, torrent, CompletionCallback());
  bool sync = false;
  RunIO(context);
  return Future<int>(context->sync_event, sync);
}

void Storage::OpenTorrentImpl(scoped_refptr<StorageContext> context) {
  context->next_callback = base::Bind(&Storage::OnOpenTorrent, weak_this_for_task_, context);//GetWeakPtr(), context);
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // //D//LOG(INFO) << "Storage::OpenTorrentImpl: torrent = " << torrent->id().to_string();
  if (!torrent->is_open()) {
    int result = backend_->OpenEntry(
        torrent->id(),
        &torrent->entry_,
        context->next_callback);

    if (result != net::ERR_IO_PENDING) {
      context->next_callback.Run(result);
    }
  } else {
    // //D//LOG(INFO) << "Storage::OpenTorrentImpl: torrent " << torrent->id().to_string() << " already open. just moving forward";
    context->was_open = true;
    context->Signal(0);
    TerminateContext(context);
  }
}

void Storage::OnOpenTorrent(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //D//LOG(INFO) << "Storage::OnOpenTorrent: key = " << torrent->id().to_string() << " r = " << result;
  if (result == 0) {    
    int64_t size = torrent->GetEntryDataSize(kDATA_MANIFEST);

    CompletionCallback callback = base::Bind(&Storage::OnOpenTorrentReadManifest, 
      weak_this_for_task_, 
      context, 
      size);
      
    if (context->is_journal) {
      context->Signal(0);
      TerminateContext(context);
    } else {
      // only read the manifest if its not already cached
      context->header_data = new net::IOBufferWithSize((size_t)size);
      context->header.bytes = torrent->ReadEntryData(
        kDATA_MANIFEST,
        0,
        context->header_data.get(),
        size,
        callback);
      if (context->header.bytes != net::ERR_IO_PENDING) {
        callback.Run(context->header.bytes);
      }
    }
  } else {
    context->read.bytes = result;
    context->Signal(-1);
    TerminateContext(context);
  }
}

void Storage::OnOpenTorrentReadManifest(scoped_refptr<StorageContext> context, int64_t expected, int64_t bytes) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // //D//LOG(INFO) << "Storage::OnOpenTorrentReadManifest: " << torrent->id().to_string() << " expected: " << expected << " readed: " << bytes;
  
  if (bytes < 0) {
    LOG(ERROR) << "Error while reading manifest for blob";
    context->Signal(-1);
    TerminateContext(context);
    return;
  }
  if (!torrent->LoadInfoFromBytes(context->header_data->data(), bytes)) {
    LOG(ERROR) << "Error while reading header for blob";
    context->Signal(-1);
    TerminateContext(context);
    return;
  }

  // printf("recovered info\n%s\n  path: %s\n  comment: %s\n  root hash: %s\n  piece_length: %ld\n  piece_count: %ld\n  length: %ld\n  inodes: %d\n", 
  //     torrent->id().to_string().c_str(),
  //     torrent->info().path().c_str(),
  //     torrent->info().comment().c_str(),
  //     base::HexEncode(torrent->info().root_hash().data(), torrent->info().root_hash().size()).c_str(),
  //     torrent->info().piece_length(),
  //     torrent->info().piece_count(),
  //     torrent->info().length(),
  //     torrent->info().inodes().size());
  
  int64_t size = torrent->GetEntryDataSize(kDATA_MERKLE);
  CompletionCallback callback = base::Bind(
      &Storage::OnOpenTorrentReadMerkle, 
      weak_this_for_task_, 
      context, 
      size);
  context->hash_buffer = new net::IOBufferWithSize((size_t)size);
  context->header.bytes = torrent->ReadEntryData(
    kDATA_MERKLE,
    0,
    context->hash_buffer.get(),
    size,
    callback);

  if (context->header.bytes != net::ERR_IO_PENDING) {
    callback.Run(context->header.bytes);
  }
}

void Storage::OnOpenTorrentReadMerkle(scoped_refptr<StorageContext> context, int64_t expected, int64_t bytes) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //DLOG(INFO) << "Storage::OnOpenTorrentReadMerkle: " << torrent->id().to_string() << " expected: " << expected << " readed: " << bytes;
  
  if (bytes <= 0) {
   LOG(ERROR) << "OnOpenBlobReadMerkle error: failed while reading hash metadata from " << torrent->id().to_string() << " bytes = " <<  bytes;
   context->Signal(bytes);
   TerminateContext(context);
   return;
  }
  // theres no way the entry is not on the list at this point
  // so this should be safe, unless theres a big mistake somewhere else
  
  storage_proto::EntryMerkleHeader merkle_header;
  int64_t blob_size = (size_t)torrent->GetEntryDataSize(kDATA_CONTENT);
  //int64_t merkle_hash_size = blob_size > 0 ? MerkleTree::GetTreeLength(blob_size) * kDefaultHashSize : 0;
  //int64_t header_size = bytes - merkle_hash_size;
  uint64_t header_size = 0; 
  char* header_buffer = context->hash_buffer->data();
  // read the header size and jump the buffer offset pointing to the header payload
  header_buffer += csqliteGetVarint(reinterpret_cast<unsigned char *>(header_buffer), (u64*)&header_size);
  if (!merkle_header.ParseFromArray(header_buffer, header_size)) {
    LOG(ERROR) << "OnOpenBlobReadMerkle error: decoding protobuf merkle tree metadata with header size = " << header_size << " total size = " << bytes << " failed";
    context->Signal(-1);
    TerminateContext(context);
    return;
  }
  int header_content_size = merkle_header.content_size();
  //char* ptr = context->hash_buffer->data(); 
  // jump the section of the payload with the header on it
  header_buffer += header_size;

  const auto& merkle_tree_header = merkle_header.node(0);
  std::unique_ptr<MerkleTree> merkle_tree = MerkleTree::Load(header_buffer, blob_size);
    
  //printf("open (%s): adding recovered merkle tree: hash size = %zu blob size = %ld leaf_count = %zu\n", context->key.to_string().c_str(), bytes, blob_size, merkle_tree->leaf_count());
  //merkle_tree->Print();
  //merkle_tree_list_.emplace(std::make_pair(context->key, std::move(merkle_tree)));
  torrent->set_merkle_tree(std::move(merkle_tree));
  
  // 27-11-2020: ADDED HERE
  torrent->OnMetadataDone();

  context->Signal(0);
  TerminateContext(context);
}

Future<int> Storage::CloseTorrent(scoped_refptr<Torrent> torrent, bool is_journal, int jrn_seq) {
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCLOSE_TORRENT, torrent, CompletionCallback());
  context->is_journal = is_journal;
  context->jrn_seq = jrn_seq;
  context->should_close = true;
  bool sync = false;
  if (!is_journal && !torrent->is_open()) {
    context->Signal(net::OK);
    TerminateContext(context);
    return Future<int>(context->sync_event, true);
  }
  RunIO(context);
  return Future<int>(context->sync_event, sync);
}

// void Storage::UpdateTorrentMetadataImpl(scoped_refptr<StorageContext> context) {
//   const scoped_refptr<Torrent>& torrent = context->torrent;
//   //D//LOG(INFO) << "Storage::UpdateTorrentMetadataImpl: " << torrent->id().to_string() << " journal? " << context->is_journal;

//   /*
//    * The idea here is to use the Close of the database journal file
//    * as a trigger to update the merkle tree of the main database file
//    * and already save it in the merkle header section of the entry
//    * 
//    * As the journal are only closed after it wrote the pages to the 
//    * db file, we can have a safe partial merkle tree here
//    *
//    * Before this trick, we could only have a saved partial merkle tree of the 
//    * db, on the event of closing the main db file
//    *
//    * Note: The merkle were being updated at every write, but we were only consolidating
//    * it in the header on main db close
//    *
//    * Note 2: We use the "is_journal" flag to know when this operation
//    * are being done on the main file, but on behalf of the journal file
//    * so we dont acidentally close the main file and erase the merkle tree from the cache
//    * while we are still using the main db file
//    */
//   if (context->is_journal) {
//     torrent->CloseJournal(context->jrn_seq);
//   }

//   bool merkle_tree_changed = false;
//   MerkleTree* merkle_tree = torrent->merkle_tree();
//   if (merkle_tree && merkle_tree->is_dirty()) {
//     // if the digest buffer had to grow, it means there was no fixed initial size
//     // so theres a need to recalculate the parent nodes of the merkle tree
//     // and thats a thing 'Rebuild()' is prepared for
//     // while 'Build()' is meant for when we know the full size when we create the merkle tree
//     // so is just a matter of zero the leafs that left, and calculate the parents
//     if (torrent->EntryIsNew()) {
//       ////D//LOG(INFO) << "UpdateTorrentMetadataImpl: calling merkle tree Build()";
//       merkle_tree->Build();
//     } else {
//       ////D//LOG(INFO) << "UpdateTorrentMetadataImpl: calling merkle tree Rebuild()";
//       merkle_tree->Rebuild();
//     }
//     WriteTorrentMerkleImpl(context);
//   } else {
//     if (!context->is_journal && context->should_close && torrent->is_open()) {
//       ////LOG(INFO) << "not a journal file, no change on data and is open. just closing..";
//       torrent->CloseEntry();
//       torrent->opened_ = false;
//     }
//     context->Signal(net::OK);
//     TerminateContext(context);
//   }
//   //// //D//LOG(INFO) << "Storage::CloseBlobImpl end";
// }

void Storage::UpdateTorrentMetadataImpl(scoped_refptr<StorageContext> context) {
  const scoped_refptr<Torrent>& torrent = context->torrent;

  /*
   * The idea here is to use the Close of the database journal file
   * as a trigger to update the merkle tree of the main database file
   * and already save it in the merkle header section of the entry
   * 
   * As the journal are only closed after it wrote the pages to the 
   * db file, we can have a safe partial merkle tree here
   *
   * Before this trick, we could only have a saved partial merkle tree of the 
   * db, on the event of closing the main db file
   *
   * Note: The merkle were being updated at every write, but we were only consolidating
   * it in the header on main db close
   *
   * Note 2: We use the "is_journal" flag to know when this operation
   * are being done on the main file, but on behalf of the journal file
   * so we dont acidentally close the main file and erase the merkle tree from the cache
   * while we are still using the main db file
   */
  if (context->is_journal) {
    torrent->CloseJournal(context->jrn_seq);
  }

  if (!context->is_journal && context->should_close && torrent->is_open()) {
    torrent->CloseEntry();
    torrent->opened_ = false;
  }
  context->Signal(net::OK);
  TerminateContext(context);
}

Future<int> Storage::DeleteTorrent(scoped_refptr<Torrent> torrent, bool is_journal) {
  //// //D//LOG(INFO) << "Storage::DeleteBlob: " << key;
  // //D//LOG(INFO) << "Storage::DeleteTorrent: " << torrent->id().to_string() << " journal? " << is_journal;
  bool sync = false;
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kDELETE_TORRENT, torrent, CompletionCallback());
  context->is_journal = is_journal;
  RunIO(context);
  return Future<int>(context->sync_event, sync);
}

void Storage::DeleteTorrentImpl(scoped_refptr<StorageContext> context) {
  context->BindNext(&Storage::OnDeleteTorrent, weak_this_for_task_);
  int rc = net::ERR_FAILED;
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // //D//LOG(INFO) << "Storage::DeleteTorrentImpl: " << torrent->id().to_string() << " journal? " << context->is_journal;
  if (context->is_journal) {
    std::pair<std::string, StorageEntry*> entry = torrent->PopJournalFromDeleteList();
    // //D//LOG(INFO) << "Storage::DeleteTorrentImpl: deleting '" << entry.first << "'";
    rc = backend_->DoomEntry(entry.first, context->next_callback); 
  } else { 
    // //D//LOG(INFO) << "Storage::DeleteTorrentImpl: deleting '" << torrent->id().to_string() << "'";
    rc = backend_->DoomEntry(torrent->id(), context->next_callback);
  }
  
  if (rc != net::ERR_IO_PENDING) {
    context->next_callback.Run(rc);
  }
}

void Storage::OnDeleteTorrent(scoped_refptr<StorageContext> context, int64_t result) {
  //LOG(ERROR) << "Storage::OnDeleteTorrent: r = " << result;
  const scoped_refptr<Torrent>& torrent = context->torrent;
  if (result != 0) {
     LOG(ERROR) << "Storage::OnDeleteTorrent: failed deleting torrent for entry = " << context->key.to_string();
  }
  context->Signal(result);
  TerminateContext(context);
}

Future<int> Storage::SyncTorrent(scoped_refptr<Torrent> torrent) {
  if (torrent->is_syncing()) {
    ////DLOG(INFO) << "Storage::SyncTorrent: " << torrent->id().to_string() << " alredy syncing. cancelling..";
    return Future<int>(0); 
  }
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kSYNC_TORRENT, torrent, CompletionCallback());
  context->torrent->BeginSync();
  RunIO(context);
  return Future<int>(context->sync_event, true);
}

void Storage::SyncTorrentImpl(scoped_refptr<StorageContext> context) {
  //DLOG(INFO) << "Storage::SyncTorrentImpl: updating metadata first, before real sync. " << context->torrent->id().to_string();
  //context->torrent->EntrySync(base::Bind(&Storage::OnSyncTorrent, base::Unretained(this), context));
  //context->torrent->entry_->Release();
  //UpdateTorrentMetadataImpl(context);  
  MerkleTree* merkle_tree = context->torrent->merkle_tree();
  //D//LOG(INFO) << "Storage::SyncTorrentImpl: merkle_tree: " << merkle_tree;
  if (merkle_tree && context->torrent->EntryIsModified()) {//&& merkle_tree->is_dirty()) {
    //D//LOG(INFO) << "Storage::SyncTorrentImpl: merkle_tree: " << merkle_tree << " merkle_tree->is_dirty() = true";
    // if the digest buffer had to grow, it means there was no fixed initial size
    // so theres a need to recalculate the parent nodes of the merkle tree
    // and thats a thing 'Rebuild()' is prepared for
    // while 'Build()' is meant for when we know the full size when we create the merkle tree
    // so is just a matter of zero the leafs that left, and calculate the parents
    if (context->torrent->EntryIsNew()) {
      //DLOG(INFO) << "Storage::SyncTorrentImpl: merkle tree for " << context->torrent->id().to_string() << " is null. caalling Build()";
      merkle_tree->Build();
      // not suppose to work like this but for now i think it will do the trick
      // TODO: we actually dont need to depend of a flag from a external entity..
      //       its better if we let the merkle tree itself decide about this
      //       we should just call a build, and then internally the merkle tree
      //       decides if its the first time, or if its an update
      context->torrent->EntrySetIsNew(false);
    } else {
      merkle_tree->Rebuild();
    }
    WriteTorrentMerkleImpl(context);
  } else {
    SyncTorrentAfterMetadataSync(context, net::OK);
  }
}

void Storage::SyncTorrentAfterMetadataSync(scoped_refptr<StorageContext> context, int64_t r) {
  //DLOG(INFO) << "Storage::SyncTorrentAfterMetadataSync: " << context->torrent->id().to_string();
  //context->torrent->entry_->Close(
  //  base::Bind(&Storage::OnSyncClose,
  //    base::Unretained(this),
  //    context));
  context->torrent->EntrySync(
    base::Bind(&Storage::OnSyncTorrent, 
      weak_this_for_task_, 
      context));
}

// void Storage::OnSyncTorrent(scoped_refptr<StorageContext> context, int64_t r) {
//   //D//LOG(INFO) << "Storage::OnSyncTorrent: syncing result = " << r;
//   backend_task_runner_->PostTask(
//     FROM_HERE, 
//     base::BindOnce(&Storage::SyncOpenEntry, 
//       base::Unretained(this), 
//       context));  
// }

// void Storage::SyncOpenEntry(scoped_refptr<StorageContext> context) {
//   context->torrent->entry_ = nullptr;
//   //D//LOG(INFO) << "Storage::SyncOpenEntry: reopening entry";
//   scoped_refptr<StorageEntry> entry;
//   int result = backend_->SyncOpenEntry(context->torrent->id().to_string(), &entry);
//   if (result == net::OK) {
//     entry->OnEntryCreated(backend_.get());
//     context->torrent->entry_ = LeakStorageEntry(std::move(entry));
//   }
  
//   //D//LOG(INFO) << "Storage::SyncOpenEntry: done. result = " << result;  
//   OnSyncTorrent(context, net::OK);
// }

void Storage::OnSyncTorrent(scoped_refptr<StorageContext> context, int64_t result) {
  //DLOG(INFO) << "Storage::OnSyncTorrent: " << context->torrent->id().to_string();
  
  // the entry is not 'dirty' anymore. flag it
  context->torrent->EntrySetModified(false);
  context->torrent->OnMetadataDone();
  context->torrent->EndSync();
  // theres a workflow that we use SyncImpl internally
  // instead of a Sync op called from a external actor
  // so we need to call the parent op callback before
  // removing the context
  context->Signal(result);
  TerminateContext(context);
}

void Storage::OnWriteTorrentMerkle(scoped_refptr<StorageContext> context, int64_t expected, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //LOG(INFO) << "Storage::OnWriteTorrentMerkle: " << torrent->id().to_string() << " expected: " << expected << " wrote: " << result;
  MerkleTree* merkle_tree = torrent->merkle_tree();//merkle_tree_list_.find(context->key)->second.get();
  if (torrent && (torrent->EntryIsModified() || torrent->EntryIsNew()) ) {
    //LOG(INFO) << "Storage::OnWriteTorrentMerkle: " << torrent->id().to_string() << " set_piece_count: " << merkle_tree->block_count();
    int64_t data_size = torrent->GetEntryDataSize(kDATA_CONTENT);
    int piece_count = (data_size + kBlockSize - 1) / kBlockSize;
    torrent->mutable_info()->set_root_hash(merkle_tree->root_hash());
    torrent->mutable_info()->set_piece_count(piece_count);
    torrent->mutable_info()->set_length(data_size);
    torrent->mutable_info()->set_state(storage_proto::STATE_FINISHED);

    // OnWriteBlobMerkle are used only for databases..
    // so i think is safe to reset the file to have the same lenght
    // as the whole entry.
    // For blobs, we can have one-to-many relationships
    // so this would be not right in that case
    for (int i = 0; i < torrent->info().inodes_size(); i++) {
      //DLOG(INFO) << "processing inode " << i;
      auto* inode = torrent->mutable_info()->mutable_inodes(i);
      DCHECK(inode);
      //DLOG(INFO) << "processing inode " << i << " name => " << inode->name();
      inode->set_root_hash(merkle_tree->root_hash());
      if (inode->length() == 0 && torrent->is_data()) {
        inode->set_length(torrent->GetEntryDataSize(kDATA_CONTENT));
      }
    }
    
    if (torrent->entity()) {
      ////LOG(INFO) << "Storage::OnWriteBlobMerkle: io entity for " << context->key.to_string() << " found = " << torrent->entity();
      torrent->entity()->OnInfoHeaderChanged(torrent->info());
    } else {
      ////LOG(INFO) << "Storage::OnWriteBlobMerkle: io entity for " << context->key.to_string() << " is null";
    }

    if (!torrent->SerializeInfoToString(&context->encoded_header)) {
      //context->Exit(net::ERR_FAILED);
      LOG(ERROR) << "Error while encoding header for blob";
      context->Signal(-1);
      TerminateContext(context);
      return;
    }

    // if (!context->is_journal) {
    //   printf("WriteTorrentMerkle: %s\n  path: %s\n  comment: %s\n  root hash: %s\n  piece_length: %ld\n  piece_count: %ld\n  length: %ld\n  inodes: %d\n", 
    //     torrent->id().to_string().c_str(),
    //     torrent->info().path().c_str(),
    //     torrent->info().comment().c_str(),
    //     base::HexEncode(torrent->info().root_hash().data(), torrent->info().root_hash().size()).c_str(),
    //     torrent->info().piece_length(),
    //     torrent->info().piece_count(),
    //     torrent->info().length(),
    //     torrent->info().inodes().size());
    // }
    
    CompletionCallback callback = base::Bind(&Storage::OnWriteTorrentHeaderResult, weak_this_for_task_, context, context->encoded_header.size());

    scoped_refptr<net::StringIOBuffer> header_data = new net::StringIOBuffer(context->encoded_header);
    
    //LOG(INFO) << "Storage::OnWriteTorrentMerkle: " << torrent->id().to_string() << ". writing entry kDATA_MANIFEST";
    context->header.bytes = torrent->WriteEntryData(
        kDATA_MANIFEST, 
        0,
        header_data.get(),
        context->encoded_header.size(),
        callback,
        false);
      
    if (context->header.bytes != net::ERR_IO_PENDING) {
      callback.Run(context->header.bytes);
    }
  } else {
    OnWriteTorrentHeaderResult(context, 0, 0);
  }
}

void Storage::OnWriteTorrentHeaderResult(scoped_refptr<StorageContext> context, int64_t expected, int64_t result) {
  //auto merkle_it = merkle_tree_list_.find(context->key);
  //auto entry_it = entries_.find(context->key);
  const scoped_refptr<Torrent>& torrent = context->torrent;
  ////LOG(INFO) << "Storage::OnWriteTorrentHeaderResult: " << torrent->id().to_string() << " journal? " << context->is_journal << " expected: " << expected << " wrote: " << result;
  if (!context->is_journal && context->should_close) {
    ////LOG(INFO) << "Storage::OnWriteTorrentHeaderResult: not journal. so closing " << torrent->id().to_string() << "...";
    torrent->CloseEntry();
    torrent->entry_ = nullptr;
    torrent->opened_ = false;
  }
  
  // torrent->OnMetadataDone();
  if (context->op == StorageContext::kSYNC_TORRENT) {
    context->BindNext(&Storage::SyncTorrentAfterMetadataSync, weak_this_for_task_);
    context->Next(net::OK);
  } else {
    // unblock the db thread on Close
    torrent->OnMetadataDone();
    context->Signal(0);
    context->BindNext(&Storage::OnWriteTorrentIndex, weak_this_for_task_);
    context->Next(net::OK);
  }
}

void Storage::OnWriteTorrentIndex(scoped_refptr<StorageContext> context, int64_t result) {
  // //D//LOG(INFO) << "Storage::OnWriteTorrentIndex: result " << result;
  TerminateContext(context);
}


void Storage::OnWriteTorrent(scoped_refptr<StorageContext> context, int64_t expected, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  ////DLOG(INFO) << "Storage::OnWriteTorrent: " << torrent->id().to_string() << " result " << result;

  if (expected == result && !context->is_journal) {
    // if is the first time of a write after a sync.. flag it as dirty
    if (!torrent->EntryIsModified()) {
      torrent->EntrySetModified(true);
    }
  }
  context->write.bytes = result;
  context->Signal(0);
  TerminateContext(context);
}

void Storage::OnCreateDatabase(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // //D//LOG(INFO) << "Storage::OnCreateDatabase: " << torrent->id().to_string() << " r = " << result;
  if (result == net::OK) {
    // in case of databases, we add it to the persistent cache
    //entries_.emplace(std::make_pair(context->key, std::make_unique<Storage::Inode>(context->ptr)));
    DCHECK(torrent);

    context->BindNext(&Storage::OnCreateDatabaseWriteManifest, weak_this_for_task_);
    
    base::Time creation_time = base::Time::Now();

    std::string content_type;
  
    // form the header
    storage_proto::Info header;
    header.set_kind(context->create_db_params.type);
    header.set_state(storage_proto::STATE_FINISHED);
    header.set_id(torrent->id().string());
    header.set_comment(torrent->info().path()  + " database");
    header.set_creation_date(creation_time.ToInternalValue());
    header.set_mtime(creation_time.ToInternalValue());
    header.set_readonly(false);
    
    //std::string table_id = base32::Base32Encode("hello_table", base32::Base32EncodePolicy::OMIT_PADDING);;

    const std::vector<std::string>& keyspaces = context->create_db_params.keyspaces;
    // FIXME: what about the sql tables => create_table_stmts
    //const std::vector<std::string>& statements = context->create_db_params.create_table_stmts;
    //header.set_inode_count(keyspaces.size());
    // one for each keyspace in the database
    // as we start with at least one
    int offset = 0;
    for (auto it = keyspaces.begin(); it != keyspaces.end(); ++it) {
      auto* inode = header.add_inodes();
      inode->set_name(*it);
      inode->set_offset(offset + 1);
      inode->set_path(torrent->info().path() + "/" + *it);
      inode->set_creation_date(creation_time.ToInternalValue());
      inode->set_mtime(creation_time.ToInternalValue());
#if defined(OS_WIN)
      net::GetMimeTypeFromExtension(L"db", &content_type);
#else
      net::GetMimeTypeFromExtension("db", &content_type);
#endif
      inode->set_content_type(content_type.empty() ? "application/octet-stream" : content_type);
      offset++;
    }
    for (auto it = keyspaces.begin(); it != keyspaces.end(); ++it) {
      auto* inode = header.add_inodes();
      inode->set_name(*it);
      inode->set_offset(offset + 1);
      inode->set_path(torrent->info().path() + "/" + *it);
      inode->set_creation_date(creation_time.ToInternalValue());
      inode->set_mtime(creation_time.ToInternalValue());
#if defined(OS_WIN)
      net::GetMimeTypeFromExtension(L"db", &content_type);
#else
      net::GetMimeTypeFromExtension("db", &content_type);
#endif
      inode->set_content_type(content_type.empty() ? "application/octet-stream" : content_type);
      offset++;
    }

    torrent->MergeInfo(header);

    // write it
    std::string encoded_header;
    if (!torrent->SerializeInfoToString(&encoded_header)) {
      CompletionCallback callback;
      TerminateContext(context, &callback);
      if (!callback.is_null()) {
        callback.Run(net::ERR_FAILED);
      }
      return;
    }

    scoped_refptr<net::StringIOBuffer> header_data = new net::StringIOBuffer(encoded_header);
    
    context->header.bytes = torrent->WriteEntryData(
      kDATA_MANIFEST,
      0,
      header_data.get(),
      encoded_header.size(),
      context->next_callback,
      false);

    if (context->header.bytes != net::ERR_IO_PENDING) {
      context->Next(context->header.bytes);
    }
  } else {
    CompletionCallback callback;
    TerminateContext(context, &callback);
    if (!callback.is_null()) {
      callback.Run(result);
    }
  }
}

void Storage::OnOpenDatabase(scoped_refptr<StorageContext> context, int64_t result) {
  //// //D//LOG(INFO) << "Storage::OnOpenDatabase: " << context->key << " r = " << result;
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // //D//LOG(INFO) << "Storage::OnOpenDatabase: " << torrent->id().to_string() << " r = " << result;
  if (result == net::OK) {
    // in case of databases, we add it to the persistent cache
    //entries_.emplace(std::make_pair(context->key, std::make_unique<Storage::Inode>(context->ptr)));
    DCHECK(torrent);
    context->BindNext(&Storage::OnOpenDatabaseReadManifest, weak_this_for_task_);

    context->header_data = new net::IOBufferWithSize(1024 * 16);
    context->header.bytes = torrent->ReadEntryData(//context->ReadEntryData(
      kDATA_MANIFEST,
      context->header.offset,
      context->header_data.get(),
      context->header_data->size(),
      context->next_callback);

    if (context->header.bytes != net::ERR_IO_PENDING) {
      context->Next(context->header.bytes);
    }
  } else {
    context->Exit(result);
  }
}

void Storage::OnOpenDatabaseReadManifest(scoped_refptr<StorageContext> context, int64_t bytes_readed) {
 const scoped_refptr<Torrent>& torrent = context->torrent;

  // //D//LOG(INFO) << "Storage::OnOpenDatabaseReadManifest: " << torrent->id().to_string() << " r = " << bytes_readed;
  
  if (bytes_readed > 0) {
    DCHECK(torrent);
    if (!torrent->LoadInfoFromBytes(context->header_data->data(), bytes_readed)) {
      DLOG(ERROR) << "error parsing db entry manifest";
      context->Exit(net::ERR_FAILED);
      return;
    }
    context->Exit(net::OK);
  } else {
    context->Exit(bytes_readed);
  }
}

void Storage::OnCreateDatabaseWriteManifest(scoped_refptr<StorageContext> context, int64_t bytes_written) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  
  // //D//LOG(INFO) << "Storage::OnCreateDatabaseWriteManifest: " << torrent->id().to_string() << " r = " << bytes_written;
  
  DCHECK(torrent);
  CompletionCallback callback;
  TerminateContext(context, &callback);
  if (!callback.is_null()) {
    callback.Run(bytes_written);
  }
  
}

void Storage::OnGetEntryInfo(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;

  context->BindNext(&Storage::DecodeEntryInfo, weak_this_for_task_);
  
  context->header_data = new net::IOBufferWithSize(1024 * 32);

  context->header.bytes = torrent->ReadEntryData(
    kDATA_MANIFEST, // slot offset
    0, // byte offset
    context->header_data.get(),
    context->header_data->size(),
    context->next_callback);

  if (context->header.bytes != net::ERR_IO_PENDING) {
    context->Next(context->header.bytes);
  }
}

void Storage::DecodeEntryInfo(scoped_refptr<StorageContext> context, int64_t result) {
  storage_proto::Info empty_info;
  if (result < 0) {
    context->Exit(std::move(empty_info), net::ERR_FAILED);
    return;
  }
  
  if (!context->info.ParseFromArray(context->header_data->data(), result)) {
    DLOG(ERROR) << "error parsing entry manifest";
    context->Exit(std::move(empty_info), net::ERR_FAILED);
    return;
  }

  context->Exit(std::move(context->info), net::OK);
}


void Storage::ReplyAddIndex(scoped_refptr<StorageContext> context, CompletionCallback user_callback, int64_t result) {
  main_task_runner_->PostTask(FROM_HERE, base::Bind(user_callback, result));
}

void Storage::ReplyCopyFile(scoped_refptr<StorageContext> context, CompletionCallback user_callback, int64_t result) {
  //base::HexEncode(context->computed_hash->data(), context->computed_hash->size());
  main_task_runner_->PostTask(FROM_HERE, base::Bind(user_callback, result));
}

void Storage::ReplyCopyEntry(scoped_refptr<StorageContext> context, CompletionCallback user_callback, int64_t result) {
  //base::HexEncode(context->computed_hash->data(), 
  //                context->computed_hash->size());
  
  main_task_runner_->PostTask(FROM_HERE, base::Bind(user_callback, result));
}

void Storage::ReplyCopyEntryFile(scoped_refptr<StorageContext> context, CompletionCallback user_callback, int64_t result) {
  main_task_runner_->PostTask(FROM_HERE, base::Bind(user_callback, result));
}

void Storage::ReplyReadEntryFileWithBuffer(scoped_refptr<StorageContext> context, base::Callback<void(int64_t, mojo::ScopedSharedBufferHandle, int64_t)> user_callback, int64_t file_size, mojo::ScopedSharedBufferHandle file_data, int64_t result) {
  //DLOG(INFO) << "\n\nStorage::ReplyReadEntryFileWithBuffer";
  main_task_runner_->PostTask(FROM_HERE, base::Bind(user_callback, file_size, base::Passed(std::move(file_data)), result));
}

void Storage::ReplyWriteEntryFile(
    scoped_refptr<StorageContext> context, 
    base::Callback<void(int64_t)> user_callback, 
    int64_t result) {
  main_task_runner_->PostTask(FROM_HERE, base::Bind(user_callback, result)); 
}

void Storage::ReplyGetEntryInfo(
    scoped_refptr<StorageContext> context,
    base::Callback<void(storage_proto::Info, int64_t)> callback,
    storage_proto::Info header,
    int64_t result) {

  main_task_runner_->PostTask(FROM_HERE, base::Bind(callback, std::move(header), result));
}

void Storage::ReplyAddEntry(scoped_refptr<StorageContext> context, CompletionCallback user_callback, int64_t result) {
  //DLOG(INFO) << "Storage::ReplyAddEntry: " << context->torrent->id().to_string() << " r = " << result;
  main_task_runner_->PostTask(FROM_HERE, base::Bind(user_callback, result == -2 ? result : net::OK));
}

//void Storage::ReplyQuery(
//  scoped_refptr<StorageContext> context, 
//  base::Callback<void(std::unique_ptr<Block>, int64_t)> callback,
//  std::unique_ptr<Block> block,
//  int64_t result) {

//  main_task_runner_->PostTask(FROM_HERE, base::Bind(callback, base::Passed(std::move(block)), result));
//  TerminateContext(context);
//}

void Storage::ReplyOpenDatabase(
    base::Callback<void(int64_t)> callback,
    int64_t result) {
  if (!callback.is_null()) {
    main_task_runner_->PostTask(
    FROM_HERE,
    base::Bind(callback, result));
  } else {
    DLOG(ERROR) << "warning: ReplyOpenDatabase callback is null";
  }
}

void Storage::ReplyCreateDatabase(
    base::Callback<void(int64_t)> callback,
    int64_t result) {
  if (!callback.is_null()) {
    main_task_runner_->PostTask(
      FROM_HERE,
      base::Bind(callback, result));
  } else {
    DLOG(ERROR) << "warning: ReplyCreateDatabase callback is null";
  }
}

scoped_refptr<StorageContext> Storage::GetContext(int key) {
  contexts_lock_.Acquire();
  auto context_it = contexts_.find(key);
  if (context_it == contexts_.end()) {
    return nullptr;
  }
  scoped_refptr<StorageContext> result = context_it->second;
  contexts_lock_.Release(); 
  return result;
}

int Storage::GetContextId(StorageContext::Opcode code, const base::UUID& key) {
  int result = -1;
  contexts_lock_.Acquire();
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    const scoped_refptr<StorageContext>& current = it->second;
    if (current->op == code && current->key == key) {
      result = it->first;
      break;
    }
  }
  contexts_lock_.Release();
  return result;
}

scoped_refptr<StorageContext> Storage::GetContext(StorageContext::Opcode code, const base::UUID& key) {
  scoped_refptr<StorageContext> result;
  contexts_lock_.Acquire();
  for (auto it = contexts_.begin(); it != contexts_.end(); it++) {
    scoped_refptr<StorageContext> current = it->second;
    if (current->op == code && current->key == key) {
      result = current;
      break;
    }
  }
  contexts_lock_.Release();
  return result;
}

scoped_refptr<StorageContext> Storage::CreateContext(StorageContext::Opcode code, scoped_refptr<Torrent> torrent, base::Callback<void(int64_t)> cb) {
  scoped_refptr<StorageContext> context = new StorageContext(code, this);
  int id = context_id_gen_.GetNext() + 1;
  context->id = id;
  context->torrent = torrent;
  if (code == StorageContext::kCREATE_DATABASE || code == StorageContext::kOPEN_DATABASE) {
    //context->task_runner = db_task_runner_;
    // context->task_runner =
    //   base::CreateSingleThreadTaskRunnerWithTraits(
    //     { base::MayBlock(),
    //       base::WithBaseSyncPrimitives() },
    //     base::SingleThreadTaskRunnerThreadMode::DEDICATED);
    if (!db_task_runner_) {
      db_task_runner_ = base::CreateSingleThreadTaskRunnerWithTraits(
         { base::MayBlock(),
           base::WithBaseSyncPrimitives() },
         base::SingleThreadTaskRunnerThreadMode::DEDICATED);
    }
    context->task_runner = db_task_runner_;

    // context->task_runner = base::CreateSingleThreadTaskRunnerWithTraits(
    //      { base::MayBlock(),
    //        base::WithBaseSyncPrimitives() },
    //      base::SingleThreadTaskRunnerThreadMode::DEDICATED);
  } else {
    context->task_runner = frontend_task_runner_;
  }
  //context->original_task_runner = base::ThreadTaskRunnerHandle::Get();
  context->key = torrent->id();
  context->exit_callback = std::move(cb);
  contexts_lock_.Acquire();
  contexts_.emplace(id, context);
  contexts_lock_.Release();
  torrent->retain(context);

  return context;
}

scoped_refptr<StorageContext> Storage::CreateContext(StorageContext::Opcode code, base::Callback<void(int64_t)> cb) {
  scoped_refptr<StorageContext> context = new StorageContext(code, this);
  int id = context_id_gen_.GetNext() + 1;
  context->id = id;
  
  if (code == StorageContext::kCREATE_DATABASE || code == StorageContext::kOPEN_DATABASE) {
    // context->task_runner = db_task_runner_;
    //context->task_runner = backend_task_runner_;
    if (!db_task_runner_) {
      db_task_runner_ = base::CreateSingleThreadTaskRunnerWithTraits(
         { base::MayBlock(),
           base::WithBaseSyncPrimitives() },
         base::SingleThreadTaskRunnerThreadMode::DEDICATED);
    }
    context->task_runner = db_task_runner_;

    // context->task_runner = base::CreateSingleThreadTaskRunnerWithTraits(
    //      { base::MayBlock(),
    //        base::WithBaseSyncPrimitives() },
    //      base::SingleThreadTaskRunnerThreadMode::DEDICATED);

  //} else if (code == StorageContext::kSYNC_TORRENT) {
    //context->task_runner = backend_task_runner_;
    //context->task_runner = backend_->GetBackgroundQueue()->background_thread();
    //context->task_runner = frontend_task_runner_;
  //  context->task_runner = frontend_task_runner_;
  } else {
    context->task_runner = frontend_task_runner_;
  }
  //context->original_task_runner = base::ThreadTaskRunnerHandle::Get();
  context->exit_callback = std::move(cb);
  contexts_lock_.Acquire();
  contexts_.emplace(id, context);
  contexts_lock_.Release();

  return context;
}

void Storage::TerminateContext(scoped_refptr<StorageContext> context, CompletionCallback* user_callback) {
  contexts_lock_.Acquire();
  
  scoped_refptr<Torrent> torrent;
  if (context->torrent) {
    torrent = std::move(context->torrent);
  }

  auto context_it = contexts_.find(context->id);
  if (context_it == contexts_.end()) {
    DLOG(ERROR) << "TerminateContext: context for " << context->id << " not found.";
    return;
  }
 
  if (!context_it->second->exit_callback.is_null()) {
    *user_callback = std::move(context_it->second->exit_callback);
  }

  if (torrent) {
    torrent->release(context);
  }

  context_it->second->parent = nullptr;
  contexts_.erase(context_it);
  contexts_lock_.Release();
}

void Storage::ProcessScheduledIO() {
  for (auto it = scheduled_io_.begin(); it != scheduled_io_.end(); ++it) {
   //frontend_task_runner_->PostTask(
   it->first->task_runner->PostTask(
    FROM_HERE,
    std::move(it->second));
  }
  scheduled_io_.clear();
}

bool Storage::GetUUID(const std::string& name, base::UUID* id) {
  name_index_lock_.Acquire();
  auto it = name_index_.find(name);
  if (it != name_index_.end()) {
    *id = base::UUID(it->second.data);
    name_index_lock_.Release();
    return true;
  }
  bool ok = ResolveUUID(name, id);
  if (ok) {
    name_index_.emplace(std::make_pair(name, *id));
  }
  name_index_lock_.Release();
  return ok;
}

bool Storage::ResolveUUID(const std::string& name, base::UUID* out) {
  storage::Transaction* tr = root_tree_->db().Begin(false);
  auto cursor = tr->CreateCursor("index");
  DCHECK(cursor);
  base::StringPiece data_view;
  bool r = cursor->GetValue(name, &data_view);
  if (!r) {
    tr->Rollback();
    return false;
  }
  DCHECK(data_view.size());
  bool ok = false;
  *out = base::UUID::from_string(data_view.as_string(), &ok);
  if (!ok) {
    tr->Rollback();
    return false;
  }
  tr->Commit();
  return true;
}

bool Storage::HasUUID(const base::UUID& uuid) {
  bool found = false;
  std::string uuid_str = uuid.to_string();
  storage::Transaction* tr = root_tree_->db().Begin(false);
  auto cursor = tr->CreateCursor("index");
  if (!cursor) {
    return false;
  } 
  cursor->First();
  while (cursor->IsValid()) {
    KeyValuePair kv = cursor->GetKV();
    if (uuid_str == kv.second) {
      found = true;
      break;
    }
    cursor->Next();
  }
  tr->Commit();
  return found; 
}

bool Storage::HasEntryNamed(const std::string& name) {
  bool found = false;
  storage::Transaction* tr = root_tree_->db().Begin(false);
  auto cursor = tr->CreateCursor("index");
  if (!cursor) {
    return false;
  } 
  cursor->First();
  while (cursor->IsValid()) {
    KeyValuePair kv = cursor->GetKV();
    if (name == kv.first) {
      found = true;
      break;
    }
    cursor->Next();
  }
  tr->Commit();
  return found;
}

void Storage::RunIO(scoped_refptr<StorageContext> context) {
  base::OnceCallback<void()> to_run;
  switch (context->op) {
    case StorageContext::kCOPY_ENTRY: {
      to_run = base::BindOnce(&Storage::CopyEntryImpl, 
        weak_this_, 
        context);      
      break;
    }
    case StorageContext::kREAD_ENTRY_FILE: {
      to_run = base::BindOnce(&Storage::ReadEntryFileImpl, 
        weak_this_,
        context);
      break;
    }
    case StorageContext::kWRITE_ENTRY_FILE: {
      to_run = base::BindOnce(&Storage::ReadEntryFileImpl, 
        weak_this_,
        context);
      break;
    }
    case StorageContext::kADD_ENTRY: {
      to_run = base::BindOnce(&Storage::AddEntryImpl, 
        weak_this_,
        context);
      break;
    }
    case StorageContext::kADD_INDEX: {
      to_run = base::BindOnce(&Storage::AddIndexImpl, 
        weak_this_,
        context);
      break;
    }
    case StorageContext::kADD_ENTRY_EMPTY: {
      to_run = base::BindOnce(&Storage::AddEmptyEntry, 
        weak_this_,
        context);
      break;
    }
    case StorageContext::kCREATE_TORRENT: {
      to_run = base::BindOnce(&Storage::CreateTorrentImpl,
        weak_this_,
        context);
      break;
    }
    case StorageContext::kOPEN_TORRENT: {
      to_run = base::BindOnce(&Storage::OpenTorrentImpl, 
        weak_this_,
        context);
      break;
    }    
    case StorageContext::kREAD_TORRENT: {
      to_run = base::BindOnce(&Storage::ReadTorrentImpl,
        weak_this_,
        context);
      break;
    }
    case StorageContext::kWRITE_TORRENT: {
      to_run = base::BindOnce(&Storage::WriteTorrentImpl, 
        weak_this_,
        context);
      break;
    }
    case StorageContext::kCLOSE_TORRENT: {
      to_run = base::BindOnce(&Storage::UpdateTorrentMetadataImpl, 
        weak_this_,
        context);
      break;
    }
    case StorageContext::kDELETE_TORRENT: {
      to_run = base::BindOnce(&Storage::DeleteTorrentImpl, 
        weak_this_,
        context);
      break;
    }
    case StorageContext::kGET_ENTRY_INFO: {
      to_run = base::BindOnce(&Storage::GetEntryInfoImpl, 
        weak_this_,
        context);
      break;
    }
    case StorageContext::kSYNC_METADATA: {
      to_run = base::BindOnce(&Storage::UpdateTorrentMetadataImpl, 
        weak_this_,
        context);
      break;
    }
    case StorageContext::kOPEN_DATABASE: {
      to_run = base::BindOnce(&Storage::OpenDatabaseImpl, 
        //weak_this_, 
        // FIXME
        base::Unretained(this),
        context);
      break;
    }
    case StorageContext::kCREATE_DATABASE: {
      to_run = base::BindOnce(&Storage::CreateDatabaseImpl, 
        //weak_this_, 
        // FIXME
        base::Unretained(this),
        context);
      break;
    }
    case StorageContext::kSYNC_TORRENT: {
      to_run = base::BindOnce(&Storage::SyncTorrentImpl, 
        weak_this_, 
        context);
      break;
    }
    case StorageContext::kLIST_ENTRIES: // List entries is sync and returns a vector
    default:
     NOTREACHED();
  }
  DCHECK(!to_run.is_null());
  if (initialized_) {
    if (context->is_sync) {
      std::move(to_run).Run();
    } else {
      context->task_runner->PostTask(
        FROM_HERE,
        std::move(to_run));
    }
  } else {
    scheduled_io_.push_back(std::make_pair(std::move(context), std::move(to_run)));
  }
}

}
