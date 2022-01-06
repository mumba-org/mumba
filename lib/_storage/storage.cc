// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/storage.h"

#include "base/macros.h"
#include "base/logging.h"
#include "base/base64url.h"
#include "base/strings/stringprintf.h"
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
#include "storage/proto/storage.pb.h"
#include "storage/hash.h"
#include "storage/io_completion_callback.h"
#include "net/base/net_errors.h"
#include "net/base/io_buffer.h"
#include "net/base/mime_util.h"
#include "storage/backend/addr.h"
#include "storage/torrent.h"
#include "storage/torrent_cache.h"
#include "third_party/protobuf/src/google/protobuf/util/json_util.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"

namespace storage {

namespace {

constexpr size_t kBlockSize = 65536;
// the mininal number of blocks a sqlite database starts with
constexpr size_t kSqliteInitialBlocks = 2;

constexpr int kDefaultHashSize = SHA_DIGEST_LENGTH;

constexpr int kHEADER_VERSION_MAJOR = 0;
constexpr int kHEADER_VERSION_MINOR = 1;

void CleanupTrackerResult() {
  //// DLOG(INFO) << "BackendCleanupTracker::TryCreate callback called";
}

base::StringPiece FormatFilePath(base::StringPiece input) {
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

class DBOpenCloser {
public:
  DBOpenCloser(scoped_refptr<Torrent> torrent): torrent_(torrent) {
    //if (torrent_->db_policy() == Torrent::kOPEN_CLOSE && !torrent_->db_is_open()) {
    //  Database::Open(torrent_);
    //}
    if (!torrent_->db_is_open()) {
      Database::Open(torrent_);
    }
  }

  ~DBOpenCloser() {
    if (torrent_->db_policy() == Torrent::kOPEN_CLOSE && torrent_->db_is_open()) {
      torrent_->db().Close();
    }
  }

private:
  scoped_refptr<Torrent> torrent_;
  DISALLOW_COPY_AND_ASSIGN(DBOpenCloser);
};

class DBCreateCloser {
public:
  DBCreateCloser(scoped_refptr<Torrent> torrent, std::vector<std::string> keyspaces = std::vector<std::string>()): torrent_(torrent) {
    Database::Create(torrent, std::move(keyspaces));
    //if (torrent_->db_policy() == Torrent::kOPEN_CLOSE) {}
  }

  ~DBCreateCloser() {
    if (torrent_->db_policy() == Torrent::kOPEN_CLOSE && torrent_->db_is_open()) {
      DLOG(INFO) << "closing " << torrent_->id().to_string();
      torrent_->db().Close();
    }
  }

private:
  scoped_refptr<Torrent> torrent_;
  DISALLOW_COPY_AND_ASSIGN(DBCreateCloser);
};

}

IOBufferWrapper::IOBufferWrapper(void* data, int64_t size)
    : IOBuffer(static_cast<char*>(NULL)),
      real_data_(data),
      size_(size) {
  data_ = reinterpret_cast<char*>(real_data_);
}

IOBufferWrapper::IOBufferWrapper(const void* data, int64_t size)
    : IOBuffer(static_cast<char*>(NULL)),
      real_data_(const_cast<void *>(data)),
      size_(size) {
  data_ = reinterpret_cast<char*>(real_data_);
}

IOBufferWrapper::~IOBufferWrapper() {
  // We haven't allocated the buffer, so remove it before the base class
  // destructor tries to delete[] it.
  data_ = NULL;
}

std::unique_ptr<Storage> Storage::Create(const base::FilePath& input_dir,
                                         TorrentCache* torrent_cache,
                                         scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
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
        torrent_cache,
        input_dir,
        main_task_runner,
        backend_task_runner,
        std::move(disk_state),
        first_run,
        std::string(), 
        nullptr));
}

std::unique_ptr<Storage> Storage::Clone(const base::FilePath& input_dir,
                                        TorrentCache* torrent_cache,
                                        scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
                                        scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                        std::string id,
                                        const char* pkey,
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
        torrent_cache,
        input_dir,
        main_task_runner,
        backend_task_runner,
        std::move(disk_state),
        first_run,
        std::move(id),
        pkey));
}

// static 
std::unique_ptr<Storage> Storage::Open(const base::FilePath& path,
                                 TorrentCache* torrent_cache,
                                 scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
                                 scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner) {//,
   std::unique_ptr<storage_proto::StorageState> state(new storage_proto::StorageState());
   return Storage::Open(
    path, 
    torrent_cache, 
    main_task_runner, 
    backend_task_runner, 
    std::move(state), 
    false);
}

// static 
std::unique_ptr<Storage> Storage::Open(
  const base::FilePath& path,
  TorrentCache* torrent_cache,
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
  scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
  std::unique_ptr<storage_proto::StorageState> state,
  bool first_run) {
  base::FilePath dir_path = path;
  if (path.MatchesExtension(kStorageFileExtensionWithDot)) {
    dir_path = dir_path.RemoveExtension();
  }
  
  return std::unique_ptr<Storage>(new Storage(
        torrent_cache,
        dir_path,
        main_task_runner,
        backend_task_runner,
        std::move(state),
        first_run,
        std::string(),
        nullptr));
}

Storage::Storage(
    TorrentCache* torrent_cache,
    const base::FilePath& path,
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner, 
    scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner, 
    std::unique_ptr<storage_proto::StorageState> disk_state,
    bool first_run,
    std::string id,
    const char* pkey):
  torrent_cache_(torrent_cache),
  path_(path),
  state_(std::move(disk_state)),
  main_task_runner_(main_task_runner),
  frontend_task_runner_(
    base::CreateSingleThreadTaskRunnerWithTraits(
       { base::MayBlock(),
         base::WithBaseSyncPrimitives() },
       base::SingleThreadTaskRunnerThreadMode::DEDICATED)
  ),
  backend_task_runner_(backend_task_runner),
  //db_task_runner_(
  //  base::CreateSingleThreadTaskRunnerWithTraits(
  //    { base::MayBlock(), 
  //      base::WithBaseSyncPrimitives(),
  //      base::TaskShutdownBehavior::BLOCK_SHUTDOWN },
  //    base::SingleThreadTaskRunnerThreadMode::DEDICATED)
  //),
  given_pkey_if_cloned_(pkey),
  given_id_if_cloned_(std::move(id)),
  initialized_(false),
  initializing_(false),
  shutdown_(false),
  first_run_(first_run),
  is_owner_(false),
  init_event_(
    base::WaitableEvent::ResetPolicy::MANUAL, 
    base::WaitableEvent::InitialState::NOT_SIGNALED),
  event_wait_(
    base::WaitableEvent::ResetPolicy::MANUAL, 
    base::WaitableEvent::InitialState::NOT_SIGNALED) {

  DCHECK(state_.get());
  // sanitize state
  state_->set_status(storage_proto::STORAGE_STATUS_NONE);
  state_->set_local_path(path_.value());
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
  DLOG(INFO) << "Storage::Start";
  if (state_->status() == storage_proto::STORAGE_STATUS_ONLINE || initializing_) {
    if (!callback.is_null()) {
      DLOG(INFO) << "Storage::Start: storage_proto::STORAGE_STATUS_ONLINE || initializing_. calling callback";
      callback.Run(this, -2);
    }
    return;
  }
  initializing_ = true;
  Manifest::InitParams params;
  if (first_run_) {
    if (given_pkey_if_cloned_) {
      memcpy(params.public_key.bytes.data(), given_pkey_if_cloned_, 32);
      params.is_owner = false;
      params.root_tree = base::UUID(reinterpret_cast<const uint8_t *>(given_id_if_cloned_.data()));
      is_owner_ = false;
      DLOG(INFO) << "setting root tree to " << params.root_tree.to_string() << ". CLONED storage version";
    } else {
      std::array<char, 32> seed = libtorrent::dht::ed25519_create_seed();
      std::tuple<libtorrent::dht::public_key, libtorrent::dht::secret_key> keys = libtorrent::dht::ed25519_create_keypair(seed);
      params.public_key = std::move(std::get<0>(keys));
      params.private_key = std::move(std::get<1>(keys));
      params.root_tree = base::UUID::generate();
      DLOG(INFO) << "setting root tree to " << params.root_tree.to_string() << ". NEW storage version";
      params.is_owner = true;
      is_owner_ = true;
    }
    params.base32_address = path_.BaseName().value();//base32::Base32Encode(base::StringPiece(params.public_key.bytes.data(), params.public_key.bytes.size()), base32::Base32EncodePolicy::OMIT_PADDING);
    params.creator = "Donald Duck";
    printf("address: %s\nroot: %s\npublic key: %s\n", params.base32_address.c_str(), params.root_tree.to_string().c_str(), base::HexEncode(params.public_key.bytes.data(), 32).c_str());
    
  }
 
  frontend_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(
      &Storage::StartImpl, 
       base::Unretained(this),
       base::Passed(std::move(params)),
       base::Passed(std::move(callback))));
  
  init_event_.Wait();
}

void Storage::StartImpl(Manifest::InitParams params, base::Callback<void(Storage*, int)> callback) {
  DLOG(INFO) << "Storage::StartImpl";
  int result = -1;

  CompletionCallback on_init = base::Bind(&Storage::OnBackendInit, base::Unretained(this), base::Passed(std::move(callback)));
  //if (initialized_) {
  //  on_init.Run(0);
  //  return;
  //}

  cleanup_tracker_ = disk_cache::BackendCleanupTracker::TryCreate(
    path_, base::BindOnce(&CleanupTrackerResult));

  StorageBackend* block_cache =
      new StorageBackend(path_, 
                      cleanup_tracker_.get(),
                      backend_task_runner_, 
                      &log_);
  
  backend_.reset(block_cache);
  result = block_cache->Init(std::move(params), on_init);
  if (result != net::ERR_IO_PENDING) {
    on_init.Run(result);
  }
}

void Storage::OnBackendInit(base::Callback<void(Storage*, int)> callback, int64_t code) {
  DLOG(INFO) << "Storage::OnBackendInit";
  if (code == 0) {
    if (being_cloned()) {
      OnInit(std::move(callback), true);
    } else {
      scoped_refptr<StorageContext> context;
      const Manifest* manifest = backend_->manifest();
      base::StringPiece root_tree_str = manifest->GetProperty(Manifest::TREE);
      DLOG(INFO) << "Storage::OnBackendInit: manifest = " << manifest <<
       "\n root tree size = " << root_tree_str.size();
      base::UUID root_tree(reinterpret_cast<const uint8_t*>(root_tree_str.data()));
      LOG(INFO) << "Storage::OpenRootTreeOnInit: received root uuid " << root_tree.to_string();
      root_tree_ = torrent_cache_->NewTorrent(this, std::move(root_tree), true /* is_root*/);
      if (first_run_) {
        context = CreateContext(StorageContext::kCREATE_CATALOG, root_tree_, CompletionCallback());
        // the path of the root tree = the disk's 'name'
        root_tree_->mutable_info()->set_path(path_.BaseName().value());
        root_tree_->mutable_info()->set_kind(storage_proto::INFO_DATA);
        context->create_db_params.keyspaces.push_back("keyspaces");
        context->create_db_params.keyspaces.push_back("inodes");
        context->create_db_params.keyspaces.push_back("index");
      } else {
        context = CreateContext(StorageContext::kOPEN_CATALOG, root_tree_, CompletionCallback());
      }
      //db_task_runner_->PostTask(FROM_HERE,
      context->task_runner->PostTask(FROM_HERE,
        base::BindOnce(
          &Storage::OpenRootTreeOnInit,
          base::Unretained(this), 
          context,
          first_run_,
          base::Passed(std::move(callback))));
    }
    initialized_ = true;
  } else {
    OnInit(std::move(callback), false);
  }
}

void Storage::OnInit(base::Callback<void(Storage*, int)> callback, bool result) {
  if (result) {
    bool manifest_error = false;
    initialized_ = true;
    // we might not have it yet if we are cloning it
    //if (registry) {
    //  registry_ = std::move(registry);
    //}
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
  init_event_.Signal();
  if (!callback.is_null()) {
    callback.Run(this, result ? 0 : 2);
  }
  initializing_ = false;
}

void Storage::OpenRootTreeOnInit(scoped_refptr<Storage::StorageContext> context, bool create, base::Callback<void(Storage*, int)> callback) {
   DLOG(INFO) << "Storage::OpenRootTreeOnInit";
   Database* db = create ? 
     Database::Create(root_tree_, context->create_db_params.keyspaces) : 
     Database::Open(root_tree_);

   if (!db) {
     LOG(ERROR) << "Storage::OpenRootTreeOnInit: failed to open/create root tree db";
   }

   if (create) {
    db->Close();
   }

   TerminateContext(context);
   OnInit(std::move(callback), true);
}

void Storage::Stop(CompletionCallback callback) {
  frontend_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&Storage::StopImpl, 
      base::Unretained(this), 
      base::Unretained(&event_wait_)));
  event_wait_.Wait();
  state_->set_status(storage_proto::STORAGE_STATUS_OFFLINE);
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
  //db_task_runner_ = nullptr;
  
  // DbShutdown();

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
  std::vector<std::unique_ptr<storage_proto::Info>> entries = GetAllEntriesInfos();
  std::move(cb).Run(std::move(entries), net::OK);
}

std::vector<std::unique_ptr<storage_proto::Info>> Storage::GetAllEntriesInfos() {
  std::vector<std::unique_ptr<storage_proto::Info>> result;
  frontend_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&Storage::GetAllEntriesInfosImpl, base::Unretained(this), base::Unretained(&result)));
  event_wait_.Wait();
  event_wait_.Reset();
  return result;
}

void Storage::GetAllEntriesInfosImpl(std::vector<std::unique_ptr<storage_proto::Info>>* out) {
  ListAllEntriesInfo(out, &event_wait_);
}

void Storage::ListAllEntriesInfo(std::vector<std::unique_ptr<storage_proto::Info>>* out, base::WaitableEvent* event) {
  backend_task_runner_->PostTask(FROM_HERE, 
    base::Bind(&Storage::ListAllEntriesInfoImpl, 
        base::Unretained(this),
        base::Unretained(out),
        base::Unretained(event)));
}

void Storage::ListAllEntriesInfoImpl(std::vector<std::unique_ptr<storage_proto::Info>>* out, base::WaitableEvent* event) {
  scoped_refptr<StorageEntry> node;
  std::unique_ptr<Rankings::Iterator> iterator(new Rankings::Iterator());
  int rv = backend_->SyncOpenNextEntry(iterator.get(), &node);
  while (rv == net::OK) {
    std::unique_ptr<storage_proto::Info> info = std::make_unique<storage_proto::Info>();
    size_t size = static_cast<size_t>(node->GetDataSize(kDATA_MANIFEST)); 
    scoped_refptr<net::IOBufferWithSize> header_data = new net::IOBufferWithSize(size);
    int r = node->ReadDataImpl(kDATA_MANIFEST, 
                               0,
                               header_data.get(),
                               size,
                               CompletionCallback());
    if (r > 0) {
      if (info->ParseFromArray(header_data->data(), r)) {
        out->push_back(std::move(info));
      } else {
        LOG(ERROR) << "failed to decode info header for entry '" << node->GetKey() << "'. size " << size << " bytes. readed " << r << " bytes";
      }
    } else {
      LOG(ERROR) << "failed to read header data for entry " << node->GetKey() << " r =" << r;
    }
    //node->Close();
    rv = backend_->SyncOpenNextEntry(iterator.get(), &node);
  }
  event->Signal();
}


void Storage::OpenDatabase(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb) {
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kOPEN_CATALOG, torrent, std::move(cb));   
  base::OnceCallback<void()> closure = 
    base::BindOnce(&Storage::OpenDatabaseImpl, 
      base::Unretained(this), 
      context);
  if (initialized_) {
    std::move(closure).Run();
    //frontend_task_runner_->PostTask(
    //  FROM_HERE,
    //  std::move(closure));
  } else {
    scheduled_io_.push_back(std::make_pair(std::move(context), std::move(closure)));
  }
}

void Storage::OpenDatabaseImpl(scoped_refptr<Storage::StorageContext> context) {
   context->task_runner->PostTask(FROM_HERE,
  //db_task_runner_->PostTask(FROM_HERE, 
    base::BindOnce(
      &Storage::OpenSQLiteDatabase, 
      base::Unretained(this),
      context));
}

void Storage::CreateDatabase(const scoped_refptr<Torrent>& torrent, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) {
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCREATE_CATALOG, torrent, std::move(cb));
  context->create_db_params.keyspaces = std::move(keyspaces);
  
  base::OnceCallback<void()> closure = 
    base::BindOnce(&Storage::CreateDatabaseImpl, 
      base::Unretained(this), 
      context);
  if (initialized_) {
    //frontend_task_runner_->PostTask(
    //  FROM_HERE,
    //  std::move(closure));
    std::move(closure).Run();
  } else {
    scheduled_io_.push_back(std::make_pair(std::move(context), std::move(closure)));
  }
}

void Storage::CreateDatabaseImpl(scoped_refptr<Storage::StorageContext> context) {
  context->task_runner->PostTask(FROM_HERE,
  //db_task_runner_->PostTask(FROM_HERE, 
  base::BindOnce(
    &Storage::CreateSQLiteDatabase, 
    base::Unretained(this),
    context));
}

void Storage::OpenFileset(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb) {

}

void Storage::CreateFileset(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb) {

}

void Storage::GetInfo(base::Callback<void(storage_proto::StorageState)> callback) {
  callback.Run(*state_.get());
}

void Storage::GetInfoImpl(base::Callback<void(storage_proto::StorageState)> callback) const {
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

void Storage::CopyFile(
    const scoped_refptr<Torrent>& torrent,
    const base::FilePath& src,
    CompletionCallback callback) {
  
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCOPY_FILE, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyCopyFile, std::move(callback));
  context->src = src;
  
  base::OnceCallback<void()> closure = base::BindOnce(
      &Storage::CopyFileImpl, 
      base::Unretained(this),
      context);

  if (initialized_) {
    context->task_runner->PostTask(
      FROM_HERE,
      std::move(closure));
    //frontend_task_runner_->PostTask(
    //  FROM_HERE,
    //  std::move(closure));
  } else {
    scheduled_io_.push_back(std::make_pair(std::move(context), std::move(closure)));
  }
}


void Storage::CopyFileImpl(scoped_refptr<Storage::StorageContext> context) {
                           //const scoped_refptr<Torrent>& torrent,
                           //const base::FilePath& from,
                           //CompletionCallback callback) {
  //scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCOPY_FILE, torrent, CompletionCallback());
  //context->src = from;
  //context->BindExit(&Storage::ReplyCopyFile, std::move(callback));
  context->BindNext(&Storage::OnCopyFile);
  
  int result = backend_->CreateEntry(
    context->key,
    &context->torrent->entry_,
    context->next_callback);

  if (result != net::ERR_IO_PENDING) {
    context->Next(result);
  }

} 

void Storage::CopyEntry(
    const scoped_refptr<Torrent>& torrent,
    const base::FilePath& dest,
    CompletionCallback callback) {

  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCOPY_ENTRY, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyCopyEntry, std::move(callback));
  context->dest = dest;
  
  base::OnceCallback<void()> closure = base::BindOnce(
      &Storage::CopyEntryImpl, 
      base::Unretained(this), 
      context);
   if (initialized_) {
    context->task_runner->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::make_pair(std::move(context), std::move(closure)));
  }
}

void Storage::CopyEntryImpl(scoped_refptr<Storage::StorageContext> context) {
  context->BindNext(&Storage::OnCopyEntry);

  int result = backend_->OpenEntry(
    context->key,
    &context->torrent->entry_,
    context->next_callback);

  if (result != net::ERR_IO_PENDING) {
    context->Next(result);
  }
}

void Storage::InitEntry(const scoped_refptr<Torrent>& torrent,
                        CompletionCallback callback) {
  
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kINIT_ENTRY, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyInitEntry, std::move(callback));
  context->init.file_count = 0;

  base::OnceCallback<void()> closure = 
    base::BindOnce(&Storage::InitEmptyEntry, 
      base::Unretained(this),
      context);

  if (initialized_) {
    context->task_runner->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::make_pair(std::move(context), std::move(closure)));
  }   
}

void Storage::InitEntry(const scoped_refptr<Torrent>& torrent,
                        const base::FilePath& src,
                        CompletionCallback callback) {

  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kINIT_ENTRY, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyInitEntry, std::move(callback));
  context->src = src;

  base::OnceCallback<void()> closure = 
    base::BindOnce(&Storage::InitEntryImpl, 
      base::Unretained(this),
      context);
  if (initialized_) {
    //frontend_task_runner_->PostTask(
    context->task_runner->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::make_pair(std::move(context), std::move(closure)));
  }
}


void Storage::InitEntryImpl(scoped_refptr<Storage::StorageContext> context) {
  context->BindNext(&Storage::OnInitEntry);

  base::FileEnumerator files_to_add(context->src, true, base::FileEnumerator::FILES);
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

  context->init.file_count = context->files.file_count();

  // calculate hashes for the files (64k leafs)
  //if (!GenerateMerkleTreeForFiles(&context->files)) {
  //  context->Exit(net::ERR_FAILED);
  //  return;
  //}

  // build and the merkle for the entry with the hashes generated from files
  //context->init.entry_merkle = MerkleTree::CreateAndBuild(&context->files);
  //std::unique_ptr<MerkleTree> merkle = MerkleTree::CreateAndBuild(&context->files);
  //if (!merkle) {
  //  context->Exit(net::ERR_FAILED);
  //  return;
  //}
  //torrent->set_merkle_tree(std::move(merkle));
  //context->key = name;

  int result = backend_->CreateEntry(
    context->torrent->id(),
    &context->torrent->entry_,
    context->next_callback);

  if (result != net::ERR_IO_PENDING) {
    context->Next(result);
  }
}

void Storage::InitEmptyEntry(scoped_refptr<Storage::StorageContext> context) {
  context->BindNext(&Storage::OnInitEntry); 

  int result = backend_->CreateEntry(
    context->torrent->id(),
    &context->torrent->entry_,
    context->next_callback);

  if (result != net::ERR_IO_PENDING) {
    context->Next(result);
  }
}

void Storage::GetEntryInfo(const scoped_refptr<Torrent>& torrent, base::Callback<void(storage_proto::Info, int64_t)> cb) {
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kGET_ENTRY_INFO, torrent, CompletionCallback());
  context->BindExit(&Storage::ReplyGetEntryInfo, std::move(cb));
  
  base::OnceCallback<void()> closure = base::BindOnce(
      &Storage::GetEntryInfoImpl, 
      base::Unretained(this),
      context);
   if (initialized_) {
    context->task_runner->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::make_pair(std::move(context), std::move(closure)));
  }  
}

void Storage::GetEntryInfoImpl(scoped_refptr<Storage::StorageContext> context) {
  context->BindNext(&Storage::OnGetEntryInfo);

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

void Storage::OpenSQLiteDatabase(scoped_refptr<StorageContext> context) {
  // DLOG(INFO) << "Storage::OpenSQLiteDatabase";
  int64_t result = net::OK;
  const scoped_refptr<Torrent>& torrent = context->torrent;//torrent_cache_->NewTorrent(this, context->key);
  Database* db = Database::Open(torrent);

  if (!db) {
    // DLOG(INFO) << "Storage::OpenSQLiteDatabase: open sqlite db failed";
    result = net::ERR_FAILED;
    //context->op == StorageContext::kOPEN_CATALOG ?
    ReplyOpenDatabase(std::move(context->exit_callback), result); //:
      //ReplyOpenApplication({}, std::move(context->exit_callback), result);
    TerminateContext(context);
    return;
  }

  //Inode* inode = GetInode(context->key);
  //if (!inode) {
  //  // DLOG(INFO) << "Storage::OpenSQLiteDatabase: failed to find inode for " << context->key;
  //  result = net::ERR_FAILED;
  //  context->op == StorageContext::kOPEN_CATALOG ?
  //    ReplyOpenCatalog({}, std::move(context->exit_callback), result) :
  //    ReplyOpenApplication({}, std::move(context->exit_callback), result);
  //  TerminateContext(context);
  //  return;
  //}

  //if (context->op == StorageContext::kOPEN_CATALOG) {
    //storage_proto::Info catalog_info;
    //catalog_info.CopyFrom(torrent->info());//inode->info);
    //std::unique_ptr<Catalog> catalog = std::make_unique<DataCatalog>(std::move(catalog_info), context->key, db_task_runner_, std::move(db));
    //torrent->set_entity(catalog.get());
    //if (!catalog->Init()) {
    //  // DLOG(INFO) << "Storage::OpenSQLiteDatabase: catalog initialization failed";
    //  result = net::ERR_FAILED;
    //}
  ReplyOpenDatabase(std::move(context->exit_callback), result);
    //ReplyOpenCatalog(std::move(catalog), std::move(context->exit_callback), result);
  // } else if (context->op == StorageContext::kOPEN_APPLICATION) {
  //   Application::InitParams params;
  //   params.check = true;
  //   std::unique_ptr<Application> application = std::make_unique<Application>(torrent->id(), std::move(db));
  //   params.creating = false;
  //   if (!application->Init(params)) {
  //     result = net::ERR_FAILED;
  //   }
  //   ReplyOpenApplication(std::move(application), std::move(context->exit_callback), result);
  // }

  TerminateContext(context);
}

void Storage::CreateSQLiteDatabase(scoped_refptr<StorageContext> context) {
  //Torrent* torrent = torrent_cache_->NewTorrent(this, context->key);
  const scoped_refptr<Torrent>& torrent = context->torrent;
  torrent->mutable_info()->set_kind(storage_proto::INFO_DATA);
  
  Database* db = Database::Create(torrent, context->create_db_params.keyspaces);
  int64_t result = net::OK;
  
  if (!db) { // return early
    result = net::ERR_FAILED;
    //context->op == StorageContext::kOPEN_CATALOG ?
    //  ReplyCreateCatalog({}, std::move(context->exit_callback), result) :
    //  ReplyCreateApplication({}, std::move(context->exit_callback), result);
    ReplyCreateDatabase(std::move(context->exit_callback), result);
    TerminateContext(context);
    return;
  }
  
  if (context->op == StorageContext::kCREATE_CATALOG) {
    //Inode* inode = GetInode(context->key);
    //if (!inode) {
    //  // DLOG(INFO) << "Storage::CreateSQLiteDatabase: failed to find inode for " << context->key;
    //  ReplyCreateCatalog({}, std::move(context->exit_callback), net::ERR_FAILED);
    //  TerminateContext(context);
    //  return;
    //}
    //if (!torrent->is_root()) {
    //  if (AddIndexOnTree(context) == net::ERR_FAILED) {
    //    // DLOG(INFO) << "Storage::CreateSQLiteDatabase: error adding index on registry";
    //    ReplyCreateDatabase(std::move(context->exit_callback), net::ERR_FAILED);
    //    TerminateContext(context);
    //    return;
    //  }
    //}

    //int64_t result = WriteDatabaseMetadata(context, db);
    
    //if (catalog) {
    //  torrent->set_entity(catalog.get());
    //  if (!catalog->Init()) {
    //    result = net::ERR_FAILED;
    //  }
    //}

    if (!torrent->is_root()) {   
      //LOG(INFO) << "Storage::OnWriteTorrentHeaderResult: AddIndexOnRegistry " << torrent->id().to_string();
      if (being_cloned()) {
        DLOG(INFO) << "Storage::CreateSQLiteDatabase: being cloned. cancelling adding index";
        return;
      }
      AddIndexOnTreeOnDbThread(context);
    }
    ReplyCreateDatabase(std::move(context->exit_callback), result);
  }// else if (context->op == StorageContext::kCREATE_APPLICATION) {
  //  std::unique_ptr<Application> application = std::make_unique<Application>(torrent->id(), std::move(db));
  //  int64_t result = application ? net::OK : net::ERR_FAILED;
  //  Application::InitParams params;
  //  params.creating = true;
  //  if (application) {
  //    if (!application->Init(params)) {
  //      result = net::ERR_FAILED;
  //    }
  //  }

  //  ReplyCreateApplication(std::move(application), std::move(context->exit_callback), result);
  //}

  TerminateContext(context);
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

bool Storage::ShouldSeed(const storage_proto::Info& info) {
  // for now is just this
  return is_owner_;
}

Future<int> Storage::ReadTorrent(const scoped_refptr<Torrent>& torrent, void* buf, int64_t size, int64_t offset, bool is_journal, int jrn_seq) {
  // DLOG(INFO) << "Storage::ReadTorrent: " << torrent->id().to_string() << " journal? " << is_journal;;
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kREAD_BLOB, torrent, CompletionCallback());
  context->is_journal = is_journal;
  context->jrn_seq = jrn_seq;
  bool sync = false;
  //if (frontend_task_runner_->RunsTasksInCurrentSequence()) {
  //  sync = true;
  //  ReadTorrentImpl(context, buf, size, offset);
  //} else {
   //frontend_task_runner_->PostTask(
   //frontend_task_runner_->PostTask(
   context->task_runner->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &Storage::ReadTorrentImpl,
      base::Unretained(this),
      context,
      base::Unretained(buf),
      size,
      offset));
  //}
  return Future<int>(context->sync_event_, sync);
}

void Storage::ReadTorrentImpl(scoped_refptr<Storage::StorageContext> context, void* buf, int64_t size, int64_t offset) {
  //Inode* inode = GetInode(key);
  //if (inode) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // DLOG(INFO) << "Storage::ReadTorrentImpl: " << torrent->id().to_string() << " journal? " << context->is_journal;
  CompletionCallback callback = base::Bind(&Storage::OnReadTorrent, base::Unretained(this), context, size);//GetWeakPtr(), context, size);
  context->iobuf = new IOBufferWrapper(buf, size);
  StorageEntry* entry = context->is_journal ? torrent->GetJournalEntry(context->jrn_seq) : torrent->entry_;
//  // DLOG(INFO) << "reading blob content";
  context->read.bytes = entry->ReadData(
    kDATA_CONTENT, 
    offset,
    context->iobuf.get(),
    size,
    callback);

  if (context->read.bytes != net::ERR_IO_PENDING) {
    callback.Run(context->read.bytes);
  }
  //} else {
  //  // DLOG(INFO) << "entry for " << key << " not found";
  //  context->read.bytes = -1;
  //  context->Signal(-1);
  //  TerminateContext(context);
  //}
}

void Storage::OnReadTorrent(scoped_refptr<StorageContext> context, int64_t expected, int64_t result) {
  //// DLOG(INFO) << "Storage::OnReadBlob: " << context->key << " r = " << result;
  context->read.bytes = result;
  context->Signal(0);
  
  TerminateContext(context);
}

Future<int> Storage::WriteTorrent(const scoped_refptr<Torrent>& torrent, const void* buf, int64_t size, int64_t offset, bool is_journal, int jrn_seq) {
  DLOG(INFO) << "Storage::WriteTorrent: " << torrent->id().to_string() << " buf size = " << size << " journal? " << is_journal;
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kWRITE_BLOB, torrent, CompletionCallback());
  context->is_journal = is_journal;
  context->jrn_seq = jrn_seq;
  bool sync = false;

  // if we are coming from a create catalog, get some useful parameters from the parent context
  // who will still be alive
  scoped_refptr<StorageContext> parent_context = GetContext(StorageContext::kCREATE_CATALOG, torrent->id());
  if (parent_context) {
    context->create_db_params.keyspaces = parent_context->create_db_params.keyspaces;
    context->parent = parent_context;
  }
  //if (frontend_task_runner_->RunsTasksInCurrentSequence()) {
  //  WriteTorrentImpl(context, buf, size, offset);
  //  sync = true;
  //} else {
   //frontend_task_runner_->PostTask(
   //frontend_task_runner_->PostTask(
   context->task_runner->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &Storage::WriteTorrentImpl, 
      base::Unretained(this),
      context,
      base::Unretained(buf),
      size,
      offset));
  //}
  return Future<int>(context->sync_event_, sync);
}

void Storage::WriteTorrentImpl(scoped_refptr<Storage::StorageContext> context, const void* buf, int64_t size, int64_t offset) {
  //// DLOG(INFO) << "Storage::WriteBlobImpl: " << key;
  //Inode* inode = GetInode(key);
  //if (inode) {
    CompletionCallback callback = base::Bind(&Storage::OnWriteTorrent, base::Unretained(this), context, size);
    const scoped_refptr<Torrent>& torrent = context->torrent;
    // DLOG(INFO) << "Storage::WriteTorrentImpl: " << torrent->id().to_string() << " journal? " << context->is_journal;;
    context->iobuf = new IOBufferWrapper(buf, size);
    if (!context->is_journal) {
      //auto it = merkle_tree_list_.find(context->key);
      MerkleTree* merkle_tree = torrent->merkle_tree();
      if (!merkle_tree) {
        //DLOG(INFO) << "merkle tree for " << context->key.to_string() << " does not exist. creating";
        int table_count = context->create_db_params.keyspaces.size();
        bool ok = false;
        if (table_count) {
          //DLOG(INFO) << " creating merkle for " << table_count << " tables";
          ok = torrent->CreateMerkleTreeTables(table_count);
        } else if (torrent->info().piece_count() > 0) {
          //DLOG(INFO) << " creating merkle for " << torrent->info().piece_count() << " pieces/blocks";
          ok = torrent->CreateMerkleTreePieces(torrent->info().piece_count());
        }
        if (!ok) {
          DLOG(ERROR) << "error while creating merkle tree for torrent " << context->key.to_string();
          context->Signal(-1);
          TerminateContext(context);
          return;
        }
      }
      merkle_tree = torrent->merkle_tree();
      int64_t block_offset = offset / kBlockSize;
      int64_t leaf_offset = merkle_tree->first_leaf_offset() + block_offset;
      // get the block offset
      if (!merkle_tree->NodeIsSet(leaf_offset)) {
        //DLOG(INFO) << "adding leaf: offset = " << offset << " block offset = " << block_offset << " adding leaf = " << leaf_offset << " blocks: " << merkle_tree->block_count() << " nodes: "  << merkle_tree->node_count();
        merkle_tree->AddLeaf(leaf_offset, buf, size);
      } else {
        //DLOG(INFO) << "updating leaf: offset = " << offset << " block offset = " << block_offset << " updating leaf = " << leaf_offset<< " blocks: " << merkle_tree->block_count() << " nodes: "  << merkle_tree->node_count();
        merkle_tree->UpdateLeaf(leaf_offset, buf, size);
      }
    }
    StorageEntry* entry = context->is_journal ? torrent->GetJournalEntry(context->jrn_seq) : torrent->entry_;
    context->write.bytes = entry->WriteData(
      kDATA_CONTENT, 
      offset,
      context->iobuf.get(),
      size,
      callback,
      false);
    
    if (context->write.bytes != net::ERR_IO_PENDING) {
      callback.Run(context->write.bytes);
    }
  //} else {
  //  context->Signal(-1);
  //  TerminateContext(context);
  //}
}

void Storage::WriteTorrentMerkleImpl(scoped_refptr<Storage::StorageContext> context) {
  //// DLOG(INFO) << "Storage::WriteBlobMerkleImpl: " << key;
  //Inode* inode = GetInode(key);
  //if (inode) {
    const scoped_refptr<Torrent>& torrent = context->torrent;  
    // DLOG(INFO) << "Storage::WriteTorrentMerkleImpl: " << torrent->id().to_string() << " journal? " << context->is_journal;
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
  
    size_t allocated_size = encoded_header.size() + header_content_size;
    context->hash_buffer = new net::IOBufferWithSize(allocated_size);

    CompletionCallback callback = base::Bind(&Storage::OnWriteTorrentMerkle, base::Unretained(this), context, allocated_size);

    // TODO: this is a really dumb copy, se if we can make it better
    // by providing the buffer to all of them
    char* current_buf = context->hash_buffer->data();

    // write the header
    memcpy(current_buf, encoded_header.data(), encoded_header.size());
    current_buf += encoded_header.size();

    // write the merkle tree for the entry into the buffer
    merkle_tree->Encode(current_buf);
    
    context->write.bytes = torrent->entry()->WriteData(
      kDATA_MERKLE, 
      0,
      context->hash_buffer.get(),
      allocated_size,
      callback,
      false);
    
    if (context->write.bytes != net::ERR_IO_PENDING) {
      callback.Run(context->write.bytes);
    }
    
  //}
}

int64_t Storage::GetTorrentSize(const scoped_refptr<Torrent>& torrent) {
  // DLOG(INFO) << "Storage::GetTorrentSize: " << torrent->id().to_string();
  return torrent->entry()->GetDataSize(kDATA_CONTENT);
}

Future<int> Storage::SyncTorrentMetadata(const scoped_refptr<Torrent>& torrent) {
  // DLOG(INFO) << "Storage::SyncTorrentMetadata: " << torrent->id().to_string();
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kSYNC_METADATA, torrent, CompletionCallback());
  context->is_journal = false;
  context->should_close = false;
  bool sync = false;
  //if (frontend_task_runner_->RunsTasksInCurrentSequence()) {
  //  sync = true;
  //  UpdateTorrentMetadataImpl(context);
  //} else {
    //frontend_task_runner_->PostTask(
    //frontend_task_runner_->PostTask(
    context->task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(
        &Storage::UpdateTorrentMetadataImpl, 
        base::Unretained(this),
        context));
  //}
  return Future<int>(context->sync_event_, sync);
}

Future<int> Storage::CreateTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal, int jrn_seq) {
  // dont call this from the "storage" thread
  // DLOG(INFO) << "Storage::CreateTorrent: " << torrent->id().to_string() << " journal? " << is_journal;
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCREATE_BLOB, torrent, CompletionCallback());
  scoped_refptr<StorageContext> parent_context = GetContext(StorageContext::kCREATE_CATALOG, torrent->id());
  if (parent_context) {
    context->create_db_params.keyspaces = parent_context->create_db_params.keyspaces;
    context->parent = parent_context;
  }
  context->is_journal = is_journal;
  context->jrn_seq = jrn_seq;
  bool sync = false;
  
  //if (frontend_task_runner_->RunsTasksInCurrentSequence()) {
  //  CreateTorrentImpl(context);
  //  sync = true;
  //} else {
    //frontend_task_runner_->PostTask(
    //frontend_task_runner_->PostTask(
  context->task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(
        &Storage::CreateTorrentImpl,
        base::Unretained(this),
        context));
  //}
  
  return Future<int>(context->sync_event_, sync);
}

void Storage::CreateTorrentImpl(scoped_refptr<Storage::StorageContext> context) {

  int result = net::ERR_FAILED;
  
  context->next_callback = base::Bind(&Storage::OnCreateTorrent, base::Unretained(this), context); //GetWeakPtr(), context);
  const scoped_refptr<Torrent>& torrent = context->torrent;

  // DLOG(INFO) << "Storage::CreateTorrentImpl: key = " << torrent->id().to_string() << " journal ? " << context->is_journal;

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
  //// DLOG(INFO) << "Storage::OnCreateBlob: key = " << context->key;
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // DLOG(INFO) << "Storage::OnCreateTorrent: " << torrent->id().to_string() << " journal? " << context->is_journal << " r = " << result;
  if (result == 0) {
    if (context->is_journal) {
      torrent->SetJournalEntry(context->jrn_seq, context->journal_fd);
      context->Signal(0);
      TerminateContext(context);
    } else {
      std::string tid = torrent->id().to_string();
      // TODO: now that we have torrent as a state, use it instead of the entry
      torrent->entry()->set_is_new(true);
      //entries_.emplace(std::make_pair(context->key, std::make_unique<Storage::Inode>(context->ptr)));
      
      base::Time creation_time = base::Time::Now();
      std::string content_type;

      // form the header
      storage_proto::Info header;
      header.set_state(is_owner_ ? storage_proto::STATE_FINISHED : storage_proto::STATE_NONE);
      header.set_creation_date(creation_time.ToInternalValue());
      header.set_mtime(creation_time.ToInternalValue());
      header.set_id(torrent->id().string());
      header.set_piece_length(kBlockSize);
      header.set_readonly(false);

      //const std::vector<std::string>& keyspaces = context->create_db_params.keyspaces;

      //header.set_inode_count(keyspaces.size());
      // one for each keyspace in the database
      // as we start with at least one
      //int offset = 0;
      //for (auto it = keyspaces.begin(); it != keyspaces.end(); ++it) {
      auto* inode = header.add_inodes();
      inode->set_name(tid);
      inode->set_offset(1);
      inode->set_path(torrent->info().path() + "/" + tid);
      inode->set_creation_date(creation_time.ToInternalValue());
      inode->set_mtime(creation_time.ToInternalValue());
      net::GetMimeTypeFromExtension("db", &content_type);
      inode->set_content_type(content_type.empty() ? "application/octet-stream" : content_type);
      //inode->set_type(storage_proto::INODE_DATABASE);
      //  offset++;
      //}

      torrent->LoadInfo(header);

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
          base::Unretained(this), 
          context, 
          context->encoded_header.size());

      context->header.bytes = torrent->entry()->WriteData(//context->entry()->WriteData(
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
  DLOG(INFO) << "Storage::AddIndexOnTree";
  if (being_cloned()) {
    DLOG(INFO) << "Storage::AddIndexOnTree: being cloned returning OK instead of PENDING";
    return net::OK;
  }

  base::PostTaskWithTraits(
    FROM_HERE,
    { base::MayBlock(),
      base::WithBaseSyncPrimitives() },
    base::BindOnce(&Storage::AddIndexOnTreeOnDbThread, 
      base::Unretained(this), 
      context)
  );
   
  //AddIndexOnTreeOnDbThread(context);

  return net::ERR_IO_PENDING;
  //return net::OK;
}

void Storage::AddIndexOnTreeOnDbThread(scoped_refptr<StorageContext> context) {
  DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread";
  scoped_refptr<Torrent> torrent = context->torrent;
  DCHECK(torrent);
  std::string uuid_str = context->key.to_string();
  DCHECK(root_tree_);
  DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread: opening root database..";
  if (!root_tree_->db_is_open()) {
    Database::Open(root_tree_);
  }
  DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread: done.";
  auto tr = root_tree_->db().BeginTransaction(true);
  bool result = root_tree_->db().Put(tr.get(), "inodes", base::StringPiece(uuid_str), context->encoded_header);
  if (result) {
    result = root_tree_->db().Put(tr.get(), "index", torrent->info().path(), base::StringPiece(uuid_str));
    if (result) {
      DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread: index insertion of '" << torrent->info().path() << "' ok";
      name_index_lock_.Acquire();
      name_index_.emplace(std::make_pair(torrent->info().path(), context->key));
      name_index_lock_.Release();
    }
  }
  result ? tr->Commit() : tr->Rollback();
  DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread: closing root database.."; 
  root_tree_->db().Close();
  DLOG(INFO) << "Storage::AddIndexOnTreeOnDbThread: done.";

  // init(adding blobs) entry also adds a index, but have a different exit path
  // as it is async (unlike db ops where its already inside the consumer db task runner)
  if (context->op == StorageContext::kINIT_ENTRY) {
    context->task_runner->PostTask(  
      FROM_HERE,
      base::BindOnce(
        std::move(context->next_callback),
        result ? net::OK : net::ERR_FAILED)
    );
  }
}

void Storage::OnCreateTorrentWriteManifest(scoped_refptr<StorageContext> context, int64_t expected, int64_t bytes_written) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  DLOG(INFO) << "Storage::OnCreateTorrentWriteManifest: " << torrent->id().to_string() << " journal? " << context->is_journal << " expected: " << expected << " wrote: " << bytes_written;
  //// DLOG(INFO) << "Storage::OnCreateBlobWriteManifest: " << context->key;
  int r = 0;
  if (bytes_written < 0) {
    DLOG(ERROR) << "Error while writing manifest for blob";
    r = -1;
  } else {
    //Inode* inode = GetInode(context->key);
    //inode->info = std::move(context->info);
    if (context->parent) {
      context->parent->encoded_header = context->encoded_header;
    }
    //torrent->OnMetadataDone();
  }
  context->Signal(r);
  TerminateContext(context);

  //base::PostTask(
  //  FROM_HERE,
  //  base::BindOnce(
  //    &Torrent::OnInfoChanged,
  //    base::Unretained(torrent)));
}

Future<int> Storage::OpenTorrent(const scoped_refptr<Torrent>& torrent) {
  //DCHECK(base::ThreadTaskRunnerHandle::Get() != frontend_task_runner_);
  // DLOG(INFO) << "Storage::OpenTorrent: key = " << torrent->id().to_string();
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kOPEN_BLOB, torrent, CompletionCallback());
  bool sync = false;
  //if (frontend_task_runner_->RunsTasksInCurrentSequence()) {
  //  sync = true;
  //  OpenTorrentImpl(context);
  //} else {
   //frontend_task_runner_->PostTask(
   context->task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(
        &Storage::OpenTorrentImpl, 
        base::Unretained(this),
        context));
  //}
  return Future<int>(context->sync_event_, sync);
}

void Storage::OpenTorrentImpl(scoped_refptr<Storage::StorageContext> context) {
  context->next_callback = base::Bind(&Storage::OnOpenTorrent, base::Unretained(this), context);//GetWeakPtr(), context);
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // DLOG(INFO) << "Storage::OpenTorrentImpl: torrent = " << torrent->id().to_string();
  if (!torrent->is_open()) {
    int result = backend_->OpenEntry(
        torrent->id(),
        &torrent->entry_,
        context->next_callback);

    if (result != net::ERR_IO_PENDING) {
      context->next_callback.Run(result);
    }
  } else {
    // DLOG(INFO) << "Storage::OpenTorrentImpl: torrent " << torrent->id().to_string() << " already open. just moving forward";
    context->was_open = true;
    context->Signal(0);
    TerminateContext(context);
  }
}

void Storage::OnOpenTorrent(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  DLOG(INFO) << "Storage::OnOpenTorrent: key = " << torrent->id().to_string() << " r = " << result;
  if (result == 0) {
    //if (entries_.find(context->key) == entries_.end()) {
    //  entries_.emplace(std::make_pair(context->key, std::make_unique<Storage::Inode>(context->ptr)));
    //}
    //Inode* inode = GetInode(context->key);
    //DCHECK(inode);
    
    int64_t size = torrent->entry()->GetDataSize(kDATA_MANIFEST);

    CompletionCallback callback = base::Bind(&Storage::OnOpenTorrentReadManifest, 
      base::Unretained(this), 
      context, 
      size);
      
    if (context->is_journal) {
      // //// DLOG(INFO) << context->key << " journal file, not reading a header";  
      context->Signal(0);
      TerminateContext(context);
    } else {
      // only read the manifest if its not already cached
      context->header_data = new net::IOBufferWithSize((size_t)size);
      context->header.bytes = torrent->entry()->ReadData(//inode->entry->ReadData(
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
  // DLOG(INFO) << "Storage::OnOpenTorrentReadManifest: " << torrent->id().to_string() << " expected: " << expected << " readed: " << bytes;
  
  if (bytes < 0) {
    LOG(ERROR) << "Error while reading manifest for blob";
    context->Signal(-1);
    TerminateContext(context);
    return;
  }
  //Inode* inode = GetInode(context->key);
  if (!torrent->LoadInfoFromBytes(context->header_data->data(), bytes)) {
    LOG(ERROR) << "Error while reading header for blob";
    context->Signal(-1);
    TerminateContext(context);
    return;
  }

  printf("recovered info\n%s\n  path: %s\n  comment: %s\n  root hash: %s\n  piece_length: %ld\n  piece_count: %ld\n  length: %ld\n  inodes: %d\n", 
      torrent->id().to_string().c_str(),
      torrent->info().path().c_str(),
      torrent->info().comment().c_str(),
      base::HexEncode(torrent->info().root_hash().data(), torrent->info().root_hash().size()).c_str(),
      torrent->info().piece_length(),
      torrent->info().piece_count(),
      torrent->info().length(),
      torrent->info().inodes().size());
  
  int64_t size = torrent->entry()->GetDataSize(kDATA_MERKLE);
  CompletionCallback callback = base::Bind(
      &Storage::OnOpenTorrentReadMerkle, 
      base::Unretained(this), 
      context, 
      size);
  context->hash_buffer = new net::IOBufferWithSize((size_t)size);
  context->header.bytes = torrent->entry()->ReadData(
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
  DLOG(INFO) << "Storage::OnOpenTorrentReadMerkle: " << torrent->id().to_string() << " expected: " << expected << " readed: " << bytes;
  
  if (bytes < 0) {
   LOG(ERROR) << "OnOpenBlobReadMerkle error: error code = " <<  bytes;
   context->Signal(bytes);
   TerminateContext(context);
   return;
  }
  // theres no way the entry is not on the list at this point
  // so this should be safe, unless theres a big mistake somewhere else
  //Inode* inode = GetInode(context->key);
  
  storage_proto::EntryMerkleHeader merkle_header;
  size_t blob_size = (size_t)torrent->entry()->GetDataSize(kDATA_CONTENT);
  size_t merkle_hash_size = blob_size > 0 ? MerkleTree::GetTreeLength(blob_size) * kDefaultHashSize : 0;
  size_t header_size = bytes - merkle_hash_size;
  if (!merkle_header.ParseFromArray(context->hash_buffer->data(), header_size)) {
    LOG(ERROR) << "OnOpenBlobReadMerkle error: decoding protobuf merkle tree metadata with size " << header_size << " failed";
    context->Signal(-1);
    TerminateContext(context);
    return;
  }
  int header_content_size = merkle_header.content_size();
  char* ptr = context->hash_buffer->data(); 
  // jump the section of the payload with the header on it
  ptr += header_size;

  const auto& merkle_tree_header = merkle_header.node(0);
  std::unique_ptr<MerkleTree> merkle_tree = MerkleTree::Load(ptr, blob_size);
    
  //printf("open (%s): adding recovered merkle tree: hash size = %zu blob size = %ld leaf_count = %zu\n", context->key.to_string().c_str(), bytes, blob_size, merkle_tree->leaf_count());
  //merkle_tree->Print();
  //merkle_tree_list_.emplace(std::make_pair(context->key, std::move(merkle_tree)));
  torrent->set_merkle_tree(std::move(merkle_tree));

  //torrent->OnMetadataDone();

  context->Signal(0);
  TerminateContext(context);
}

Future<int> Storage::CloseTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal, int jrn_seq) {
  // DLOG(INFO) << "Storage::CloseTorrent: " << torrent->id().to_string() << " journal? " << is_journal;
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kCLOSE_BLOB, torrent, CompletionCallback());
  context->is_journal = is_journal;
  context->jrn_seq = jrn_seq;
  context->should_close = true;
  bool sync = false;
  if (!is_journal && !torrent->is_open()) {
    // DLOG(INFO) << "Storage::CloseTorrent: " << torrent->id().to_string() << " not open. just returning";
    context->Signal(net::OK);
    TerminateContext(context);
    return Future<int>(context->sync_event_, true);
  }
//  if (frontend_task_runner_->RunsTasksInCurrentSequence()) {
//    sync = true;
//    UpdateTorrentMetadataImpl(context);
//  } else {
    //frontend_task_runner_->PostTask(
    context->task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(
        &Storage::UpdateTorrentMetadataImpl, 
        base::Unretained(this),
        context));
 // }
  return Future<int>(context->sync_event_, sync);
}

void Storage::UpdateTorrentMetadataImpl(scoped_refptr<Storage::StorageContext> context) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //DLOG(INFO) << "Storage::UpdateTorrentMetadataImpl: " << torrent->id().to_string() << " journal? " << context->is_journal;

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
    //real_key = key.substr(0, offset);
    //context->key = real_key;
    //// DLOG(INFO) << "Storage::CloseBlobImpl: real key = " << real_key;
    // close the journal, right now
    //auto it = entries_.find(key);
    //if (it != entries_.end()) {
    // DLOG(INFO) << "Storage::UpdateTorrentMetadataImpl: is journal file. closing " << torrent->GetJournalPath(context->jrn_seq) << " journal";
    //it->second->entry->Close();
    //entries_.erase(it);
    //}
    torrent->CloseJournal(context->jrn_seq);
    //context->is_journal = false;
  }

  bool merkle_tree_changed = false;
  MerkleTree* merkle_tree = torrent->merkle_tree();
  if (merkle_tree && merkle_tree->is_dirty()) {
    // if the digest buffer had to grow, it means there was no fixed initial size
    // so theres a need to recalculate the parent nodes of the merkle tree
    // and thats a thing 'Rebuild()' is prepared for
    // while 'Build()' is meant for when we know the full size when we create the merkle tree
    // so is just a matter of zero the leafs that left, and calculate the parents
    if (torrent->entry()->is_new()) {
      //DLOG(INFO) << "UpdateTorrentMetadataImpl: calling merkle tree Build()";
      merkle_tree->Build();
    } else {
      //DLOG(INFO) << "UpdateTorrentMetadataImpl: calling merkle tree Rebuild()";
      merkle_tree->Rebuild();
    }
    WriteTorrentMerkleImpl(context);
  } else {
    if (!context->is_journal && context->should_close && torrent->is_open()) {
      //LOG(INFO) << "not a journal file, no change on data and is open. just closing..";
      torrent->entry()->Close();
      torrent->opened_ = false;
    }
    context->Signal(net::OK);
    TerminateContext(context);
  }
  //// DLOG(INFO) << "Storage::CloseBlobImpl end";
}

Future<int> Storage::DeleteTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal) {
  //// DLOG(INFO) << "Storage::DeleteBlob: " << key;
  // DLOG(INFO) << "Storage::DeleteTorrent: " << torrent->id().to_string() << " journal? " << is_journal;
  scoped_refptr<StorageContext> context = CreateContext(StorageContext::kDELETE_BLOB, torrent, CompletionCallback());
  context->is_journal = is_journal;
  bool sync = false;
  //if (frontend_task_runner_->RunsTasksInCurrentSequence()) {
  //  DeleteTorrentImpl(context);
  //  sync = true;
  //} else {
    //frontend_task_runner_->PostTask(
    //frontend_task_runner_->PostTask(
    context->task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(
        &Storage::DeleteTorrentImpl, 
        base::Unretained(this),
        context));
  //}
  return Future<int>(context->sync_event_, sync);
}

void Storage::DeleteTorrentImpl(scoped_refptr<Storage::StorageContext> context) {
  context->BindNext(&Storage::OnDeleteTorrent);
  int rc = net::ERR_FAILED;
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // DLOG(INFO) << "Storage::DeleteTorrentImpl: " << torrent->id().to_string() << " journal? " << context->is_journal;
  //StorageEntry* entry = context->is_journal ? torrent->journal_entry_ : torrent->entry_;
  //if (entry) {
  //  entry->Close();
  //}
  if (context->is_journal) {
    std::pair<std::string, StorageEntry*> entry = torrent->PopJournalFromDeleteList();
    // DLOG(INFO) << "Storage::DeleteTorrentImpl: deleting '" << entry.first << "'";
    rc = backend_->DoomEntry(entry.first, context->next_callback); 
  } else { 
    // DLOG(INFO) << "Storage::DeleteTorrentImpl: deleting '" << torrent->id().to_string() << "'";
    rc = backend_->DoomEntry(torrent->id(), context->next_callback);
  }
  
  if (rc != net::ERR_IO_PENDING) {
    context->next_callback.Run(rc);
  }
}

void Storage::OnDeleteTorrent(scoped_refptr<Storage::StorageContext> context, int64_t result) {
  //LOG(ERROR) << "Storage::OnDeleteTorrent: r = " << result;
  const scoped_refptr<Torrent>& torrent = context->torrent;
  if (result != 0) {
     LOG(ERROR) << "Storage::OnDeleteTorrent: failed deleting torrent for entry = " << context->key.to_string();
  }
  context->Signal(result);
  TerminateContext(context);
}

void Storage::OnWriteTorrentMerkle(scoped_refptr<StorageContext> context, int64_t expected, int64_t result) {
  //if (expected != result) {
   //LOG(ERROR) << "OnWriteBlobMerkle: expected = " << expected << " != result " << result;
  //}

  //Inode* inode = GetInode(context->key);
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //LOG(INFO) << "Storage::OnWriteTorrentMerkle: " << torrent->id().to_string() << " expected: " << expected << " wrote: " << result;
  MerkleTree* merkle_tree = torrent->merkle_tree();//merkle_tree_list_.find(context->key)->second.get();
  if (torrent && (torrent->entry()->is_modified() || torrent->entry()->is_new()) ) {
    torrent->mutable_info()->set_root_hash(merkle_tree->root_hash());
    torrent->mutable_info()->set_piece_count(merkle_tree->block_count());
    torrent->mutable_info()->set_length(torrent->entry()->GetDataSize(kDATA_CONTENT));
    torrent->mutable_info()->set_state(storage_proto::STATE_FINISHED);

    //int last_pos = torrent->info().pieces_size();
    //int piece_dif = merkle_tree->block_count() - last_pos; 
    //for (int i = 0; i < piece_dif; i++) {
    //  auto piece = torrent->mutable_info()->add_pieces();
    //  piece->set_index(last_pos);
    //  piece->set_length(kBlockSize);
    //  piece->set_state(storage_proto::STATE_FINISHED);
    //  last_pos++;
    //}
    // OnWriteBlobMerkle are used only for databases..
    // so i think is safe to reset the file to have the same lenght
    // as the whole entry.
    // For blobs, we can have one-to-many relationships
    // so this would be not right in that case
    for (int i = 0; i < torrent->info().inodes_size(); i++) {
      auto* inode = torrent->mutable_info()->mutable_inodes(i);
      inode->set_root_hash(merkle_tree->root_hash());
      inode->set_length(torrent->entry()->GetDataSize(kDATA_CONTENT));
    }
    
    if (torrent->entity()) {
      //LOG(INFO) << "Storage::OnWriteBlobMerkle: io entity for " << context->key.to_string() << " found = " << torrent->entity();
      torrent->entity()->OnInfoHeaderChanged(torrent->info());
    } else {
      //LOG(INFO) << "Storage::OnWriteBlobMerkle: io entity for " << context->key.to_string() << " is null";
    }

    if (!torrent->SerializeInfoToString(&context->encoded_header)) {
      //context->Exit(net::ERR_FAILED);
      LOG(ERROR) << "Error while encoding header for blob";
      context->Signal(-1);
      TerminateContext(context);
      return;
    }

    if (!context->is_journal) {
      printf("%s\n  path: %s\n  comment: %s\n  root hash: %s\n  piece_length: %ld\n  piece_count: %ld\n  length: %ld\n  inodes: %d\n", 
        torrent->id().to_string().c_str(),
        torrent->info().path().c_str(),
        torrent->info().comment().c_str(),
        base::HexEncode(torrent->info().root_hash().data(), torrent->info().root_hash().size()).c_str(),
        torrent->info().piece_length(),
        torrent->info().piece_count(),
        torrent->info().length(),
        torrent->info().inodes().size());
    }
    
    CompletionCallback callback = base::Bind(&Storage::OnWriteTorrentHeaderResult, base::Unretained(this), context, context->encoded_header.size());

    scoped_refptr<net::StringIOBuffer> header_data = new net::StringIOBuffer(context->encoded_header);
    
    context->header.bytes = torrent->entry()->WriteData(
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
  //LOG(INFO) << "Storage::OnWriteTorrentHeaderResult: " << torrent->id().to_string() << " journal? " << context->is_journal << " expected: " << expected << " wrote: " << result;
  if (!context->is_journal && context->should_close) {
    //LOG(INFO) << "Storage::OnWriteTorrentHeaderResult: not journal. so closing " << torrent->id().to_string() << "...";
    torrent->entry()->Close();
    torrent->entry_ = nullptr;
    torrent->opened_ = false;
  }

  torrent->OnMetadataDone();
  //MerkleTree* merkle_tree = torrent->merkle_tree();
    
  //if (merkle_tree && !context->is_journal) {
  //  torrent->merkle_tree_.reset();
  //}
  // unblock the db thread on Close
  context->Signal(0);
  context->BindNext(&Storage::OnWriteTorrentIndex);

   //if (!torrent->is_root() && result > 0 && !context->is_journal) {   
   // if (!torrent->is_root() && result > 0 && context->is_journal) {   
   //   //LOG(INFO) << "Storage::OnWriteTorrentHeaderResult: AddIndexOnRegistry " << torrent->id().to_string();
   //   int r = AddIndexOnTree(context);
   //   if (r != net::ERR_IO_PENDING) {
   //     context->Next(r);
   //   }
   // } else {
   context->Next(net::OK);
   //}
  //TerminateContext(context);
}

void Storage::OnWriteTorrentIndex(scoped_refptr<StorageContext> context, int64_t result) {
  // DLOG(INFO) << "Storage::OnWriteTorrentIndex: result " << result;
  //context->Signal(0);
  TerminateContext(context);
}


void Storage::OnWriteTorrent(scoped_refptr<StorageContext> context, int64_t expected, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // DLOG(INFO) << "Storage::OnWriteTorrent: " << torrent->id().to_string() << " result " << result;

  if (expected == result && !context->is_journal) {
    // only schedule checkpoints if this is not the root
    if (root_tree_->id() != torrent->id()) {
      torrent->set_dirty(true);
    } else {
      DLOG(INFO) << "Storage::OnWriteTorrent: root tree torrent detected. not scheduling checkpoints";
    }
    torrent->entry()->set_modified(true);
  }
  context->write.bytes = result;
  context->Signal(0);
  TerminateContext(context);
}

void Storage::OnCreateDatabase(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // DLOG(INFO) << "Storage::OnCreateDatabase: " << torrent->id().to_string() << " r = " << result;
  if (result == net::OK) {
    // in case of databases, we add it to the persistent cache
    //entries_.emplace(std::make_pair(context->key, std::make_unique<Storage::Inode>(context->ptr)));
    DCHECK(torrent);

    context->BindNext(&Storage::OnCreateDatabaseWriteManifest);
    
    base::Time creation_time = base::Time::Now();

    std::string content_type;
  
    // form the header
    storage_proto::Info header;
    header.set_kind(storage_proto::INFO_DATA);
    header.set_state(storage_proto::STATE_FINISHED);
    header.set_id(torrent->id().string());
    header.set_comment(torrent->info().path()  + " database");
    header.set_creation_date(creation_time.ToInternalValue());
    header.set_mtime(creation_time.ToInternalValue());
    header.set_readonly(false);
    
    //std::string table_id = base32::Base32Encode("hello_table", base32::Base32EncodePolicy::OMIT_PADDING);;

    const std::vector<std::string>& keyspaces = context->create_db_params.keyspaces;
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
      net::GetMimeTypeFromExtension("db", &content_type);
      inode->set_content_type(content_type.empty() ? "application/octet-stream" : content_type);
//      inode->set_type(storage_proto::INODE_KEYSPACE);
      offset++;
    }

    torrent->LoadInfo(header);

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
    
    context->header.bytes = torrent->entry()->WriteData(
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
  //// DLOG(INFO) << "Storage::OnOpenDatabase: " << context->key << " r = " << result;
  const scoped_refptr<Torrent>& torrent = context->torrent;
  // DLOG(INFO) << "Storage::OnOpenDatabase: " << torrent->id().to_string() << " r = " << result;
  if (result == net::OK) {
    // in case of databases, we add it to the persistent cache
    //entries_.emplace(std::make_pair(context->key, std::make_unique<Storage::Inode>(context->ptr)));
    DCHECK(torrent);
    context->BindNext(&Storage::OnOpenDatabaseReadManifest);

    context->header_data = new net::IOBufferWithSize(1024 * 16);
    context->header.bytes = torrent->entry()->ReadData(//context->entry()->ReadData(
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

  // DLOG(INFO) << "Storage::OnOpenDatabaseReadManifest: " << torrent->id().to_string() << " r = " << bytes_readed;
  
  if (bytes_readed > 0) {
    DCHECK(torrent);
    if (!torrent->LoadInfoFromBytes(context->header_data->data(), bytes_readed)) {
      DLOG(ERROR) << "error parsing db entry manifest";
      context->Exit(net::ERR_FAILED);
      return;
    }
    //context->db = Database::Open(torrent);
    //if (!context->db) {
    //  context->Exit(net::ERR_FAILED);
    //  return;
    //}
    context->Exit(net::OK);
  } else {
    context->Exit(bytes_readed);
  }
}

void Storage::OnCreateDatabaseWriteManifest(scoped_refptr<StorageContext> context, int64_t bytes_written) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  
  // DLOG(INFO) << "Storage::OnCreateDatabaseWriteManifest: " << torrent->id().to_string() << " r = " << bytes_written;
  
  //if (bytes_written > 0) {
    DCHECK(torrent);
    //context->db = Database::Create(torrent, context->key);
    //if (!context->db) {
    //  CompletionCallback callback;
    //  TerminateContext(context, &callback);
    //  if (!callback.is_null()) {
    //    callback.Run(net::ERR_FAILED);
    //  }
    //  return;
    //}
  //} else {
    CompletionCallback callback;
    TerminateContext(context, &callback);
    if (!callback.is_null()) {
      callback.Run(bytes_written);
    }
  //}
}

void Storage::OnCopyFile(scoped_refptr<StorageContext> context, int64_t result) {
  ////// DLOG(INFO) << "Storage::OnCopyFile. result = " << result;
  if (result == net::OK) {
    context->BindNext(&Storage::ReadFile); 
    //context->entry()->ReadyForSparseIO(CompletionCallback());
    context->file = context->files.Load(context->src);
    if (context->file < 0) {
      printf("error: could not open input file '%s'\n", context->src_string().c_str());
      context->Exit(net::ERR_FAILED);
      return;
    }
    // now write the data from the input file
    context->bytes_total = context->files.GetLength(context->file);
    context->Next(0);
  } else {
    //printf("blob storage entry create error. code =  %ld\n", result);
    context->Exit(result);
  }
}

void Storage::OnCopyEntry(scoped_refptr<StorageContext> context, int64_t result) {
  ////// DLOG(INFO) << "Storage::OnCopyEntry. result = " << result;
  const scoped_refptr<Torrent>& torrent = context->torrent;
  if (result == net::OK) {
    context->BindNext(&Storage::ReadEntry);
    context->bytes_total = torrent->entry()->GetDataSize(kDATA_CONTENT);
    //context->entry()->ReadyForSparseIO(CompletionCallback());
    context->copy_file = base::File(context->dest, base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_READ | base::File::FLAG_WRITE);
    //context->file = context->files.Load(context->dest, context->bytes_total, false);
    if (!context->copy_file.IsValid()) {
      printf("error: could not create/open output file '%s'\n", context->dest_string().c_str());
      context->Exit(net::ERR_FAILED);
      return;
    }
    // now write the data from the input file
    context->Next(0);
  } else {
    //printf("blob storage entry open error. code = %ld\n", result);
    context->Exit(result);
  }
}

void Storage::OnGetEntryInfo(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;

  context->BindNext(&Storage::DecodeEntryInfo);
  
  context->header_data = new net::IOBufferWithSize(1024 * 32);

  context->header.bytes = torrent->entry()->ReadData(
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

void Storage::OnInitEntry(scoped_refptr<StorageContext> context, int64_t result) {
  if (result != 0) {
    context->Exit(net::ERR_FAILED);
    return;
  }
   
  OnInitEntryWriteContent(context, 0, 0, 0);
}

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

void Storage::OnInitEntryWriteContent(scoped_refptr<StorageContext> context, int file_offset, int64_t expected, int64_t result) { 
  DLOG(INFO) << "Storage::OnInitEntryWriteContent: file_offset = " << file_offset << " expected = " << expected << " wrote = " << result;

  const scoped_refptr<Torrent>& torrent = context->torrent;

  if (result != expected) {
    DLOG(ERROR) << "write content failed: expected " << expected << " wrote " << result;
    context->Exit(net::ERR_FAILED);
    return;
  }

  // check if we are done
  if (file_offset >= int(context->files.file_count())) {
    context->BindNext(&Storage::OnInitEntryWriteHashes);
    context->Next(net::OK);
    return;
  }
  
  size_t size = context->files.GetLength(file_offset);
  
  CompletionCallback cb = base::Bind(&Storage::OnInitEntryWriteContent, base::Unretained(this), context, file_offset + 1, size); //GetWeakPtr(), context, file_offset + 1, size);

  size_t offset = 0;
  for (int i = 0; i < file_offset; ++i) {
    offset += context->files.GetLength(i);
  }
  
  char* data = reinterpret_cast<char *>(context->files.Map(file_offset));
  DCHECK(data);
  scoped_refptr<net::WrappedIOBuffer> buffer = new net::WrappedIOBuffer(data);

  DLOG(INFO) << "writing file " << file_offset << " with size " << size << " from " << offset  << " to " << offset + size << " on CONTENT sector";

  int r = torrent->entry()->WriteData(
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

void Storage::OnInitEntryWriteHashes(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  
  //DLOG(INFO) << "Storage::OnInitEntryWriteHashes: " << torrent->id().to_string() << " r = " << result << "\ntotal blob content size = " << 
  //  torrent->entry()->GetDataSize(kDATA_CONTENT) << "\ntotal input files size = " << context->files.GetTotalLength();

  storage_proto::EntryMerkleHeader merkle_header;
  
  context->BindNext(&Storage::OnInitEntryWriteManifest);

  size_t total_len = context->files.GetTotalLength();
  int block_count = context->files.GetTotalBlockCount();
    
  context->init.block_count = block_count;
  context->init.content_len = total_len;
  context->init.block_size = kBlockSize;

  merkle_header.set_count(1);//context->files.file_count() + 1);

  // create the merkle tree for all the files
  std::unique_ptr<MerkleTree> merkle = GenerateMerkleTreeForFiles(&context->files);
  if (!merkle) {
    DLOG(ERROR) << "error while generating merkle tree for blobs";
    context->Exit(net::ERR_FAILED);
    return;
  }

  torrent->set_merkle_tree(std::move(merkle));

  MerkleTree* entry_merkle = torrent->merkle_tree();//context->init.entry_merkle.get();

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
  
  // now add a header 'node' for each file
  //for (size_t i = 0; i < context->files.file_count(); i++) {
  //  MerkleTree* merkle_tree = context->files.GetMerkleTree(i);
  //  
  //  auto* node = merkle_header.add_node();
  //  node->set_content_size(merkle_tree->digest_size());
  //  node->set_node_count(merkle_tree->node_count());
  //  node->set_leaf_count(merkle_tree->leaf_count());
  //  node->set_block_count(merkle_tree->block_count());
  //  node->set_first_leaf(merkle_tree->first_leaf_offset());
  //  
  //  header_content_size += merkle_tree->digest_size();
  //}
  
  merkle_header.set_content_size(header_content_size);

  std::string encoded_header;
  merkle_header.SerializeToString(&encoded_header);
  
  size_t allocated_size = encoded_header.size() + header_content_size;

  context->init.hash_header_len = encoded_header.size();
  context->init.hash_content_len = header_content_size;

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

  // write the header
  memcpy(current_buf, encoded_header.data(), encoded_header.size());
  current_buf += encoded_header.size();

  // write the merkle tree for the entry into the buffer
  entry_merkle->Encode(current_buf);

  // write the merkle trees for each file into the buffer 
  //for (size_t i = 0; i < context->files.file_count(); i++) {
  //  MerkleTree* merkle_tree = context->files.GetMerkleTree(i);
  //  merkle_tree->Encode(current_buf);
  //}
  
  // now persist into the entry 'DATA_MERKLE' sector
  int r = torrent->entry()->WriteData(
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

void Storage::OnInitEntryWriteManifest(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  //DLOG(INFO) << "Storage::OnInitEntryWriteManifest: r = " << result;
  //storage_proto::Info header;
  // if error exit early
  if (result < 0) {
    context->Exit(net::ERR_FAILED);
    return;
  }

  context->BindNext(&Storage::OnInitEntryWriteHeader);

  base::Time creation_time = base::Time::Now();
  
  MerkleTree* entry_merkle = torrent->merkle_tree();

  std::string entry_root_hash = entry_merkle->root_hash();

  storage_proto::Info header;
  header.set_kind(storage_proto::INFO_FILE);
  header.set_state(storage_proto::STATE_FINISHED);
  header.set_id(torrent->id().string());
  header.set_path(context->src.BaseName().value());
  header.set_root_hash(entry_root_hash);
  header.set_piece_length(context->init.block_size);
  header.set_piece_count(context->init.block_count);
  header.set_length(context->init.content_len);
  header.set_hash_header_length(context->init.hash_header_len);
  header.set_hash_content_length(context->init.hash_content_len);
  //header->set_comment(description);
  header.set_creation_date(creation_time.ToInternalValue());
  header.set_mtime(creation_time.ToInternalValue());
  
  printf("id: %s\n  root hash: %s\n  piece_length: %ld\n  piece_count: %ld\n  length: %ld\n  hashes size: %d\n  files: %ld\n", 
    torrent->id().to_string().c_str(),
    //description.c_str(),
    base::HexEncode(entry_root_hash.data(), entry_root_hash.size()).c_str(),
    context->init.block_size,
    context->init.block_count,
    context->init.content_len,
    context->hash_buffer->size(),
    context->init.file_count);
  
  //for (int i = 0; i < context->init.block_count; i++) {
  //  auto piece = header.add_pieces();
  //  piece->set_index(i);
  //  piece->set_length(kBlockSize);
  //  piece->set_state(storage_proto::STATE_FINISHED);
  //}

  int block_start = 1;
  for (int i = 0; i < context->init.file_count; i++) {
    std::string content_type;
    base::Time time = base::Time::Now();
    base::StringPiece file_fullpath = context->files.GetPath(i);
    base::StringPiece file_path = FormatFilePath(file_fullpath);
    size_t file_size = context->files.GetLength(i);
    int block_count = context->files.GetBlockCount(i);

    net::GetMimeTypeFromFile(base::FilePath(file_fullpath), &content_type);

    int block_end = block_start + block_count - 1;
    //std::string blob_root_hash = context->files.GetMerkleRoot(i);
    //MerkleTree* merkle_tree = context->files.GetMerkleTree(i);
    
    // add it
    auto* inode = header.add_inodes();
    inode->set_parent(context->key.string());
    inode->set_name(file_path.as_string());
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
 //   inode->set_type(storage_proto::INODE_FILE);
    // if (is_executable)
    //   inode->set_attr("x");
    std::string json_str;
    google::protobuf::util::JsonPrintOptions options;
    options.add_whitespace = true;
    options.always_print_primitive_fields = true;
    options.preserve_proto_field_names = true;
    google::protobuf::util::MessageToJsonString(*inode, &json_str, options);

    printf("%s\n", json_str.c_str());
    block_start += block_count;
  }

  torrent->LoadInfo(header);
  
  if (!torrent->SerializeInfoToString(&context->encoded_header)) {
    LOG(ERROR) << "init: serializing protobuf header to string failed";
    context->Exit(net::ERR_FAILED);
    TerminateContext(context);
    return;
  }

  scoped_refptr<net::StringIOBuffer> manifest_buf = new net::StringIOBuffer(context->encoded_header);
  // write the manifest
  int r = torrent->entry()->WriteData(
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

void Storage::OnInitEntryWriteHeader(scoped_refptr<StorageContext> context, int64_t result) {
  DLOG(INFO) << "Storage::OnInitEntryWriteHeader: r = " << result;
  const scoped_refptr<Torrent>& torrent = context->torrent;
  
  if (result < 0) {
    context->Exit(net::ERR_FAILED);
    TerminateContext(context);
    return;
  }

  // for safety we close the entry now
  torrent->entry()->Close();

  context->BindNext(&Storage::OnInitEntryWriteIndex);
  int r = AddIndexOnTree(context);
  if (r != net::ERR_IO_PENDING) {
    context->Next(r);
  }
}
 
void Storage::OnInitEntryWriteIndex(scoped_refptr<StorageContext> context, int64_t result) {
  DLOG(INFO) << "Storage::OnInitEntryWriteIndex: r = " << result;
  context->Exit(result);
  TerminateContext(context);
}

void Storage::ReadFile(scoped_refptr<StorageContext> context, int64_t bytes_written) {
  context->BindNext(&Storage::WriteEntryManifest);
  
  int last_pos = context->read.offset + context->read.bytes;

  if (bytes_written < 0) {
    printf("write error. cancelling\n");
    context->Exit(-2);
    return;
  }

  bool is_done = context->bytes_total == last_pos ? true : false;
  
  // update
  context->write.bytes = bytes_written;

  // write was ok, so update the offset
  context->read.offset += bytes_written;

  // we need to check seek first
  
  // we dont need to check the error here, cause its done on the next callback
  FileSet::Reader reader;
  context->files.GetReader(context->file, &reader);
  char* buf = context->buffer->data();
  context->read.bytes = reader.Read(context->read.offset, &buf, context->buffer->size());
  int result = is_done ? net::OK : context->read.bytes;
  context->Next(result);
}

void Storage::ReadEntry(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  context->BindNext(&Storage::ReadEntryContent);
  
  // we dont know the real size, so we try to make enough room
  context->header_data = new net::IOBufferWithSize(1024 * 32);

  context->header.bytes = torrent->entry()->ReadData(
    kDATA_MANIFEST, // slot offset:  0 = header
    context->header.offset, // byte offset
    context->header_data.get(),
    context->header_data->size(),
    context->next_callback);

  if (context->header.bytes != net::ERR_IO_PENDING) {
    context->Next(context->header.bytes);
  }
}


void Storage::WriteEntryContent(scoped_refptr<StorageContext> context, int64_t bytes_readed) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  if (bytes_readed <= 0) { // its either EOF or an error
                           // so we change the course
    if (bytes_readed == 0) {
      context->BindNext(&Storage::WriteEntryManifest);
      context->Next(bytes_readed);
    } else {
      context->Exit(bytes_readed);
    }
    return;
  }

  context->BindNext(&Storage::ReadFile);
   
  // update the hash first
  //SHA256_Update(&context->sha2_ctx, context->buffer->data(), context->read.bytes);
  
  context->write.status = torrent->entry()->WriteData(
                                  kDATA_CONTENT, // slot offset:  1 = content
                                  context->read.offset, 
                                  context->buffer.get(), 
                                  context->read.bytes,
                                  context->next_callback,
                                  false);

  if (context->write.status != net::ERR_IO_PENDING) {
    context->Next(context->write.status);
  }
}

void Storage::WriteEntryManifest(scoped_refptr<StorageContext> context, int64_t result) {
  // NOTE: this method is not a valid way to save blobs anymore
  // so im disabling it til i figure it out who uses it 
  DCHECK(false);
}

void Storage::ReadEntryContent(scoped_refptr<StorageContext> context, int64_t result) {
  const scoped_refptr<Torrent>& torrent = context->torrent;
  context->BindNext(&Storage::OnReadEntryContent);

  int size_to_read = context->buffer->size();
  // first.. check if the reading the header succeeded.
  if (context->read.offset == 0 && context->header.status != net::OK) { 
    // there was an error reading the header, exit early
    context->Exit(context->header.status);
    return;
  }

  context->read.bytes = torrent->entry()->ReadData(
    kDATA_CONTENT,
    context->read.offset, 
    context->buffer.get(), 
    size_to_read,
    context->next_callback);

  if (context->read.bytes != net::ERR_IO_PENDING) {
    context->Next(context->read.bytes);
  }
}


void Storage::OnReadEntryContent(scoped_refptr<StorageContext> context, int64_t readed) {

  context->BindNext(&Storage::ReadEntryContent);

  if (readed < 0 ) {
    printf("read error at offset %ld: %ld", context->read.offset, readed);
    context->copy_file.Close();
    context->Exit(readed);
    return;
  }
  
  // this is EOF. we are done
  if (readed == 0) {
    //SHA256_Final(reinterpret_cast<uint8_t *>(context->computed_hash->data()), &context->sha2_ctx);
    context->copy_file.Close();
    context->Exit(readed);
    return;
  }
  
  int wr = 0;
  if ((wr = context->copy_file.Write(context->read.offset, context->buffer->data(), readed)) == -1) {
    LOG(ERROR) << "file.Write error ("<< wr << ") at offset " << context->read.offset << 
      " while trying to write " << readed << " bytes";
    context->copy_file.Close();
    context->Exit(-2);
    return;
  }

  context->write.bytes = wr;

  if (context->write.bytes != readed) {
    LOG(ERROR) << "write != readed " << context->write.bytes << " vs. " << readed;
    context->copy_file.Close();
    context->Exit(-2);
  }

  //SHA256_Update(&context->sha2_ctx, context->buffer->data(), readed);
  context->read.offset += context->write.bytes;
  context->Next(0);
}

void Storage::OnReadEntryManifest(scoped_refptr<StorageContext> context, int64_t result) {
  // NOTE: this method is not a valid way to save blobs anymore
  // so im disabling it til i figure it out who uses it 
  DCHECK(false);
}

// TODO: we should move this to catalog
// int64_t Storage::WriteDatabaseMetadata(scoped_refptr<StorageContext> context, Database* db) {
//   //// DLOG(INFO) << "Storage::WriteDatabaseMetadata";
//   storage_proto::CatalogMetadata catalog_meta_proto;
  
//   int table_count = context->create_db_params.initial_table_count;
//   // now fill the meta with catalog metadata
//   storage_proto::Catalog* catalog_proto = catalog_meta_proto.mutable_catalog();
//   catalog_proto->set_name(context->key);
//   catalog_proto->set_table_count(table_count);
  
//   storage_proto::Table* meta_table = catalog_proto->mutable_meta_table();
//   meta_table->set_name("meta");
//   // meta is equivalent to table 0. and starts at the first page
//   meta_table->set_index(0);
 
//   auto* id_column = meta_table->add_column();

//   id_column->set_name("id");
//   id_column->set_type(storage_proto::COLUMN_INT32);
//   id_column->set_offset(0);

//   auto* table_name_column = meta_table->add_column();
  
//   table_name_column->set_name("table_name");
//   table_name_column->set_type(storage_proto::COLUMN_STRING);
//   table_name_column->set_offset(1);

//   for (int i = 0; i < table_count; i++) {
//     storage_proto::Table* table = catalog_proto->add_table();
//     table->set_name("table"+ base::NumberToString(i));
//     // first page is reserved to meta, so we need to skip one
//     table->set_index(i + 1);
//   }
  
//   std::string encoded_catalog;
//   if (!catalog_meta_proto.SerializeToString(&encoded_catalog)) {
//     DLOG(ERROR) << "failed encoding catalog";
//     return {};
//   }

//   if (!db->Put(meta_table->index(), "catalog.proto", encoded_catalog)) {
//     DLOG(ERROR) << "failed while writing catalog into db";
//     return {};
//   }

//   //// DLOG(INFO) << "Storage::WriteDatabaseMetadata: copying info";
//   storage_proto::Info catalog_info;
//   catalog_info.CopyFrom(context->info);
//   return std::make_unique<DataCatalog>(std::move(catalog_info), context->key, db_task_runner_, std::move(db));
// }

void Storage::ReplyCopyFile(scoped_refptr<StorageContext> context, CompletionCallback user_callback, int64_t result) {
  //base::HexEncode(context->computed_hash->data(), context->computed_hash->size());
  main_task_runner_->PostTask(FROM_HERE, base::Bind(user_callback, result));
}

void Storage::ReplyCopyEntry(scoped_refptr<StorageContext> context, CompletionCallback user_callback, int64_t result) {
  //base::HexEncode(context->computed_hash->data(), 
  //                context->computed_hash->size());
  
  main_task_runner_->PostTask(FROM_HERE, base::Bind(user_callback, result));
}

void Storage::ReplyGetEntryInfo(
    scoped_refptr<StorageContext> context,
    base::Callback<void(storage_proto::Info, int64_t)> callback,
    storage_proto::Info header,
    int64_t result) {

  main_task_runner_->PostTask(FROM_HERE, base::Bind(callback, std::move(header), result));
}

void Storage::ReplyInitEntry(scoped_refptr<StorageContext> context, CompletionCallback user_callback, int64_t result) {
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
    //std::unique_ptr<Catalog> db,
    base::Callback<void(int64_t)> callback,
    int64_t result) {
  //main_task_runner_->PostTask(
  //  FROM_HERE, 
  //  base::Bind(&Delegate::OnCatalogOpen, 
  //    base::Unretained(delegate_),
  //    base::Passed(std::move(callback)),
  //    base::Passed(std::move(db)),  
  //    result));

  main_task_runner_->PostTask(
    FROM_HERE,
    base::Bind(callback, result));
}

void Storage::ReplyCreateDatabase(
    //std::unique_ptr<Catalog> db,
    base::Callback<void(int64_t)> callback,
    int64_t result) {

  //main_task_runner_->PostTask(
  //  FROM_HERE, 
  //  base::Bind(&Delegate::OnCatalogCreate, 
  //    base::Unretained(delegate_),
  //    base::Passed(std::move(callback)),
  //    base::Passed(std::move(db)), 
  //    result));

  main_task_runner_->PostTask(
    FROM_HERE,
    base::Bind(callback, result));
}

// void Storage::ReplyOpenApplication(
//     //std::unique_ptr<Application> application,
//     base::Callback<void(int64_t)> callback,
//     int64_t result) {
//   main_task_runner_->PostTask(
//     FROM_HERE, 
//     base::Bind(&Delegate::OnApplicationOpen, 
//       base::Unretained(delegate_),
//       base::Passed(std::move(callback)),
//       base::Passed(std::move(application)),  
//       result));
// }

// void Storage::ReplyCreateApplication(
//     //std::unique_ptr<Application> application,
//     base::Callback<void(int64_t)> callback,
//     int64_t result) {
//   main_task_runner_->PostTask(
//     FROM_HERE, 
//     base::Bind(&Delegate::OnApplicationCreate, 
//       base::Unretained(delegate_),
//       base::Passed(std::move(callback)),
//       base::Passed(std::move(application)), 
//       result));
// }

scoped_refptr<Storage::StorageContext> Storage::GetContext(int key) {
  contexts_lock_.Acquire();
  auto context_it = contexts_.find(key);
  if (context_it == contexts_.end()) {
    return nullptr;
  }
  scoped_refptr<Storage::StorageContext> result = context_it->second;
  contexts_lock_.Release(); 
  return result;
}

int Storage::GetContextId(Storage::StorageContext::Opcode code, const base::UUID& key) {
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

scoped_refptr<Storage::StorageContext> Storage::GetContext(Storage::StorageContext::Opcode code, const base::UUID& key) {
  scoped_refptr<Storage::StorageContext> result;
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

scoped_refptr<Storage::StorageContext> Storage::CreateContext(Storage::StorageContext::Opcode code, const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb) {
  scoped_refptr<StorageContext> context = new StorageContext(code, this);
  int id = context_id_gen_.GetNext() + 1;
  context->id = id;
  context->torrent = torrent;
  if (code == Storage::StorageContext::kCREATE_CATALOG || code == Storage::StorageContext::kOPEN_CATALOG) {
    context->task_runner =
      base::CreateSingleThreadTaskRunnerWithTraits(
        { base::MayBlock(),
          base::WithBaseSyncPrimitives() },
        base::SingleThreadTaskRunnerThreadMode::DEDICATED);
  } else {
    context->task_runner = frontend_task_runner_;
  }
  context->key = torrent->id();
  context->exit_callback = std::move(cb);
  contexts_lock_.Acquire();
  contexts_.emplace(id, context);
  contexts_lock_.Release();
  torrent->inc_busy_counter();

  return context;
}

void Storage::TerminateContext(scoped_refptr<StorageContext> context, CompletionCallback* user_callback) {
  scoped_refptr<Torrent> torrent = std::move(context->torrent);

  contexts_lock_.Acquire();
  auto context_it = contexts_.find(context->id);
  if (context_it == contexts_.end()) {
    DLOG(ERROR) << "TerminateContext: context for " << context->id << " not found.";
    return;
  }

  if (!context_it->second->exit_callback.is_null()) {
    *user_callback = std::move(context_it->second->exit_callback);
  }

  context_it->second->parent = nullptr;
  contexts_.erase(context_it);
  contexts_lock_.Release();
  
  torrent->dec_busy_counter();
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
  DLOG(INFO) << "Storage::GetUUID";
  name_index_lock_.Acquire();
  auto it = name_index_.find(name);
  if (it != name_index_.end()) {
    *id = it->second;
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
  DLOG(INFO) << "Storage::ResolveUUID";
  DBOpenCloser closer(root_tree_);
  std::unique_ptr<storage::Transaction> tr = root_tree_->db().BeginTransaction(false);
  auto cursor = root_tree_->db().CreateCursor(tr.get(), "index");
  DCHECK(cursor);
  base::StringPiece data_view;
  bool r = cursor->GetValue(name, &data_view);
  if (!r) {
    DLOG(ERROR) << "resolving name '" << name << "' to uuid failed. nothing found on the index";
    tr->Rollback();
    return false;
  }
  DCHECK(data_view.size());
  bool ok = false;
  *out = base::UUID::from_string(data_view.as_string(), &ok);//base::UUID(reinterpret_cast<const uint8_t *>(data_view.data()));
  if (!ok) {
    DLOG(ERROR) << "resolving name '" << name << "' to uuid failed. could not convert result uuid in string format '" << data_view <<"'";
    tr->Rollback();
    return false;
  }
  tr->Commit();

  return true;
}

void Storage::RunIO(scoped_refptr<StorageContext> context) {
  context->task_runner->PostTask(
    FROM_HERE, 
    base::BindOnce(&Storage::RunIOImpl, context));
}

void Storage::RunIOImpl(scoped_refptr<StorageContext> context) {
  switch (context->op) {
    case x:
    default:
  }
}

}
