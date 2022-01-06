// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/storage.h"

#include "base/macros.h"
#include "base/logging.h"
#include "base/uuid.h"
#include "base/threading/thread_restrictions.h"
#include "base/strings/stringprintf.h"
#include "base/files/file_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/files/file.h"
#include "base/bind.h"
#include "base/sequenced_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "storage/storage_file.h"
//#include "storage/application.h"
#include "storage/storage_utils.h"
#include "storage/storage_file.h"
#include "storage/storage_constants.h"
#include "storage/storage_backend.h"
#include "storage/db/db.h"
#include "storage/torrent.h"
//#include "storage/catalog.h"
//#include "storage/data_catalog.h"
//#include "storage/data_table.h"
#include "components/base32/base32.h"
//#include "storage/registry_catalog.h"
#include "net/base/net_errors.h"
#include "net/base/io_buffer.h"
#include "third_party/zetasql/public/analyzer.h"
#include "third_party/zetasql/resolved_ast/resolved_ast.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/sha.h"

namespace storage {

// static 
std::unique_ptr<Storage> Storage::Create(const base::FilePath& input_dir,
                                   TorrentCache* torrent_cache,
                                   scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
                                   //scoped_refptr<base::SingleThreadTaskRunner> frontend_task_runner,
                                   scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
                                   //scoped_refptr<base::SingleThreadTaskRunner> db_task_runner,
                                   std::string id,
                                   const char* pkey,
                                   bool force) {
  bool first_run = false; 
  if (!base::DirectoryExists(input_dir)) {
    first_run = true;
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
    first_run = true;
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
        //frontend_task_runner,
        backend_task_runner,
        std::move(disk_state),
        std::move(id),
        pkey,
        first_run));
}

// static 
std::unique_ptr<Storage> Storage::Open(const base::FilePath& path,
                                 TorrentCache* torrent_cache,
                                 scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
          //                       scoped_refptr<base::SingleThreadTaskRunner> frontend_task_runner,
                                 scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner) {//,
                                 //scoped_refptr<base::SingleThreadTaskRunner> db_task_runner) {
   std::unique_ptr<storage_proto::StorageState> state(new storage_proto::StorageState());
   return Storage::Open(
    path, 
    torrent_cache, 
    main_task_runner, 
    //frontend_task_runner, 
    backend_task_runner, 
    std::move(state), 
    false);//db_task_runner, std::move(state), false);
}

// static 
std::unique_ptr<Storage> Storage::Open(
  const base::FilePath& path,
  TorrentCache* torrent_cache,
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
  //scoped_refptr<base::SingleThreadTaskRunner> frontend_task_runner,
  scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
  //scoped_refptr<base::SingleThreadTaskRunner> db_task_runner,
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
    //    frontend_task_runner,
        backend_task_runner,
        std::move(state),
        std::string(),
        nullptr,
        first_run));
}

Storage::Storage(TorrentCache* torrent_cache,
           const base::FilePath& path,
           scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
      //     scoped_refptr<base::SingleThreadTaskRunner> frontend_task_runner,
           scoped_refptr<base::SingleThreadTaskRunner> backend_task_runner,
           std::unique_ptr<storage_proto::StorageState> disk_state,
           std::string id,
           const char* pkey,
           bool first_run):
  path_(path),
  state_(std::move(disk_state)),
  frontend_task_runner_(
    base::CreateSingleThreadTaskRunnerWithTraits(
      { base::MayBlock()//, 
        //base::WithBaseSyncPrimitives() 
      },
      base::SingleThreadTaskRunnerThreadMode::SHARED)
  ),
  backend_task_runner_(backend_task_runner),
  backend_(new StorageBackend(this, torrent_cache, main_task_runner, backend_task_runner, frontend_task_runner_, path, first_run)),
  given_pkey_if_cloned_(pkey),
  given_id_if_cloned_(std::move(id)),
  initialized_(false),
  first_run_(first_run),
  initializing_(false),
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
  //db_task_runner_ = nullptr;
}

void Storage::Start(base::Callback<void(Storage*, int)> callback) {
  //DLOG(INFO) << "Storage::Start: " << path_.BaseName().value();
  if (state_->status() == storage_proto::STORAGE_STATUS_ONLINE || initializing_) {
    //DLOG(INFO) << "Storage start: cancelled. already online or in the middle of initialization process";
    if (!callback.is_null())
      callback.Run(this, -2);
    return;
  }
  initializing_ = true;
  Manifest::InitParams params;
  if (first_run_) {
    if (given_pkey_if_cloned_) {
      memcpy(params.public_key.bytes.data(), given_pkey_if_cloned_, 32);
      params.is_owner = false;
      params.root_tree = base::UUID(reinterpret_cast<const uint8_t *>(given_id_if_cloned_.data()));
    } else {
      std::array<char, 32> seed = libtorrent::dht::ed25519_create_seed();
      std::tuple<libtorrent::dht::public_key, libtorrent::dht::secret_key> keys = libtorrent::dht::ed25519_create_keypair(seed);
      params.public_key = std::move(std::get<0>(keys));
      params.private_key = std::move(std::get<1>(keys));
      params.root_tree = base::UUID::generate();
      params.is_owner = true;
    }
    params.base32_address = path_.BaseName().value();//base32::Base32Encode(base::StringPiece(params.public_key.bytes.data(), params.public_key.bytes.size()), base32::Base32EncodePolicy::OMIT_PADDING);
    params.creator = "Pato Donald";
    printf("address: %s\nroot: %s\nchave publica: %s\n", params.base32_address.c_str(), params.root_tree.to_string().c_str(), base::HexEncode(params.public_key.bytes.data(), 32).c_str());
    
  }
  //if (frontend_task_runner_ == base::ThreadTaskRunnerHandle::Get()) {
  //  backend_->Init(
  //        std::move(params),
  //        base::Bind(&Storage::OnBackendInit,
  //          base::Unretained(this),
  //          callback));
  //}
  //else {
  
    frontend_task_runner_->PostTask(
    //frontend_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
        &StorageBackend::Init, 
        base::Unretained(backend_.get()),
        base::Passed(std::move(params)),
        base::Bind(&Storage::OnBackendInit, 
          base::Unretained(this), callback)));
    init_event_.Wait();
  ////}
}

void Storage::Stop(CompletionCallback callback) {
  //db_task_runner_->PostTask(FROM_HERE,
  //    base::BindOnce(&Storage::CloseCatalogsOnDbThread, 
  //      base::Unretained(this))); 
  //event_wait_.Wait();
  //if (frontend_task_runner_ == base::ThreadTaskRunnerHandle::Get()) {
  //  StopImpl();
  //} else {
    //event_wait_.Reset();
    //frontend_task_runner_->PostTask(
    frontend_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&Storage::StopImpl, 
        base::Unretained(this)));
    event_wait_.Wait();
  //}  
  state_->set_status(storage_proto::STORAGE_STATUS_OFFLINE);
  if (!callback.is_null()) {
    callback.Run(0);
  }
}

void Storage::StopImpl() {
  backend_->Shutdown(&event_wait_);
}

storage_proto::ResourceKind Storage::resource_type() const {
  return storage_proto::STORAGE_RESOURCE;
}

const base::FilePath& Storage::path() const {
  return path_;
}

size_t Storage::size() const {
  return static_cast<size_t>(backend_->GetAllocatedSize());
}

const std::string& Storage::address() const {
  return state_->address();
}

bool Storage::is_signed() const {
  return false;
}

storage_proto::StorageStatus Storage::status() const {
  return state_->status(); 
}

scoped_refptr<Torrent> Storage::root_tree() const {
  return backend_->root_tree();
}

void Storage::CopyFile(
    const scoped_refptr<Torrent>& torrent,
    const base::FilePath& src,
    const CompletionCallback& callback) {

  base::OnceCallback<void()> closure = base::BindOnce(
      &StorageBackend::CopyFile, 
      base::Unretained(backend_.get()), 
      torrent, 
      src, 
      callback);

  if (initialized_) {
    //frontend_task_runner_->PostTask(
    frontend_task_runner_->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::move(closure));
  }
}

void Storage::CopyEntry(
    const scoped_refptr<Torrent>& torrent,
    const base::FilePath& dest,
    const CompletionCallback& callback) {
  
  base::OnceCallback<void()> closure = base::BindOnce(
      &StorageBackend::CopyEntry, 
      base::Unretained(backend_.get()), 
      torrent,
      dest, 
      callback);
   if (initialized_) {
    //frontend_task_runner_->PostTask(
    frontend_task_runner_->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::move(closure));
  }
}

void Storage::GetEntryInfo(const scoped_refptr<Torrent>& torrent, base::Callback<void(storage_proto::Info, int64_t)> cb) {
  base::OnceCallback<void()> closure = base::BindOnce(
      &StorageBackend::GetEntryInfo, 
      base::Unretained(backend_.get()), 
      torrent,
      base::Passed(std::move(cb)));
   if (initialized_) {
    //frontend_task_runner_->PostTask(
    frontend_task_runner_->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::move(closure));
  }  
}

void Storage::ListEntries(base::Callback<void(std::vector<std::unique_ptr<storage_proto::Info>>, int64_t)> cb) {
  std::vector<std::unique_ptr<storage_proto::Info>> entries = GetAllEntriesInfos();
  std::move(cb).Run(std::move(entries), net::OK);
}

std::vector<std::unique_ptr<storage_proto::Info>> Storage::GetAllEntriesInfos() {
  std::vector<std::unique_ptr<storage_proto::Info>> result;
  //frontend_task_runner_->PostTask(
  frontend_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&Storage::GetAllEntriesInfosImpl, base::Unretained(this), base::Unretained(&result)));
  event_wait_.Wait();
  event_wait_.Reset();
  return result;
}

void Storage::GetAllEntriesInfosImpl(std::vector<std::unique_ptr<storage_proto::Info>>* out) {
  backend_->ListAllEntriesInfo(out, &event_wait_);
}

void Storage::Query(const std::string& query_string,
                 const std::string& catalog_name,
                 base::Callback<void(std::unique_ptr<Block>, int64_t)> callback) {
  // auto catalog_it = catalogs_.find(catalog_name);
  // if (catalog_it == catalogs_.end()) {
  //   DLOG(ERROR) << "catalog not found: " << catalog_name;
  //   std::unique_ptr<Block> block;
  //   std::move(callback).Run(std::move(block), -1);
  //   return;
  // }

  // Catalog* catalog = catalog_it->second.get();

  // base::OnceCallback<void()> closure = 
  //   base::BindOnce(&StorageBackend::Query, 
  //     backend_->GetWeakPtr(),
  //     query_string, 
  //     base::Unretained(catalog),
  //     base::Passed(std::move(callback)));
  // if (initialized_) {
  //   frontend_task_runner_->PostTask(
  //     FROM_HERE,
  //     std::move(closure));
  // } else {
  //   scheduled_io_.push_back(std::move(closure));
  // }
  std::move(callback).Run({}, -1);
}


void Storage::InitEntry(const scoped_refptr<Torrent>& torrent,
                     const CompletionCallback& callback) {
  // for now its init entry.. later a full add
  base::OnceCallback<void()> closure = 
    base::BindOnce(&StorageBackend::InitEmptyEntry, 
      base::Unretained(backend_.get()),
      torrent, 
      callback);
  if (initialized_) {
    frontend_task_runner_->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::move(closure));
  }   
}

void Storage::InitEntry(const scoped_refptr<Torrent>& torrent,
                     const base::FilePath& src,
                     const CompletionCallback& callback) {

  // for now its init entry.. later a full add
  base::OnceCallback<void()> closure = 
    base::BindOnce(&StorageBackend::InitEntry, 
      base::Unretained(backend_.get()),
      torrent, 
      src, 
      callback);
  if (initialized_) {
    //frontend_task_runner_->PostTask(
    frontend_task_runner_->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::move(closure));
  }
}

void Storage::GetInfo(base::Callback<void(storage_proto::StorageState)> callback) {
  if (initialized_) {
    callback.Run(*state_.get());
  } else {
    base::OnceCallback<void()> closure = base::BindOnce(&StorageBackend::GetInfo, base::Unretained(backend_.get()), callback);
    scheduled_io_.push_back(std::move(closure));
  }
}

// Catalog* Storage::GetCatalog(const std::string& name) const {
//   if (name == "registry") {
//     return registry_.get();
//   }
//   auto it = catalogs_.find(name);
//   if (it == catalogs_.end()) {
//     return nullptr;
//   }
//   return it->second.get();
// }

void Storage::OpenDatabase(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb) {
  base::OnceCallback<void()> closure = 
    base::BindOnce(&StorageBackend::OpenDatabase, 
      base::Unretained(backend_.get()), 
      torrent, 
      base::Passed(std::move(cb)));
  if (initialized_) {
    //frontend_task_runner_->PostTask(
    frontend_task_runner_->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::move(closure));
  }
}


void Storage::CreateDatabase(const scoped_refptr<Torrent>& torrent, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) {
  base::OnceCallback<void()> closure = 
    base::BindOnce(&StorageBackend::CreateDatabase, 
      base::Unretained(backend_.get()), 
      torrent,
      base::Passed(std::move(keyspaces)),
      base::Passed(std::move(cb)));
  if (initialized_) {
    //frontend_task_runner_->PostTask(
    frontend_task_runner_->PostTask(
      FROM_HERE,
      std::move(closure));
  } else {
    scheduled_io_.push_back(std::move(closure));
  }
}

void Storage::OpenFileset(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb) {

}

void Storage::CreateFileset(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb) {

}

// void Storage::OpenApplication(Torrent* torrent, base::Callback<void(int64_t)> cb) {
//   base::OnceCallback<void()> closure = 
//     base::BindOnce(&StorageBackend::OpenApplication, 
//       backend_->GetWeakPtr(), 
//       base::Unretained(torrent), 
//       base::Passed(std::move(cb)));
//   if (initialized_) {
//     frontend_task_runner_->PostTask(
//       FROM_HERE,
//       std::move(closure));
//   } else {
//     scheduled_io_.push_back(std::move(closure));
//   }
// }

// void Storage::CreateApplication(Torrent* torrent, base::Callback<void(int64_t)> cb) {
//   base::OnceCallback<void()> closure = 
//     base::BindOnce(&StorageBackend::CreateApplication, 
//       backend_->GetWeakPtr(), 
//       base::Unretained(torrent),
//       base::Passed(std::move(cb)));
//   if (initialized_) {
//     frontend_task_runner_->PostTask(
//       FROM_HERE,
//       std::move(closure));
//   } else {
//     scheduled_io_.push_back(std::move(closure));
//   }
// }

const base::FilePath& Storage::GetPath() const {
  return path();
}

bool Storage::ShouldSeed(const storage_proto::Info& info) {
  // for now is just this
  return is_owner();
}

Future<int> Storage::CreateTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal, int jrn_seq) {
  return backend_->CreateTorrent(torrent, is_journal, jrn_seq);
}

Future<int> Storage::OpenTorrent(const scoped_refptr<Torrent>& torrent) {
  return backend_->OpenTorrent(torrent);
}

Future<int> Storage::CloseTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal, int jrn_seq) {
  return backend_->CloseTorrent(torrent, is_journal, jrn_seq);
}

Future<int> Storage::ReadTorrent(const scoped_refptr<Torrent>& torrent, void* buf, int64_t size, int64_t offset, bool is_journal, int jrn_seq) {
  return backend_->ReadTorrent(torrent, buf, size, offset, is_journal, jrn_seq);
}

Future<int> Storage::WriteTorrent(const scoped_refptr<Torrent>& torrent, const void* buf, int64_t size, int64_t offset, bool is_journal, int jrn_seq) {
  return backend_->WriteTorrent(torrent, buf, size, offset, is_journal, jrn_seq);
}

Future<int> Storage::DeleteTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal) {
  return backend_->DeleteTorrent(torrent, is_journal);
}

int64_t Storage::GetTorrentSize(const scoped_refptr<Torrent>& torrent) {
  return backend_->GetTorrentSize(torrent); 
}

Future<int> Storage::SyncTorrentMetadata(const scoped_refptr<Torrent>& torrent) {
  return backend_->SyncTorrentMetadata(torrent); 
}

void Storage::OnBackendInit(base::Callback<void(Storage*, int)> callback, bool result) {
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

    const Manifest* manifest = backend_->GetManifest();
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
    state_->set_size(backend_->GetAllocatedSize());
    state_->set_entry_count(backend_->GetEntryCount());
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

void Storage::ProcessScheduledIO() {
  for (auto it = scheduled_io_.begin(); it != scheduled_io_.end(); ++it) {
   //frontend_task_runner_->PostTask(
   frontend_task_runner_->PostTask(
    FROM_HERE,
    std::move(*it));
  }
  scheduled_io_.clear();
}

//void Storage::CloseCatalogsOnDbThread() {
  //for (auto it = catalogs_.begin(); it != catalogs_.end(); it++) {
  //  it->second->Close();
  //}
  //registry_->Shutdown(&event_wait_);
//}

// void Storage::OnCatalogOpen(base::Callback<void(int64_t)> cb, std::unique_ptr<Catalog> catalog, int64_t result) {
//   if (result == net::OK) {
//     std::string name = catalog->FullName();
//     LOG(INFO) << "Storage::OnCatalogOpen: adding catalog " << name << " to disk cache";
//     // in certain conditions: when we are cloning for instance
//     // instead of receiving the registry on initialization
//     // it is opened as a catalog after its received
//     // so we need to check it here and add it accordingly
//     if (name == "registry") {
//       registry_.reset(static_cast<RegistryCatalog *>(catalog.release()));
//     } else {
//       catalogs_.emplace(std::move(name), std::move(catalog));
//     }
//   } else {
//     LOG(INFO) << "Storage::OnCatalogOpen: adding catalog failed";
//   }
//   std::move(cb).Run(result);
// }

// void Storage::OnCatalogCreate(base::Callback<void(int64_t)> cb, std::unique_ptr<Catalog> catalog, int64_t result) {
//   if (result == net::OK) {
//     std::string name = catalog->FullName();
//     catalogs_.emplace(std::move(name), std::move(catalog));
//   }
//   std::move(cb).Run(result);
// }

// void Storage::OnApplicationOpen(base::Callback<void(int64_t)> cb, std::unique_ptr<Application> app, int64_t result) {
//   if (result == net::OK) {
//     std::string name(app->identifier());
//     applications_.emplace(std::move(name), std::move(app));
//   }
//   std::move(cb).Run(result);
// }

// void Storage::OnApplicationCreate(base::Callback<void(int64_t)> cb, std::unique_ptr<Application> app, int64_t result) {
//   if (result == net::OK) {
//     std::string name(app->identifier());
//     applications_.emplace(std::move(name), std::move(app));
//   }
//   std::move(cb).Run(result);
// }

}
