// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "RepoShims.h"

#include "EngineHelper.h"
#include "base/sha1.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/domain/repo/repo_dispatcher.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/application_process.h"
#include "core/shared/common/mojom/repo.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"

struct RepoRegistryWatcherCallbacks {
  void(*OnEntryAdded)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*);
  void(*OnEntryRemoved)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*);
};

class RepoRegistryWatcherImpl : public common::mojom::RepoWatcher {
public:
  RepoRegistryWatcherImpl(
    void* state, 
    RepoRegistryWatcherCallbacks cb,
    common::mojom::RepoWatcherRequest request) {//: 
    //state_(state),
    //cb_(std::move(cb)),
    //binding_(this) {
    
    //binding_.Bind(std::move(request));
  }

  ~RepoRegistryWatcherImpl() {
    
  }

  void OnEntryAdded(common::mojom::RepoEntryPtr entry) override {

  }
  
  void OnEntryRemoved(common::mojom::RepoEntryPtr entry) override {

  }

};

struct RepoHaveCallbackState {
  void* state;
  void(*cb)(void*, int);
};

struct RepoGetCallbackState {
  void* state;
  void(*cb)(void*, int, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*);
};

struct RepoListCallbackState {
  void* state;
  void(*cb)(void*, int, const char**, int*, const char**, const char**, int*, const char**, const char**, int*, const char**, const char**);
};

struct SchemeListCallbackState {
  void* state;
  void(*cb)(void*, int, const char**);
};

struct RepoAddWatcherCallbackState {
  void* state;
  void* watcher_state;
  void(*OnRepoAdded)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*);
  void(*OnRepoRemoved)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*);
  common::mojom::RepoWatcherPtr watcher_ptr;
};

void OnAddRepoResult(common::mojom::RepoStatusCode reply) {
    //DLOG(INFO) << "RepoRegistry: AddEntry returned with code " << static_cast<int>(reply);
}

void OnGetRepoResult(RepoGetCallbackState cb_state, common::mojom::RepoStatusCode r, common::mojom::RepoEntryPtr entry) {

}

void OnHaveRepoResult(RepoHaveCallbackState cb_state, bool r) {
  //cb_state.cb(cb_state.state, r ? 1 : 0);
}

void OnCountReposResult(RepoHaveCallbackState cb_state, uint32_t count) {
  //cb_state.cb(cb_state.state, static_cast<int>(count));
}

void OnListReposResult(RepoListCallbackState cb_state, std::vector<common::mojom::RepoEntryPtr> entries) {
  // if (entries.size() > 0) {
  //   size_t count = entries.size();
  //   int types[count];
  //   int transportTypes[count];
  //   int methodTypes[count];
  //   const char* names[count];
  //   const char* paths[count];
  //   const char* urls[count];
  //   for (size_t i = 0; i < count; ++i) {
  //     types[i] = static_cast<int>(entries[i]->type);
  //     transportTypes[i] = static_cast<int>(entries[i]->transport_type);
  //     methodTypes[i] = static_cast<int>(entries[i]->rpc_method_type);
  //     names[i] = entries[i]->name.c_str();
  //     paths[i] = entries[i]->path.c_str();
  //     urls[i] = entries[i]->url.spec().c_str();
  //   }
  //   cb_state.cb(
  //     cb_state.state, 
  //     0,
  //     count,
  //     types,
  //     transportTypes,
  //     methodTypes,
  //     names,
  //     paths, 
  //     urls);
  // } else {
  //   cb_state.cb(cb_state.state, 2, 0, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
  // }
}

void OnAddWatcherResult(
  RepoRegistryWatcherImpl* watcher,
  RepoAddWatcherCallbackState cb_state, 
  int32_t id) {
  //  cb_state.cb(cb_state.state, id, cb_state.watcher_state, watcher);
}

struct RepoRegistryWrapper : public domain::RepoDispatcher::Delegate {

  RepoRegistryWrapper(domain::RepoDispatcher* dispatcher, 
                      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner): 
    dispatcher(dispatcher),
    task_runner(task_runner) {
    if (dispatcher) {
      dispatcher->set_delegate(this);
    }
  }

  domain::RepoDispatcher* dispatcher;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner;

  void AddWatcher(
    RepoAddWatcherCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::AddWatcherImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void RemoveWatcher(int id) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::RemoveWatcherImpl, 
        base::Unretained(this),
        id));
  }

  void HaveRepo(std::string address, RepoHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::HaveRepoImpl, 
        base::Unretained(this),
        base::Passed(std::move(address)),
        base::Passed(std::move(cb_state))));
  }

  void HaveRepoByName(std::string name, RepoHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::HaveRepoByNameImpl, 
        base::Unretained(this),
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }

  void HaveRepoByUUID(std::string uuid, RepoHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::HaveRepoByUUIDImpl, 
        base::Unretained(this),
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void GetRepoCount(RepoHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::GetRepoCountImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void LookupRepo(std::string path, RepoGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::LookupRepoImpl, 
        base::Unretained(this), 
        base::Passed(std::move(path)),
        base::Passed(std::move(cb_state))));
  }
  
  void LookupRepoByName(std::string name, RepoGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::LookupRepoByNameImpl, 
        base::Unretained(this), 
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }

  void LookupRepoByUUID(std::string uuid, RepoGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::LookupRepoByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void AddRepo(common::mojom::RepoEntryPtr entry) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::AddRepoImpl, 
        base::Unretained(this),
        base::Passed(std::move(entry))));
  }

  void RemoveRepo(std::string path) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::RemoveRepoImpl, 
        base::Unretained(this), 
        base::Passed(std::move(path))));
  }

  void RemoveRepoByUUID(std::string uuid) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::RemoveRepoByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid))));
  }

  void ListRepos(RepoListCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RepoRegistryWrapper::ListReposImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }


  void AddRepoImpl(common::mojom::RepoEntryPtr entry) {
    dispatcher->AddRepo(
      std::move(entry),
      base::BindOnce(&OnAddRepoResult));
  }

  void RemoveRepoImpl(std::string path) {
    dispatcher->RemoveRepo(path, base::BindOnce(&OnAddRepoResult));
  }

  void RemoveRepoByUUIDImpl(std::string uuid) {
    dispatcher->RemoveRepoByUUID(uuid, base::BindOnce(&OnAddRepoResult));
  }

  void HaveRepoImpl(std::string address, RepoHaveCallbackState cb_state) {
    dispatcher->HaveRepo(address, base::BindOnce(&OnHaveRepoResult, base::Passed(std::move(cb_state))));
  }

  void HaveRepoByNameImpl(std::string name, RepoHaveCallbackState cb_state) {
    dispatcher->HaveRepoByName(name, base::BindOnce(&OnHaveRepoResult, base::Passed(std::move(cb_state))));
  }

  void HaveRepoByUUIDImpl(std::string uuid, RepoHaveCallbackState cb_state) {
    dispatcher->HaveRepoByUUID(uuid, base::BindOnce(&OnHaveRepoResult, base::Passed(std::move(cb_state))));
  }

  void GetRepoCountImpl(RepoHaveCallbackState cb_state) {
    dispatcher->GetRepoCount(base::BindOnce(&OnCountReposResult, base::Passed(std::move(cb_state))));
  }

  void LookupRepoImpl(std::string path, RepoGetCallbackState cb_state) {
    dispatcher->LookupRepo(path, base::BindOnce(&OnGetRepoResult, base::Passed(std::move(cb_state))));
  }

  void LookupRepoByNameImpl(std::string name, RepoGetCallbackState cb_state) {
    dispatcher->LookupRepoByName(name, base::BindOnce(&OnGetRepoResult, base::Passed(std::move(cb_state))));
  }

  void LookupRepoByUUIDImpl(std::string uuid, RepoGetCallbackState cb_state) {
    dispatcher->LookupRepoByUUID(uuid, base::BindOnce(&OnGetRepoResult, base::Passed(std::move(cb_state))));
  }

  void ListReposImpl(RepoListCallbackState cb_state) {
    dispatcher->ListRepos(base::BindOnce(&OnListReposResult, base::Passed(std::move(cb_state))));
  }

  void AddWatcherImpl(RepoAddWatcherCallbackState cb_state) {
    common::mojom::RepoWatcherPtrInfo url_watcher_info;
    RepoRegistryWatcherImpl* watcher = new RepoRegistryWatcherImpl(
      cb_state.watcher_state, 
      RepoRegistryWatcherCallbacks{cb_state.OnRepoAdded, cb_state.OnRepoRemoved},
      mojo::MakeRequest(&url_watcher_info));
    dispatcher->AddWatcher(
      common::mojom::RepoWatcherPtr(std::move(url_watcher_info)),
      base::BindOnce(&OnAddWatcherResult, 
        base::Unretained(watcher),
        base::Passed(std::move(cb_state))));
  }

  void RemoveWatcherImpl(int id) {
    dispatcher->RemoveWatcher(id);
  }

};

RepoRegistryRef _RepoRegistryCreateFromEngine(EngineInstanceRef handle) {
  domain::ModuleState* module = reinterpret_cast<_EngineInstance *>(handle)->module_state();
  return new RepoRegistryWrapper(
    module->repo_dispatcher(), 
    module->GetMainTaskRunner());
}

void _RepoRegistryDestroy(RepoRegistryRef handle) {
  delete reinterpret_cast<RepoRegistryWrapper *>(handle);
}

void _RepoRegistryAddRepo(RepoRegistryRef handle, const char* uuid, int type, const char* name, const char* address, int addr_format, const char* addr_format_ver, const char* pk, int pk_format, const char* root_tree, const char* creator, void* state, void(*callback)(void*, int)) {
  common::mojom::RepoEntryPtr entry = common::mojom::RepoEntry::New();
  
  entry->uuid = std::string(uuid);
  entry->type = static_cast<common::mojom::RepoType>(type);
  entry->name = std::string(name);
  entry->address = std::string(address);
  entry->address_format = static_cast<common::mojom::RepoAddressFormat>(addr_format);
  entry->public_key = std::string(pk);
  entry->pk_crypto_format = static_cast<common::mojom::PKCryptoFormat>(pk_format);
  entry->root_tree = std::string(root_tree);
  entry->creator = std::string(creator);
  reinterpret_cast<RepoRegistryWrapper *>(handle)->AddRepo(std::move(entry));
}

void _RepoRegistryAddRepoByAddress(RepoRegistryRef handle, const char* address, void* state, void(*callback)(void*, int)) {
  
}

void _RepoRegistryRemoveRepo(RepoRegistryRef handle, const char* address, void* state, void(*callback)(void*, int)) {
  reinterpret_cast<RepoRegistryWrapper *>(handle)->RemoveRepo(address);
}

void _RepoRegistryRemoveRepoByUUID(RepoRegistryRef handle, const char* uuid, void* state, void(*callback)(void*, int)) {
  reinterpret_cast<RepoRegistryWrapper *>(handle)->RemoveRepoByUUID(uuid);
}

void _RepoRegistryLookupRepo(RepoRegistryRef handle, const char* address, void* state, void(*callback)(void*, int, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*)) {
  RepoRegistryWrapper* registry = reinterpret_cast<RepoRegistryWrapper *>(handle);
  RepoGetCallbackState cb_state{state, callback};  
  registry->LookupRepo(address, std::move(cb_state));
}

void _RepoRegistryLookupRepoByName(RepoRegistryRef handle, const char* name, void* state, void(*callback)(void*, int, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*)) {
  RepoRegistryWrapper* registry = reinterpret_cast<RepoRegistryWrapper *>(handle);
  RepoGetCallbackState cb_state{state, callback};  
  registry->LookupRepoByName(name, std::move(cb_state));
}

void _RepoRegistryLookupRepoByUUID(RepoRegistryRef handle, const char* uuid, void* state, void(*callback)(void*, int, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*)) {
  RepoRegistryWrapper* registry = reinterpret_cast<RepoRegistryWrapper *>(handle);
  RepoGetCallbackState cb_state{state, callback};  
  registry->LookupRepoByUUID(uuid, std::move(cb_state));
}

void _RepoRegistryHaveRepo(RepoRegistryRef handle, const char* address, void* state, void(*callback)(void*, int)) {
  RepoRegistryWrapper* registry = reinterpret_cast<RepoRegistryWrapper *>(handle);
  RepoHaveCallbackState cb_state{state, callback};  
  registry->HaveRepo(address, std::move(cb_state));
}

void _RepoRegistryHaveRepoByName(RepoRegistryRef handle, const char* name, void* state, void(*callback)(void*, int)) {
  RepoRegistryWrapper* registry = reinterpret_cast<RepoRegistryWrapper *>(handle);
  RepoHaveCallbackState cb_state{state, callback};  
  registry->HaveRepoByName(name, std::move(cb_state));
}

void _RepoRegistryHaveRepoByUUID(RepoRegistryRef handle, const char* uuid, void* state, void(*callback)(void*, int)) {
  RepoRegistryWrapper* registry = reinterpret_cast<RepoRegistryWrapper *>(handle);
  RepoHaveCallbackState cb_state{state, callback};  
  registry->HaveRepoByUUID(uuid, std::move(cb_state));
}

void _RepoRegistryListRepos(RepoRegistryRef handle, void* state, void(*callback)(void*, int, const char**, int*, const char**, const char**, int*, const char**, const char**, int*, const char**, const char**)) {
  RepoRegistryWrapper* registry = reinterpret_cast<RepoRegistryWrapper *>(handle);
  RepoListCallbackState cb_state{state, callback};  
  registry->ListRepos(std::move(cb_state));
}

void _RepoRegistryGetRepoCount(RepoRegistryRef handle, void* state, void(*callback)(void*, int)) {
  RepoRegistryWrapper* registry = reinterpret_cast<RepoRegistryWrapper *>(handle);
  RepoHaveCallbackState cb_state{state, callback};  
  registry->GetRepoCount(std::move(cb_state));
}

void _RepoRegistryAddWatcher(
  RepoRegistryRef handle, 
  void* state,
  void* watcher_state, 
  void(*OnEntryAdded)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*),
  void(*OnEntryRemoved)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*)) {

  RepoRegistryWrapper* registry = reinterpret_cast<RepoRegistryWrapper *>(handle);
  RepoAddWatcherCallbackState cb_state{state, watcher_state, OnEntryAdded, OnEntryRemoved};  
  registry->AddWatcher(std::move(cb_state));  
}

void _RepoRegistryRemoveWatcher(RepoRegistryRef handle, int32_t watcher) {
  reinterpret_cast<RepoRegistryWrapper*>(handle)->RemoveWatcher(watcher);
}

void _RepoWatcherDestroy(void* handle) {
  delete reinterpret_cast<RepoRegistryWatcherImpl *>(handle);
}