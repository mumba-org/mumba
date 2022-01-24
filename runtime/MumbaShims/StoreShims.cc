// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "StoreShims.h"

#include "EngineHelper.h"
#include "base/sha1.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/domain/store/app_store_dispatcher.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/application_process.h"
#include "core/shared/common/mojom/app_store.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"

struct AppStoreWatcherCallbacks {
  void(*OnEntryAdded)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*);
  void(*OnEntryRemoved)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*);
};

class AppStoreWatcherImpl : public common::mojom::AppStoreWatcher {
public:
  AppStoreWatcherImpl(
    void* state, 
    AppStoreWatcherCallbacks cb,
    common::mojom::AppStoreWatcherRequest request) {//: 
    //state_(state),
    //cb_(std::move(cb)),
    //binding_(this) {
    
    //binding_.Bind(std::move(request));
  }

  ~AppStoreWatcherImpl() {
    
  }

  void OnEntryAdded(common::mojom::AppStoreEntryPtr entry) override {

  }
  
  void OnEntryRemoved(common::mojom::AppStoreEntryPtr entry) override {

  }

};

struct AppStoreHaveCallbackState {
  void* state;
  void(*cb)(void*, int);
};

struct AppStoreGetCallbackState {
  void* state;
  void(*cb)(void*, int, const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**);
};

struct AppStoreListCallbackState {
  void* state;
  void(*cb)(void*, int, 
  const char**, const char**, const char**, const char**, 
  const char**, const char**, const char**, const char**, 
  const char**, uint64_t*, const char**, const char**,
  int*, int*, uint64_t*, uint32_t*, const char**, 
  int, const char***, int, const char***);
};

struct SchemeListCallbackState {
  void* state;
  void(*cb)(void*, int, const char**);
};

struct AppStoreAddWatcherCallbackState {
  void* state;
  void* watcher_state;
  void(*cb)(void*, int, void*, void*);
  void(*OnEntryAdded)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*);
  void(*OnEntryRemoved)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*);
  common::mojom::AppStoreWatcherPtr watcher_ptr;
};

void OnAddEntryResult(common::mojom::AppStoreStatusCode reply) {
    //DLOG(INFO) << "AppStore: AddEntry returned with code " << static_cast<int>(reply);
}

void OnGetEntryResult(AppStoreGetCallbackState cb_state, common::mojom::AppStoreStatusCode r, common::mojom::AppStoreEntryPtr entry) {

}

void OnHaveEntryResult(AppStoreHaveCallbackState cb_state, bool r) {
  //cb_state.cb(cb_state.state, r ? 1 : 0);
}

void OnCountEntriesResult(AppStoreHaveCallbackState cb_state, uint32_t count) {
  //cb_state.cb(cb_state.state, static_cast<int>(count));
}

void OnListEntriesResult(AppStoreListCallbackState cb_state, std::vector<common::mojom::AppStoreEntryPtr> entries) {
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
  AppStoreWatcherImpl* watcher,
  AppStoreAddWatcherCallbackState cb_state, 
  int32_t id) {
  //  cb_state.cb(cb_state.state, id, cb_state.watcher_state, watcher);
}

struct AppStoreWrapper : public domain::AppStoreDispatcher::Delegate {

  AppStoreWrapper(domain::AppStoreDispatcher* dispatcher, 
                  void* handler_state,
                  AppStoreCallbacks handler_callbacks,
                  const scoped_refptr<base::SingleThreadTaskRunner>& task_runner): 
    dispatcher(dispatcher),
    handler_state(handler_state),
    handler_callbacks(std::move(handler_callbacks)),
    task_runner(task_runner) {
    // if (dispatcher) {
    //   dispatcher->set_delegate(this);
    // }
  }

  domain::AppStoreDispatcher* dispatcher;
  void* handler_state;
  AppStoreCallbacks handler_callbacks;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner;

  void AddWatcher(
    AppStoreAddWatcherCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::AddWatcherImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void RemoveWatcher(int id) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::RemoveWatcherImpl, 
        base::Unretained(this),
        id));
  }

  void HaveEntry(std::string address, AppStoreHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::HaveEntryImpl, 
        base::Unretained(this),
        base::Passed(std::move(address)),
        base::Passed(std::move(cb_state))));
  }

  void HaveEntryByName(std::string name, AppStoreHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::HaveEntryByNameImpl, 
        base::Unretained(this),
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }

  void HaveEntryByUUID(std::string uuid, AppStoreHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::HaveEntryByUUIDImpl, 
        base::Unretained(this),
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void GetEntryCount(AppStoreHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::GetEntryCountImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void LookupEntry(std::string path, AppStoreGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::LookupEntryImpl, 
        base::Unretained(this), 
        base::Passed(std::move(path)),
        base::Passed(std::move(cb_state))));
  }
  
  void LookupEntryByName(std::string name, AppStoreGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::LookupEntryByNameImpl, 
        base::Unretained(this), 
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }

  void LookupEntryByUUID(std::string uuid, AppStoreGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::LookupEntryByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void AddEntry(common::mojom::AppStoreEntryPtr entry) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::AddEntryImpl, 
        base::Unretained(this),
        base::Passed(std::move(entry))));
  }

  void RemoveEntry(std::string path) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::RemoveEntryImpl, 
        base::Unretained(this), 
        base::Passed(std::move(path))));
  }

  void RemoveEntryByUUID(std::string uuid) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::RemoveEntryByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid))));
  }

  void ListEntries(AppStoreListCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&AppStoreWrapper::ListEntriesImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }


  void AddEntryImpl(common::mojom::AppStoreEntryPtr entry) {
    dispatcher->AddEntry(
      std::move(entry),
      base::BindOnce(&OnAddEntryResult));
  }

  void RemoveEntryImpl(std::string path) {
    dispatcher->RemoveEntry(path, base::BindOnce(&OnAddEntryResult));
  }

  void RemoveEntryByUUIDImpl(std::string uuid) {
    dispatcher->RemoveEntryByUUID(uuid, base::BindOnce(&OnAddEntryResult));
  }

  void HaveEntryImpl(std::string address, AppStoreHaveCallbackState cb_state) {
    dispatcher->HaveEntry(address, base::BindOnce(&OnHaveEntryResult, base::Passed(std::move(cb_state))));
  }

  void HaveEntryByNameImpl(std::string name, AppStoreHaveCallbackState cb_state) {
    dispatcher->HaveEntryByName(name, base::BindOnce(&OnHaveEntryResult, base::Passed(std::move(cb_state))));
  }

  void HaveEntryByUUIDImpl(std::string uuid, AppStoreHaveCallbackState cb_state) {
    dispatcher->HaveEntryByUUID(uuid, base::BindOnce(&OnHaveEntryResult, base::Passed(std::move(cb_state))));
  }

  void GetEntryCountImpl(AppStoreHaveCallbackState cb_state) {
    dispatcher->GetEntryCount(base::BindOnce(&OnCountEntriesResult, base::Passed(std::move(cb_state))));
  }

  void LookupEntryImpl(std::string path, AppStoreGetCallbackState cb_state) {
    dispatcher->LookupEntry(path, base::BindOnce(&OnGetEntryResult, base::Passed(std::move(cb_state))));
  }

  void LookupEntryByNameImpl(std::string name, AppStoreGetCallbackState cb_state) {
    dispatcher->LookupEntryByName(name, base::BindOnce(&OnGetEntryResult, base::Passed(std::move(cb_state))));
  }

  void LookupEntryByUUIDImpl(std::string uuid, AppStoreGetCallbackState cb_state) {
    dispatcher->LookupEntryByUUID(uuid, base::BindOnce(&OnGetEntryResult, base::Passed(std::move(cb_state))));
  }

  void ListEntriesImpl(AppStoreListCallbackState cb_state) {
    dispatcher->ListEntries(base::BindOnce(&OnListEntriesResult, base::Passed(std::move(cb_state))));
  }

  void AddWatcherImpl(AppStoreAddWatcherCallbackState cb_state) {
    common::mojom::AppStoreWatcherPtrInfo url_watcher_info;
    AppStoreWatcherImpl* watcher = new AppStoreWatcherImpl(
      cb_state.watcher_state, 
      AppStoreWatcherCallbacks{cb_state.OnEntryAdded, cb_state.OnEntryRemoved},
      mojo::MakeRequest(&url_watcher_info));
    dispatcher->AddWatcher(
      common::mojom::AppStoreWatcherPtr(std::move(url_watcher_info)),
      base::BindOnce(&OnAddWatcherResult, 
        base::Unretained(watcher),
        base::Passed(std::move(cb_state))));
  }

  void RemoveWatcherImpl(int id) {
    dispatcher->RemoveWatcher(id);
  }

};


AppStoreRef _AppStoreCreateFromEngine(EngineInstanceRef handle, void* state, AppStoreCallbacks callbacks) {
  domain::ModuleState* module = reinterpret_cast<_EngineInstance *>(handle)->module_state();
  return new AppStoreWrapper(
    module->app_store_dispatcher(), 
    state, 
    std::move(callbacks), 
    module->GetMainTaskRunner());
}

void _AppStoreDestroy(AppStoreRef handle) {
  delete reinterpret_cast<AppStoreWrapper *>(handle);
}

void _AppStoreAddEntry(AppStoreRef handle, 
  const char* uuid, 
  const char* name, 
  const char* description, 
  const char* version, 
  const char* license, 
  const char* publisher, 
  const char* publisher_url, 
  const char* publisher_public_key, 
  const char* logo_path, 
  uint64_t size, 
  const char* repo_uuid, 
  const char* repo_public_key,
  int install_state, 
  int availability_state, 
  uint64_t install_counter, 
  uint32_t rating, 
  const char* app_public_key, 
  int supported_platforms_count, 
  const char** supported_platforms, 
  int supported_languages_count, 
  const char** supported_languages, 
  void(*callback)(void*, int)) {
  
  common::mojom::AppStoreEntryPtr entry = common::mojom::AppStoreEntry::New();
  
  // string uuid;
  // string name;
  // string description;
  // string version;
  // string license;
  // string publisher;
  // string publisher_url;  
  // string publisher_public_key;
  // string logo_path;
  // uint64 size;
  // string repo_uuid;
  // string repo_public_key;
  // AppStoreInstallState install_state;
  // AppStoreAvailabilityState availability_state;
  // uint64 install_counter;
  // uint32 rating;
  // string app_public_key;
  // array<string> supported_platforms;
  // array<string> supported_languages;

  entry->uuid = std::string(uuid);
  entry->name = std::string(name);
  entry->description = std::string(description);
  entry->version = std::string(version);
  entry->license = std::string(license);
  entry->publisher = std::string(publisher);
  entry->publisher_url = std::string(publisher_url);
  entry->publisher_public_key = std::string(publisher_public_key);
  entry->logo_path = std::string(logo_path);
  entry->size = size;
  entry->repo_uuid = std::string(repo_uuid);
  entry->repo_public_key = std::string(repo_public_key);
  entry->install_state = static_cast<common::mojom::AppStoreInstallState>(install_state);
  entry->availability_state = static_cast<common::mojom::AppStoreAvailabilityState>(availability_state);
  entry->install_counter = install_counter;
  entry->rating = rating;
  entry->app_public_key = std::string(app_public_key);
  for (int i = 0; i < supported_platforms_count; ++i) {
    entry->supported_platforms.push_back(supported_platforms[i]);
  }
  for (int i = 0; i < supported_languages_count; ++i) {
    entry->supported_languages.push_back(supported_languages[i]);
  }

  reinterpret_cast<AppStoreWrapper *>(handle)->AddEntry(std::move(entry));
}

void _AppStoreAddEntryByAddress(AppStoreRef handle, 
  const char*, 
  void(*callback)(void*, int)) {

  
}

void _AppStoreRemoveEntry(AppStoreRef handle, const char* address, void(*callback)(void*, int)) {
  reinterpret_cast<AppStoreWrapper *>(handle)->RemoveEntry(address);
}

void _AppStoreRemoveEntryByUUID(AppStoreRef handle, const char* uuid, void(*callback)(void*, int)) {
  reinterpret_cast<AppStoreWrapper *>(handle)->RemoveEntryByUUID(uuid);
}

void _AppStoreLookupEntry(AppStoreRef handle, const char* address, void(*callback)(
  void*, int, const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**)) {

  AppStoreWrapper* store = reinterpret_cast<AppStoreWrapper *>(handle);
  AppStoreGetCallbackState cb_state{store->handler_state, callback};  
  store->LookupEntry(address, std::move(cb_state));
}

void _AppStoreLookupEntryByName(AppStoreRef handle, const char* name, void(*callback)(
  void*, int, const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**)) {

  AppStoreWrapper* store = reinterpret_cast<AppStoreWrapper *>(handle);
  AppStoreGetCallbackState cb_state{store->handler_state, callback};  
  store->LookupEntryByName(name, std::move(cb_state));  
}

void _AppStoreLookupEntryByUUID(AppStoreRef handle, const char* uuid, void(*callback)(
  void*, int, const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**)) {
  
  AppStoreWrapper* store = reinterpret_cast<AppStoreWrapper *>(handle);
  AppStoreGetCallbackState cb_state{store->handler_state, callback};  
  store->LookupEntryByUUID(uuid, std::move(cb_state));
}

void _AppStoreHaveEntry(AppStoreRef handle, const char* address, void(*callback)(void*, int)) {
  AppStoreWrapper* store = reinterpret_cast<AppStoreWrapper *>(handle);
  AppStoreHaveCallbackState cb_state{store->handler_state, callback};  
  store->HaveEntry(address, std::move(cb_state));
}

void _AppStoreHaveEntryByName(AppStoreRef handle, const char* name, void(*callback)(void*, int)) {
  AppStoreWrapper* store = reinterpret_cast<AppStoreWrapper *>(handle);
  AppStoreHaveCallbackState cb_state{store->handler_state, callback};  
  store->HaveEntryByName(name, std::move(cb_state));
}

void _AppStoreHaveEntryByUUID(AppStoreRef handle, const char* uuid, void(*callback)(void*, int)) {
  AppStoreWrapper* store = reinterpret_cast<AppStoreWrapper *>(handle);
  AppStoreHaveCallbackState cb_state{store->handler_state, callback};  
  store->HaveEntryByUUID(uuid, std::move(cb_state));
}

void _AppStoreListEntries(AppStoreRef handle, void(*callback)(
  void*, int,
  const char**, const char**, const char**, const char**, 
  const char**, const char**, const char**, const char**, 
  const char**, uint64_t*, const char**, const char**,
  int*, int*, uint64_t*, uint32_t*, const char**, 
  int, const char***, int, const char***)) {

  AppStoreWrapper* store = reinterpret_cast<AppStoreWrapper *>(handle);
  AppStoreListCallbackState cb_state{store->handler_state, callback};  
  store->ListEntries(std::move(cb_state));
}

void _AppStoreGetEntryCount(AppStoreRef handle, void(*callback)(void*, int)) {
  AppStoreWrapper* store = reinterpret_cast<AppStoreWrapper *>(handle);
  AppStoreHaveCallbackState cb_state{store->handler_state, callback};  
  store->GetEntryCount(std::move(cb_state));
}

void _AppStoreAddWatcher(
  AppStoreRef handle, 
  void* state,
  void* watcher_state, 
  void(*cb)(void*, int, void*, void*),
  void(*OnEntryAdded)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*),
  void(*OnEntryRemoved)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*)) {

  AppStoreAddWatcherCallbackState cb_state{state, watcher_state, cb, OnEntryAdded, OnEntryRemoved};
  reinterpret_cast<AppStoreWrapper *>(handle)->AddWatcher(std::move(cb_state));   
}

void _AppStoreRemoveWatcher(AppStoreRef handle, int32_t watcher) {
  reinterpret_cast<AppStoreWrapper *>(handle)->RemoveWatcher(watcher);
}