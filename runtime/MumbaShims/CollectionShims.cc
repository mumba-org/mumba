// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "CollectionShims.h"

#include "EngineHelper.h"
#include "base/sha1.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/domain/collection/collection_dispatcher.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/application_process.h"
#include "core/shared/common/mojom/collection.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"

struct CollectionWatcherCallbacks {
  void(*OnEntryAdded)(void*, const char*, const char*, const char*, const char*, 
    const char*, const char*, const char*, const char*, 
    const char*, uint64_t, const char*, const char*,
    int, int, uint64_t, uint32_t, const char*, 
    int, const char**, int, const char**);
  void(*OnEntryRemoved)(void*, const char*, const char*, const char*, const char*, 
    const char*, const char*, const char*, const char*, 
    const char*, uint64_t, const char*, const char*,
    int, int, uint64_t, uint32_t, const char*, 
    int, const char**, int, const char**);
};

class CollectionWatcherImpl : public common::mojom::CollectionWatcher {
public:
  CollectionWatcherImpl(
    void* state, 
    CollectionWatcherCallbacks cb,
    common::mojom::CollectionWatcherRequest request): 
    state_(state),
    cb_(std::move(cb)),
    binding_(this) {
    
    binding_.Bind(std::move(request));
  }

  ~CollectionWatcherImpl() {
    
  }

  void OnEntryAdded(common::mojom::CollectionEntryPtr entry) override {
    const char* platforms[entry->supported_platforms.size()];
    const char* languages[entry->supported_languages.size()];
    std::vector<std::string> supported_platforms;
    std::vector<std::string> supported_languages;

    for (size_t i = 0; i < entry->supported_platforms.size(); i++) {
      platforms[i] = entry->supported_platforms[i].c_str();
    }

    for (size_t i = 0; i < entry->supported_languages.size(); i++) {
      languages[i] = entry->supported_languages[i].c_str();
    }

    cb_.OnEntryAdded(
      state_, 
      entry->uuid.c_str(),
      entry->name.c_str(),
      entry->description.c_str(),
      entry->version.c_str(),
      entry->license.c_str(),
      entry->publisher.c_str(),
      entry->publisher_url.c_str(),
      entry->publisher_public_key.c_str(),
      entry->logo_path.c_str(),
      entry->size,
      entry->repo_uuid.c_str(),
      entry->repo_public_key.c_str(),
      static_cast<int>(entry->install_state),
      static_cast<int>(entry->availability_state),
      entry->install_counter,
      entry->rating,
      entry->app_public_key.c_str(),
      entry->supported_platforms.size(),
      platforms,
      entry->supported_languages.size(),
      languages);
  }
  
  void OnEntryRemoved(common::mojom::CollectionEntryPtr entry) override {
    const char* platforms[entry->supported_platforms.size()];
    const char* languages[entry->supported_languages.size()];
    std::vector<std::string> supported_platforms;
    std::vector<std::string> supported_languages;

    for (size_t i = 0; i < entry->supported_platforms.size(); i++) {
      platforms[i] = entry->supported_platforms[i].c_str();
    }

    for (size_t i = 0; i < entry->supported_languages.size(); i++) {
      languages[i] = entry->supported_languages[i].c_str();
    }

    cb_.OnEntryRemoved(
      state_, 
      entry->uuid.c_str(),
      entry->name.c_str(),
      entry->description.c_str(),
      entry->version.c_str(),
      entry->license.c_str(),
      entry->publisher.c_str(),
      entry->publisher_url.c_str(),
      entry->publisher_public_key.c_str(),
      entry->logo_path.c_str(),
      entry->size,
      entry->repo_uuid.c_str(),
      entry->repo_public_key.c_str(),
      static_cast<int>(entry->install_state),
      static_cast<int>(entry->availability_state),
      entry->install_counter,
      entry->rating,
      entry->app_public_key.c_str(),
      entry->supported_platforms.size(),
      platforms,
      entry->supported_languages.size(),
      languages);
  }

private:
  void* state_;
  CollectionWatcherCallbacks cb_;
  mojo::Binding<common::mojom::CollectionWatcher> binding_;
};

struct CollectionHaveCallbackState {
  void* state;
  void(*cb)(void*, int);
};

struct CollectionGetCallbackState {
  void* state;
  void(*cb)(void*, int, const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**);
};

struct CollectionListCallbackState {
  void* state;
  void(*cb)(void*, int, 
  const char**, const char**, const char**, const char**, 
  const char**, const char**, const char**, const char**, 
  const char**, uint64_t*, const char**, const char**,
  int*, int*, uint64_t*, uint32_t*, const char**, 
  int*, const char***, int*, const char***);
};

struct SchemeListCallbackState {
  void* state;
  void(*cb)(void*, int, const char**);
};

struct CollectionAddWatcherCallbackState {
  void* state;
  void* watcher_state;
  void(*OnEntryAdded)(void*, const char*, const char*, const char*, const char*, 
                      const char*, const char*, const char*, const char*, 
                      const char*, uint64_t, const char*, const char*,
                      int, int, uint64_t, uint32_t, const char*, 
                      int, const char**, int, const char**);
  void(*OnEntryRemoved)(void*, const char*, const char*, const char*, const char*, 
                        const char*, const char*, const char*, const char*, 
                        const char*, uint64_t, const char*, const char*,
                        int, int, uint64_t, uint32_t, const char*, 
                        int, const char**, int, const char**);
  common::mojom::CollectionWatcherPtr watcher_ptr;
};

void OnAddEntryResult(CollectionHaveCallbackState cb_state, common::mojom::CollectionStatusCode reply) {
    //DLOG(INFO) << "Collection: AddEntry returned with code " << static_cast<int>(reply);
  cb_state.cb(cb_state.state, static_cast<int>(reply));  
}

void OnGetEntryResult(CollectionGetCallbackState cb_state, common::mojom::CollectionStatusCode r, common::mojom::CollectionEntryPtr entry) {
  const char* platforms[entry->supported_platforms.size()];
  const char* languages[entry->supported_languages.size()];
  std::vector<std::string> supported_platforms;
  std::vector<std::string> supported_languages;

  for (size_t i = 0; i < entry->supported_platforms.size(); i++) {
    platforms[i] = entry->supported_platforms[i].c_str();
  }

  for (size_t i = 0; i < entry->supported_languages.size(); i++) {
    languages[i] = entry->supported_languages[i].c_str();
  }

  cb_state.cb(cb_state.state,
    static_cast<int>(r),
    entry->uuid.c_str(),
    entry->name.c_str(),
    entry->description.c_str(),
    entry->version.c_str(),
    entry->license.c_str(),
    entry->publisher.c_str(),
    entry->publisher_url.c_str(),
    entry->publisher_public_key.c_str(),
    entry->logo_path.c_str(),
    entry->size,
    entry->repo_uuid.c_str(),
    entry->repo_public_key.c_str(),
    static_cast<int>(entry->install_state),
    static_cast<int>(entry->availability_state),
    entry->install_counter,
    entry->rating,
    entry->app_public_key.c_str(),
    entry->supported_platforms.size(),
    platforms,
    entry->supported_languages.size(),
    languages);
}

void OnHaveEntryResult(CollectionHaveCallbackState cb_state, bool r) {
  cb_state.cb(cb_state.state, r ? 1 : 0);
}

void OnCountEntriesResult(CollectionHaveCallbackState cb_state, uint32_t count) {
  cb_state.cb(cb_state.state, static_cast<int>(count));
}

void OnListEntriesResult(CollectionListCallbackState cb_state, std::vector<common::mojom::CollectionEntryPtr> entries) {
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
  CollectionWatcherImpl* watcher,
  CollectionAddWatcherCallbackState cb_state, 
  int32_t id) {
  //cb_state.cb(cb_state.state, id, cb_state.watcher_state, watcher);
}

struct CollectionWrapper : public domain::CollectionDispatcher::Delegate {

  CollectionWrapper(domain::CollectionDispatcher* dispatcher, 
                  const scoped_refptr<base::SingleThreadTaskRunner>& task_runner): 
    dispatcher(dispatcher),
    task_runner(task_runner) {
    
  }

  domain::CollectionDispatcher* dispatcher;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner;

  void AddWatcher(CollectionAddWatcherCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::AddWatcherImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void RemoveWatcher(int id) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::RemoveWatcherImpl, 
        base::Unretained(this),
        id));
  }

  void HaveEntry(std::string address, CollectionHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::HaveEntryImpl, 
        base::Unretained(this),
        base::Passed(std::move(address)),
        base::Passed(std::move(cb_state))));
  }

  void HaveEntryByName(std::string name, CollectionHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::HaveEntryByNameImpl, 
        base::Unretained(this),
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }

  void HaveEntryByUUID(std::string uuid, CollectionHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::HaveEntryByUUIDImpl, 
        base::Unretained(this),
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void GetEntryCount(CollectionHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::GetEntryCountImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void LookupEntry(std::string path, CollectionGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::LookupEntryImpl, 
        base::Unretained(this), 
        base::Passed(std::move(path)),
        base::Passed(std::move(cb_state))));
  }
  
  void LookupEntryByName(std::string name, CollectionGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::LookupEntryByNameImpl, 
        base::Unretained(this), 
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }

  void LookupEntryByUUID(std::string uuid, CollectionGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::LookupEntryByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void AddEntry(common::mojom::CollectionEntryPtr entry, CollectionHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::AddEntryImpl, 
        base::Unretained(this),
        base::Passed(std::move(entry)),
        base::Passed(std::move(cb_state))));
  }

  void RemoveEntry(std::string path, CollectionHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::RemoveEntryImpl, 
        base::Unretained(this), 
        base::Passed(std::move(path)),
        base::Passed(std::move(cb_state))));
  }

  void RemoveEntryByUUID(std::string uuid, CollectionHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::RemoveEntryByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void ListEntries(CollectionListCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&CollectionWrapper::ListEntriesImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void AddEntryImpl(common::mojom::CollectionEntryPtr entry, CollectionHaveCallbackState cb_state) {
    dispatcher->AddEntry(
      std::move(entry),
      base::BindOnce(&OnAddEntryResult,
                     base::Passed(std::move(cb_state))));
  }

  void RemoveEntryImpl(std::string path, CollectionHaveCallbackState cb_state) {
    dispatcher->RemoveEntry(path, base::BindOnce(&OnAddEntryResult,
                                                 base::Passed(std::move(cb_state))));
  }

  void RemoveEntryByUUIDImpl(std::string uuid, CollectionHaveCallbackState cb_state) {
    dispatcher->RemoveEntryByUUID(uuid, base::BindOnce(&OnAddEntryResult,
                                                        base::Passed(std::move(cb_state))));
  }

  void HaveEntryImpl(std::string address, CollectionHaveCallbackState cb_state) {
    dispatcher->HaveEntry(address, base::BindOnce(&OnHaveEntryResult, base::Passed(std::move(cb_state))));
  }

  void HaveEntryByNameImpl(std::string name, CollectionHaveCallbackState cb_state) {
    dispatcher->HaveEntryByName(name, base::BindOnce(&OnHaveEntryResult, base::Passed(std::move(cb_state))));
  }

  void HaveEntryByUUIDImpl(std::string uuid, CollectionHaveCallbackState cb_state) {
    dispatcher->HaveEntryByUUID(uuid, base::BindOnce(&OnHaveEntryResult, base::Passed(std::move(cb_state))));
  }

  void GetEntryCountImpl(CollectionHaveCallbackState cb_state) {
    dispatcher->GetEntryCount(base::BindOnce(&OnCountEntriesResult, base::Passed(std::move(cb_state))));
  }

  void LookupEntryImpl(std::string path, CollectionGetCallbackState cb_state) {
    dispatcher->LookupEntry(path, base::BindOnce(&OnGetEntryResult, base::Passed(std::move(cb_state))));
  }

  void LookupEntryByNameImpl(std::string name, CollectionGetCallbackState cb_state) {
    dispatcher->LookupEntryByName(name, base::BindOnce(&OnGetEntryResult, base::Passed(std::move(cb_state))));
  }

  void LookupEntryByUUIDImpl(std::string uuid, CollectionGetCallbackState cb_state) {
    dispatcher->LookupEntryByUUID(uuid, base::BindOnce(&OnGetEntryResult, base::Passed(std::move(cb_state))));
  }

  void ListEntriesImpl(CollectionListCallbackState cb_state) {
    dispatcher->ListEntries(base::BindOnce(&OnListEntriesResult, base::Passed(std::move(cb_state))));
  }

  void AddWatcherImpl(CollectionAddWatcherCallbackState cb_state) {
    common::mojom::CollectionWatcherPtrInfo url_watcher_info;
    CollectionWatcherImpl* watcher = new CollectionWatcherImpl(
      cb_state.watcher_state, 
      CollectionWatcherCallbacks{cb_state.OnEntryAdded, cb_state.OnEntryRemoved},
      mojo::MakeRequest(&url_watcher_info));
    dispatcher->AddWatcher(
      common::mojom::CollectionWatcherPtr(std::move(url_watcher_info)),
      base::BindOnce(&OnAddWatcherResult, 
        base::Unretained(watcher),
        base::Passed(std::move(cb_state))));
  }

  void RemoveWatcherImpl(int id) {
    dispatcher->RemoveWatcher(id);
  }

};


CollectionRef _CollectionCreateFromEngine(EngineInstanceRef handle) {
  domain::ModuleState* module = reinterpret_cast<_EngineInstance *>(handle)->module_state();
  return new CollectionWrapper(
    module->collection_dispatcher(), 
    module->GetMainTaskRunner());
}

void _CollectionDestroy(CollectionRef handle) {
  delete reinterpret_cast<CollectionWrapper *>(handle);
}

void _CollectionAddEntry(CollectionRef handle, 
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
  void* state, 
  void(*callback)(void*, int)) {
  
  common::mojom::CollectionEntryPtr entry = common::mojom::CollectionEntry::New();
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
  entry->install_state = static_cast<common::mojom::CollectionEntryInstallState>(install_state);
  entry->availability_state = static_cast<common::mojom::CollectionEntryAvailabilityState>(availability_state);
  entry->install_counter = install_counter;
  entry->rating = rating;
  entry->app_public_key = std::string(app_public_key);
  for (int i = 0; i < supported_platforms_count; ++i) {
    entry->supported_platforms.push_back(supported_platforms[i]);
  }
  for (int i = 0; i < supported_languages_count; ++i) {
    entry->supported_languages.push_back(supported_languages[i]);
  }

  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionHaveCallbackState cb_state{state, callback};  
  collection->AddEntry(std::move(entry), std::move(cb_state));
  //callback(reinterpret_cast<CollectionWrapper *>(handle)->handler_state, 0);
}

void _CollectionAddEntryByAddress(CollectionRef handle, 
  const char*, 
  void* state, 
  void(*callback)(void*, int)) {
 
}

void _CollectionRemoveEntry(CollectionRef handle, const char* address, void* state,  void(*callback)(void*, int)) {
  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionHaveCallbackState cb_state{state, callback};
  collection->RemoveEntry(address, std::move(cb_state));
}

void _CollectionRemoveEntryByUUID(CollectionRef handle, const char* uuid, void* state, void(*callback)(void*, int)) {
  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionHaveCallbackState cb_state{state, callback};
  collection->RemoveEntryByUUID(uuid, std::move(cb_state));
}

void _CollectionLookupEntry(CollectionRef handle, const char* address, void* state,  void(*callback)(
  void*, int, const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**)) {

  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionGetCallbackState cb_state{state, callback};  
  collection->LookupEntry(address, std::move(cb_state));
}

void _CollectionLookupEntryByName(CollectionRef handle, const char* name, void* state, void(*callback)(
  void*, int, const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**)) {

  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionGetCallbackState cb_state{state, callback};  
  collection->LookupEntryByName(name, std::move(cb_state));  
}

void _CollectionLookupEntryByUUID(CollectionRef handle, const char* uuid, void* state, void(*callback)(
  void*, int, const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**)) {
  
  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionGetCallbackState cb_state{state, callback};  
  collection->LookupEntryByUUID(uuid, std::move(cb_state));
}

void _CollectionHaveEntry(CollectionRef handle, const char* address, void* state, void(*callback)(void*, int)) {
  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionHaveCallbackState cb_state{state, callback};  
  collection->HaveEntry(address, std::move(cb_state));
}

void _CollectionHaveEntryByName(CollectionRef handle, const char* name, void* state, void(*callback)(void*, int)) {
  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionHaveCallbackState cb_state{state, callback};  
  collection->HaveEntryByName(name, std::move(cb_state));
}

void _CollectionHaveEntryByUUID(CollectionRef handle, const char* uuid, void* state, void(*callback)(void*, int)) {
  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionHaveCallbackState cb_state{state, callback};  
  collection->HaveEntryByUUID(uuid, std::move(cb_state));
}

void _CollectionListEntries(CollectionRef handle, void* state, void(*callback)(
  void*, int,
  const char**, const char**, const char**, const char**, 
  const char**, const char**, const char**, const char**, 
  const char**, uint64_t*, const char**, const char**,
  int*, int*, uint64_t*, uint32_t*, const char**, 
  int*, const char***, int*, const char***)) {

  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionListCallbackState cb_state{state, callback};  
  collection->ListEntries(std::move(cb_state));
}

void _CollectionGetEntryCount(CollectionRef handle, void* state, void(*callback)(void*, int)) {
  CollectionWrapper* collection = reinterpret_cast<CollectionWrapper *>(handle);
  CollectionHaveCallbackState cb_state{state, callback};  
  collection->GetEntryCount(std::move(cb_state));
}

void _CollectionAddWatcher(
  CollectionRef handle, 
  void* state,
  void* watcher_state, 
  void(*OnEntryAdded)(void*, const char*, const char*, const char*, const char*, 
                      const char*, const char*, const char*, const char*, 
                      const char*, uint64_t, const char*, const char*,
                      int, int, uint64_t, uint32_t, const char*, 
                      int, const char**, int, const char**),
  void(*OnEntryRemoved)(void*, const char*, const char*, const char*, const char*, 
                        const char*, const char*, const char*, const char*, 
                        const char*, uint64_t, const char*, const char*,
                        int, int, uint64_t, uint32_t, const char*, 
                        int, const char**, int, const char**)) {

  CollectionAddWatcherCallbackState cb_state{state, watcher_state, OnEntryAdded, OnEntryRemoved};
  reinterpret_cast<CollectionWrapper *>(handle)->AddWatcher(std::move(cb_state));   
}

void _CollectionRemoveWatcher(CollectionRef handle, int32_t watcher) {
  reinterpret_cast<CollectionWrapper *>(handle)->RemoveWatcher(watcher);
}

void _CollectionWatcherDestroy(void* handle) {
  delete reinterpret_cast<CollectionWatcherImpl *>(handle);
}