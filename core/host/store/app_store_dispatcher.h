// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_APP_STORE_REGISTRY_H_
#define MUMBA_HOST_STORE_APP_STORE_REGISTRY_H_

#include "core/shared/common/mojom/app_store.mojom.h"

#include "core/common/proto/objects.pb.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "core/host/share/share_controller.h"
#include "core/host/store/app_store_controller.h"

namespace host {
class Workspace;
class AppStore;

class AppStoreDispatcher : public common::mojom::AppStoreDispatcher {
public:
  AppStoreDispatcher(scoped_refptr<Workspace> workspace, AppStore* app_store);
  ~AppStoreDispatcher();

  void AddBinding(common::mojom::AppStoreDispatcherAssociatedRequest request);

  void Init();
  void Shutdown();

  AppStore* app_store() {
    return app_store_;
  }

  void AddEntry(common::mojom::AppStoreEntryPtr entry, AddEntryCallback callback) final;
  void AddEntryByAddress(common::mojom::AppStoreEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback) final;
  void RemoveEntry(const std::string& address, RemoveEntryCallback callback) final;
  void RemoveEntryByUUID(const std::string& uuid, RemoveEntryByUUIDCallback callback) final;
  void LookupEntry(const std::string& address, LookupEntryCallback callback) final;
  void LookupEntryByName(const std::string& name, LookupEntryCallback callback) final;
  void LookupEntryByUUID(const std::string& uuid, LookupEntryByUUIDCallback callback) final;
  void HaveEntry(const std::string& address, HaveEntryCallback callback) final;
  void HaveEntryByName(const std::string& name, HaveEntryCallback callback) final;
  void HaveEntryByUUID(const std::string& uuid, HaveEntryByUUIDCallback callback) final;
  void ListEntries(ListEntriesCallback callback) final;
  void GetEntryCount(GetEntryCountCallback callback) final;
  void AddWatcher(common::mojom::AppStoreWatcherPtr watcher, AddWatcherCallback callback) final;
  void RemoveWatcher(int watcher) final;

private:

  void AddEntryImpl(common::mojom::AppStoreEntryPtr entry, AddEntryCallback callback);
  void AddEntryByAddressImpl(common::mojom::AppStoreEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback);
  void RemoveEntryImpl(const std::string& address, RemoveEntryCallback callback);
  void RemoveEntryByUUIDImpl(const std::string& uuid, RemoveEntryByUUIDCallback callback);
  void LookupEntryImpl(const std::string& address, LookupEntryCallback callback);
  void LookupEntryByNameImpl(const std::string& name, LookupEntryCallback callback);
  void LookupEntryByUUIDImpl(const std::string& uuid, LookupEntryByUUIDCallback callback);
  void HaveEntryImpl(const std::string& address, HaveEntryCallback callback);
  void HaveEntryByNameImpl(const std::string& name, HaveEntryCallback callback);
  void HaveEntryByUUIDImpl(const std::string& uuid, HaveEntryByUUIDCallback callback);
  void ListEntriesImpl(ListEntriesCallback callback);
  void GetEntryCountImpl(GetEntryCountCallback callback);

  void AddWatcherImpl(common::mojom::AppStoreWatcherPtr watcher, AddWatcherCallback callback);
  void RemoveWatcherImpl(int watcher);

  void OnStorageCloned(AddEntryByAddressCallback callback, int result);
  void OnShareCreated(AddEntryByAddressCallback callback, int result);
 
  scoped_refptr<Workspace> workspace_;
  AppStore* app_store_;
  ShareController share_controller_;
  AppStoreController controller_;
  mojo::AssociatedBindingSet<common::mojom::AppStoreDispatcher> app_store_dispatcher_binding_;
  std::unordered_map<int, common::mojom::AppStoreWatcherPtr> watchers_;
  int next_watcher_id_;

  DISALLOW_COPY_AND_ASSIGN(AppStoreDispatcher);
};

}

#endif