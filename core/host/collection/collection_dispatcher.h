// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_COLLECTION_REGISTRY_H_
#define MUMBA_HOST_STORE_COLLECTION_REGISTRY_H_

#include "core/shared/common/mojom/collection.mojom.h"

#include "core/common/proto/objects.pb.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "core/host/share/share_controller.h"
#include "core/host/collection/collection_controller.h"

namespace host {
class Workspace;
class Collection;

class CollectionDispatcher : public common::mojom::CollectionDispatcher {
public:
  CollectionDispatcher(scoped_refptr<Workspace> workspace, Collection* collection);
  ~CollectionDispatcher();

  void AddBinding(common::mojom::CollectionDispatcherAssociatedRequest request);

  void Init();
  void Shutdown();

  Collection* collection() {
    return collection_;
  }

  void AddEntry(common::mojom::CollectionEntryPtr entry, AddEntryCallback callback) final;
  void AddEntryByAddress(common::mojom::CollectionEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback) final;
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
  void AddWatcher(common::mojom::CollectionWatcherPtr watcher, AddWatcherCallback callback) final;
  void RemoveWatcher(int watcher) final;

private:

  void AddEntryImpl(common::mojom::CollectionEntryPtr entry, AddEntryCallback callback);
  void AddEntryByAddressImpl(common::mojom::CollectionEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback);
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

  void AddWatcherImpl(common::mojom::CollectionWatcherPtr watcher, AddWatcherCallback callback);
  void RemoveWatcherImpl(int watcher);

  void OnStorageCloned(AddEntryByAddressCallback callback, int result);
  void OnShareCreated(AddEntryByAddressCallback callback, int result);
 
  scoped_refptr<Workspace> workspace_;
  Collection* collection_;
  ShareController share_controller_;
  CollectionController controller_;
  mojo::AssociatedBindingSet<common::mojom::CollectionDispatcher> collection_dispatcher_binding_;
  std::unordered_map<int, common::mojom::CollectionWatcherPtr> watchers_;
  int next_watcher_id_;

  DISALLOW_COPY_AND_ASSIGN(CollectionDispatcher);
};

}

#endif