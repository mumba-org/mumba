// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_SHARED_DOMAIN_STORE_APP_STORE_DISPATCHER_H_
#define MUMBA_SHARED_DOMAIN_STORE_APP_STORE_DISPATCHER_H_

#include <memory>

#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/optional.h"
#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "core/shared/common/mojom/collection.mojom.h"
#include "core/shared/common/content_export.h"

namespace domain {
class DomainMainThread;

// AddEntry(CollectionEntry entry) => (CollectionStatusCode reply);
// AddEntryByAddress(CollectionEntryDescriptor descriptor) => (CollectionStatusCode reply);
// RemoveEntry(string address) => (CollectionStatusCode reply);
// RemoveEntryByUUID(string uuid) => (CollectionStatusCode reply);
// LookupEntry(string address) => (CollectionStatusCode code, CollectionEntry? entry);
// LookupEntryByName(string name) => (CollectionStatusCode code, CollectionEntry? entry);
// LookupEntryByUUID(string uuid) => (CollectionStatusCode code, CollectionEntry? entry);
// HaveEntry(string address) => (bool have);
// HaveEntryByName(string name) => (bool have);
// HaveEntryByUUID(string uuid) => (bool have);
// ListEntries() => (array<CollectionEntry> entries);
// GetEntryCount() => (uint32 count);
// AddWatcher(CollectionWatcher watcher) => (int32 id);
// RemoveWatcher(int32 watcher);

class CONTENT_EXPORT CollectionDispatcher : public common::mojom::CollectionDispatcher {
public:
  class CONTENT_EXPORT Delegate {
  public:
    virtual ~Delegate() {}
  };
  CollectionDispatcher();
  ~CollectionDispatcher() override;

  Delegate* delegate() const {
    return delegate_;
  }

  void set_delegate(Delegate* delegate) {
    delegate_ = delegate;
  }

  void Initialize(scoped_refptr<base::SingleThreadTaskRunner> task_runner);
  
  void AddEntry(common::mojom::CollectionEntryPtr entry, AddEntryCallback callback) override;
  void AddEntryByAddress(common::mojom::CollectionEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback) override;
  void RemoveEntry(const std::string& address, RemoveEntryCallback callback) override;
  void RemoveEntryByUUID(const std::string& uuid, RemoveEntryByUUIDCallback callback) override;
  void LookupEntry(const std::string& address, LookupEntryCallback callback) override;
  void LookupEntryByName(const std::string& path, LookupEntryByNameCallback callback) override;
  void LookupEntryByUUID(const std::string& uuid, LookupEntryByUUIDCallback callback) override;
  void HaveEntry(const std::string& address, HaveEntryCallback callback) override;
  void HaveEntryByName(const std::string& name, HaveEntryByNameCallback callback) override;
  void HaveEntryByUUID(const std::string& uuid, HaveEntryByUUIDCallback callback) override;
  void ListEntries(ListEntriesCallback callback) override;
  void GetEntryCount(GetEntryCountCallback callback) override;
  void AddWatcher(common::mojom::CollectionWatcherPtr subscriber, AddWatcherCallback callback) override;
  void RemoveWatcher(int32_t subscriber_id) override;

private:
  friend class DomainMainThread;

  Delegate* delegate_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  scoped_refptr<base::SequencedTaskRunner> impl_task_runner_;
  
  common::mojom::CollectionDispatcherAssociatedPtr collection_dispatcher_;

  base::WeakPtrFactory<CollectionDispatcher> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(CollectionDispatcher);
};

}

#endif