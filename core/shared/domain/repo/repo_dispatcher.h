// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_SHARED_DOMAIN_REPO_REPO_DISPATCHER_H_
#define MUMBA_SHARED_DOMAIN_REPO_REPO_DISPATCHER_H_

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
#include "core/shared/common/mojom/repo.mojom.h"
#include "core/shared/common/content_export.h"

namespace domain {
class DomainMainThread;

// AddRepo(RepoEntry entry) => (RepoStatusCode reply);
// AddRepoByAddress(RepoDescriptor descriptor) => (RepoStatusCode reply);
// RemoveRepo(string address) => (RepoStatusCode reply);
// RemoveRepoByUUID(string uuid) => (RepoStatusCode reply);
// LookupRepo(string address) => (RepoStatusCode code, RepoEntry? entry);
// LookupRepoByName(string name) => (RepoStatusCode code, RepoEntry? entry);
// LookupRepoByUUID(string uuid) => (RepoStatusCode code, RepoEntry? entry);
// HaveRepo(string address) => (bool have);
// HaveRepoByName(string name) => (bool have);
// HaveRepoByUUID(string uuid) => (bool have);
// ListRepos() => (array<RepoEntry> entries);
// GetRepoCount() => (uint32 count);

// AddWatcher(RepoWatcher watcher) => (int32 id);
// RemoveWatcher(int32 watcher);

class CONTENT_EXPORT RepoDispatcher : public common::mojom::RepoRegistry {
public:
  class CONTENT_EXPORT Delegate {
  public:
    virtual ~Delegate() {}
  };
  RepoDispatcher();
  ~RepoDispatcher() override;

  Delegate* delegate() const {
    return delegate_;
  }

  void set_delegate(Delegate* delegate) {
    delegate_ = delegate;
  }

  void Initialize(scoped_refptr<base::SingleThreadTaskRunner> task_runner);
  
  void AddRepo(common::mojom::RepoEntryPtr entry, AddRepoCallback callback) override;
  void AddRepoByAddress(common::mojom::RepoDescriptorPtr descriptor, AddRepoByAddressCallback callback) override;
  void RemoveRepo(const std::string& address, RemoveRepoCallback callback) override;
  void RemoveRepoByUUID(const std::string& uuid, RemoveRepoByUUIDCallback callback) override;
  void LookupRepo(const std::string& address, LookupRepoCallback callback) override;
  void LookupRepoByName(const std::string& name, LookupRepoByNameCallback callback) override;
  void LookupRepoByUUID(const std::string& uuid, LookupRepoByUUIDCallback callback) override;
  void HaveRepo(const std::string& address, HaveRepoCallback callback) override;
  void HaveRepoByName(const std::string& name, HaveRepoByNameCallback callback) override;
  void HaveRepoByUUID(const std::string& uuid, HaveRepoByUUIDCallback callback) override;
  void ListRepos(ListReposCallback callback) override;
  void GetRepoCount(GetRepoCountCallback callback) override;
  void AddWatcher(common::mojom::RepoWatcherPtr watcher, AddWatcherCallback callback) override;
  void RemoveWatcher(int32_t watcher_id) override;

private:
  friend class DomainMainThread;

  Delegate* delegate_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  scoped_refptr<base::SequencedTaskRunner> impl_task_runner_;
  
  common::mojom::RepoRegistryAssociatedPtr repo_dispatcher_;
  
  base::WeakPtrFactory<RepoDispatcher> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(RepoDispatcher);
};

}

#endif