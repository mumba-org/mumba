// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_REPO_REPO_REGISTRY_H_
#define MUMBA_HOST_REPO_REPO_REGISTRY_H_

#include "core/shared/common/mojom/repo.mojom.h"

#include "core/common/proto/objects.pb.h"
#include "core/host/repo/repo_controller.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"

namespace host {
class Workspace;
class RepoManager;

class RepoRegistry : public common::mojom::RepoRegistry {
public:
  RepoRegistry(scoped_refptr<Workspace> workspace, RepoManager* repo_manager);
  ~RepoRegistry();

  void AddBinding(common::mojom::RepoRegistryAssociatedRequest request);

  void Init();
  void Shutdown();

  RepoManager* repo_manager() {
    return repo_manager_;
  }

  void AddRepo(common::mojom::RepoEntryPtr entry, AddRepoCallback callback) final;
  void AddRepoByAddress(common::mojom::RepoDescriptorPtr descriptor, AddRepoByAddressCallback callback) final;
  void RemoveRepo(const std::string& address, RemoveRepoCallback callback) final;
  void RemoveRepoByUUID(const std::string& uuid, RemoveRepoByUUIDCallback callback) final;
  void LookupRepo(const std::string& address, LookupRepoCallback callback) final;
  void LookupRepoByName(const std::string& name, LookupRepoCallback callback) final;
  void LookupRepoByUUID(const std::string& uuid, LookupRepoByUUIDCallback callback) final;
  void HaveRepo(const std::string& address, HaveRepoCallback callback) final;
  void HaveRepoByName(const std::string& name, HaveRepoCallback callback) final;
  void HaveRepoByUUID(const std::string& uuid, HaveRepoByUUIDCallback callback) final;
  void ListRepos(ListReposCallback callback) final;
  void GetRepoCount(GetRepoCountCallback callback) final;
  void AddWatcher(common::mojom::RepoWatcherPtr watcher, AddWatcherCallback callback) final;
  void RemoveWatcher(int watcher) final;

private:

  void AddRepoImpl(common::mojom::RepoEntryPtr entry, AddRepoCallback callback);
  void AddRepoByAddressImpl(common::mojom::RepoDescriptorPtr descriptor, AddRepoByAddressCallback callback);
  void RemoveRepoImpl(const std::string& address, RemoveRepoCallback callback);
  void RemoveRepoByUUIDImpl(const std::string& uuid, RemoveRepoByUUIDCallback callback);
  void LookupRepoImpl(const std::string& address, LookupRepoCallback callback);
  void LookupRepoByNameImpl(const std::string& name, LookupRepoCallback callback);
  void LookupRepoByUUIDImpl(const std::string& uuid, LookupRepoByUUIDCallback callback);
  void HaveRepoImpl(const std::string& address, HaveRepoCallback callback);
  void HaveRepoByNameImpl(const std::string& name, HaveRepoCallback callback);
  void HaveRepoByUUIDImpl(const std::string& uuid, HaveRepoByUUIDCallback callback);
  void ListReposImpl(ListReposCallback callback);
  void GetRepoCountImpl(GetRepoCountCallback callback);

  void AddWatcherImpl(common::mojom::RepoWatcherPtr watcher, AddWatcherCallback callback);
  void RemoveWatcherImpl(int watcher);
 
  RepoController controller_;
  scoped_refptr<Workspace> workspace_;
  RepoManager* repo_manager_;
  mojo::AssociatedBindingSet<common::mojom::RepoRegistry> repo_registry_binding_;

  DISALLOW_COPY_AND_ASSIGN(RepoRegistry);
};

}

#endif