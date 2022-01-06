// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SHARE_SHARE_REGISTRY_H_
#define MUMBA_HOST_SHARE_SHARE_REGISTRY_H_

#include "core/shared/common/mojom/share.mojom.h"

#include "core/common/proto/objects.pb.h"
#include "core/host/share/share_controller.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"

namespace host {
class Workspace;
class ShareManager;

class ShareRegistry : public common::mojom::ShareRegistry {
public:
  ShareRegistry(scoped_refptr<Workspace> workspace, ShareManager* share_manager);
  ~ShareRegistry();

  void AddBinding(common::mojom::ShareRegistryAssociatedRequest request);

  void Init();
  void Shutdown();

  ShareManager* share_manager() {
    return share_manager_;
  }
  
  void AddShare(common::mojom::ShareEntryPtr entry, AddShareCallback callback) final;
  void AddShareByAddress(common::mojom::ShareDescriptorPtr descriptor, AddShareByAddressCallback callback) final;
  void RemoveShare(const std::string& address, RemoveShareCallback callback) final;
  void RemoveShareByUUID(const std::string& uuid, RemoveShareByUUIDCallback callback) final;
  void LookupShare(const std::string& address, LookupShareCallback callback) final;
  void LookupShareByName(const std::string& name, LookupShareCallback callback) final;
  void LookupShareByUUID(const std::string& uuid, LookupShareByUUIDCallback callback) final;
  void HaveShare(const std::string& address, HaveShareCallback callback) final;
  void HaveShareByName(const std::string& name, HaveShareCallback callback) final;
  void HaveShareByUUID(const std::string& uuid, HaveShareByUUIDCallback callback) final;
  void ListShares(ListSharesCallback callback) final;
  void ListSharesByDomain(const std::string& domain_name, ListSharesByDomainCallback callback) final;
  void GetShareCount(GetShareCountCallback callback) final;
  void PauseShare(const std::string& address, PauseShareCallback callback) final;
  void ResumeShare(const std::string& address, ResumeShareCallback callback) final;
  void AnnounceShare(const std::string& address, AnnounceShareCallback callback) final;
  void SeedShare(const std::string& address, SeedShareCallback callback) final;
  void ListSharePeers(const std::string& address, ListSharePeersCallback callback) final;
  void ListSharePieces(const std::string& address, ListSharePiecesCallback callback) final;
  void ListShareFiles(const std::string& address, ListShareFilesCallback callback) final;

  void AddWatcher(common::mojom::ShareWatcherPtr watcher, AddWatcherCallback callback) final;
  void RemoveWatcher(int watcher) final;

private:

  void AddShareImpl(common::mojom::ShareEntryPtr entry, AddShareCallback callback);
  void AddShareByAddressImpl(common::mojom::ShareDescriptorPtr descriptor, AddShareByAddressCallback callback);
  void RemoveShareImpl(const std::string& address, RemoveShareCallback callback);
  void RemoveShareByUUIDImpl(const std::string& uuid, RemoveShareByUUIDCallback callback);
  void LookupShareImpl(const std::string& address, LookupShareCallback callback);
  void LookupShareByNameImpl(const std::string& name, LookupShareCallback callback);
  void LookupShareByUUIDImpl(const std::string& uuid, LookupShareByUUIDCallback callback);
  void HaveShareImpl(const std::string& address, HaveShareCallback callback);
  void HaveShareByNameImpl(const std::string& name, HaveShareCallback callback);
  void HaveShareByUUIDImpl(const std::string& uuid, HaveShareByUUIDCallback callback);
  void ListSharesImpl(ListSharesCallback callback);
  void ListSharesByDomainImpl(const std::string& domain_name, ListSharesByDomainCallback callback);
  void GetShareCountImpl(GetShareCountCallback callback);
  void PauseShareImpl(const std::string& address, PauseShareCallback callback);
  void ResumeShareImpl(const std::string& address, ResumeShareCallback callback);
  void AnnounceShareImpl(const std::string& address, AnnounceShareCallback callback);
  void SeedShareImpl(const std::string& address, SeedShareCallback callback);
  void ListSharePeersImpl(const std::string& address, ListSharePeersCallback callback);
  void ListSharePiecesImpl(const std::string& address, ListSharePiecesCallback callback);
  void ListShareFilesImpl(const std::string& address, ListShareFilesCallback callback);
  void AddWatcherImpl(common::mojom::ShareWatcherPtr watcher, AddWatcherCallback callback);
  void RemoveWatcherImpl(int watcher);  

  ShareController controller_;
  scoped_refptr<Workspace> workspace_;
  ShareManager* share_manager_;
  mojo::AssociatedBindingSet<common::mojom::ShareRegistry> share_registry_binding_;

  DISALLOW_COPY_AND_ASSIGN(ShareRegistry);
};

}

#endif