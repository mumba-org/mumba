// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/share/share_registry.h"

#include "core/host/host_thread.h"
#include "core/host/workspace/workspace.h"

namespace host {

ShareRegistry::ShareRegistry(scoped_refptr<Workspace> workspace, ShareManager* share_manager):
  controller_(share_manager),
  workspace_(workspace),
  share_manager_(share_manager) {

}

ShareRegistry::~ShareRegistry() {
  workspace_ = nullptr;
}

void ShareRegistry::AddBinding(common::mojom::ShareRegistryAssociatedRequest request) {
  share_registry_binding_.AddBinding(this, std::move(request));
}

void ShareRegistry::Init() {

}

void ShareRegistry::Shutdown() {

}
  
void ShareRegistry::AddShare(common::mojom::ShareEntryPtr entry, AddShareCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::AddShareImpl, 
      base::Unretained(this),
      base::Passed(std::move(entry)),
      base::Passed(std::move(callback))));
}

void ShareRegistry::AddShareByAddress(common::mojom::ShareDescriptorPtr descriptor, AddShareByAddressCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::AddShareByAddressImpl, 
      base::Unretained(this),
      base::Passed(std::move(descriptor)),
      base::Passed(std::move(callback))));
}

void ShareRegistry::RemoveShare(const std::string& address, RemoveShareCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::RemoveShareImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void ShareRegistry::RemoveShareByUUID(const std::string& uuid, RemoveShareByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::RemoveShareByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));  
}

void ShareRegistry::LookupShare(const std::string& address, LookupShareCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::LookupShareImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback)))); 
}

void ShareRegistry::LookupShareByName(const std::string& name, LookupShareCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::LookupShareByNameImpl, 
      base::Unretained(this),
      name,
      base::Passed(std::move(callback)))); 
}

void ShareRegistry::LookupShareByUUID(const std::string& uuid, LookupShareByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::LookupShareByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback)))); 
}

void ShareRegistry::HaveShare(const std::string& address, HaveShareCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::HaveShareImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback)))); 
}

void ShareRegistry::HaveShareByName(const std::string& name, HaveShareCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::HaveShareByNameImpl, 
      base::Unretained(this),
      name,
      base::Passed(std::move(callback))));
}

void ShareRegistry::HaveShareByUUID(const std::string& uuid, HaveShareByUUIDCallback callback) {
   HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::HaveShareByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void ShareRegistry::ListShares(ListSharesCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::ListSharesImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void ShareRegistry::ListSharesByDomain(const std::string& domain_name, ListSharesByDomainCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::ListSharesByDomainImpl, 
      base::Unretained(this),
      domain_name,
      base::Passed(std::move(callback))));
}

void ShareRegistry::GetShareCount(GetShareCountCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::GetShareCountImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void ShareRegistry::PauseShare(const std::string& address, PauseShareCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::PauseShareImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void ShareRegistry::ResumeShare(const std::string& address, ResumeShareCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::ResumeShareImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void ShareRegistry::AnnounceShare(const std::string& address, AnnounceShareCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::AnnounceShareImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void ShareRegistry::SeedShare(const std::string& address, SeedShareCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::SeedShareImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void ShareRegistry::ListSharePeers(const std::string& address, ListSharePeersCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::ListSharePeersImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void ShareRegistry::ListSharePieces(const std::string& address, ListSharePiecesCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::ListSharePiecesImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void ShareRegistry::ListShareFiles(const std::string& address, ListShareFilesCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::ListShareFilesImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void ShareRegistry::AddWatcher(common::mojom::ShareWatcherPtr watcher, AddWatcherCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::AddWatcherImpl, 
      base::Unretained(this),
      base::Passed(std::move(watcher)),
      base::Passed(std::move(callback))));
}

void ShareRegistry::RemoveWatcher(int watcher) {
   HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&ShareRegistry::RemoveWatcherImpl, 
      base::Unretained(this),
      watcher));
}

void ShareRegistry::AddShareImpl(common::mojom::ShareEntryPtr entry, AddShareCallback callback) {
  const std::string& address = entry->address;
  controller_.CreateShareWithPath(address);
}

void ShareRegistry::AddShareByAddressImpl(common::mojom::ShareDescriptorPtr descriptor, AddShareByAddressCallback callback) {
  const std::string& address = descriptor->address;
  controller_.CreateShareWithPath(address);
}

void ShareRegistry::RemoveShareImpl(const std::string& address, RemoveShareCallback callback) {
  controller_.RemoveShare(address);
  std::move(callback).Run(common::mojom::ShareStatusCode::kSHARE_STATUS_OK);
}

void ShareRegistry::RemoveShareByUUIDImpl(const std::string& uuid, RemoveShareByUUIDCallback callback) {
  controller_.RemoveShare(uuid);
  std::move(callback).Run(common::mojom::ShareStatusCode::kSHARE_STATUS_OK);
}

void ShareRegistry::LookupShareImpl(const std::string& address, LookupShareCallback callback) {
  controller_.LookupShareByAddress(address);
}

void ShareRegistry::LookupShareByNameImpl(const std::string& name, LookupShareCallback callback) {
  controller_.LookupShareByName(name);
}

void ShareRegistry::LookupShareByUUIDImpl(const std::string& uuid, LookupShareByUUIDCallback callback) {
  bool ok = false;
  base::UUID id = base::UUID::from_string(uuid, &ok);
  controller_.LookupShareByUUID(id);
}

void ShareRegistry::HaveShareImpl(const std::string& address, HaveShareCallback callback) {
  bool have_share = controller_.HaveShareByAddress(address);
  std::move(callback).Run(have_share); 
}

void ShareRegistry::HaveShareByNameImpl(const std::string& name, HaveShareCallback callback) {
  bool have_share = controller_.HaveShareByName(name);
  std::move(callback).Run(have_share); 
}

void ShareRegistry::HaveShareByUUIDImpl(const std::string& uuid, HaveShareByUUIDCallback callback) {
  bool ok = false;
  base::UUID id = base::UUID::from_string(uuid, &ok);
  bool have_share = controller_.HaveShareByUUID(id);
  std::move(callback).Run(have_share);
}

void ShareRegistry::ListSharesImpl(ListSharesCallback callback) {

}

void ShareRegistry::ListSharesByDomainImpl(const std::string& domain_name, ListSharesByDomainCallback callback) {

}

void ShareRegistry::GetShareCountImpl(GetShareCountCallback callback) {

}

void ShareRegistry::PauseShareImpl(const std::string& address, PauseShareCallback callback) {
    
}

void ShareRegistry::ResumeShareImpl(const std::string& address, ResumeShareCallback callback) {

}

void ShareRegistry::AnnounceShareImpl(const std::string& address, AnnounceShareCallback callback) {

}

void ShareRegistry::SeedShareImpl(const std::string& address, SeedShareCallback callback) {

}

void ShareRegistry::ListSharePeersImpl(const std::string& address, ListSharePeersCallback callback) {

}

void ShareRegistry::ListSharePiecesImpl(const std::string& address, ListSharePiecesCallback callback) {

}

void ShareRegistry::ListShareFilesImpl(const std::string& address, ListShareFilesCallback callback) {

}

void ShareRegistry::AddWatcherImpl(common::mojom::ShareWatcherPtr watcher, AddWatcherCallback callback) {

}

void ShareRegistry::RemoveWatcherImpl(int watcher) {

}

}