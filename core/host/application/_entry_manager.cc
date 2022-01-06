// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/entry_manager.h"

namespace host {

EntryManager::EntryManager() {

}

EntryManager::~EntryManager() {

}

void EntryManager::AddEntry(const Scheme& scheme, const Path& path, std::unique_ptr<EntryNode> entry) {
  base::AutoLock lock(lock_);
  int id = entry_id_gen_.GetNext();
  index_.emplace(std::make_pair(std::make_pair(scheme, path), id));
  entries_.emplace(std::make_pair(id, std::move(entry)));
}

void EntryManager::RemoveEntry(const Scheme& scheme, const Path& path) {
  base::AutoLock lock(lock_);
  
  Address address = std::make_pair(scheme, path);
  auto index_it = index_.find(address);
  if (index_it == index_.end()) {
    return;
  }
  entries_.erase(entries_.find(index_it->second));
  index_.erase(index_it);
}

EntryNode* EntryManager::LookupEntry(const Scheme& scheme, const Path& path) {
  base::AutoLock lock(lock_);
  
  Address address = std::make_pair(scheme, path);
  auto index_it = index_.find(address);
  if (index_it == index_.end()) {
    return nullptr;
  }
  return entries_.find(index_it->second)->second.get();
}

std::vector<EntryNode*> EntryManager::GetEntryListForScheme(const Scheme& scheme) {
  base::AutoLock lock(lock_);
  
  std::vector<int> keys;
  std::vector<EntryNode*> result;
  for (auto it = index_.begin(); it != index_.end(); ++it) {
    const Address& addr = it->first;
    if (addr.first == scheme) {
      keys.push_back(it->second);
    }
  }
  for (auto it = keys.begin(); it != keys.end(); it++) {
    auto found = entries_.find(*it);
    if (found != entries_.end()) {
      result.push_back(found->second.get());
    }
  }
  return result; 
}

}