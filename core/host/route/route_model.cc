// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/route_model.h"

#include "core/host/route/route_scheme.h"

namespace host {

RouteModel::RouteModel() {

}

RouteModel::~RouteModel() {

}

size_t RouteModel::entry_count() {
  base::AutoLock l(entry_lock_);
  return entries_.size(); 
}

bool RouteModel::HaveEntry(const std::string& path) {
  base::AutoLock l(entry_lock_);
  return entries_path_index_.find(path) != entries_path_index_.end() ? true : false;
}

bool RouteModel::HaveEntry(const GURL& url) {
  base::AutoLock l(entry_lock_);
  GURL key(url.scheme() + ":" + url.path());
  return entries_route_index_.find(key.spec()) != entries_route_index_.end() ? true : false;
}

bool RouteModel::HaveEntry(const base::UUID& uuid) {
  base::AutoLock l(entry_lock_);
  return entries_uuid_index_.find(uuid) != entries_uuid_index_.end() ? true : false;
}

RouteEntry* RouteModel::GetEntry(const std::string& path) {
  base::AutoLock l(entry_lock_);
  auto it = entries_path_index_.find(path);
  if (it != entries_path_index_.end()) {
    return entries_.find(it->second)->second.get();
  }
  return nullptr;
}

RouteEntry* RouteModel::GetEntry(const base::UUID& uuid) {
  base::AutoLock l(entry_lock_);
  auto it = entries_uuid_index_.find(uuid);
  if (it != entries_uuid_index_.end()) {
    return entries_.find(it->second)->second.get();
  }
  return nullptr;
}

RouteEntry* RouteModel::GetEntry(const std::string& scheme, const std::string& path) {
  base::AutoLock l(entry_lock_);
  GURL url(scheme + ":/" + path);
  auto it = entries_route_index_.find(url.spec());
  if (it != entries_route_index_.end()) {
    return entries_.find(it->second)->second.get();
  }
  return nullptr;
}

RouteEntry* RouteModel::GetEntry(const GURL& url) {
  base::AutoLock l(entry_lock_);
  std::string path = url.path();

  auto start_offset = path.find_first_of("/");
  if (start_offset == std::string::npos) {
    return nullptr;
  }
  // jump the next '/'
  start_offset++;
  path = path.substr(start_offset+1);
  auto end_offset = path.find_first_of("/");
  if (end_offset != std::string::npos) {
    path = "//" + path.substr(0, end_offset);
  }

  GURL key(url.scheme() + ":" + path);
  auto it = entries_route_index_.find(key.spec());
  if (it != entries_route_index_.end()) {
    return entries_.find(it->second)->second.get();
  }
  return nullptr;
}

void RouteModel::AddEntry(OwnedEntry entry) {
  base::AutoLock l(entry_lock_);
  int index = ++entry_next_index_;
  entries_path_index_.emplace(std::make_pair(entry->path(), index));
  entries_route_index_.emplace(std::make_pair(entry->url().spec(), index));
  entries_uuid_index_.emplace(std::make_pair(entry->uuid(), index));
  entries_.emplace(std::make_pair(index, std::move(entry)));
}

RouteModel::OwnedEntry RouteModel::RemoveEntry(const std::string& path, common::mojom::RouteEntryPtr* entry_ptr) {
  base::AutoLock l(entry_lock_);
  auto it = entries_path_index_.find(path);
  if (it != entries_path_index_.end()) {
    return RemoveEntryInternal(it->second, entry_ptr);
  }
  return OwnedEntry();
}

RouteModel::OwnedEntry RouteModel::RemoveEntry(const base::UUID& uuid, common::mojom::RouteEntryPtr* entry_ptr) {
  base::AutoLock l(entry_lock_);
  auto it = entries_uuid_index_.find(uuid);
  if (it != entries_uuid_index_.end()) {
    return RemoveEntryInternal(it->second, entry_ptr);
  }
  return OwnedEntry();
}

RouteModel::OwnedEntry RouteModel::RemoveEntry(const GURL& url, common::mojom::RouteEntryPtr* entry_ptr) {
  base::AutoLock l(entry_lock_);
  auto it = entries_route_index_.find(url.spec());
  if (it != entries_route_index_.end()) {
    return RemoveEntryInternal(it->second, entry_ptr);
  }
  return OwnedEntry();
}

RouteModel::OwnedEntry RouteModel::RemoveEntryInternal(int id, common::mojom::RouteEntryPtr* entry_ptr) {
  auto it = entries_.find(id);
  if (it != entries_.end()) {
    OwnedEntry entry = std::move(it->second);
    entries_route_index_.erase(entries_route_index_.find(entry->url().spec()));
    entries_uuid_index_.erase(entries_uuid_index_.find(entry->uuid()));
    entries_path_index_.erase(entries_path_index_.find(entry->path()));
    *entry_ptr = std::move(entry->entry_);
    entries_.erase(it);
    return entry;
  }
  return OwnedEntry();
}

std::vector<RouteEntry*> RouteModel::GetAllEntries() {
  base::AutoLock l(entry_lock_);
  std::vector<RouteEntry*> result;
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    result.push_back(it->second.get());
  }
  return result;
}

std::vector<RouteEntry*> RouteModel::GetEntriesForScheme(const std::string& scheme) {
  base::AutoLock l(entry_lock_);
  std::vector<RouteEntry*> result;
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if (it->second->url().scheme() == scheme) {
      result.push_back(it->second.get());
    }
  }
  return result;
}

std::vector<common::mojom::RouteEntryPtr> RouteModel::GetAllMojoEntries() {
  base::AutoLock l(entry_lock_);
  std::vector<common::mojom::RouteEntryPtr> result;
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    result.push_back(it->second->entry_.Clone());
  }
  return result;
}

std::vector<common::mojom::RouteEntryPtr> RouteModel::GetMojoEntriesForScheme(const std::string& scheme) {
  base::AutoLock l(entry_lock_);
  std::vector<common::mojom::RouteEntryPtr> result;
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if (it->second->url().scheme() == scheme) {
      result.push_back(it->second->entry_.Clone());
    }
  }
  return result;
}

void RouteModel::AddScheme(std::unique_ptr<RouteScheme> scheme) {
  base::AutoLock l(scheme_lock_);
  schemes_.emplace(std::make_pair(scheme->name(), std::move(scheme)));
}

void RouteModel::RemoveScheme(const std::string& scheme_name) {
  base::AutoLock l(scheme_lock_);
  auto it = schemes_.find(scheme_name);
  if (it != schemes_.end()) {
    schemes_.erase(it);
  }
}

RouteScheme* RouteModel::GetScheme(const std::string& scheme_name) {
  base::AutoLock l(scheme_lock_);
  auto it = schemes_.find(scheme_name);
  if (it != schemes_.end()) {
    return it->second.get();
  }
  return nullptr;
}

bool RouteModel::HasScheme(const std::string& scheme_name) {
  base::AutoLock l(scheme_lock_);
  return schemes_.find(scheme_name) != schemes_.end();
}

size_t RouteModel::GetSchemeCount() {
  base::AutoLock l(scheme_lock_);
  return schemes_.size(); 
}

std::vector<common::mojom::RouteEntryPtr> RouteModel::GetAllSchemes() {
  base::AutoLock l(scheme_lock_);
  std::vector<common::mojom::RouteEntryPtr> result;
  for (auto it = schemes_.begin(); it != schemes_.end(); ++it) {
    result.push_back(it->second->entry_.Clone());
  }
  return result;
}

// void RouteModel::AddHandler(OwnedHandler handler) {
//   base::AutoLock l(handler_lock_);
//   int index = ++handler_next_index_;
//   handlers_name_index_.emplace(std::make_pair(handler->name(), index));
//   handlers_.emplace(std::make_pair(index, std::move(handler)));
// }

// void RouteModel::RemoveHandler(const std::string& handler_name) {
//   base::AutoLock l(handler_lock_);
//   auto it = handlers_name_index_.find(handler_name);
//   if (it != handlers_name_index_.end()) {
//     auto handlers_it = handlers_.find(it->second);
//     handlers_name_index_.erase(it);
//     handlers_.erase(handlers_it);
//   }
// }

// RouteHandler* RouteModel::GetHandler(const std::string& handler_name) {
//   base::AutoLock l(handler_lock_);
//   auto it = handlers_name_index_.find(handler_name);
//   if (it != handlers_name_index_.end()) {
//     return handlers_.find(it->second)->second.get();
//   }
//   return nullptr;
// }

// bool RouteModel::HasHandler(const std::string& handler_name) {
//   base::AutoLock l(handler_lock_);
//   return handlers_name_index_.find(handler_name) != handlers_name_index_.end();
// }

// std::vector<common::mojom::RouteHandlerPtr> RouteModel::GetMojoHandlers() {
//   base::AutoLock l(handler_lock_);
//   std::vector<common::mojom::RouteHandlerPtr> result;
//   for (auto it = handlers_.begin(); it != handlers_.end(); ++it) {
//     result.push_back(it->second->handler_.Clone());
//   }
//   return result;
// }

}