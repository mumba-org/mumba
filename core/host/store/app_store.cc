// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/store/app_store.h"

#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/paths.h"
#include "core/host/host_thread.h"
#include "core/host/store/app_store_entry.h"
#include "core/host/store/app_store_model.h"
#include "core/host/store/app_store_observer.h"
#include "core/host/workspace/workspace.h"
#include "core/host/share/share_database.h"
#include "storage/torrent.h"

namespace host {

AppStore::AppStore(): weak_factory_(this) {
  
}

AppStore::~AppStore() {

}

void AppStore::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy) {
  entries_ = std::make_unique<AppStoreModel>(db, policy);
  InitImpl();
}

void AppStore::Shutdown() {
  ShutdownImpl();
}

void AppStore::InitImpl() {
  entries_->Load(base::Bind(&AppStore::OnLoad, base::Unretained(this)));
}

void AppStore::ShutdownImpl() {
  entries_.reset();
}

bool AppStore::EntryExists(const base::UUID& id) {
  return entries_->EntryExists(id);
}

bool AppStore::EntryExists(const std::string& name) {
  return entries_->EntryExists(name);
}

bool AppStore::EntryExists(AppStoreEntry* entry) {
  return entries_->EntryExists(entry);
}

AppStoreEntry* AppStore::GetEntryById(const base::UUID& id) {
  return entries_->GetEntryById(id);
}

AppStoreEntry* AppStore::GetEntryByName(const std::string& name) {
  return entries_->GetEntryByName(name);
}

const std::vector<std::unique_ptr<AppStoreEntry>>& AppStore::GetEntries() const {
  return entries_->entries();
}

size_t AppStore::GetEntryCount() {
  return entries_->entry_count();
}

void AppStore::InsertEntry(std::unique_ptr<AppStoreEntry> entry, bool persist) {
  AppStoreEntry* reference = entry.get();
  entries_->InsertEntry(std::move(entry), persist);
  NotifyEntryAdded(reference);
}

bool AppStore::RemoveEntry(AppStoreEntry* entry) {
  NotifyEntryRemoved(entry);
  return entries_->RemoveEntry(entry->id());
}

bool AppStore::RemoveEntry(const base::UUID& uuid) {
  AppStoreEntry* entry = entries_->GetEntryById(uuid);
  if (entry) {
    NotifyEntryRemoved(entry);
    return entries_->RemoveEntry(uuid);
  }
  return false;
}

void AppStore::AddObserver(AppStoreObserver* observer) {
  observers_.push_back(observer);
}

void AppStore::RemoveObserver(AppStoreObserver* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void AppStore::OnLoad(int r, int count) {
  NotifyEntriesLoad(r, count);
}

void AppStore::NotifyEntriesLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    AppStoreObserver* observer = *it;
    observer->OnAppStoreEntriesLoad(r, count);
  }
}

void AppStore::NotifyEntryAdded(AppStoreEntry* entry) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    AppStoreObserver* observer = *it;
    observer->OnAppStoreEntryAdded(entry);
  }
}

void AppStore::NotifyEntryRemoved(AppStoreEntry* entry) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    AppStoreObserver* observer = *it;
    observer->OnAppStoreEntryRemoved(entry);
  }
}

}
