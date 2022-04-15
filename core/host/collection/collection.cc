// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/collection/collection.h"

#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/paths.h"
#include "core/host/host_thread.h"
#include "core/host/collection/collection_model.h"
#include "core/host/collection/collection_observer.h"
#include "core/host/workspace/workspace.h"
#include "core/host/share/share_database.h"
#include "storage/torrent.h"

namespace host {

Collection::Collection(scoped_refptr<Workspace> workspace): 
  workspace_(std::move(workspace)),
  weak_factory_(this) {
  
}

Collection::~Collection() {

}

void Collection::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy) {
  entries_ = std::make_unique<CollectionModel>(db, policy);
  InitImpl();
}

void Collection::Shutdown() {
  ShutdownImpl();
}

void Collection::InitImpl() {
  entries_->Load(base::Bind(&Collection::OnLoad, base::Unretained(this)));
}

void Collection::ShutdownImpl() {
  entries_.reset();
}

bool Collection::EntryExists(const base::UUID& id) {
  return entries_->EntryExists(id);
}

bool Collection::EntryExists(const std::string& name) {
  return entries_->EntryExists(name);
}

bool Collection::EntryExists(CollectionEntry* entry) {
  return entries_->EntryExists(entry);
}

CollectionEntry* Collection::GetEntryById(const base::UUID& id) {
  return entries_->GetEntryById(id);
}

CollectionEntry* Collection::GetEntryByName(const std::string& name) {
  return entries_->GetEntryByName(name);
}

const std::vector<std::unique_ptr<CollectionEntry>>& Collection::GetEntries() const {
  return entries_->entries();
}

size_t Collection::GetEntryCount() {
  return entries_->entry_count();
}

void Collection::InsertEntry(std::unique_ptr<CollectionEntry> entry, bool persist) {
  CollectionEntry* reference = entry.get();
  entries_->InsertEntry(std::move(entry), persist);
  NotifyEntryAdded(reference);
}

bool Collection::RemoveEntry(CollectionEntry* entry) {
  NotifyEntryRemoved(entry);
  return entries_->RemoveEntry(entry->id());
}

bool Collection::RemoveEntry(const base::UUID& uuid) {
  CollectionEntry* entry = entries_->GetEntryById(uuid);
  if (entry) {
    NotifyEntryRemoved(entry);
    return entries_->RemoveEntry(uuid);
  }
  return false;
}

void Collection::AddObserver(CollectionObserver* observer) {
  observers_.push_back(observer);
}

void Collection::RemoveObserver(CollectionObserver* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void Collection::OnLoad(int r, int count) {
  NotifyEntriesLoad(r, count);
}

void Collection::NotifyEntriesLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    CollectionObserver* observer = *it;
    observer->OnCollectionEntriesLoad(r, count);
  }
}

void Collection::NotifyEntryAdded(CollectionEntry* entry) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    CollectionObserver* observer = *it;
    observer->OnCollectionEntryAdded(entry);
  }
}

void Collection::NotifyEntryRemoved(CollectionEntry* entry) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    CollectionObserver* observer = *it;
    observer->OnCollectionEntryRemoved(entry);
  }
}

const google::protobuf::Descriptor* Collection::resource_descriptor() {
  Schema* schema = workspace_->schema_registry()->GetSchemaByName("objects.proto");
  DCHECK(schema);
  return schema->GetMessageDescriptorNamed("CollectionEntry");
}

std::string Collection::resource_classname() const {
  return CollectionEntry::kClassName;
}

}
