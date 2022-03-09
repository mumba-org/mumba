// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle_model.h"

#include "core/host/share/share_database.h"
#include "core/host/bundle/bundle.h"
#include "storage/db/db.h"
#include "storage/torrent.h"

namespace host {

BundleModel::BundleModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy):
 policy_(policy),
 db_(db) {
  
}

BundleModel::~BundleModel() {
  
}

void BundleModel::Load(base::Callback<void(int, int)> cb) {
  LoadBundlesFromDB(std::move(cb));
}

void BundleModel::AddBundle(std::unique_ptr<Bundle> bundle, bool persist) {
  AddBundleInternal(std::move(bundle), persist); 
}

bool BundleModel::HaveBundle(const base::UUID& id) {
  for (auto it = bundles_.begin(); it != bundles_.end(); ++it) {
    if ((*it)->id() == id) {
      return true;
    }
  }
  return false;
}

bool BundleModel::HaveBundle(const std::string& name) {
  for (auto it = bundles_.begin(); it != bundles_.end(); ++it) {
    if ((*it)->name() == name) {
      return true;
    }
  }
  return false;
}

Bundle* BundleModel::GetBundle(const std::string& name) {
  for (auto it = bundles_.begin(); it != bundles_.end(); ++it) {
    if ((*it)->name() == name) {
      return it->get();
    }
  }
  return nullptr;
}

Bundle* BundleModel::GetBundle(const base::UUID& id) {
  for (auto it = bundles_.begin(); it != bundles_.end(); ++it) {
    if ((*it)->id() == id) {
      return it->get();
    }
  }
  return nullptr;
}

void BundleModel::RemoveBundle(const base::UUID& id) {
  RemoveBundleInternal(id);
}

void BundleModel::AddBundleInternal(std::unique_ptr<Bundle> bundle, bool persist) {
  // after is added to the db, add it to the cache
  if (!BundleExists(bundle.get())) {
    Bundle* bundle_ptr = bundle.get();
    AddBundleToDB(bundle_ptr);
    AddBundleToCache(std::move(bundle));
  } else {
    LOG(ERROR) << "Failed to add bundle " << bundle->name() << " to DB. Already exists";
  }
}

void BundleModel::RemoveBundleInternal(const base::UUID& id) {
  // after is removed from the db, remove it from cache
  Bundle* bundle = GetBundle(id);
  if (bundle) {
    RemoveBundleFromDB(bundle);
    RemoveBundleFromCache(bundle);
  } else {
    LOG(ERROR) << "Failed to remove bundle. Bundle with id " << id.to_string() << " not found.";
  }
}

void BundleModel::AddBundleToDB(Bundle* bundle) {
  //bool result = false;
  scoped_refptr<net::IOBufferWithSize> data = bundle->Serialize();
  if (data) {
    MaybeOpen();
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, Bundle::kClassName, bundle->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    MaybeClose();
  }
}

void BundleModel::RemoveBundleFromDB(Bundle* bundle) {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, Bundle::kClassName, bundle->name());
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
}

void BundleModel::LoadBundlesFromDB(base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(Bundle::kClassName);
  if (!it) {
    DLOG(ERROR) << "BundleModel::LoadBundlesFromDB: creating cursor for 'bundle' failed.";
    std::move(cb).Run(net::ERR_FAILED, count);
    return;
  }
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      // even if this is small.. having to heap allocate here is not cool
      scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
      std::unique_ptr<Bundle> bundle = Bundle::Deserialize(buffer.get(), kv.second.size());
      if (bundle) {
        AddBundleToCache(std::move(bundle));
      } else {
        LOG(ERROR) << "failed to deserialize bundle";
      }
    } else {
      LOG(ERROR) << "failed to deserialize bundle: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  trans->Commit();
  MaybeClose();
  std::move(cb).Run(net::OK, count);
}

bool BundleModel::BundleExists(Bundle* bundle) const {
  for (auto it = bundles_.begin(); it != bundles_.end(); ++it) {
    if ((*it)->name() == bundle->name()) {
      return true;
    }
  }
  return false; 
}

void BundleModel::AddBundleToCache(std::unique_ptr<Bundle> bundle) {
  bundle->set_managed(true);
  bundles_.push_back(std::move(bundle));
}

void BundleModel::RemoveBundleFromCache(const base::UUID& id) {
  Bundle* found = nullptr;
  for (auto it = bundles_.begin(); it != bundles_.end(); ++it) {
    if ((*it)->id() == id) {
      found = it->get();
      found->set_managed(false);
      bundles_.erase(it);
      break;
    }
  }
}

void BundleModel::RemoveBundleFromCache(Bundle* bundle) {
  for (auto it = bundles_.begin(); it != bundles_.end(); ++it) {
    if (it->get() == bundle) {
      (*it)->set_managed(false);
      bundles_.erase(it);
      break;
    }
  }
}

void BundleModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    DLOG(INFO) << "IdentityModel::MaybeOpen: db is not open, reopening...";
    db_->Open(true);
  }
}

void BundleModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

}