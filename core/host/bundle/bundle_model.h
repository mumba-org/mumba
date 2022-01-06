// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_BUNDLE_MODEL_H_
#define MUMBA_HOST_BUNDLE_MODEL_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "core/host/database_policy.h"

namespace host {
class Bundle;
class ShareDatabase;

class BundleModel {
public:
  BundleModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~BundleModel();

  void Load(base::Callback<void(int, int)> cb);
  void AddBundle(std::unique_ptr<Bundle> bundle, bool persist = true);
  bool HaveBundle(const base::UUID& id);
  bool HaveBundle(const std::string& name);
  Bundle* GetBundle(const base::UUID& id);
  Bundle* GetBundle(const std::string& name);
  void RemoveBundle(const base::UUID& id);

private:

  void AddBundleInternal(std::unique_ptr<Bundle> bundle, bool persist);
  void RemoveBundleInternal(const base::UUID& id);
  void AddBundleToDB(Bundle* bundle);
  void RemoveBundleFromDB(Bundle* bundle);
  void LoadBundlesFromDB(base::Callback<void(int, int)> cb);
  bool BundleExists(Bundle* bundle) const;
  void AddBundleToCache(std::unique_ptr<Bundle> bundle);
  void RemoveBundleFromCache(const base::UUID& id);
  void RemoveBundleFromCache(Bundle* bundle);
  void MaybeOpen();
  void MaybeClose();


  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;
  
  std::vector<std::unique_ptr<Bundle>> bundles_;

  DISALLOW_COPY_AND_ASSIGN(BundleModel);
};

}

#endif