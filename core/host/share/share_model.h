// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_REPO_SHARE_MODEL_H_
#define MUMBA_HOST_REPO_SHARE_MODEL_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "net/base/io_buffer.h"
#include "core/host/database_policy.h"

namespace host {
class Share;
class ShareDatabase;
class ShareManager;

class ShareModel : public DatabasePolicyObserver {
public:
  ShareModel(ShareManager* manager, scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~ShareModel();

  const std::vector<std::unique_ptr<Share>>& shares() const {
    return shares_;
  }

  std::vector<std::unique_ptr<Share>>& shares() {
    return shares_;
  }

  void Load(base::Callback<void(int, int)> cb);
  bool ShareExists(Share* share) const;
  Share* GetShare(const std::string& domain, const std::string& name);
  Share* GetShareById(const base::UUID& id);
  void InsertShare(const base::UUID& id, std::unique_ptr<Share> share, bool persist = false);
  void RemoveShare(const base::UUID& id);
 
  void Close();

private:
  
  void InsertShareInternal(const base::UUID& id, std::unique_ptr<Share> share, bool persist);
  void RemoveShareInternal(const base::UUID& id);

  void InsertShareToDB(const base::UUID& id, Share* share);
  void RemoveShareFromDB(Share* share);

  void AddToCache(const base::UUID& id, std::unique_ptr<Share> share);
  void RemoveFromCache(const base::UUID& id);
  void RemoveFromCache(Share* share);

  void LoadSharesFromDB(base::Callback<void(int, int)> cb);

  void MaybeOpen();
  void MaybeClose();

  void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;

  ShareManager* manager_;
  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;
  
  std::vector<std::unique_ptr<Share>> shares_;

private:

 DISALLOW_COPY_AND_ASSIGN(ShareModel);
};

}

#endif