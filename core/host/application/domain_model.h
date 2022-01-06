// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DOMAIN_MODEL_H_
#define MUMBA_HOST_APPLICATION_DOMAIN_MODEL_H_

#include <functional>
#include <map>
#include <unordered_map>

#include <memory>
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/atomic_sequence_num.h"
#include "base/synchronization/lock.h"
#include "url/gurl.h"
#include "base/uuid.h"
#include "core/common/common_data.h"
#include "core/host/application/domain.h"
#include "core/host/database_policy.h"

namespace host {
class Workspace;
class ShareDatabase;

class DomainModel : public DatabasePolicyObserver {
public:
  typedef std::unordered_map<base::UUID, Domain*> Domains;
  
  DomainModel(scoped_refptr<Workspace> workspace, scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~DomainModel();

  const Domains& apps() const {
    return domains_;
  }

  inline bool HasDomain(const std::string& name) const {
    for (auto it = domains_.begin(); it != domains_.end(); ++it) {
      if ((*it).second->name() == name) {
        return true;
      }
    }
    return false;
  }

  inline bool HasDomainUUID(const std::string& uuid) const {
    for (auto it = domains_.begin(); it != domains_.end(); ++it) {
      if ((*it).first.StartsWith(uuid, 8)) {
        return true;
      }
    }
    return false;
  }

  inline bool HasDomain(const base::UUID& uuid) const {
    return domains_.end() != domains_.find(uuid);
  }

  inline bool HasDomain(const common::DomainInfo& info) const {
    return info.name.empty() ? HasDomain(info.uuid) : HasDomain(info.name);
  }

  bool HasDomain(const GURL& urn) const;
  Domain* GetDomain(const std::string& name) const;
  Domain* GetDomain(const base::UUID& uuid) const;
  Domain* GetDomain(const GURL& url) const;
  Domain* GetDomain(const common::DomainInfo& info) const;
  const Domains& GetDomains() const;
  Domains& GetDomains();

  void LoadDomains(base::Callback<void(int, int)> cb);
  void AddDomain(std::unique_ptr<Domain> shell);
  bool RemoveDomain(const std::string& name);
  bool RemoveDomain(const base::UUID& uuid);

  void AddDomainIntoDB(Domain* shell);
  void RemoveDomainFromDB(Domain* shell);

private:

  void LoadDomainsFromDB(base::Callback<void(int, int)> cb);
  
  void AddDomainIntoDBImpl(Domain* shell);
  void RemoveDomainFromDBImpl(Domain* shell);

  std::string ParseTargetFromURL(const GURL& url, bool* ok) const;

  void OnInsertReply(bool result);
  void OnRemoveReply(bool result);

  void MaybeOpen();
  void MaybeClose();

  void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;

  scoped_refptr<Workspace> workspace_;
  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;

  Domains domains_;

  DISALLOW_COPY_AND_ASSIGN(DomainModel);
};

}

#endif