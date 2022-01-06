// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DOMAIN_MANAGER_H_
#define MUMBA_HOST_APPLICATION_DOMAIN_MANAGER_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "core/common/common_data.h"
#include "core/host/application/domain_model.h"
#include "core/host/host_controller.h"
#include "core/host/database_policy.h"
#include "url/gurl.h"

namespace host {
class Domain;
class VolumeManager;
class IOThread;
class StorageManager;
class ShareDatabase;

class DomainManager {
public:
  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnApplicationsLoad(int r, int count) {}
    virtual void OnDomainAdded(Domain* app) {}
    virtual void OnDomainRemoved(Domain* app) {}
    virtual void OnDomainLaunched(Domain* app) {}
    virtual void OnDomainShutdown(Domain* app) {}
  };
  DomainManager(scoped_refptr<Workspace> workspace, scoped_refptr<HostController> controller);
  ~DomainManager();

  void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy, const base::FilePath& root_path, IOThread* io_thread);
  void Shutdown();

  DomainModel* model() const { return hosts_.get() ;}

  const DomainModel::Domains& apps() const {
    return GetDomains();
  }
    
  bool HasDomain(const std::string& name) const;
  bool HasDomainUUID(const std::string& uuid) const;
  bool HasDomain(const base::UUID& uuid) const;
  bool HasDomain(const common::DomainInfo& info) const;
  bool HasDomain(const GURL& urn) const;
  Domain* GetDomain(const std::string& name) const;
  Domain* GetDomain(const base::UUID& uuid) const;
  Domain* GetDomain(const GURL& url) const;
  Domain* GetDomain(const common::DomainInfo& info) const;
  const DomainModel::Domains& GetDomains() const;
  DomainModel::Domains& GetDomains();

  // shell management
  void CreateDomain(std::unique_ptr<Domain> shell, base::Callback<void(int)> callback, bool sync = false);
  void DestroyDomain(const std::string& name);
  void DestroyDomain(const base::UUID& uuid);
  void LaunchDomain(const base::UUID& uuid, StorageManager* storage_manager, const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner, base::Callback<void(int)> callback);
  void LaunchDomain(const std::string& name, StorageManager* storage_manager, const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner, base::Callback<void(int)> callback);
  void LaunchDomain(Domain* shell, StorageManager* storage_manager, const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner, base::Callback<void(int)> callback);
  void ShutdownDomain(const std::string& name, base::Callback<void(int)> callback);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

private:
  friend class VolumeManager;
  
  void InitImpl(const base::FilePath& root_path);
  void ShutdownImpl();

  void CreateDomainImpl(std::unique_ptr<Domain> shell, base::Callback<void(int)> callback);
  void DestroyDomainImpl(Domain* shell);
  bool LoadDomainsFromIndex();
  void OnLoad(int r, int count);

  void LaunchDomainImpl(Domain* shell, StorageManager* storage_manager, const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner, base::Callback<void(int)> callback);
  void MaybeOpen();
  void MaybeClose();
  void OnDomainLaunched(Domain* shell, DomainProcessHost* process, base::Callback<void(int)> callback);

  void NotifyDomainAdded(Domain* app);
  void NotifyDomainRemoved(Domain* app);
  void NotifyDomainLaunched(Domain* app);
  void NotifyDomainShutdown(Domain* app);
  void NotifyApplicationsLoad(int r, int count);

  base::FilePath root_path_;

  scoped_refptr<Workspace> workspace_;

  scoped_refptr<HostController> controller_;

  std::unique_ptr<DomainModel> hosts_;

  std::vector<Observer *> observers_;

  IOThread* io_thread_;

  bool clean_shutdown_;

  DISALLOW_COPY_AND_ASSIGN(DomainManager);
};

}


#endif