// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/domain_model.h"

#include "base/guid.h"
#include "base/logging.h"
#include "base/base64url.h"
#include "base/stl_util.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/share/share_database.h"
#include "storage/db/db.h"
#include "storage/torrent.h"
#include "core/host/workspace/workspace.h"

namespace host {

DomainModel::DomainModel(scoped_refptr<Workspace> workspace, scoped_refptr<ShareDatabase> db, DatabasePolicy policy):
  workspace_(workspace),
  policy_(policy),
  db_(db) {
}

DomainModel::~DomainModel() {
  for (auto it = domains_.begin(); it != domains_.end(); ++it) {
    delete it->second;
  }
  domains_.clear();
  db_ = nullptr;
}

bool DomainModel::HasDomain(const GURL& urn) const {
  bool parse_ok = false;

  std::string target = ParseTargetFromURL(urn, &parse_ok);
  if (!parse_ok)
    return parse_ok;

  //DLOG(INFO) << "shell: " << target;

  if (target.size() == 36) {
    bool convert_result = false;
    base::UUID uuid = base::UUID::from_string(target, &convert_result);
    
    if(!convert_result)
      return false;
    
    return HasDomain(uuid);
  }

  if (!HasDomain(target)) { // try by name
    return HasDomainUUID(target); // than by uuid start
  }

  // by name match
  return true;
}

Domain* DomainModel::GetDomain(const std::string& name) const {
  for (auto it = domains_.begin(); it != domains_.end(); ++it) {
    if ((*it).second->name() == name) {
      return it->second;
    }
  }
  return nullptr; 
}

Domain* DomainModel::GetDomain(const base::UUID& uuid) const {
  auto it = domains_.find(uuid);
  if (it == domains_.end()) {
    return nullptr;
  }
  return it->second;
  return nullptr;
}

Domain* DomainModel::GetDomain(const GURL& urn) const {
  bool parse_ok = false;
  Domain* result = nullptr;

  std::string target = ParseTargetFromURL(urn, &parse_ok);
  if (!parse_ok)
    return nullptr;

  if (target.size() == 36) {
    bool convert_result = false;
    base::UUID uuid = base::UUID::from_string(target, &convert_result);
    
    if(!convert_result)
      return nullptr;
    
    result = GetDomain(uuid);
    return result;
  }

  if ((result = GetDomain(target)) == nullptr) { // try by name
    for (auto it = domains_.begin(); it != domains_.end(); ++it) {
      if ((*it).first.StartsWith(target, 8)) {
        result = (*it).second;
      }
    }
  }

  return result;
}

Domain* DomainModel::GetDomain(const common::DomainInfo& info) const {
  return info.name.empty() ? GetDomain(info.uuid) : GetDomain(info.name);
}

const DomainModel::Domains& DomainModel::GetDomains() const {
  return domains_;
}

DomainModel::Domains& DomainModel::GetDomains() {
  return domains_;
}

void DomainModel::AddDomain(std::unique_ptr<Domain> shell) { 
  Domain* domain_ptr = shell.release();
  if (!domain_ptr) {
    DLOG(ERROR) << "error: trying to add a null Domain";
    return;
  }
  domains_.emplace(std::make_pair(domain_ptr->id(), domain_ptr));
}

bool DomainModel::RemoveDomain(const std::string& name) {
  Domain* shell = GetDomain(name);
  if (shell) {
    domains_.erase(shell->id());
    delete shell;
    return true;
  }
  return false;
}

bool DomainModel::RemoveDomain(const base::UUID& uuid) {
  Domain* shell = GetDomain(uuid);
  if (shell) {
    domains_.erase(shell->id());
    delete shell;
    return true;
  }
  return false;
}

void DomainModel::LoadDomains(base::Callback<void(int, int)> cb) {
  //db_context_->io_task_runner()->PostTask(
  //  FROM_HERE,
  //  base::Bind(
  //      &DomainModel::LoadDomainsFromDB,
  //        base::Unretained(this),
  //        base::Passed(std::move(cb))));
  LoadDomainsFromDB(std::move(cb));
}

void DomainModel::AddDomainIntoDB(Domain* shell) {
  AddDomainIntoDBImpl(shell);
}

void DomainModel::RemoveDomainFromDB(Domain* shell) {
  RemoveDomainFromDBImpl(shell);
}

void DomainModel::AddDomainIntoDBImpl(Domain* shell) {
  scoped_refptr<net::IOBufferWithSize> data = shell->Serialize();
  if (data) {
    MaybeOpen();
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, Domain::kClassName, shell->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    MaybeClose();
    // 
    shell->set_managed(true);
  }
}

void DomainModel::RemoveDomainFromDBImpl(Domain* shell) {
 
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, Domain::kClassName, shell->name());
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
  shell->set_managed(false);
}

void DomainModel::LoadDomainsFromDB(base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(Domain::kClassName);
  if (!it) {
    DLOG(ERROR) << "DomainModel::LoadDomainsFromDB: creating cursor for 'app' failed.";
    cb.Run(net::ERR_FAILED, count);
    return;
  }
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      // even if this is small.. having to heap allocate here is not cool
      scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
      std::unique_ptr<Domain> domain = Domain::Deserialize( workspace_, buffer.get(), kv.second.size());
      if (domain) {
        //Domain* handle = c.get();
        domain->set_managed(true);
        // this should be temporary.. just for test
        //c->set_window_host_shell(true);
        domains_.emplace(std::make_pair(domain->id(), domain.release()));
      } else {
        LOG(ERROR) << "failed to deserialize shell";
      }
    } else {
      LOG(ERROR) << "failed to deserialize shell: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  trans->Commit();
  MaybeClose();
  //
  if (!cb.is_null()) {
    cb.Run(net::OK, count);
  }
}

std::string DomainModel::ParseTargetFromURL(const GURL& url, bool* ok) const {
  std::string input = url.spec();
  std::string result;
  //size_t target_start = 0;//std::string::npos;
  size_t target_end;

  if (input.empty()) {// || (target_start = input.find(':')) == std::string::npos) {
    *ok = false;
    return std::string();
  }

  target_end = input.find(':');//input.find('/');

  if (target_end == std::string::npos) {
    *ok = false;
    return std::string(); 
  }

  //if (target_end == std::string::npos) {
  //  input = input.substr(target_start+1);
  //} else {
    //size_t count = (target_end) - (target_start+1);
    //input = input.substr(target_start+1, count);
  //}

  result = input.substr(0, target_end);

  // in 'shell:x' case the shell is 'x'
  // in other cases like 'doom:x' the shell is 'doom'
  if (result == "app") {
    size_t last = std::string::npos;
    result = input.substr(target_end+1);
    if ((last = result.find('/')) != std::string::npos) {
      result = result.substr(0, last);
    }
  }

  *ok = true;

  return result;
}

void DomainModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    db_->Open(true);
  }
}

void DomainModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void DomainModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}