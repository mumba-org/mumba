// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/url_data_manager.h"

#include <stddef.h>

#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/lazy_instance.h"
#include "base/memory/ref_counted_memory.h"
#include "base/strings/string_util.h"
#include "base/synchronization/lock.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/application/url_data_manager_backend.h"
#include "core/host/application/url_data_source.h"
//#include "core/host/application/rpc_data_source.h"
#include "core/host/application/application_contents.h"
#include "core/host/host_thread.h"
#include "core/host/application/domain.h"
#include "core/host/application/url_data_source.h"

namespace host {
namespace {

//const char kURLDataManagerKeyName[] = "url_data_manager";
//const char kURLDataManagerBackendKeyName[] = "url_data_manager_backend";

base::LazyInstance<base::Lock>::Leaky g_delete_lock = LAZY_INSTANCE_INITIALIZER;

URLDataManager* GetFromDomain(Domain* domain) {
  ResourceContext* context = domain->GetResourceContext();
  if (!context->GetDataManager()) {
    context->SetDataManager(std::make_unique<URLDataManager>(domain));
  }
  return context->GetDataManager();
}

// Invoked on the IO thread to do the actual adding of the DataSource.
static void AddDataSourceOnIOThread(
    ResourceContext* context,
    scoped_refptr<URLDataSource> data_source) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  GetURLDataManagerForResourceContext(context)->AddDataSource(
      data_source.get());
}

static void UpdateAppDataSourceOnIOThread(
    ResourceContext* context,
    std::string source_name,
    const base::DictionaryValue* update) {
  GetURLDataManagerForResourceContext(context)
      ->UpdateAppDataSource(source_name, *update);
}

}  // namespace

// static
URLDataManager::URLDataSources* URLDataManager::data_sources_ = nullptr;

URLDataManager::URLDataManager(Domain* domain)
    : domain_(domain) {
}

URLDataManager::~URLDataManager() {
}

void URLDataManager::AddDataSource(URLDataSource* source) {
  // DCHECK_CURRENTLY_ON(HostThread::UI);
  // correction: theres no problem not being on UI
  // its just about not being called on IO now
  HostThread::PostTask(HostThread::IO, FROM_HERE,
                          base::BindOnce(&AddDataSourceOnIOThread,
                                         base::Unretained(domain_->GetResourceContext()),
                                         base::WrapRefCounted(source)));
}

void URLDataManager::UpdateAppDataSource(
    const std::string& source_name,
    std::unique_ptr<base::DictionaryValue> update) {
  // DCHECK_CURRENTLY_ON(HostThread::UI);
  // correction: theres no problem not being on UI
  // its just about not being called on IO now
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&UpdateAppDataSourceOnIOThread,
                     base::Unretained(domain_->GetResourceContext()), source_name,
                     base::Owned(update.release())));
}

// static
void URLDataManager::DeleteDataSources() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  URLDataSources sources;
  {
    base::AutoLock lock(g_delete_lock.Get());
    if (!data_sources_)
      return;
    data_sources_->swap(sources);
  }
  for (size_t i = 0; i < sources.size(); ++i)
    delete sources[i];
}

// static
void URLDataManager::DeleteDataSource(const URLDataSource* data_source) {
  // Invoked when a DataSource is no longer referenced and needs to be deleted.
  if (HostThread::CurrentlyOn(HostThread::UI)) {
    // We're on the UI thread, delete right away.
    delete data_source;
    return;
  }

  // We're not on the UI thread, add the DataSource to the list of DataSources
  // to delete.
  bool schedule_delete = false;
  {
    base::AutoLock lock(g_delete_lock.Get());
    if (!data_sources_)
      data_sources_ = new URLDataSources();
    schedule_delete = data_sources_->empty();
    data_sources_->push_back(data_source);
  }
  if (schedule_delete) {
    // Schedule a task to delete the DataSource back on the UI thread.
    HostThread::PostTask(HostThread::UI, FROM_HERE,
                         base::BindOnce(&URLDataManager::DeleteDataSources));
  }
}

//static
bool URLDataManager::HaveDataSourceForURL(Domain* domain, const GURL& url) {
  URLDataManagerBackend* backend = GetURLDataManagerForDomain(domain);
  return backend->HaveDataSourceForURL(url);
}

// static
void URLDataManager::AddDataSource(Domain* domain,
                                   URLDataSource* source) {
  GetFromDomain(domain)->
      AddDataSource(source);
}

// static
void URLDataManager::AddAppDataSource(Domain* domain,
                                      RpcDataSource* source) {
  DCHECK(false);
  //AppDataSourceImpl* impl = static_cast<AppDataSourceImpl*>(source);
  //GetFromDomain(domain)->AddDataSource(source);
}

void URLDataManager::UpdateAppDataSource(
    Domain* domain,
    const std::string& source_name,
    std::unique_ptr<base::DictionaryValue> update) {
  GetFromDomain(domain)
      ->UpdateAppDataSource(source_name, std::move(update));
}

// static
bool URLDataManager::IsScheduledForDeletion(
    const URLDataSource* data_source) {
  base::AutoLock lock(g_delete_lock.Get());
  if (!data_sources_)
    return false;
  return std::find(data_sources_->begin(), data_sources_->end(), data_source) !=
      data_sources_->end();
}

URLDataManagerBackend* GetURLDataManagerForDomain(Domain* domain) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  ResourceContext* context = domain->GetResourceContext();
  return GetURLDataManagerForResourceContext(context);
}

URLDataManagerBackend* GetURLDataManagerForResourceContext(ResourceContext* context) {
  Domain* domain = static_cast<ResourceContextImpl*>(context)->GetDomain();
  if (!context->GetDataManagerBackend()) {
    context->SetDataManagerBackend(
      std::make_unique<URLDataManagerBackend>(domain));
  }
  return context->GetDataManagerBackend(); 
}

}  // namespace host
