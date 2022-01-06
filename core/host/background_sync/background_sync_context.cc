// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/background_sync/background_sync_context.h"

#include <utility>

#include "base/bind.h"
#include "base/memory/ptr_util.h"
#include "base/stl_util.h"
#include "core/host/background_sync/background_sync_manager.h"
#include "core/host/background_sync/background_sync_service_impl.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/host/host_thread.h"

namespace host {

BackgroundSyncContext::BackgroundSyncContext() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
}

BackgroundSyncContext::~BackgroundSyncContext() {
  DCHECK(!background_sync_manager_);
  DCHECK(services_.empty());
}

void BackgroundSyncContext::Init(
    const scoped_refptr<ServiceWorkerContextWrapper>& context) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&BackgroundSyncContext::CreateBackgroundSyncManager, this,
                     context));
}

void BackgroundSyncContext::Shutdown() {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&BackgroundSyncContext::ShutdownOnIO, this));
}

void BackgroundSyncContext::CreateService(
    blink::mojom::BackgroundSyncServiceRequest request) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&BackgroundSyncContext::CreateServiceOnIOThread, this,
                     std::move(request)));
}

void BackgroundSyncContext::ServiceHadConnectionError(
    BackgroundSyncServiceImpl* service) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(base::ContainsKey(services_, service));

  services_.erase(service);
}

BackgroundSyncManager* BackgroundSyncContext::background_sync_manager() const {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  return background_sync_manager_.get();
}

void BackgroundSyncContext::set_background_sync_manager_for_testing(
    std::unique_ptr<BackgroundSyncManager> manager) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  background_sync_manager_ = std::move(manager);
}

void BackgroundSyncContext::CreateBackgroundSyncManager(
    scoped_refptr<ServiceWorkerContextWrapper> context) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(!background_sync_manager_);

  background_sync_manager_ = BackgroundSyncManager::Create(context);
}

void BackgroundSyncContext::CreateServiceOnIOThread(
    mojo::InterfaceRequest<blink::mojom::BackgroundSyncService> request) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(background_sync_manager_);
  BackgroundSyncServiceImpl* service =
      new BackgroundSyncServiceImpl(this, std::move(request));
  services_[service] = base::WrapUnique(service);
}

void BackgroundSyncContext::ShutdownOnIO() {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  services_.clear();
  background_sync_manager_.reset();
}

}  // namespace host
