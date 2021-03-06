// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/service_worker_unregister_job.h"

#include "base/memory/weak_ptr.h"
#include "core/host/service_worker/service_worker_context_core.h"
#include "core/host/service_worker/service_worker_job_coordinator.h"
#include "core/host/service_worker/service_worker_registration.h"
#include "core/host/service_worker/service_worker_storage.h"
#include "core/host/service_worker/service_worker_version.h"
#include "core/shared/common/service_worker/service_worker_utils.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_registration.mojom.h"

namespace host {

typedef ServiceWorkerRegisterJobBase::RegistrationJobType RegistrationJobType;

ServiceWorkerUnregisterJob::ServiceWorkerUnregisterJob(
    base::WeakPtr<ServiceWorkerContextCore> context,
    const GURL& pattern)
    : context_(context),
      pattern_(pattern),
      is_promise_resolved_(false),
      weak_factory_(this) {
}

ServiceWorkerUnregisterJob::~ServiceWorkerUnregisterJob() {}

void ServiceWorkerUnregisterJob::AddCallback(UnregistrationCallback callback) {
  callbacks_.emplace_back(std::move(callback));
}

void ServiceWorkerUnregisterJob::Start() {
  context_->storage()->FindRegistrationForPattern(
      pattern_, kPROCESS_TYPE_APPLICATION, -5, base::BindOnce(&ServiceWorkerUnregisterJob::OnRegistrationFound,
                               weak_factory_.GetWeakPtr()));
}

void ServiceWorkerUnregisterJob::Abort() {
  CompleteInternal(blink::mojom::kInvalidServiceWorkerRegistrationId,
                   common::SERVICE_WORKER_ERROR_ABORT);
}

bool ServiceWorkerUnregisterJob::Equals(
    ServiceWorkerRegisterJobBase* job) const {
  if (job->GetType() != GetType())
    return false;
  return static_cast<ServiceWorkerUnregisterJob*>(job)->pattern_ == pattern_;
}

RegistrationJobType ServiceWorkerUnregisterJob::GetType() const {
  return UNREGISTRATION_JOB;
}

void ServiceWorkerUnregisterJob::OnRegistrationFound(
    common::ServiceWorkerStatusCode status,
    scoped_refptr<ServiceWorkerRegistration> registration) {
  if (status == common::SERVICE_WORKER_ERROR_NOT_FOUND) {
    DCHECK(!registration.get());
    Complete(blink::mojom::kInvalidServiceWorkerRegistrationId,
             common::SERVICE_WORKER_ERROR_NOT_FOUND);
    return;
  }

  if (status != common::SERVICE_WORKER_OK || registration->is_uninstalling()) {
    Complete(blink::mojom::kInvalidServiceWorkerRegistrationId, status);
    return;
  }

  // TODO: "7. If registration.updatePromise is not null..."

  // "8. Resolve promise."
  ResolvePromise(registration->id(), common::SERVICE_WORKER_OK);

  registration->ClearWhenReady();

  Complete(registration->id(), common::SERVICE_WORKER_OK);
}

void ServiceWorkerUnregisterJob::Complete(int64_t registration_id,
                                          common::ServiceWorkerStatusCode status) {
  CompleteInternal(registration_id, status);
  context_->job_coordinator()->FinishJob(pattern_, this);
}

void ServiceWorkerUnregisterJob::CompleteInternal(
    int64_t registration_id,
    common::ServiceWorkerStatusCode status) {
  if (!is_promise_resolved_)
    ResolvePromise(registration_id, status);
}

void ServiceWorkerUnregisterJob::ResolvePromise(
    int64_t registration_id,
    common::ServiceWorkerStatusCode status) {
  DCHECK(!is_promise_resolved_);
  is_promise_resolved_ = true;
  for (UnregistrationCallback& callback : callbacks_)
    std::move(callback).Run(registration_id, status);
}

}  // namespace host
