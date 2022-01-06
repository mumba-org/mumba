// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/gpu/gpu_feature_checker_impl.h"

#include "base/logging.h"
#include "build/build_config.h"
#include "core/host/gpu/gpu_data_manager_impl.h"
#include "core/host/host_thread.h"

namespace host {

// static
scoped_refptr<GpuFeatureChecker> GpuFeatureChecker::Create(
    gpu::GpuFeatureType feature,
    FeatureAvailableCallback callback) {
  return new GpuFeatureCheckerImpl(feature, std::move(callback));
}

GpuFeatureCheckerImpl::GpuFeatureCheckerImpl(gpu::GpuFeatureType feature,
                                             FeatureAvailableCallback callback)
    : feature_(feature), callback_(callback) {}

GpuFeatureCheckerImpl::~GpuFeatureCheckerImpl() {}

void GpuFeatureCheckerImpl::CheckGpuFeatureAvailability() {
  CHECK(HostThread::CurrentlyOn(HostThread::UI));
  AddRef();  // Matched with a Release in OnGpuInfoUpdate.
  GpuDataManagerImpl* manager = GpuDataManagerImpl::GetInstance();
  manager->AddObserver(this);
  OnGpuInfoUpdate();
}

void GpuFeatureCheckerImpl::OnGpuInfoUpdate() {
  GpuDataManagerImpl* manager = GpuDataManagerImpl::GetInstance();
  if (manager->IsGpuFeatureInfoAvailable()) {
    manager->RemoveObserver(this);
    bool feature_allowed =
        manager->GetFeatureStatus(feature_) == gpu::kGpuFeatureStatusEnabled;
    callback_.Run(feature_allowed);
    Release();  // Matches the AddRef in CheckGpuFeatureAvailability().
  }
}

}  // namespace host
