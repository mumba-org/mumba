// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/gpu/content_gpu_client.h"

#if BUILDFLAG(ENABLE_LIBRARY_CDMS)
#include "media/cdm/cdm_proxy.h"
#endif

namespace gpu {

gpu::SyncPointManager* ContentGpuClient::GetSyncPointManager() {
  return nullptr;
}

#if BUILDFLAG(ENABLE_LIBRARY_CDMS)
std::unique_ptr<media::CdmProxy> ContentGpuClient::CreateCdmProxy(
    const std::string& cdm_guid) {
  return nullptr;
}
#endif

}  // namespace gpu
