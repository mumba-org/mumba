// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MAIN_SHADOW_PAGE_DELEGATE_H_
#define MUMBA_DOMAIN_MAIN_SHADOW_PAGE_DELEGATE_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/scoped_refptr.h"
#include "base/unguessable_token.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/compositor_dependencies.h"

namespace cc {
class SwapPromise;
}

namespace viz {
class CopyOutputRequest;
class RasterContextProvider;
}

namespace gpu {
class GpuChannelHost;  
}

namespace blink {
class ContentSecurityPolicy;
class WebApplicationCacheHost;
class WebApplicationCacheHostClient;
class WebSettings;
}

namespace common {
namespace mojom {
class FrameSinkProvider;  
}  
}

namespace domain {

class CONTENT_EXPORT MainShadowPageDelegate : public common::CompositorDependencies {
public:
  ~MainShadowPageDelegate() override = default;
  // Called when Initialize() is completed.
  virtual void OnMainShadowPageInitialized() = 0;
  virtual std::unique_ptr<blink::WebApplicationCacheHost> CreateApplicationCacheHost(
      blink::WebApplicationCacheHostClient*) = 0;
  virtual const base::UnguessableToken& GetDevToolsWorkerToken() = 0;
  virtual std::unique_ptr<cc::SwapPromise> RequestCopyOfOutputForLayoutTest(
    std::unique_ptr<viz::CopyOutputRequest> request) = 0;
  virtual scoped_refptr<viz::RasterContextProvider> SharedCompositorWorkerContextProvider() = 0;
  virtual scoped_refptr<gpu::GpuChannelHost> EstablishGpuChannelSync() = 0;
  virtual common::mojom::FrameSinkProvider* frame_sink_provider() const = 0;
};

}

#endif