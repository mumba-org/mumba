// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MAIN_SHADOW_PAGE_H_
#define MUMBA_DOMAIN_MAIN_SHADOW_PAGE_H_

#ifndef INSIDE_BLINK
#define INSIDE_BLINK 1
#endif

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/template_util.h"
#include "base/command_line.h"
#include "base/files/file.h"
#include "base/memory/shared_memory.h"
#include "base/memory/memory_coordinator_client.h"
#include "base/memory/weak_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/message_loop/message_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "ipc/ipc_sender.h"
#include "ipc/ipc_listener.h"
#include "ipc/ipc_platform_file.h"
#include "ipc/message_router.h"
#include "ipc/ipc_channel_proxy.h"
#include "core/shared/common/compositor_dependencies.h"
#include "core/shared/common/screen_info.h"
#include "core/domain/layer_tree_view_delegate.h"
#include "cc/trees/layer_tree_settings.h"
#include "components/viz/common/surfaces/local_surface_id.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/compiler.h"
#include "third_party/blink/public/platform/web_common.h"
#include "third_party/blink/public/platform/web_cursor_info.h"
#include "third_party/blink/public/platform/web_private_ptr.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/platform/web_float_rect.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/public/web/web_document_loader.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "core/domain/main_shadow_page_delegate.h"

#ifdef INSIDE_BLINK
#undef INSIDE_BLINK
#endif

#include "third_party/blink/public/web/web_frame_client.h"

#ifndef INSIDE_BLINK
#define INSIDE_BLINK 1
#endif

namespace blink {
class ContentSecurityPolicy;
class WebApplicationCacheHost;
class WebApplicationCacheHostClient;
class WebSettings;
class WebLocalFrameImpl;
class WebFrameWidget;
}

namespace domain {
class LayerTreeView;

class CONTENT_EXPORT MainShadowPage : public blink::WebFrameClient,
                                      public blink::WebViewClient,
                                      public LayerTreeViewDelegate {
 public:
  static cc::LayerTreeSettings GenerateLayerTreeSettings(
    common::CompositorDependencies* compositor_deps,
    bool is_for_subframe,
    const gfx::Size& initial_screen_size,
    float initial_device_scale_factor);

  explicit MainShadowPage(MainShadowPageDelegate* delegate, common::ScreenInfo screen_info, float scale_factor);
  ~MainShadowPage() override;

  void Initialize();

  void SetContentSecurityPolicyAndReferrerPolicy(blink::ContentSecurityPolicy*,
                                                 String referrer_policy);

  // WebFrameClient overrides.
  std::unique_ptr<blink::WebApplicationCacheHost> CreateApplicationCacheHost(
      blink::WebApplicationCacheHostClient*) override;
  void DidFinishDocumentLoad() override;
  std::unique_ptr<blink::WebURLLoaderFactory> CreateURLLoaderFactory() override;
  base::UnguessableToken GetDevToolsFrameToken() override;
  std::unique_ptr<blink::WebSocketHandshakeThrottle> CreateWebSocketHandshakeThrottle() override;
  blink::Document* GetDocument();
  blink::WebSettings* GetSettings() { return web_view_->GetSettings(); }
  blink::WebDocumentLoader* DocumentLoader();

  // WebViewClient
  blink::WebLayerTreeView* InitializeLayerTreeView() override;
  
  bool WasInitialized() const;

  // LayerTreeViewDelegate
  void ApplyViewportDeltas(
      const gfx::Vector2dF& inner_delta,
      const gfx::Vector2dF& outer_delta,
      const gfx::Vector2dF& elastic_overscroll_delta,
      float page_scale,
      float top_controls_delta) override;
  void RecordWheelAndTouchScrollingCount(
      bool has_scrolled_by_wheel,
      bool has_scrolled_by_touch) override;
  void BeginMainFrame(base::TimeTicks frame_time) override;
  void RequestNewLayerTreeFrameSink(
      LayerTreeFrameSinkCallback callback) override;
  void DidCommitAndDrawCompositorFrame() override;
  void DidCommitCompositorFrame() override;
  void DidCompletePageScaleAnimation() override;
  void DidReceiveCompositorFrameAck() override;
  bool IsClosing() const override;
  void RequestScheduleAnimation() override;
  void UpdateVisualState(VisualStateUpdate requested_update) override;
  void WillBeginCompositorFrame() override;
  std::unique_ptr<cc::SwapPromise> RequestCopyOfOutputForLayoutTest(
      std::unique_ptr<viz::CopyOutputRequest> request) override;

 private:

  MainShadowPageDelegate* delegate_;
  blink::WebView* web_view_;
  //blink::Persistent<blink::WebLocalFrameImpl> main_frame_;
  blink::Member<blink::WebLocalFrameImpl> main_frame_;
  blink::WebFrameWidget* widget_;
  std::unique_ptr<LayerTreeView> layer_tree_view_;
  cc::LayerTreeHost* layer_tree_host_ = nullptr;
  viz::LocalSurfaceId local_surface_id_allocation_from_parent_;
  common::ScreenInfo screen_info_;
  float device_scale_factor_;
  bool initialized_;
};


}

#endif