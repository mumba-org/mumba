// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_OVERLAY_DISPATCHER_H_
#define MUMBA_APPLICATION_OVERLAY_DISPATCHER_H_

//#include <v8-inspector.h>
#include <memory>

#include "base/macros.h"
#include "base/memory/scoped_refptr.h"
#include "core/shared/common/mojom/automation.mojom.h"
#include "core/shared/application/automation/inspector_highlight.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/inspector/inspector_base_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_overlay_host.h"
#include "third_party/blink/renderer/core/inspector/protocol/Overlay.h"
#include "third_party/blink/renderer/platform/geometry/float_quad.h"
#include "third_party/blink/renderer/platform/geometry/layout_rect.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ipc/ipc_sync_channel.h"

namespace blink {
class Color;
class GraphicsLayer;
class InspectedFrames;
class InspectorDOMAgent;
class LocalFrame;
class Node;
class Page;
class PageOverlay;
class WebGestureEvent;
class WebMouseEvent;
class WebLocalFrameImpl;
class WebLocalFrame;
class WebPointerEvent;
class FloatQuad;
}

namespace service_manager {
class InterfaceProvider;
}

namespace IPC {
class SyncChannel;
}

namespace application {
class DOMDispatcher;
class DOMDispatcher;
class PageInstance;
class InspectorOverlayAgentImpl;
// TODO: Adaptar para o caso de podermos criar um PageOverlay remoto
//       renderizado pelo 'Domain'
class OverlayDispatcher : public automation::Overlay {
public:
  static void Create(automation::OverlayRequest request, 
                     PageInstance* page_instance,
                    // blink::WebLocalFrameImpl* frame_impl,
                     DOMDispatcher* dom_dispatcher);

  OverlayDispatcher(automation::OverlayRequest request,
                    PageInstance* page_instance,
                    //blink::WebLocalFrameImpl* frame_impl,
                    DOMDispatcher* dom_dispatcher);
  OverlayDispatcher(PageInstance* page_instance,
                    //blink::WebLocalFrameImpl* frame_impl,
                    DOMDispatcher* dom_dispatcher);
  ~OverlayDispatcher() override;

  
  void Init(IPC::SyncChannel* channel);
  void Bind(automation::OverlayAssociatedRequest request);

  void Register(int32_t application_id) override;
  void Disable() override;
  void Enable() override;
  void HideHighlight() override;
  void HighlightFrame(const std::string& frame_id, automation::RGBAPtr content_color, automation::RGBAPtr content_outline_color) override;
  void HighlightNode(automation::HighlightConfigPtr highlight_config, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) override;
  void HighlightQuad(const std::vector<double>& quad, automation::RGBAPtr color, automation::RGBAPtr outline_color) override;
  void HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) override;
  void SetInspectMode(automation::InspectMode mode, automation::HighlightConfigPtr highlight_config) override;
  void SetPausedInDebuggerMessage(const base::Optional<std::string>& message) override;
  void SetShowDebugBorders(bool show) override;
  void SetShowFPSCounter(bool show) override;
  void SetShowPaintRects(bool result) override;
  void SetShowScrollBottleneckRects(bool show) override;
  void SetShowViewportSizeOnResize(bool show) override;
  void SetSuspended(bool suspended) override;

  bool HandleInputEvent(const blink::WebInputEvent& input_event);

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void PageLayoutInvalidated(bool resized);
  automation::OverlayClient* GetClient();

  DOMDispatcher* dom_dispatcher() const;

  void OnWebFrameCreated(blink::WebLocalFrame* frame);
  
private:
  friend class InspectorOverlayAgentImpl;
  class InspectorOverlayChromeClient;
  class InspectorPageOverlayDelegate;

  enum SearchMode {
    kNotSearching,
    kSearchingForNormal,
    kSearchingForUAShadow,
  };
  
  bool IsEmpty();
  void DrawNodeHighlight();
  void DrawQuadHighlight();
  void DrawPausedInDebuggerMessage();
  void DrawViewSize();
  void DrawScreenshotBorder();

  float WindowToViewportScale() const;

  blink::Page* OverlayPage();
  blink::LocalFrame* OverlayMainFrame();
  void Reset(const blink::IntSize& viewport_size,
             const blink::IntPoint& document_scroll_offset);
  void EvaluateInOverlay(const String& method, const String& argument);
  void EvaluateInOverlay(const String& method,
                         std::unique_ptr<base::DictionaryValue> argument);
  void OnTimer(blink::TimerBase*);
  void RebuildOverlayPage();
  void Invalidate();
  void ScheduleUpdate();
  void ClearInternal();
  void UpdateAllLifecyclePhases();

  bool HandleMouseDown(const blink::WebMouseEvent&);
  bool HandleMouseUp(const blink::WebMouseEvent&);
  bool HandleGestureEvent(const blink::WebGestureEvent&);
  bool HandlePointerEvent(const blink::WebPointerEvent&);
  bool HandleMouseMove(const blink::WebMouseEvent&);

  bool CompositingEnabled();

  bool ShouldSearchForNode();
  void NodeHighlightRequested(blink::Node*);
  bool SetSearchingForNode(SearchMode, base::Optional<automation::HighlightConfigPtr>);
  bool HighlightConfigFromInspectorObject(
    base::Optional<automation::HighlightConfigPtr> highlight_inspector_object,
    std::unique_ptr<InspectorHighlightConfig>*);
  void InnerHighlightQuad(std::unique_ptr<blink::FloatQuad>,
                          base::Optional<automation::RGBAPtr> color,
                          base::Optional<automation::RGBAPtr> outline_color);
  void InnerHighlightNode(blink::Node*,
                          blink::Node* event_target,
                          const InspectorHighlightConfig&,
                          bool omit_tooltip);
  void InnerHideHighlight();

  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::Overlay> binding_;
  automation::OverlayClientAssociatedPtr overlay_client_ptr_;

  blink::Member<blink::WebLocalFrameImpl> frame_impl_;
  bool enabled_;
  String paused_in_debugger_message_;
  blink::Member<blink::Node> highlight_node_;
  blink::Member<blink::Node> event_target_node_;
  InspectorHighlightConfig node_highlight_config_;
  std::unique_ptr<blink::FloatQuad> highlight_quad_;
  blink::Member<blink::Page> overlay_page_;
  blink::Member<InspectorOverlayChromeClient> overlay_chrome_client_;
  blink::Member<blink::InspectorOverlayHost> overlay_host_;
  blink::Color quad_content_color_;
  blink::Color quad_content_outline_color_;
  bool draw_view_size_;
  bool resize_timer_active_;
  bool omit_tooltip_;
  std::unique_ptr<blink::TaskRunnerTimer<OverlayDispatcher>> timer_;
  bool suspended_;
  bool disposed_;
  bool show_reloading_blanket_;
  bool in_layout_;
  bool needs_update_;
  DOMDispatcher* dom_dispatcher_;
  std::unique_ptr<blink::PageOverlay> page_overlay_;
  blink::Member<blink::Node> hovered_node_for_inspect_mode_;
  blink::Persistent<InspectorOverlayAgentImpl> overlay_agent_;
  bool swallow_next_mouse_up_;
  SearchMode inspect_mode_;
  std::unique_ptr<InspectorHighlightConfig> inspect_mode_highlight_config_;
  int backend_node_id_to_inspect_;
  bool screenshot_mode_ = false;
  blink::IntPoint screenshot_anchor_;
  blink::IntPoint screenshot_position_;
  bool show_debug_borders_;
  bool show_fps_borders_;
  bool show_paint_rects_;
  bool show_scroll_bottleneck_rects_;
  bool show_size_on_resize_;
  
  DISALLOW_COPY_AND_ASSIGN(OverlayDispatcher); 
};

}

#endif
