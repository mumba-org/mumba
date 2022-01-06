// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/overlay_dispatcher.h"

#include "base/json/json_writer.h"
#include "core/shared/application/automation/dom_dispatcher.h"
#include "core/shared/application/automation/page_instance.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_source_code.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_inspector_overlay_host.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_overlay_host.h"
#include "third_party/blink/renderer/core/inspector/inspector_overlay_agent.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_overlay.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"
#include "third_party/blink/renderer/platform/wtf/auto_reset.h"
#include "v8/include/v8.h"

namespace application {

namespace {

blink::Node* HoveredNodeForPoint(
  blink::LocalFrame* frame,
  const blink::IntPoint& point_in_root_frame,
  bool ignore_pointer_events_none) {
  blink::HitTestRequest::HitTestRequestType hit_type =
      blink::HitTestRequest::kMove | blink::HitTestRequest::kReadOnly |
      blink::HitTestRequest::kAllowChildFrameContent;
  if (ignore_pointer_events_none)
    hit_type |= blink::HitTestRequest::kIgnorePointerEventsNone;
  blink::HitTestRequest request(hit_type);
  blink::HitTestResult result(request,
                       frame->View()->RootFrameToContents(point_in_root_frame));
  frame->ContentLayoutObject()->HitTest(result);
  blink::Node* node = result.InnerPossiblyPseudoNode();
  while (node && node->getNodeType() == blink::Node::kTextNode)
    node = node->parentNode();
  return node;
}

blink::Node* HoveredNodeForEvent(blink::LocalFrame* frame,
                          const blink::WebGestureEvent& event,
                          bool ignore_pointer_events_none) {
  return HoveredNodeForPoint(frame,
                             blink::RoundedIntPoint(event.PositionInRootFrame()),
                             ignore_pointer_events_none);
}

blink::Node* HoveredNodeForEvent(blink::LocalFrame* frame,
                                 const blink::WebMouseEvent& event,
                                 bool ignore_pointer_events_none) {
  return HoveredNodeForPoint(frame,
                             blink::RoundedIntPoint(event.PositionInRootFrame()),
                             ignore_pointer_events_none);
}

blink::Node* HoveredNodeForEvent(blink::LocalFrame* frame,
                                 const blink::WebPointerEvent& event,
                                 bool ignore_pointer_events_none) {
  blink::WebPointerEvent transformed_point = event.WebPointerEventInRootFrame();
  return HoveredNodeForPoint(
      frame, RoundedIntPoint(transformed_point.PositionInWidget()),
      ignore_pointer_events_none);
}

bool ParseQuad(const std::vector<double>& quad_array,
               blink::FloatQuad* quad) {
  const size_t kCoordinatesInQuad = 8;
  if (quad_array.size() != kCoordinatesInQuad)
    return false;
  quad->SetP1(blink::FloatPoint(quad_array[0], quad_array[1]));
  quad->SetP2(blink::FloatPoint(quad_array[2], quad_array[3]));
  quad->SetP3(blink::FloatPoint(quad_array[4], quad_array[5]));
  quad->SetP4(blink::FloatPoint(quad_array[6], quad_array[7]));
  return true;
}

std::unique_ptr<base::DictionaryValue> BuildObjectForSize(const blink::IntSize& size) {
  std::unique_ptr<base::DictionaryValue> result = std::make_unique<base::DictionaryValue>();
  result->SetKey("width", base::Value(size.Width()));
  result->SetKey("height", base::Value(size.Height()));
  return result;
}

#if defined(OS_MACOSX)
const int kCtrlOrMeta = blink::WebInputEvent::kMetaKey;
#else
const int kCtrlOrMeta = blink::WebInputEvent::kControlKey;
#endif

}  // namespace

class InspectorOverlayAgentImpl : public blink::InspectorOverlayAgent {
public:
  InspectorOverlayAgentImpl(
    OverlayDispatcher* dispatcher, 
    blink::WebLocalFrameImpl* frame_impl,
    blink::InspectedFrames* inspected_frames): 
    blink::InspectorOverlayAgent(frame_impl, inspected_frames, nullptr, dispatcher->dom_dispatcher()->dom_agent()),
    dispatcher_(dispatcher) {}

  void PageLayoutInvalidated(bool resized) override {
    dispatcher_->PageLayoutInvalidated(resized);
  }

private:
  OverlayDispatcher* dispatcher_;
};

class OverlayDispatcher::InspectorPageOverlayDelegate final
    : public blink::PageOverlay::Delegate {
 public:
  explicit InspectorPageOverlayDelegate(OverlayDispatcher* overlay)
      : overlay_(overlay) {}

  void PaintPageOverlay(const blink::PageOverlay&,
                        blink::GraphicsContext& graphics_context,
                        const blink::WebSize& web_view_size) const override {
    if (overlay_->IsEmpty())
      return;

    blink::LocalFrameView* view = overlay_->OverlayMainFrame()->View();
    DCHECK(!view->NeedsLayout());
    view->PaintWithLifecycleUpdate(
        graphics_context, blink::kGlobalPaintNormalPhase,
        blink::CullRect(blink::IntRect(0, 0, view->Width(), view->Height())));
  }

 private:
   OverlayDispatcher* overlay_;
};

class OverlayDispatcher::InspectorOverlayChromeClient final
    : public blink::EmptyChromeClient {
 public:
  static InspectorOverlayChromeClient* Create(blink::ChromeClient& client,
                                              OverlayDispatcher* overlay) {
    return new InspectorOverlayChromeClient(client, overlay);
  }

  void Trace(blink::Visitor* visitor) override {
    visitor->Trace(client_);
    //visitor->Trace(overlay_);
    blink::EmptyChromeClient::Trace(visitor);
  }

  void SetCursor(const blink::Cursor& cursor, blink::LocalFrame* local_root) override {
    client_->SetCursorOverridden(false);
    client_->SetCursor(cursor, overlay_->frame_impl_->GetFrame());
    client_->SetCursorOverridden(false);
  }

  void SetToolTip(blink::LocalFrame& frame,
                  const String& tooltip,
                  blink::TextDirection direction) override {
    DCHECK_EQ(&frame, overlay_->OverlayMainFrame());
    client_->SetToolTip(*overlay_->frame_impl_->GetFrame(), tooltip, direction);
  }

  void InvalidateRect(const blink::IntRect&) override { overlay_->Invalidate(); }

 private:
  InspectorOverlayChromeClient(blink::ChromeClient& client,
                               OverlayDispatcher* overlay)
      : client_(&client), overlay_(overlay) {}

  blink::Member<blink::ChromeClient> client_;
  OverlayDispatcher* overlay_;
};

// static 
void OverlayDispatcher::Create(
  automation::OverlayRequest request, 
  PageInstance* page_instance,
  //blink::WebLocalFrameImpl* frame_impl,
  DOMDispatcher* dom_dispatcher) {
  // new OverlayDispatcher(std::move(request), page_instance, frame_impl, dom_dispatcher);
  new OverlayDispatcher(std::move(request), page_instance, dom_dispatcher);
}

OverlayDispatcher::OverlayDispatcher(
  automation::OverlayRequest request, 
  PageInstance* page_instance,
  // blink::WebLocalFrameImpl* frame_impl,
  DOMDispatcher* dom_dispatcher): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this),
  //frame_impl_(frame_impl),
  enabled_(false),
  draw_view_size_(false),
  resize_timer_active_(false),
  omit_tooltip_(false),
  // timer_(
  //     frame_impl->GetFrame()->GetTaskRunner(blink::TaskType::kInternalInspector),
  //     this,
  //     &OverlayDispatcher::OnTimer),
  suspended_(false),
  disposed_(false),
  show_reloading_blanket_(false),
  in_layout_(false),
  needs_update_(false),
  dom_dispatcher_(dom_dispatcher),
  swallow_next_mouse_up_(false),
  inspect_mode_(kNotSearching),
  backend_node_id_to_inspect_(0),
  show_debug_borders_(false),
  show_fps_borders_(false),
  show_paint_rects_(false),
  show_scroll_bottleneck_rects_(false),
  show_size_on_resize_(false) {

}

OverlayDispatcher::OverlayDispatcher(
  PageInstance* page_instance,
  //blink::WebLocalFrameImpl* frame_impl,
  DOMDispatcher* dom_dispatcher): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this),
 // frame_impl_(frame_impl),
  enabled_(false),
  draw_view_size_(false),
  resize_timer_active_(false),
  omit_tooltip_(false),
  // timer_(
  //     frame_impl->GetFrame()->GetTaskRunner(blink::TaskType::kInternalInspector),
  //     this,
  //     &OverlayDispatcher::OnTimer),
  suspended_(false),
  disposed_(false),
  show_reloading_blanket_(false),
  in_layout_(false),
  needs_update_(false),
  dom_dispatcher_(dom_dispatcher),
  swallow_next_mouse_up_(false),
  inspect_mode_(kNotSearching),
  backend_node_id_to_inspect_(0),
  show_debug_borders_(false),
  show_fps_borders_(false),
  show_paint_rects_(false),
  show_scroll_bottleneck_rects_(false),
  show_size_on_resize_(false) {

  
}

OverlayDispatcher::~OverlayDispatcher() {

}

void OverlayDispatcher::OnWebFrameCreated(blink::WebLocalFrame* frame) {
  frame_impl_ = static_cast<blink::WebLocalFrameImpl*>(frame);
  timer_.reset(new blink::TaskRunnerTimer<OverlayDispatcher>(
        frame_impl_->GetFrame()->GetTaskRunner(blink::TaskType::kInternalInspector),
        this,
        &OverlayDispatcher::OnTimer));

  overlay_agent_ = new InspectorOverlayAgentImpl(
    this, 
    frame_impl_.Get(),
    page_instance_->inspected_frames());
  
  overlay_agent_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());

  Enable();
}

// void OverlayDispatcher::Restore() {
//   if (state_->booleanProperty(OverlayAgentState::kEnabled, false))
//     enabled_ = true;
//   setShowDebugBorders(
//       state_->booleanProperty(OverlayAgentState::kShowDebugBorders, false));
//   setShowFPSCounter(
//       state_->booleanProperty(OverlayAgentState::kShowFPSCounter, false));
//   setShowPaintRects(
//       state_->booleanProperty(OverlayAgentState::kShowPaintRects, false));
//   setShowScrollBottleneckRects(state_->booleanProperty(
//       OverlayAgentState::kShowScrollBottleneckRects, false));
//   setShowViewportSizeOnResize(
//       state_->booleanProperty(OverlayAgentState::kShowSizeOnResize, false));
//   String message;
//   if (state_->getString(OverlayAgentState::kPausedInDebuggerMessage, &message))
//     setPausedInDebuggerMessage(message);
//   setSuspended(state_->booleanProperty(OverlayAgentState::kSuspended, false));
// }

// void OverlayDispatcher::Dispose() {
//   show_reloading_blanket_ = false;
//   disposed_ = true;
//   ClearInternal();
// }

DOMDispatcher* OverlayDispatcher::dom_dispatcher() const {
  return dom_dispatcher_;
}

void OverlayDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&overlay_client_ptr_);
}

void OverlayDispatcher::Bind(automation::OverlayAssociatedRequest request) {
  //DLOG(INFO) << "OverlayDispatcher::BindAssociated (application)";
  binding_.Bind(std::move(request)); 
}

void OverlayDispatcher::Register(int32_t application_id) {
  //DLOG(INFO) << "OverlayDispatcher::Register (application process)";
  application_id_ = application_id;
}

void OverlayDispatcher::Enable() {
  //DLOG(INFO) << "OverlayDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
 if (!dom_dispatcher() || !dom_dispatcher()->enabled()) {
  //DLOG(ERROR) << "DOM should be enabled first. doing it..";
  dom_dispatcher()->Enable();
  //return;
 }
  enabled_ = true;
  if (backend_node_id_to_inspect_) {
    GetClient()->InspectNodeRequested(backend_node_id_to_inspect_);
  }
  backend_node_id_to_inspect_ = 0;
  //page_instance_->probe_sink()->addInspectorOverlayAgent(overlay_agent_.Get()); 
}

void OverlayDispatcher::Disable() {
  //DLOG(ERROR) << "OverlayDispatcher::Disable";
  enabled_ = false;
  SetShowDebugBorders(false);
  SetShowFPSCounter(false);
  SetShowPaintRects(false);
  SetShowScrollBottleneckRects(false);
  SetShowViewportSizeOnResize(false);
  SetPausedInDebuggerMessage(std::string());
  SetSuspended(false);
  SetSearchingForNode(kNotSearching,
                      base::Optional<automation::HighlightConfigPtr>());
  //page_instance_->probe_sink()->removeInspectorOverlayAgent(overlay_agent_.Get()); 
}


void OverlayDispatcher::HideHighlight() {
  //DLOG(ERROR) << "OverlayDispatcher::HideHighlight";
  InnerHideHighlight();
}

void OverlayDispatcher::HighlightFrame(const std::string& frame_id, automation::RGBAPtr content_color, automation::RGBAPtr content_outline_color) {
  //DLOG(ERROR) << "OverlayDispatcher::HighlightFrame";
  blink::LocalFrame* frame =
      blink::IdentifiersFactory::FrameById(page_instance_->inspected_frames(), String::FromUTF8(frame_id.data()));
  
  automation::RGBA* color_ptr = content_color.get();
  automation::RGBA* outline_color_ptr = content_outline_color.get();
  // FIXME: Inspector doesn't currently work cross process.
  if (frame && frame->DeprecatedLocalOwner()) {
    std::unique_ptr<InspectorHighlightConfig> highlight_config =
        std::make_unique<InspectorHighlightConfig>();
    highlight_config->show_info = true;  // Always show tooltips for frames.
    highlight_config->content = DOMDispatcher::ParseColor(color_ptr);
    highlight_config->content_outline = DOMDispatcher::ParseColor(outline_color_ptr);
    InnerHighlightNode(frame->DeprecatedLocalOwner(), nullptr,
                       *highlight_config, false);
  }
}

void OverlayDispatcher::HighlightNode(automation::HighlightConfigPtr highlight_inspector_object, int32_t node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id) {
  //DLOG(ERROR) << "OverlayDispatcher::HighlightNode";
  blink::Node* node = nullptr;
  bool node_ok = dom_dispatcher()->AssertNode(node_id, backend_node_id, object_id, node);
  if (!node_ok) {
    return;
  }

  std::unique_ptr<InspectorHighlightConfig> highlight_config;
  bool ok = HighlightConfigFromInspectorObject(std::move(highlight_inspector_object), &highlight_config);
  if (!ok) {
    return;
  }

  InnerHighlightNode(node, nullptr, *highlight_config, false);
}

void OverlayDispatcher::HighlightQuad(const std::vector<double>& quad_array, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  //DLOG(ERROR) << "OverlayDispatcher::HighlightQuad";
  std::unique_ptr<blink::FloatQuad> quad = std::make_unique<blink::FloatQuad>();
  if (!ParseQuad(quad_array, quad.get())) {
    //DLOG(INFO) << "Invalid Quad format";
    return;
  }
  InnerHighlightQuad(std::move(quad), 
                     std::move(color),
                     std::move(outline_color));
}

void OverlayDispatcher::HighlightRect(int32_t x, int32_t y, int32_t width, int32_t height, automation::RGBAPtr color, automation::RGBAPtr outline_color) {
  //DLOG(INFO) << "OverlayDispatcher::HighlightRect: (application): x: " << x << " y: " << y << " width: " << width << " height: " << height 
  //  << " color: (" << color->r << "," << color->g << "," << color->b << "," << color->a << ")" 
  //  << " outline color: (" << outline_color->r << "," << outline_color->g << "," << outline_color->b << "," << outline_color->a << ")";
  std::unique_ptr<blink::FloatQuad> quad = std::make_unique<blink::FloatQuad>(blink::FloatRect(x, y, width, height));
  InnerHighlightQuad(std::move(quad), std::move(color),
                     std::move(outline_color));
}

void OverlayDispatcher::SetInspectMode(automation::InspectMode mode, automation::HighlightConfigPtr highlight_config) {}
void OverlayDispatcher::SetPausedInDebuggerMessage(const base::Optional<std::string>& message) {}
void OverlayDispatcher::SetSuspended(bool suspended) {}

void OverlayDispatcher::SetShowDebugBorders(bool show) {
  //DLOG(ERROR) << "OverlayDispatcher::SetShowDebugBorders";
  show_debug_borders_ = show;
  if (show) {
    bool enabled = CompositingEnabled();
    if (!enabled)
      return;
  }
  frame_impl_->ViewImpl()->SetShowDebugBorders(show);
}

void OverlayDispatcher::SetShowFPSCounter(bool show) {
  //DLOG(ERROR) << "OverlayDispatcher::SetShowFPSCounter";
  show_fps_borders_ = show;
  if (show) {
    bool enabled = CompositingEnabled();
    if (!enabled) {
      return;
    }
  }
  frame_impl_->ViewImpl()->SetShowFPSCounter(show);
}

void OverlayDispatcher::SetShowPaintRects(bool show) {
  //DLOG(ERROR) << "OverlayDispatcher::SetShowPaintRects";
  show_paint_rects_ = show;
  if (show) {
    bool enabled = CompositingEnabled();
    if (!enabled)
      return;
  }
  frame_impl_->ViewImpl()->SetShowPaintRects(show);
  if (!show && frame_impl_->GetFrameView())
    frame_impl_->GetFrameView()->Invalidate();
}

void OverlayDispatcher::SetShowScrollBottleneckRects(bool show) {
  //DLOG(ERROR) << "OverlayDispatcher::SetShowScrollBottleneckRects";
  show_scroll_bottleneck_rects_ = show;
  if (show) {
    bool enabled = CompositingEnabled();
    if (!enabled)
      return;
  }
  frame_impl_->ViewImpl()->SetShowScrollBottleneckRects(show);
}

void OverlayDispatcher::SetShowViewportSizeOnResize(bool show) {
  //DLOG(ERROR) << "OverlayDispatcher::SetShowViewportSizeOnResize";
  show_size_on_resize_ = show;
  draw_view_size_ = show;
}

bool OverlayDispatcher::IsEmpty() {
  if (disposed_) {
    //DLOG(INFO) << "OverlayDispatcher::IsEmpty: disposed_ == true => TRUE";
    return true;
  }
  if (show_reloading_blanket_) {
    //DLOG(INFO) << "OverlayDispatcher::IsEmpty: show_reloading_blanket_ == true => FALSE";
    return false;
  }
  if (suspended_) {
    //DLOG(INFO) << "OverlayDispatcher::IsEmpty: suspended_ == true => TRUE";
    return true;
  }
  bool has_visible_elements = highlight_node_ || event_target_node_ ||
                              highlight_quad_ ||
                              (resize_timer_active_ && draw_view_size_) ||
                              !paused_in_debugger_message_.IsNull();
  //DLOG(INFO) << "OverlayDispatcher::IsEmpty: has_visible_elements ? " << (has_visible_elements) << " inspect_mode_ == kNotSearching ? " << (inspect_mode_ == kNotSearching);
  return !has_visible_elements && inspect_mode_ == kNotSearching;
}

void OverlayDispatcher::InnerHideHighlight() {
  //DLOG(ERROR) << "OverlayDispatcher::InnerHideHighlight";
  highlight_node_.Clear();
  event_target_node_.Clear();
  highlight_quad_.reset();
  ScheduleUpdate();
}

void OverlayDispatcher::InnerHighlightNode(
  blink::Node* node,
  blink::Node* event_target,
  const InspectorHighlightConfig& highlight_config,
  bool omit_tooltip) {
  //DLOG(ERROR) << "OverlayDispatcher::InnerHighlightNode";
  node_highlight_config_ = highlight_config;
  highlight_node_ = node;
  event_target_node_ = event_target;
  omit_tooltip_ = omit_tooltip;
  ScheduleUpdate();
}

void OverlayDispatcher::InnerHighlightQuad(
  std::unique_ptr<blink::FloatQuad> quad,
  base::Optional<automation::RGBAPtr> color,
  base::Optional<automation::RGBAPtr> outline_color) {
  //DLOG(ERROR) << "OverlayDispatcher::InnerHighlightQuad";
  automation::RGBA* color_ptr = color.has_value() ? color.value().get() : nullptr;
  automation::RGBA* outline_color_ptr = outline_color.has_value() ? outline_color.value().get() : nullptr;
  quad_content_color_ = DOMDispatcher::ParseColor(color_ptr);
  quad_content_outline_color_ = DOMDispatcher::ParseColor(outline_color_ptr);
  highlight_quad_ = std::move(quad);
  omit_tooltip_ = false;
  ScheduleUpdate();
}

void OverlayDispatcher::DrawNodeHighlight() {
  //DLOG(INFO) << "OverlayDispatcher::DrawNodeHighlight";
  if (!highlight_node_) {
    //DLOG(INFO) << "OverlayDispatcher::DrawNodeHighlight: highlight_node_ = null";
    return;
  }

  String selectors = node_highlight_config_.selector_list;
  blink::StaticElementList* elements = nullptr;
  blink::DummyExceptionStateForTesting exception_state;
  blink::ContainerNode* query_base = highlight_node_->ContainingShadowRoot();
  if (!query_base)
    query_base = highlight_node_->ownerDocument();
  if (selectors.length()) {
    elements =
        query_base->QuerySelectorAll(AtomicString(selectors), exception_state);
  }
  if (elements && !exception_state.HadException()) {
    for (unsigned i = 0; i < elements->length(); ++i) {
      blink::Element* element = elements->item(i);
      InspectorHighlight highlight(element, node_highlight_config_, false);
      std::unique_ptr<base::DictionaryValue> highlight_json = highlight.AsProtocolValue();
      EvaluateInOverlay("drawHighlight", std::move(highlight_json));
    }
  }

  bool append_element_info =
      highlight_node_->IsElementNode() && !omit_tooltip_ &&
      node_highlight_config_.show_info && highlight_node_->GetLayoutObject() &&
      highlight_node_->GetDocument().GetFrame();
  InspectorHighlight highlight(highlight_node_.Get(), node_highlight_config_,
                               append_element_info);
  if (event_target_node_) {
    highlight.AppendEventTargetQuads(event_target_node_.Get(),
                                     node_highlight_config_);
  }
  std::unique_ptr<base::DictionaryValue> highlight_json = highlight.AsProtocolValue();
  EvaluateInOverlay("drawHighlight", std::move(highlight_json));
}

void OverlayDispatcher::DrawQuadHighlight() {
  //DLOG(INFO) << "OverlayDispatcher::DrawQuadHighlight";
  if (!highlight_quad_) {
    //DLOG(INFO) << "OverlayDispatcher::DrawQuadHighlight: highlight_quad_ == null. cancelling";
    return;
  }

  InspectorHighlight highlight(WindowToViewportScale());
  highlight.AppendQuad(*highlight_quad_, quad_content_color_,
                       quad_content_outline_color_);
  EvaluateInOverlay("drawHighlight", highlight.AsProtocolValue());
}

void OverlayDispatcher::DrawPausedInDebuggerMessage() {
  if (inspect_mode_ == kNotSearching && !paused_in_debugger_message_.IsNull()) {
    EvaluateInOverlay("drawPausedInDebuggerMessage",
                      paused_in_debugger_message_);
  }
}

void OverlayDispatcher::DrawViewSize() {
  //DLOG(INFO) << "OverlayDispatcher::DrawViewSize";
  if (resize_timer_active_ && draw_view_size_)
    EvaluateInOverlay("drawViewSize", "");
}

void OverlayDispatcher::DrawScreenshotBorder() {
  //DLOG(INFO) << "OverlayDispatcher::DrawScreenshotBorder";
  if (!screenshot_mode_)
    return;
  blink::VisualViewport& visual_viewport =
      frame_impl_->GetFrame()->GetPage()->GetVisualViewport();
  blink::IntPoint p1 = visual_viewport.RootFrameToViewport(screenshot_anchor_);
  blink::IntPoint p2 = visual_viewport.RootFrameToViewport(screenshot_position_);
  std::unique_ptr<base::DictionaryValue> data = std::make_unique<base::DictionaryValue>();
  data->SetKey("x1", base::Value(p1.X()));
  data->SetKey("y1", base::Value(p1.Y()));
  data->SetKey("x2", base::Value(p2.X()));
  data->SetKey("y2", base::Value(p2.Y()));
  EvaluateInOverlay("drawScreenshotBorder", std::move(data));
}

float OverlayDispatcher::WindowToViewportScale() const {
  blink::LocalFrame* frame = frame_impl_->GetFrame();
  if (!frame)
    return 1.0f;
  return frame->GetPage()->GetChromeClient().WindowToViewportScalar(1.0f);
}

blink::Page* OverlayDispatcher::OverlayPage() {
  //DLOG(INFO) << "OverlayDispatcher::OverlayPage";
  if (overlay_page_) {
    //DLOG(INFO) << "OverlayDispatcher::OverlayPage: already created. returning cached version";
    return overlay_page_.Get();
  }

  blink::ScriptForbiddenScope::AllowUserAgentScript allow_script;

  DEFINE_STATIC_LOCAL(blink::LocalFrameClient, dummy_local_frame_client,
                      (blink::EmptyLocalFrameClient::Create()));
  blink::Page::PageClients page_clients;
  FillWithEmptyClients(page_clients);
  DCHECK(!overlay_chrome_client_);
  overlay_chrome_client_ = InspectorOverlayChromeClient::Create(
      frame_impl_->GetFrame()->GetPage()->GetChromeClient(), this);
  page_clients.chrome_client = overlay_chrome_client_.Get();
  overlay_page_ = blink::Page::Create(page_clients);
  overlay_host_ = new blink::InspectorOverlayHost(overlay_agent_.Get());

  blink::Settings& settings = frame_impl_->GetFrame()->GetPage()->GetSettings();
  blink::Settings& overlay_settings = overlay_page_->GetSettings();

  overlay_settings.GetGenericFontFamilySettings().UpdateStandard(
      settings.GetGenericFontFamilySettings().Standard());
  overlay_settings.GetGenericFontFamilySettings().UpdateSerif(
      settings.GetGenericFontFamilySettings().Serif());
  overlay_settings.GetGenericFontFamilySettings().UpdateSansSerif(
      settings.GetGenericFontFamilySettings().SansSerif());
  overlay_settings.GetGenericFontFamilySettings().UpdateCursive(
      settings.GetGenericFontFamilySettings().Cursive());
  overlay_settings.GetGenericFontFamilySettings().UpdateFantasy(
      settings.GetGenericFontFamilySettings().Fantasy());
  overlay_settings.GetGenericFontFamilySettings().UpdatePictograph(
      settings.GetGenericFontFamilySettings().Pictograph());
  overlay_settings.SetMinimumFontSize(settings.GetMinimumFontSize());
  overlay_settings.SetMinimumLogicalFontSize(
      settings.GetMinimumLogicalFontSize());
  overlay_settings.SetScriptEnabled(true);
  overlay_settings.SetPluginsEnabled(false);
  overlay_settings.SetLoadsImagesAutomatically(true);
  // FIXME: http://crbug.com/363843. Inspector should probably create its
  // own graphics layers and attach them to the tree rather than going
  // through some non-composited paint function.
  overlay_settings.SetAcceleratedCompositingEnabled(false);

  blink::LocalFrame* frame = blink::LocalFrame::Create(&dummy_local_frame_client, *overlay_page_, nullptr);
  frame->SetView(blink::LocalFrameView::Create(*frame));
  frame->Init();
  frame->View()->SetCanHaveScrollbars(false);
  frame->View()->SetBaseBackgroundColor(blink::Color::kTransparent);

  const blink::WebData& overlay_page_html_resource = blink::Platform::Current()->GetDataResource("InspectorOverlayPage.html");
  const char* data;
  overlay_page_html_resource.GetSomeData(data, 0);
  //DLOG(INFO) << "OverlayDispatcher::OverlayPage: InspectorOverlayPage.html\n-----\n" << data << "\n-----";
  frame->ForceSynchronousDocumentInstall("text/html", overlay_page_html_resource);
  v8::Isolate* isolate = ToIsolate(frame);
  blink::ScriptState* script_state = ToScriptStateForMainWorld(frame);
  DCHECK(script_state);
  blink::ScriptState::Scope scope(script_state);
  v8::Local<v8::Object> global = script_state->GetContext()->Global();
  v8::Local<v8::Value> overlay_host_obj =
      ToV8(overlay_host_.Get(), global, isolate);
  DCHECK(!overlay_host_obj.IsEmpty());
  global
      ->Set(script_state->GetContext(),
            blink::V8AtomicString(isolate, "InspectorOverlayHost"), overlay_host_obj)
      .ToChecked();

#if defined(OS_WIN)
  EvaluateInOverlay("setPlatform", "windows");
#elif defined(OS_MACOSX)
  EvaluateInOverlay("setPlatform", "mac");
#elif defined(OS_POSIX)
  EvaluateInOverlay("setPlatform", "linux");
#endif

  return overlay_page_.Get();
}

blink::LocalFrame* OverlayDispatcher::OverlayMainFrame() {
  //DLOG(INFO) << "OverlayDispatcher::OverlayMainFrame";
  return blink::ToLocalFrame(OverlayPage()->MainFrame());
}

void OverlayDispatcher::OnTimer(blink::TimerBase*) {
  resize_timer_active_ = false;
  ScheduleUpdate();
}

void OverlayDispatcher::PageLayoutInvalidated(bool resized) {
  if (resized && draw_view_size_) {
    resize_timer_active_ = true;
    timer_->StartOneShot(TimeDelta::FromSeconds(1), FROM_HERE);
  }
  ScheduleUpdate();
}

bool OverlayDispatcher::HandleInputEvent(const blink::WebInputEvent& input_event) {
  //DLOG(INFO) << "OverlayDispatcher::HandleInputEvent";
  bool handled = false;

  if (IsEmpty()) {
    //DLOG(INFO) << "OverlayDispatcher::HandleInputEvent: IsEmpty() = TRUE. cancelling";
    return false;
  }

  if (input_event.GetType() == blink::WebInputEvent::kGestureTap) {
    // We only have a use for gesture tap.
    blink::WebGestureEvent transformed_event = TransformWebGestureEvent(
        frame_impl_->GetFrameView(),
        static_cast<const blink::WebGestureEvent&>(input_event));
    handled = HandleGestureEvent(transformed_event);
    if (handled)
      return true;

    OverlayMainFrame()->GetEventHandler().HandleGestureEvent(transformed_event);
  }
  if (blink::WebInputEvent::IsMouseEventType(input_event.GetType())) {
    blink::WebMouseEvent mouse_event =
        TransformWebMouseEvent(frame_impl_->GetFrameView(),
                               static_cast<const blink::WebMouseEvent&>(input_event));

    if (mouse_event.GetType() == blink::WebInputEvent::kMouseMove)
      handled = HandleMouseMove(mouse_event);
    else if (mouse_event.GetType() == blink::WebInputEvent::kMouseDown)
      handled = HandleMouseDown(mouse_event);
    else if (mouse_event.GetType() == blink::WebInputEvent::kMouseUp)
      handled = HandleMouseUp(mouse_event);

    if (handled)
      return true;

    if (mouse_event.GetType() == blink::WebInputEvent::kMouseMove) {
      handled = OverlayMainFrame()->GetEventHandler().HandleMouseMoveEvent(
                    mouse_event, TransformWebMouseEventVector(
                                     frame_impl_->GetFrameView(),
                                     std::vector<const blink::WebInputEvent*>())) !=
                blink::WebInputEventResult::kNotHandled;
    }
    if (mouse_event.GetType() == blink::WebInputEvent::kMouseDown) {
      handled = OverlayMainFrame()->GetEventHandler().HandleMousePressEvent(
                    mouse_event) != blink::WebInputEventResult::kNotHandled;
    }
    if (mouse_event.GetType() == blink::WebInputEvent::kMouseUp) {
      handled = OverlayMainFrame()->GetEventHandler().HandleMouseReleaseEvent(
                    mouse_event) != blink::WebInputEventResult::kNotHandled;
    }
  }

  if (blink::WebInputEvent::IsPointerEventType(input_event.GetType())) {
    blink::WebPointerEvent transformed_event = TransformWebPointerEvent(
        frame_impl_->GetFrameView(),
        static_cast<const blink::WebPointerEvent&>(input_event));
    handled = HandlePointerEvent(transformed_event);
    if (handled)
      return true;
    OverlayMainFrame()->GetEventHandler().HandlePointerEvent(
        transformed_event, Vector<blink::WebPointerEvent>());
  }
  if (blink::WebInputEvent::IsKeyboardEventType(input_event.GetType())) {
    OverlayMainFrame()->GetEventHandler().KeyEvent(
        static_cast<const blink::WebKeyboardEvent&>(input_event));
  }

  if (input_event.GetType() == blink::WebInputEvent::kMouseWheel) {
    blink::WebMouseWheelEvent transformed_event = TransformWebMouseWheelEvent(
        frame_impl_->GetFrameView(),
        static_cast<const blink::WebMouseWheelEvent&>(input_event));
    handled = OverlayMainFrame()->GetEventHandler().HandleWheelEvent(
                  transformed_event) != blink::WebInputEventResult::kNotHandled;
  }

  return handled;
}

bool OverlayDispatcher::HandleMouseMove(const blink::WebMouseEvent& event) {
  if (!ShouldSearchForNode())
    return false;

  if (event.GetModifiers() & kCtrlOrMeta) {
    InnerHideHighlight();
    hovered_node_for_inspect_mode_.Clear();
    if (screenshot_mode_) {
      screenshot_position_ = RoundedIntPoint(event.PositionInRootFrame());
      ScheduleUpdate();
    }
    return true;
  }

  if (screenshot_mode_) {
    screenshot_mode_ = false;
    ScheduleUpdate();
  }

  blink::LocalFrame* frame = frame_impl_->GetFrame();
  if (!frame || !frame->View() || !frame->ContentLayoutObject())
    return false;
  blink::Node* node = HoveredNodeForEvent(
      frame, event, event.GetModifiers() & blink::WebInputEvent::kShiftKey);

  // Do not highlight within user agent shadow root unless requested.
  if (inspect_mode_ != kSearchingForUAShadow) {
    blink::ShadowRoot* shadow_root = DOMDispatcher::UserAgentShadowRoot(node);
    if (shadow_root)
      node = &shadow_root->host();
  }

  // Shadow roots don't have boxes - use host element instead.
  if (node && node->IsShadowRoot())
    node = node->ParentOrShadowHostNode();

  if (!node)
    return true;

  if (node->IsFrameOwnerElement()) {
    blink::HTMLFrameOwnerElement* frame_owner = ToHTMLFrameOwnerElement(node);
    if (frame_owner->ContentFrame() &&
        !frame_owner->ContentFrame()->IsLocalFrame()) {
      // Do not consume event so that remote frame can handle it.
      InnerHideHighlight();
      hovered_node_for_inspect_mode_.Clear();
      return false;
    }
  }

  blink::Node* event_target = (event.GetModifiers() & blink::WebInputEvent::kShiftKey)
                              ? HoveredNodeForEvent(frame, event, false)
                              : nullptr;
  if (event_target == node)
    event_target = nullptr;

  if (node && inspect_mode_highlight_config_) {
    hovered_node_for_inspect_mode_ = node;
    NodeHighlightRequested(node);
    bool omit_tooltip = event.GetModifiers() &
                        (blink::WebInputEvent::kControlKey | blink::WebInputEvent::kMetaKey);
    InnerHighlightNode(node, event_target, *inspect_mode_highlight_config_,
                       omit_tooltip);
  }
  return true;
}

bool OverlayDispatcher::HandleMouseDown(const blink::WebMouseEvent& event) {
  swallow_next_mouse_up_ = false;
  screenshot_mode_ = false;
  if (!ShouldSearchForNode())
    return false;

  if ((event.GetModifiers() & kCtrlOrMeta) &&
      (event.GetModifiers() & blink::WebInputEvent::kLeftButtonDown)) {
    InnerHideHighlight();
    hovered_node_for_inspect_mode_.Clear();
    screenshot_mode_ = true;
    screenshot_anchor_ = RoundedIntPoint(event.PositionInRootFrame());
    screenshot_position_ = screenshot_anchor_;
    ScheduleUpdate();
    return true;
  }

  if (hovered_node_for_inspect_mode_) {
    swallow_next_mouse_up_ = true;
    //Inspect(hovered_node_for_inspect_mode_.Get());
    hovered_node_for_inspect_mode_.Clear();
    return true;
  }
  return false;
}

bool OverlayDispatcher::HandleMouseUp(const blink::WebMouseEvent& event) {
  if (screenshot_mode_) {
    screenshot_mode_ = false;
    float scale = 1.0f;
    blink::IntPoint p1 = screenshot_anchor_;
    blink::IntPoint p2 = screenshot_position_;
    if (blink::LocalFrame* frame = frame_impl_->GetFrame()) {
      scale = frame->GetPage()->PageScaleFactor();
      p1 = frame->View()->RootFrameToContents(p1);
      p2 = frame->View()->RootFrameToContents(p2);
    }
    int min_x = std::min(p1.X(), p2.X());
    int max_x = std::max(p1.X(), p2.X());
    int min_y = std::min(p1.Y(), p2.Y());
    int max_y = std::max(p1.Y(), p2.Y());

    automation::ViewportPtr viewport = automation::Viewport::New();
    viewport->x = min_x;
    viewport->y = min_y;
    viewport->width = max_x - min_x;
    viewport->height = max_y - min_y;
    viewport->scale = scale;
    
    GetClient()->ScreenshotRequested(std::move(viewport));
    return true;
  }
  if (swallow_next_mouse_up_) {
    swallow_next_mouse_up_ = false;
    return true;
  }
  return false;
}

bool OverlayDispatcher::HandleGestureEvent(const blink::WebGestureEvent& event) {
  if (!ShouldSearchForNode() || event.GetType() != blink::WebInputEvent::kGestureTap)
    return false;
  blink::Node* node = HoveredNodeForEvent(frame_impl_->GetFrame(), event, false);
  if (node && inspect_mode_highlight_config_) {
    InnerHighlightNode(node, nullptr, *inspect_mode_highlight_config_, false);
    //Inspect(node);
    return true;
  }
  return false;
}

bool OverlayDispatcher::HandlePointerEvent(const blink::WebPointerEvent& event) {
  if (!ShouldSearchForNode())
    return false;
  blink::Node* node = HoveredNodeForEvent(frame_impl_->GetFrame(), event, false);
  if (node && inspect_mode_highlight_config_) {
    InnerHighlightNode(node, nullptr, *inspect_mode_highlight_config_, false);
    //Inspect(node);
    return true;
  }
  return false;
}

void OverlayDispatcher::NodeHighlightRequested(blink::Node* node) {
  //DLOG(INFO) << "OverlayDispatcher::NodeHighlightRequested";
  if (!enabled_) {
    //DLOG(INFO) << "OverlayDispatcher::NodeHighlightRequested: enabled_ == false. cancelling";
    return;
  }

  while (node && !node->IsElementNode() && !node->IsDocumentNode() &&
         !node->IsDocumentFragment())
    node = node->ParentOrShadowHostNode();

  if (!node) {
    //DLOG(INFO) << "OverlayDispatcher::NodeHighlightRequested: node not found. cancelling";
    return;
  }

  int node_id = dom_dispatcher()->PushNodePathToFrontend(node);
  GetClient()->NodeHighlightRequested(node_id);
}

bool OverlayDispatcher::SetSearchingForNode(
    SearchMode search_mode,
    base::Optional<automation::HighlightConfigPtr> highlight_inspector_object) {
  if (search_mode == kNotSearching) {
    inspect_mode_ = search_mode;
    screenshot_mode_ = false;
    ScheduleUpdate();
    hovered_node_for_inspect_mode_.Clear();
    InnerHideHighlight();
    return true;
  }

  std::unique_ptr<InspectorHighlightConfig> config;
  bool ok = HighlightConfigFromInspectorObject(
      std::move(highlight_inspector_object), &config);
  if (!ok)
    return false;
  inspect_mode_ = search_mode;
  inspect_mode_highlight_config_ = std::move(config);
  ScheduleUpdate();
  return true;
}

bool OverlayDispatcher::HighlightConfigFromInspectorObject(
    base::Optional<automation::HighlightConfigPtr> highlight_inspector_object,
    std::unique_ptr<InspectorHighlightConfig>* out_config) {
  if (!highlight_inspector_object.has_value()) {
    //DLOG(ERROR) << "Internal error: highlight configuration parameter is missing";
    return false;
  }

  automation::HighlightConfigPtr config = std::move(highlight_inspector_object.value());
  std::unique_ptr<InspectorHighlightConfig> highlight_config =
      std::make_unique<InspectorHighlightConfig>();
  highlight_config->show_info = config->show_info;
  highlight_config->show_rulers = config->show_rulers;
  highlight_config->show_extension_lines = config->show_extension_lines;
  highlight_config->display_as_material = config->display_as_material;
  highlight_config->content = DOMDispatcher::ParseColor(config->content_color.get());
  highlight_config->padding = DOMDispatcher::ParseColor(config->padding_color.get());
  highlight_config->border = DOMDispatcher::ParseColor(config->border_color.get());
  highlight_config->margin = DOMDispatcher::ParseColor(config->margin_color.get());
  highlight_config->event_target = DOMDispatcher::ParseColor(config->event_target_color.get());
  highlight_config->shape = DOMDispatcher::ParseColor(config->shape_color.get());
  highlight_config->shape_margin = DOMDispatcher::ParseColor(config->shape_margin_color.get());
  highlight_config->css_grid = DOMDispatcher::ParseColor(config->css_grid_color.get());
  highlight_config->selector_list = config->selector_list.has_value() ? String::FromUTF8(config->selector_list.value().data()) : "";

  *out_config = std::move(highlight_config);
  return true;
}

void OverlayDispatcher::EvaluateInOverlay(const String& method,
                                          const String& argument) {
  //DLOG(INFO) << "OverlayDispatcher::EvaluateInOverlay: " << method;
  blink::ScriptForbiddenScope::AllowUserAgentScript allow_script;
  std::string command_json;

  std::unique_ptr<base::ListValue> command = std::make_unique<base::ListValue>();
  command->Append(std::make_unique<base::Value>(method.Utf8().data()));
  command->Append(std::make_unique<base::Value>(std::string(argument.Utf8().data())));
  
  base::JSONWriter::Write(*command, &command_json);
  std::string dispatch = "dispatch(" + command_json + ")";
  
  ToLocalFrame(OverlayPage()->MainFrame())
      ->GetScriptController()
      .ExecuteScriptInMainWorld(
          String::FromUTF8(dispatch.data()),
          blink::ScriptSourceLocationType::kInspector,
          blink::ScriptController::kExecuteScriptWhenScriptsDisabled);
}

void OverlayDispatcher::EvaluateInOverlay(
  const String& method,
  std::unique_ptr<base::DictionaryValue> argument) {
  //DLOG(INFO) << "OverlayDispatcher::EvaluateInOverlay: " << method;
  blink::ScriptForbiddenScope::AllowUserAgentScript allow_script;
  std::string command_json;
  std::unique_ptr<base::ListValue> command = std::make_unique<base::ListValue>();
  command->Append(std::make_unique<base::Value>(method.Utf8().data()));
  command->Append(std::move(argument));

  base::JSONWriter::Write(*command, &command_json);
  std::string dispatch = "dispatch(" + command_json + ")";

  ToLocalFrame(OverlayPage()->MainFrame())
      ->GetScriptController()
      .ExecuteScriptInMainWorld(
          String::FromUTF8(dispatch.data()),
          blink::ScriptSourceLocationType::kInspector,
          blink::ScriptController::kExecuteScriptWhenScriptsDisabled);
}

void OverlayDispatcher::Reset(const blink::IntSize& viewport_size,
                              const blink::IntPoint& document_scroll_offset) {
  std::unique_ptr<base::DictionaryValue> reset_data = std::make_unique<base::DictionaryValue>();
  reset_data->SetKey(
      "deviceScaleFactor",
      base::Value(frame_impl_->GetFrame()->GetPage()->DeviceScaleFactorDeprecated()));
  reset_data->SetKey(
      "pageScaleFactor",
      base::Value(frame_impl_->GetFrame()->GetPage()->GetVisualViewport().Scale()));

  blink::IntRect viewport_in_screen =
      frame_impl_->GetFrame()->GetPage()->GetChromeClient().ViewportToScreen(
          blink::IntRect(blink::IntPoint(), viewport_size), frame_impl_->GetFrame()->View());
  reset_data->SetDictionary(
      "viewportSize",
      BuildObjectForSize(viewport_in_screen.Size()));

  // The zoom factor in the overlay frame already has been multiplied by the
  // window to viewport scale (aka device scale factor), so cancel it.
  reset_data->SetKey(
      "pageZoomFactor",
      base::Value(frame_impl_->GetFrame()->PageZoomFactor() / WindowToViewportScale()));

  reset_data->SetKey(
      "scrollX", 
      base::Value(document_scroll_offset.X()));

  reset_data->SetKey(
      "scrollY", 
      base::Value(document_scroll_offset.Y()));

  EvaluateInOverlay("reset", std::move(reset_data));
}

void OverlayDispatcher::RebuildOverlayPage() {
  //DLOG(INFO) << "OverlayDispatcher::RebuildOverlayPage";

  blink::LocalFrameView* view = frame_impl_->GetFrameView();
  blink::LocalFrame* frame = frame_impl_->GetFrame();
  if (!view || !frame)
    return;

  blink::IntRect visible_rect_in_document =
      view->GetScrollableArea()->VisibleContentRect();
  blink::IntSize viewport_size = frame->GetPage()->GetVisualViewport().Size();
  OverlayMainFrame()->View()->Resize(viewport_size);
  OverlayPage()->GetVisualViewport().SetSize(viewport_size);
  OverlayMainFrame()->SetPageZoomFactor(WindowToViewportScale());

  Reset(viewport_size, visible_rect_in_document.Location());

  if (show_reloading_blanket_) {
    EvaluateInOverlay("showReloadingBlanket", "");
    return;
  }
  DrawNodeHighlight();
  DrawQuadHighlight();
  DrawPausedInDebuggerMessage();
  DrawViewSize();
  DrawScreenshotBorder();
}

void OverlayDispatcher::Invalidate() {
  //DLOG(INFO) << "OverlayDispatcher::Invalidate";
  if (IsEmpty()) {
    //DLOG(INFO) << "OverlayDispatcher::Invalidate: ";
    return;
  }

  if (!page_overlay_) {
    page_overlay_ = blink::PageOverlay::Create(
        frame_impl_, std::make_unique<InspectorPageOverlayDelegate>(this));
  }

  page_overlay_->Update();
}

void OverlayDispatcher::ScheduleUpdate() {
  //DLOG(INFO) << "OverlayDispatcher::ScheduleUpdate";
  if (IsEmpty()) {
    //DLOG(INFO) << "OverlayDispatcher::ScheduleUpdate: IsEmpty() = TRUE";
    if (page_overlay_)
      page_overlay_.reset();
    return;
  }
  needs_update_ = true;
  blink::LocalFrame* frame = frame_impl_->GetFrame();
  if (frame) {
    //DLOG(INFO) << "OverlayDispatcher::ScheduleUpdate: frame " << frame << " is here. scheduling update";
    frame->GetPage()->GetChromeClient().ScheduleAnimation(frame->View());
  } else {
    //DLOG(INFO) << "OverlayDispatcher::ScheduleUpdate: no frame. not scheduling update";
  }
}

void OverlayDispatcher::ClearInternal() {
  if (overlay_page_) {
    overlay_page_->WillBeDestroyed();
    overlay_page_.Clear();
    overlay_chrome_client_.Clear();
    overlay_host_->ClearListener();
    overlay_host_.Clear();
  }
  resize_timer_active_ = false;
  paused_in_debugger_message_ = String();
  inspect_mode_ = kNotSearching;
  screenshot_mode_ = false;
  timer_->Stop();
  page_overlay_.reset();
  InnerHideHighlight();
}

void OverlayDispatcher::UpdateAllLifecyclePhases() {
  //DLOG(INFO) << "OverlayDispatcher::UpdateAllLifecyclePhases";
  if (IsEmpty()) {
    //DLOG(INFO) << "OverlayDispatcher::UpdateAllLifecyclePhases: IsEmpty() = true";
    return;
  }

  AutoReset<bool> scoped(&in_layout_, true);
  if (needs_update_) {
    //DLOG(INFO) << "OverlayDispatcher::UpdateAllLifecyclePhases: needs_update_ = true => RebuildOverlayPage()";
    needs_update_ = false;
    RebuildOverlayPage();
  }
  OverlayMainFrame()->View()->UpdateAllLifecyclePhases();
}

bool OverlayDispatcher::CompositingEnabled() {
  bool main_frame = frame_impl_->ViewImpl() && !frame_impl_->Parent();
  if (!main_frame || !frame_impl_->ViewImpl()
                          ->GetPage()
                          ->GetSettings()
                          .GetAcceleratedCompositingEnabled()) {
    //DLOG(ERROR) << "Compositing mode is not supported";
    return false;
  }
  return true;
}

bool OverlayDispatcher::ShouldSearchForNode() {
  return inspect_mode_ != kNotSearching;
}

automation::OverlayClient* OverlayDispatcher::GetClient() {
  return overlay_client_ptr_.get();
}

}
