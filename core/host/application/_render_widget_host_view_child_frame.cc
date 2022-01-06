// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_window_host_view_child_frame.h"

#include <algorithm>
#include <utility>
#include <vector>

#include "base/debug/dump_without_crashing.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "components/viz/common/features.h"
#include "components/viz/common/frame_sinks/copy_output_request.h"
#include "components/viz/common/frame_sinks/copy_output_result.h"
#include "components/viz/host/host_frame_sink_manager.h"
#include "components/viz/service/frame_sinks/compositor_frame_sink_support.h"
#include "components/viz/service/surfaces/surface.h"
#include "components/viz/service/surfaces/surface_manager.h"
#include "core/host/accessibility/browser_accessibility_manager.h"
#include "core/host/browser_plugin/browser_plugin_guest.h"
#include "core/host/compositor/surface_utils.h"
#include "core/host/gpu/compositor_util.h"
#include "core/host/application/cursor_manager.h"
#include "core/host/application/display_util.h"
#include "core/host/application/frame_connector_delegate.h"
#include "core/host/application/input/touch_selection_controller_client_child_frame.h"
#include "core/host/application/application_window_host_impl.h"
#include "core/host/application/application_window_host_delegate.h"
#include "core/host/application/application_window_host_impl.h"
#include "core/host/application/application_window_host_input_event_router.h"
#include "core/host/application/application_window_host_view_event_handler.h"
#include "core/host/application/text_input_manager.h"
#include "core/common/text_input_state.h"
#include "core/common/view_messages.h"
#include "core/host/guest_mode.h"
#include "core/host/render_process_host.h"
#include "gpu/ipc/common/gpu_messages.h"
#include "services/service_manager/runner/common/client_util.h"
#include "third_party/blink/public/platform/web_touch_event.h"
#include "ui/base/ui_base_features.h"
#include "ui/gfx/geometry/dip_util.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/size_f.h"
#include "ui/touch_selection/touch_selection_controller.h"

#if defined(USE_AURA)
#include "services/ui/public/interfaces/window_tree.mojom.h"
#include "ui/aura/env.h"
#endif

namespace host {

// static
ApplicationWindowHostViewChildFrame* ApplicationWindowHostViewChildFrame::Create(
    ApplicationWindowHost* widget) {
  ApplicationWindowHostViewChildFrame* view =
      new ApplicationWindowHostViewChildFrame(widget);
  view->Init();
  return view;
}

ApplicationWindowHostViewChildFrame::ApplicationWindowHostViewChildFrame(
    ApplicationWindowHost* widget_host)
    : ApplicationWindowHostView(widget_host),
      frame_sink_id_(
          base::checked_cast<uint32_t>(widget_host->GetProcess()->GetID()),
          base::checked_cast<uint32_t>(widget_host->GetRoutingID())),
      current_surface_scale_factor_(1.f),
      frame_connector_(nullptr),
      enable_viz_(
          base::FeatureList::IsEnabled(features::kVizDisplayCompositor)),
      background_color_(SK_ColorWHITE),
      scroll_bubbling_state_(NO_ACTIVE_GESTURE_SCROLL),
      weak_factory_(this) {
  if (base::FeatureList::IsEnabled(features::kMash)) {
    // In Mus the RenderFrameProxy will eventually assign a viz::FrameSinkId
    // until then set ours invalid, as operations using it will be disregarded.
    frame_sink_id_ = viz::FrameSinkId();
  } else {
    GetHostFrameSinkManager()->RegisterFrameSinkId(frame_sink_id_, this);
    GetHostFrameSinkManager()->SetFrameSinkDebugLabel(
        frame_sink_id_, "ApplicationWindowHostViewChildFrame");
    CreateCompositorFrameSinkSupport();
  }
}

ApplicationWindowHostViewChildFrame::~ApplicationWindowHostViewChildFrame() {
  // TODO(wjmaclean): The next two lines are a speculative fix for
  // https://crbug.com/760074, based on the theory that perhaps something is
  // destructing the class without calling Destroy() first.
  if (frame_connector_)
    DetachFromTouchSelectionClientManagerIfNecessary();

  if (!base::FeatureList::IsEnabled(features::kMash)) {
    ResetCompositorFrameSinkSupport();
    if (GetHostFrameSinkManager())
      GetHostFrameSinkManager()->InvalidateFrameSinkId(frame_sink_id_);
  }
}

void ApplicationWindowHostViewChildFrame::Init() {
  RegisterFrameSinkId();
  host()->SetView(this);
  GetTextInputManager();
}

void ApplicationWindowHostViewChildFrame::
    DetachFromTouchSelectionClientManagerIfNecessary() {
  if (!selection_controller_client_)
    return;

  auto* root_view = frame_connector_->GetRootApplicationWindowHostView();
  if (root_view) {
    auto* manager = root_view->GetTouchSelectionControllerClientManager();
    if (manager)
      manager->RemoveObserver(this);
  } else {
    // We should never get here, but maybe we are? Test this out with a
    // diagnostic we can track. If we do get here, it would explain
    // https://crbug.com/760074.
    base::debug::DumpWithoutCrashing();
  }

  selection_controller_client_.reset();
}

void ApplicationWindowHostViewChildFrame::SetFrameConnectorDelegate(
    FrameConnectorDelegate* frame_connector) {
  if (frame_connector_ == frame_connector)
    return;

  if (frame_connector_) {
    SetParentFrameSinkId(viz::FrameSinkId());
    last_received_local_surface_id_ = viz::LocalSurfaceId();

    // Unlocks the mouse if this ApplicationWindowHostView holds the lock.
    UnlockMouse();
    DetachFromTouchSelectionClientManagerIfNecessary();
  }
  frame_connector_ = frame_connector;
  if (!frame_connector_)
    return;

  ApplicationWindowHostView* parent_view =
      frame_connector_->GetParentApplicationWindowHostView();

  if (parent_view) {
    DCHECK(parent_view->GetFrameSinkId().is_valid() ||
           base::FeatureList::IsEnabled(features::kMash));
    SetParentFrameSinkId(parent_view->GetFrameSinkId());
  }

  current_device_scale_factor_ =
      frame_connector_->screen_info().device_scale_factor;

  auto* root_view = frame_connector_->GetRootApplicationWindowHostView();
  if (root_view) {
    auto* manager = root_view->GetTouchSelectionControllerClientManager();
    if (manager) {
      // We have managers in Aura and Android, as well as outside of content/.
      // There is no manager for Mac OS.
      selection_controller_client_ =
          std::make_unique<TouchSelectionControllerClientChildFrame>(this,
                                                                     manager);
      manager->AddObserver(this);
    }
  }

#if defined(USE_AURA)
  if (features::IsMusEnabled()) {
    frame_connector_->EmbedRendererWindowTreeClientInParent(
        GetWindowTreeClientFromRenderer());
  }
#endif
}

#if defined(USE_AURA)
void ApplicationWindowHostViewChildFrame::SetFrameSinkId(
    const viz::FrameSinkId& frame_sink_id) {
  if (base::FeatureList::IsEnabled(features::kMash))
    frame_sink_id_ = frame_sink_id;
}
#endif  // defined(USE_AURA)

bool ApplicationWindowHostViewChildFrame::OnMessageReceived(
    const IPC::Message& msg) {
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(ApplicationWindowHostViewChildFrame, msg)
    IPC_MESSAGE_HANDLER(ViewHostMsg_IntrinsicSizingInfoChanged,
                        OnIntrinsicSizingInfoChanged)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()

  return handled;
}

void ApplicationWindowHostViewChildFrame::OnIntrinsicSizingInfoChanged(
    blink::WebIntrinsicSizingInfo sizing_info) {
  if (frame_connector_)
    frame_connector_->SendIntrinsicSizingInfoToParent(sizing_info);
}

void ApplicationWindowHostViewChildFrame::OnManagerWillDestroy(
    TouchSelectionControllerClientManager* manager) {
  // We get the manager via the observer callback instead of through the
  // frame_connector_ since our connection to the root_view may disappear by
  // the time this function is called, but before frame_connector_ is reset.
  manager->RemoveObserver(this);
  selection_controller_client_.reset();
}

void ApplicationWindowHostViewChildFrame::InitAsChild(gfx::NativeView parent_view) {
  NOTREACHED();
}

void ApplicationWindowHostViewChildFrame::SetSize(const gfx::Size& size) {
  // Resizing happens in CrossProcessFrameConnector for child frames.
}

void ApplicationWindowHostViewChildFrame::SetBounds(const gfx::Rect& rect) {
  // Resizing happens in CrossProcessFrameConnector for child frames.
  if (rect != last_screen_rect_) {
    last_screen_rect_ = rect;
    host()->SendScreenRects();
  }
}

void ApplicationWindowHostViewChildFrame::Focus() {}

bool ApplicationWindowHostViewChildFrame::HasFocus() const {
  if (frame_connector_)
    return frame_connector_->HasFocus();
  return false;
}

bool ApplicationWindowHostViewChildFrame::IsSurfaceAvailableForCopy() const {
  return has_frame_;
}

void ApplicationWindowHostViewChildFrame::EnsureSurfaceSynchronizedForLayoutTest() {
  // The capture sequence number which would normally be updated here is
  // actually retrieved from the frame connector.
}

uint32_t ApplicationWindowHostViewChildFrame::GetCaptureSequenceNumber() const {
  if (!frame_connector_)
    return 0u;
  return frame_connector_->capture_sequence_number();
}

void ApplicationWindowHostViewChildFrame::Show() {
  if (!host()->is_hidden())
    return;

  if (!CanBecomeVisible())
    return;

  host()->WasShown(ui::LatencyInfo());

  if (frame_connector_)
    frame_connector_->SetVisibilityForChildViews(true);
}

void ApplicationWindowHostViewChildFrame::Hide() {
  if (host()->is_hidden())
    return;
  host()->WasHidden();

  if (frame_connector_)
    frame_connector_->SetVisibilityForChildViews(false);
}

bool ApplicationWindowHostViewChildFrame::IsShowing() {
  return !host()->is_hidden();
}

gfx::Rect ApplicationWindowHostViewChildFrame::GetViewBounds() const {
  gfx::Rect rect;
  if (frame_connector_) {
    rect = frame_connector_->screen_space_rect_in_dip();

    ApplicationWindowHostView* parent_view =
        frame_connector_->GetParentApplicationWindowHostView();

    // The parent_view can be null in tests when using a TestWebContents.
    if (parent_view) {
      // Translate screen_space_rect by the parent's ApplicationWindowHostView
      // offset.
      rect.Offset(parent_view->GetViewBounds().OffsetFromOrigin());
    }
    // TODO(fsamuel): GetViewBounds is a bit of a mess. It's used to determine
    // the size of the renderer content and where to portal context menus and so
    // on. We want the location of the frame in screen coordinates to portal
    // popups but we want the size in local coordinates to produce the right-
    // sized CompositorFrames.
    rect.set_size(frame_connector_->local_frame_size_in_dip());
  }
  return rect;
}

gfx::Size ApplicationWindowHostViewChildFrame::GetVisibleViewportSize() const {
  // For subframes, the visual viewport corresponds to the main frame size, so
  // this bubbles up to the parent until it hits the main frame's
  // ApplicationWindowHostView.
  //
  // Currently this excludes webview guests, since they expect the visual
  // viewport to return the guest's size rather than the page's; one reason why
  // is that Blink ends up using the visual viewport to calculate things like
  // window.innerWidth/innerHeight for main frames, and a guest is considered
  // to be a main frame.  This should be cleaned up eventually.
  bool is_guest = BrowserPluginGuest::IsGuest(RenderViewHostImpl::From(host()));
  if (frame_connector_ && !is_guest) {
    // An auto-resize set by the top-level frame overrides what would be
    // reported by embedding ApplicationWindowHostViews.
    if (host()->delegate() &&
        !host()->delegate()->GetAutoResizeSize().IsEmpty())
      return host()->delegate()->GetAutoResizeSize();

    ApplicationWindowHostView* parent_view =
        frame_connector_->GetParentApplicationWindowHostView();
    // The parent_view can be null in unit tests when using a TestWebContents.
    if (parent_view)
      return parent_view->GetVisibleViewportSize();
  }

  gfx::Rect bounds = GetViewBounds();

  // It doesn't make sense to set insets on an OOP iframe. The only time this
  // should happen is when the virtual keyboard comes up on a <webview>.
  if (is_guest)
    bounds.Inset(insets_);

  return bounds.size();
}

void ApplicationWindowHostViewChildFrame::SetInsets(const gfx::Insets& insets) {
  // Insets are used only for <webview> and are used to let the UI know it's
  // being obscured (for e.g. by the virtual keyboard).
  insets_ = insets;
  host()->SynchronizeVisualProperties(!insets_.IsEmpty());
}

gfx::NativeView ApplicationWindowHostViewChildFrame::GetNativeView() const {
  // TODO(ekaramad): To accomodate MimeHandlerViewGuest while embedded inside
  // OOPIF-webview, we need to return the native view to be used by
  // ApplicationWindowHostViewGuest. Remove this once https://crbug.com/642826 is
  // fixed.
  if (frame_connector_)
    return frame_connector_->GetParentApplicationWindowHostView()->GetNativeView();
  return nullptr;
}

gfx::NativeViewAccessible
ApplicationWindowHostViewChildFrame::GetNativeViewAccessible() {
  NOTREACHED();
  return nullptr;
}

void ApplicationWindowHostViewChildFrame::SetBackgroundColor(SkColor color) {
  background_color_ = color;

  DCHECK(SkColorGetA(color) == SK_AlphaOPAQUE ||
         SkColorGetA(color) == SK_AlphaTRANSPARENT);
  host()->SetBackgroundOpaque(SkColorGetA(color) == SK_AlphaOPAQUE);
}

SkColor ApplicationWindowHostViewChildFrame::background_color() const {
  return background_color_;
}

gfx::Size ApplicationWindowHostViewChildFrame::GetCompositorViewportPixelSize()
    const {
  if (frame_connector_)
    return frame_connector_->local_frame_size_in_pixels();
  return gfx::Size();
}

void ApplicationWindowHostViewChildFrame::InitAsPopup(
    ApplicationWindowHostView* parent_host_view,
    const gfx::Rect& bounds) {
  NOTREACHED();
}

void ApplicationWindowHostViewChildFrame::InitAsFullscreen(
    ApplicationWindowHostView* reference_host_view) {
  NOTREACHED();
}

void ApplicationWindowHostViewChildFrame::UpdateCursor(const WebCursor& cursor) {
  if (frame_connector_)
    frame_connector_->UpdateCursor(cursor);
}

void ApplicationWindowHostViewChildFrame::SetIsLoading(bool is_loading) {
  // It is valid for an inner WebContents's SetIsLoading() to end up here.
  // This is because an inner WebContents's main frame's ApplicationWindowHostView
  // is a ApplicationWindowHostViewChildFrame. In contrast, when there is no
  // inner/outer WebContents, only subframe's ApplicationWindowHostView can be a
  // ApplicationWindowHostViewChildFrame which do not get a SetIsLoading() call.
  if (GuestMode::IsCrossProcessFrameGuest(
          WebContents::FromRenderViewHost(RenderViewHost::From(host()))))
    return;

  NOTREACHED();
}

void ApplicationWindowHostViewChildFrame::RenderProcessGone(
    base::TerminationStatus status,
    int error_code) {
  if (frame_connector_)
    frame_connector_->RenderProcessGone();
  Destroy();
}

void ApplicationWindowHostViewChildFrame::Destroy() {
  // FrameSinkIds registered with ApplicationWindowHostInputEventRouter
  // have already been cleared when ApplicationWindowHostView notified its
  // observers of our impending destruction.
  if (frame_connector_) {
    frame_connector_->SetView(nullptr);
    SetFrameConnectorDelegate(nullptr);
  }

  // We notify our observers about shutdown here since we are about to release
  // host_ and do not want any event calls coming from
  // ApplicationWindowHostInputEventRouter afterwards.
  NotifyObserversAboutShutdown();

  ApplicationWindowHostView::Destroy();

  delete this;
}

void ApplicationWindowHostViewChildFrame::SetTooltipText(
    const base::string16& tooltip_text) {
  if (!frame_connector_)
    return;

  auto* root_view = frame_connector_->GetRootApplicationWindowHostView();
  if (!root_view)
    return;

  root_view->GetCursorManager()->SetTooltipTextForView(this, tooltip_text);
}

ApplicationWindowHostView* ApplicationWindowHostViewChildFrame::GetParentView() {
  if (!frame_connector_)
    return nullptr;
  return frame_connector_->GetParentApplicationWindowHostView();
}

void ApplicationWindowHostViewChildFrame::RegisterFrameSinkId() {
  // If Destroy() has been called before we get here, host_ may be null.
  if (host() && host()->delegate() &&
      host()->delegate()->GetInputEventRouter()) {
    ApplicationWindowHostInputEventRouter* router =
        host()->delegate()->GetInputEventRouter();
    if (!router->is_registered(frame_sink_id_))
      router->AddFrameSinkIdOwner(frame_sink_id_, this);
  }
}

void ApplicationWindowHostViewChildFrame::UnregisterFrameSinkId() {
  DCHECK(host());
  if (host()->delegate() && host()->delegate()->GetInputEventRouter()) {
    host()->delegate()->GetInputEventRouter()->RemoveFrameSinkIdOwner(
        frame_sink_id_);
    DetachFromTouchSelectionClientManagerIfNecessary();
  }
}

void ApplicationWindowHostViewChildFrame::UpdateViewportIntersection(
    const gfx::Rect& viewport_intersection,
    const gfx::Rect& compositor_visible_rect) {
  if (host()) {
    host()->Send(new ViewMsg_SetViewportIntersection(host()->GetRoutingID(),
                                                     viewport_intersection,
                                                     compositor_visible_rect));
  }
}

void ApplicationWindowHostViewChildFrame::SetIsInert() {
  if (host() && frame_connector_) {
    host()->Send(new ViewMsg_SetIsInert(host()->GetRoutingID(),
                                        frame_connector_->IsInert()));
  }
}

void ApplicationWindowHostViewChildFrame::UpdateRenderThrottlingStatus() {
  if (host() && frame_connector_) {
    host()->Send(new ViewMsg_UpdateRenderThrottlingStatus(
        host()->GetRoutingID(), frame_connector_->IsThrottled(),
        frame_connector_->IsSubtreeThrottled()));
  }
}

void ApplicationWindowHostViewChildFrame::GestureEventAck(
    const blink::WebGestureEvent& event,
    common::InputEventAckState ack_result) {
  bool should_bubble =
      ack_result == INPUT_EVENT_ACK_STATE_NOT_CONSUMED ||
      ack_result == INPUT_EVENT_ACK_STATE_NO_CONSUMER_EXISTS ||
      ack_result == INPUT_EVENT_ACK_STATE_CONSUMED_SHOULD_BUBBLE;

  if (!frame_connector_)
    return;
  if (wheel_scroll_latching_enabled()) {
    if ((event.GetType() == blink::WebInputEvent::kGestureScrollBegin) &&
        should_bubble) {
      DCHECK(!is_scroll_sequence_bubbling_);
      is_scroll_sequence_bubbling_ = true;
    } else if (event.GetType() == blink::WebInputEvent::kGestureScrollEnd ||
               event.GetType() == blink::WebInputEvent::kGestureFlingStart) {
      is_scroll_sequence_bubbling_ = false;
    }

    // GestureScrollBegin is a blocking event; It is forwarded for bubbling if
    // its ack is not consumed. For the rest of the scroll events
    // (GestureScrollUpdate, GestureScrollEnd, GestureFlingStart) the
    // frame_connector_ decides to forward them for bubbling if the
    // GestureScrollBegin event is forwarded.
    if ((event.GetType() == blink::WebInputEvent::kGestureScrollBegin &&
         should_bubble) ||
        event.GetType() == blink::WebInputEvent::kGestureScrollUpdate ||
        event.GetType() == blink::WebInputEvent::kGestureScrollEnd ||
        event.GetType() == blink::WebInputEvent::kGestureFlingStart) {
      frame_connector_->BubbleScrollEvent(event);
    }
  } else {
    // Consumption of the first GestureScrollUpdate determines whether to
    // bubble the sequence of GestureScrollUpdates.
    // If the child consumed some scroll, then stopped consuming once it could
    // no longer scroll, we don't want to bubble those unconsumed GSUs as we
    // want the user to start a new gesture in order to scroll the parent.
    // Unfortunately, this is only effective for touch scrolling as wheel
    // scrolling wraps GSUs in GSB/GSE pairs.
    if (event.GetType() == blink::WebInputEvent::kGestureScrollBegin) {
      DCHECK_EQ(NO_ACTIVE_GESTURE_SCROLL, scroll_bubbling_state_);
      scroll_bubbling_state_ = AWAITING_FIRST_UPDATE;
    } else if (scroll_bubbling_state_ == AWAITING_FIRST_UPDATE &&
               event.GetType() == blink::WebInputEvent::kGestureScrollUpdate) {
      scroll_bubbling_state_ = (should_bubble ? BUBBLE : SCROLL_CHILD);
    } else if (event.GetType() == blink::WebInputEvent::kGestureScrollEnd ||
               event.GetType() == blink::WebInputEvent::kGestureFlingStart) {
      scroll_bubbling_state_ = NO_ACTIVE_GESTURE_SCROLL;
    }

    // GestureScrollBegin is consumed by the target frame and not forwarded,
    // because we don't know whether we will need to bubble scroll until we
    // receive a GestureScrollUpdate ACK. GestureScrollUpdates are forwarded
    // for bubbling if the first GSU has unused scroll extent,
    // while GestureScrollEnd is always forwarded and handled according to
    // current scroll state in the ApplicationWindowHostInputEventRouter.
    if ((event.GetType() == blink::WebInputEvent::kGestureScrollUpdate &&
         scroll_bubbling_state_ == BUBBLE) ||
        event.GetType() == blink::WebInputEvent::kGestureScrollEnd ||
        event.GetType() == blink::WebInputEvent::kGestureFlingStart) {
      frame_connector_->BubbleScrollEvent(event);
    }
  }
}

void ApplicationWindowHostViewChildFrame::DidReceiveCompositorFrameAck(
    const std::vector<viz::ReturnedResource>& resources) {
  if (renderer_compositor_frame_sink_)
    renderer_compositor_frame_sink_->DidReceiveCompositorFrameAck(resources);
}

void ApplicationWindowHostViewChildFrame::DidPresentCompositorFrame(
    uint32_t presentation_token,
    base::TimeTicks time,
    base::TimeDelta refresh,
    uint32_t flags) {
  NOTIMPLEMENTED();
}
void ApplicationWindowHostViewChildFrame::DidDiscardCompositorFrame(
    uint32_t presentation_token) {
  NOTIMPLEMENTED();
}
void ApplicationWindowHostViewChildFrame::DidCreateNewRendererCompositorFrameSink(
    viz::mojom::CompositorFrameSinkClient* renderer_compositor_frame_sink) {
  ResetCompositorFrameSinkSupport();
  renderer_compositor_frame_sink_ = renderer_compositor_frame_sink;
  CreateCompositorFrameSinkSupport();
  has_frame_ = false;
}

void ApplicationWindowHostViewChildFrame::SetParentFrameSinkId(
    const viz::FrameSinkId& parent_frame_sink_id) {
  if (parent_frame_sink_id_ == parent_frame_sink_id ||
      base::FeatureList::IsEnabled(features::kMash))
    return;

  auto* host_frame_sink_manager = GetHostFrameSinkManager();

  // Unregister hierarchy for the current parent, only if set.
  if (parent_frame_sink_id_.is_valid()) {
    host_frame_sink_manager->UnregisterFrameSinkHierarchy(parent_frame_sink_id_,
                                                          frame_sink_id_);
  }

  parent_frame_sink_id_ = parent_frame_sink_id;

  // Register hierarchy for the new parent, only if set.
  if (parent_frame_sink_id_.is_valid()) {
    host_frame_sink_manager->RegisterFrameSinkHierarchy(parent_frame_sink_id_,
                                                        frame_sink_id_);
  }
}

void ApplicationWindowHostViewChildFrame::SendSurfaceInfoToEmbedder() {
  if (base::FeatureList::IsEnabled(features::kMash))
    return;
  viz::SurfaceId surface_id(frame_sink_id_, last_received_local_surface_id_);
  viz::SurfaceInfo surface_info(surface_id, current_surface_scale_factor_,
                                current_surface_size_);
  SendSurfaceInfoToEmbedderImpl(surface_info);
}

void ApplicationWindowHostViewChildFrame::SendSurfaceInfoToEmbedderImpl(
    const viz::SurfaceInfo& surface_info) {
  if (frame_connector_)
    frame_connector_->SetChildFrameSurface(surface_info);
}

void ApplicationWindowHostViewChildFrame::SubmitCompositorFrame(
    const viz::LocalSurfaceId& local_surface_id,
    viz::CompositorFrame frame,
    viz::mojom::HitTestRegionListPtr hit_test_region_list) {
  DCHECK(!enable_viz_);
  TRACE_EVENT0("content",
               "ApplicationWindowHostViewChildFrame::OnSwapCompositorFrame");
  current_surface_size_ = frame.size_in_pixels();
  current_surface_scale_factor_ = frame.device_scale_factor();

  support_->SubmitCompositorFrame(local_surface_id, std::move(frame),
                                  std::move(hit_test_region_list));
  has_frame_ = true;

  if (last_received_local_surface_id_ != local_surface_id ||
      HasEmbedderChanged()) {
    last_received_local_surface_id_ = local_surface_id;
    SendSurfaceInfoToEmbedder();
  }

  ProcessFrameSwappedCallbacks();
}

void ApplicationWindowHostViewChildFrame::OnDidNotProduceFrame(
    const viz::BeginFrameAck& ack) {
  DCHECK(!enable_viz_);
  support_->DidNotProduceFrame(ack);
}

void ApplicationWindowHostViewChildFrame::ProcessFrameSwappedCallbacks() {
  std::vector<base::OnceClosure> process_callbacks;
  // Swap the vectors to avoid re-entrancy issues due to calls to
  // RegisterFrameSwappedCallback() while running the OnceClosures.
  process_callbacks.swap(frame_swapped_callbacks_);
  for (base::OnceClosure& callback : process_callbacks)
    std::move(callback).Run();
}

gfx::Vector2d ApplicationWindowHostViewChildFrame::GetOffsetFromRootSurface() {
  // This function is called by ApplicationWindowHostInputEventRouter only for
  // root-views.
  NOTREACHED();
  return gfx::Vector2d();
}

gfx::Rect ApplicationWindowHostViewChildFrame::GetBoundsInRootWindow() {
  gfx::Rect rect;
  if (frame_connector_) {
    ApplicationWindowHostView* root_view =
        frame_connector_->GetRootApplicationWindowHostView();

    // The root_view can be null in tests when using a TestWebContents.
    if (root_view)
      rect = root_view->GetBoundsInRootWindow();
  }
  return rect;
}

void ApplicationWindowHostViewChildFrame::ProcessAckedTouchEvent(
    const common::TouchEventWithLatencyInfo& touch,
    common::InputEventAckState ack_result) {
  if (!frame_connector_)
    return;

  frame_connector_->ForwardProcessAckedTouchEvent(touch, ack_result);
}

void ApplicationWindowHostViewChildFrame::DidStopFlinging() {
  if (selection_controller_client_)
    selection_controller_client_->DidStopFlinging();
}

bool ApplicationWindowHostViewChildFrame::LockMouse() {
  if (frame_connector_)
    return frame_connector_->LockMouse();
  return false;
}

void ApplicationWindowHostViewChildFrame::UnlockMouse() {
  if (host()->delegate() && host()->delegate()->HasMouseLock(host()) &&
      frame_connector_)
    frame_connector_->UnlockMouse();
}

bool ApplicationWindowHostViewChildFrame::IsMouseLocked() {
  if (!host()->delegate())
    return false;

  return host()->delegate()->HasMouseLock(host());
}

viz::FrameSinkId ApplicationWindowHostViewChildFrame::GetFrameSinkId() {
  return frame_sink_id_;
}

viz::LocalSurfaceId ApplicationWindowHostViewChildFrame::GetLocalSurfaceId() const {
  if (frame_connector_)
    return frame_connector_->local_surface_id();
  return viz::LocalSurfaceId();
}

void ApplicationWindowHostViewChildFrame::PreProcessTouchEvent(
    const blink::WebTouchEvent& event) {
  if (event.GetType() == blink::WebInputEvent::kTouchStart &&
      frame_connector_ && !frame_connector_->HasFocus()) {
    frame_connector_->FocusRootView();
  }
}

viz::SurfaceId ApplicationWindowHostViewChildFrame::GetCurrentSurfaceId() const {
  return viz::SurfaceId(frame_sink_id_, last_received_local_surface_id_);
}

bool ApplicationWindowHostViewChildFrame::HasSize() const {
  return frame_connector_ && frame_connector_->has_size();
}

gfx::PointF ApplicationWindowHostViewChildFrame::TransformPointToRootCoordSpaceF(
    const gfx::PointF& point) {
  if (!frame_connector_ || !last_received_local_surface_id_.is_valid())
    return point;

  return frame_connector_->TransformPointToRootCoordSpace(
      point, viz::SurfaceId(frame_sink_id_, last_received_local_surface_id_));
}

bool ApplicationWindowHostViewChildFrame::TransformPointToLocalCoordSpace(
    const gfx::PointF& point,
    const viz::SurfaceId& original_surface,
    gfx::PointF* transformed_point) {
  *transformed_point = point;
  if (!frame_connector_ || !last_received_local_surface_id_.is_valid())
    return false;

  return frame_connector_->TransformPointToLocalCoordSpace(
      point, original_surface,
      viz::SurfaceId(frame_sink_id_, last_received_local_surface_id_),
      transformed_point);
}

bool ApplicationWindowHostViewChildFrame::TransformPointToCoordSpaceForView(
    const gfx::PointF& point,
    ApplicationWindowHostView* target_view,
    gfx::PointF* transformed_point) {
  if (!frame_connector_ || !last_received_local_surface_id_.is_valid())
    return false;

  if (target_view == this) {
    *transformed_point = point;
    return true;
  }

  return frame_connector_->TransformPointToCoordSpaceForView(
      point, target_view,
      viz::SurfaceId(frame_sink_id_, last_received_local_surface_id_),
      transformed_point);
}

gfx::PointF ApplicationWindowHostViewChildFrame::TransformRootPointToViewCoordSpace(
    const gfx::PointF& point) {
  if (!frame_connector_)
    return point;

  ApplicationWindowHostView* root_rwhv =
      frame_connector_->GetRootApplicationWindowHostView();
  if (!root_rwhv)
    return point;

  gfx::PointF transformed_point;
  if (!root_rwhv->TransformPointToCoordSpaceForView(point, this,
                                                    &transformed_point)) {
    return point;
  }
  return transformed_point;
}

bool ApplicationWindowHostViewChildFrame::IsApplicationWindowHostViewChildFrame() {
  return true;
}

void ApplicationWindowHostViewChildFrame::WillSendScreenRects() {
  // TODO(kenrb): These represent post-initialization state updates that are
  // needed by the renderer. During normal OOPIF setup these are unnecessary,
  // as the parent renderer will send the information and it will be
  // immediately propagated to the OOPIF. However when an OOPIF navigates from
  // one process to another, the parent doesn't know that, and certain
  // browser-side state needs to be sent again. There is probably a less
  // spammy way to do this, but triggering on SendScreenRects() is reasonable
  // until somebody figures that out. RWHVCF::Init() is too early.
  if (frame_connector_) {
    UpdateViewportIntersection(frame_connector_->viewport_intersection_rect(),
                               frame_connector_->compositor_visible_rect());
    SetIsInert();
    UpdateRenderThrottlingStatus();
  }
}

#if defined(OS_MACOSX)
void ApplicationWindowHostViewChildFrame::SetActive(bool active) {}

void ApplicationWindowHostViewChildFrame::ShowDefinitionForSelection() {
  if (frame_connector_) {
    frame_connector_->GetRootApplicationWindowHostView()
        ->ShowDefinitionForSelection();
  }
}

void ApplicationWindowHostViewChildFrame::SpeakSelection() {}
#endif  // defined(OS_MACOSX)

void ApplicationWindowHostViewChildFrame::RegisterFrameSwappedCallback(
    base::OnceClosure callback) {
  frame_swapped_callbacks_.emplace_back(std::move(callback));
}

void ApplicationWindowHostViewChildFrame::CopyFromSurface(
    const gfx::Rect& src_subrect,
    const gfx::Size& output_size,
    base::OnceCallback<void(const SkBitmap&)> callback) {
  // TODO(crbug.com/812059): Need a "copy from surface" VIZ API.
  if (enable_viz_) {
    std::move(callback).Run(SkBitmap());
    return;
  }

  if (!IsSurfaceAvailableForCopy()) {
    // Defer submitting the copy request until after a frame is drawn, at which
    // point we should be guaranteed that the surface is available.
    RegisterFrameSwappedCallback(base::BindOnce(
        &ApplicationWindowHostViewChildFrame::CopyFromSurface, AsWeakPtr(),
        src_subrect, output_size, std::move(callback)));
    return;
  }

  std::unique_ptr<viz::CopyOutputRequest> request =
      std::make_unique<viz::CopyOutputRequest>(
          viz::CopyOutputRequest::ResultFormat::RGBA_BITMAP,
          base::BindOnce(
              [](base::OnceCallback<void(const SkBitmap&)> callback,
                 std::unique_ptr<viz::CopyOutputResult> result) {
                std::move(callback).Run(result->AsSkBitmap());
              },
              std::move(callback)));

  if (src_subrect.IsEmpty()) {
    request->set_area(gfx::Rect(current_surface_size_));
  } else {
    // |src_subrect| is in DIP coordinates; convert to Surface coordinates.
    request->set_area(
        gfx::ScaleToRoundedRect(src_subrect, current_surface_scale_factor_));
  }

  if (!output_size.IsEmpty()) {
    request->set_result_selection(gfx::Rect(output_size));
    request->SetScaleRatio(
        gfx::Vector2d(request->area().width(), request->area().height()),
        gfx::Vector2d(output_size.width(), output_size.height()));
  }

  GetHostFrameSinkManager()->RequestCopyOfOutput(
      viz::SurfaceId(frame_sink_id_, last_received_local_surface_id_),
      std::move(request));
}

void ApplicationWindowHostViewChildFrame::ReclaimResources(
    const std::vector<viz::ReturnedResource>& resources) {
  if (renderer_compositor_frame_sink_)
    renderer_compositor_frame_sink_->ReclaimResources(resources);
}

void ApplicationWindowHostViewChildFrame::OnBeginFrame(
    const viz::BeginFrameArgs& args) {
  host_->ProgressFling(args.frame_time);
  if (renderer_compositor_frame_sink_)
    renderer_compositor_frame_sink_->OnBeginFrame(args);
}

void ApplicationWindowHostViewChildFrame::OnBeginFramePausedChanged(bool paused) {
  if (renderer_compositor_frame_sink_)
    renderer_compositor_frame_sink_->OnBeginFramePausedChanged(paused);
}

void ApplicationWindowHostViewChildFrame::OnFirstSurfaceActivation(
    const viz::SurfaceInfo& surface_info) {
  SendSurfaceInfoToEmbedderImpl(surface_info);
}

void ApplicationWindowHostViewChildFrame::OnFrameTokenChanged(uint32_t frame_token) {
  OnFrameTokenChangedForView(frame_token);
}

void ApplicationWindowHostViewChildFrame::SetNeedsBeginFrames(
    bool needs_begin_frames) {
  if (support_)
    support_->SetNeedsBeginFrame(needs_begin_frames);
}

TouchSelectionControllerClientManager*
ApplicationWindowHostViewChildFrame::GetTouchSelectionControllerClientManager() {
  auto* root_view = frame_connector_->GetRootApplicationWindowHostView();
  if (!root_view)
    return nullptr;

  // There is only ever one manager, and it's owned by the root view.
  return root_view->GetTouchSelectionControllerClientManager();
}

void ApplicationWindowHostViewChildFrame::OnRenderFrameMetadataChanged() {
  ApplicationWindowHostView::OnRenderFrameMetadataChanged();
  if (selection_controller_client_) {
    const cc::RenderFrameMetadata& metadata =
        host()->render_frame_metadata_provider()->LastRenderFrameMetadata();
    selection_controller_client_->UpdateSelectionBoundsIfNeeded(
        metadata.selection, current_device_scale_factor_);
  }
}

void ApplicationWindowHostViewChildFrame::SetWantsAnimateOnlyBeginFrames() {
  if (support_)
    support_->SetWantsAnimateOnlyBeginFrames();
}

void ApplicationWindowHostViewChildFrame::TakeFallbackContentFrom(
    ApplicationWindowHostView* view) {
  // This method only makes sense for top-level views.
}

common::InputEventAckState ApplicationWindowHostViewChildFrame::FilterInputEvent(
    const blink::WebInputEvent& input_event) {
  if (input_event.GetType() == blink::WebInputEvent::kGestureFlingStart) {
    const blink::WebGestureEvent& gesture_event =
        static_cast<const blink::WebGestureEvent&>(input_event);
    // Zero-velocity touchpad flings are an Aura-specific signal that the
    // touchpad scroll has ended, and should not be forwarded to the renderer.
    if (gesture_event.SourceDevice() == blink::kWebGestureDeviceTouchpad &&
        !gesture_event.data.fling_start.velocity_x &&
        !gesture_event.data.fling_start.velocity_y) {
      // Here we indicate that there was no consumer for this event, as
      // otherwise the fling animation system will try to run an animation
      // and will also expect a notification when the fling ends. Since
      // CrOS just uses the GestureFlingStart with zero-velocity as a means
      // of indicating that touchpad scroll has ended, we don't actually want
      // a fling animation.
      // Note: this event handling is modeled on similar code in
      // TenderWidgetHostViewAura::FilterInputEvent().
      return INPUT_EVENT_ACK_STATE_NO_CONSUMER_EXISTS;
    }
  }

  if (wheel_scroll_latching_enabled() && is_scroll_sequence_bubbling_ &&
      (input_event.GetType() == blink::WebInputEvent::kGestureScrollUpdate) &&
      frame_connector_) {
    // If we're bubbling, then to preserve latching behaviour, the child should
    // not consume this event. If the child has added its viewport to the scroll
    // chain, then any GSU events we send to the renderer could be consumed,
    // even though we intend for them to be bubbled. So we immediately bubble
    // any scroll updates without giving the child a chance to consume them.
    // If the child has not added its viewport to the scroll chain, then we
    // know that it will not attempt to consume the rest of the scroll
    // sequence.
    return INPUT_EVENT_ACK_STATE_NO_CONSUMER_EXISTS;
  }

  // Allow the root RWHV a chance to consume the child's GestureScrollUpdates
  // in case the root needs to prevent the child from scrolling. For example,
  // if the root has started an overscroll gesture, it needs to process the
  // scroll events that would normally be processed by the child.
  // TODO(mcnee): With scroll-latching enabled, the child would not scroll
  // in this case. Remove this once scroll-latching lands. crbug.com/751782
  if (!wheel_scroll_latching_enabled() && frame_connector_ &&
      input_event.GetType() == blink::WebInputEvent::kGestureScrollUpdate) {
    const blink::WebGestureEvent& gesture_event =
        static_cast<const blink::WebGestureEvent&>(input_event);
    return frame_connector_->GetRootApplicationWindowHostView()
        ->FilterChildGestureEvent(gesture_event);
  }

  return INPUT_EVENT_ACK_STATE_NOT_CONSUMED;
}

common::InputEventAckState ApplicationWindowHostViewChildFrame::FilterChildGestureEvent(
    const blink::WebGestureEvent& gesture_event) {
  // We may be the owner of a ApplicationWindowHostViewGuest,
  // so we talk to the root RWHV on its behalf.
  // TODO(mcnee): Remove once MimeHandlerViewGuest is based on OOPIF.
  // See crbug.com/659750
  if (frame_connector_)
    return frame_connector_->GetRootApplicationWindowHostView()
        ->FilterChildGestureEvent(gesture_event);
  return INPUT_EVENT_ACK_STATE_NOT_CONSUMED;
}

BrowserAccessibilityManager*
ApplicationWindowHostViewChildFrame::CreateAccessibilityManager(
    BrowserAccessibilityDelegate* delegate,
    bool for_root_frame) {
  return BrowserAccessibilityManager::Create(
      BrowserAccessibilityManager::GetEmptyDocument(), delegate);
}

void ApplicationWindowHostViewChildFrame::GetScreenInfo(
    ScreenInfo* screen_info) const {
  if (frame_connector_)
    *screen_info = frame_connector_->screen_info();
  else
    DisplayUtil::GetDefaultScreenInfo(screen_info);
}

void ApplicationWindowHostViewChildFrame::EnableAutoResize(
    const gfx::Size& min_size,
    const gfx::Size& max_size) {
  if (frame_connector_)
    frame_connector_->EnableAutoResize(min_size, max_size);
}

void ApplicationWindowHostViewChildFrame::DisableAutoResize(
    const gfx::Size& new_size) {
  // For child frames, the size comes from the parent when auto-resize is
  // disabled so we ignore |new_size| here.
  if (frame_connector_)
    frame_connector_->DisableAutoResize();
}

viz::ScopedSurfaceIdAllocator
ApplicationWindowHostViewChildFrame::ResizeDueToAutoResize(
    const gfx::Size& new_size,
    const viz::LocalSurfaceId& local_surface_id) {
  base::OnceCallback<void()> allocation_task = base::BindOnce(
      &ApplicationWindowHostViewChildFrame::OnResizeDueToAutoResizeComplete,
      weak_factory_.GetWeakPtr(), local_surface_id);
  return viz::ScopedSurfaceIdAllocator(std::move(allocation_task));
}

void ApplicationWindowHostViewChildFrame::CreateCompositorFrameSinkSupport() {
  if (base::FeatureList::IsEnabled(features::kMash) || enable_viz_)
    return;

  DCHECK(!support_);
  constexpr bool is_root = false;
  constexpr bool needs_sync_points = true;
  support_ = GetHostFrameSinkManager()->CreateCompositorFrameSinkSupport(
      this, frame_sink_id_, is_root, needs_sync_points);
  if (parent_frame_sink_id_.is_valid()) {
    GetHostFrameSinkManager()->RegisterFrameSinkHierarchy(parent_frame_sink_id_,
                                                          frame_sink_id_);
  }
  if (host()->needs_begin_frames())
    support_->SetNeedsBeginFrame(true);
}

void ApplicationWindowHostViewChildFrame::ResetCompositorFrameSinkSupport() {
  if (!support_)
    return;
  if (parent_frame_sink_id_.is_valid()) {
    GetHostFrameSinkManager()->UnregisterFrameSinkHierarchy(
        parent_frame_sink_id_, frame_sink_id_);
  }
  support_.reset();
}

bool ApplicationWindowHostViewChildFrame::HasEmbedderChanged() {
  return false;
}

bool ApplicationWindowHostViewChildFrame::GetSelectionRange(
    gfx::Range* range) const {
  if (!text_input_manager_ || !GetFocusedWidget())
    return false;

  const TextInputManager::TextSelection* selection =
      text_input_manager_->GetTextSelection(GetFocusedWidget()->GetView());
  if (!selection)
    return false;

  range->set_start(selection->range().start());
  range->set_end(selection->range().end());

  return true;
}

ui::TextInputType ApplicationWindowHostViewChildFrame::GetTextInputType() const {
  if (!text_input_manager_)
    return ui::TEXT_INPUT_TYPE_NONE;

  if (text_input_manager_->GetTextInputState())
    return text_input_manager_->GetTextInputState()->type;
  return ui::TEXT_INPUT_TYPE_NONE;
}

ApplicationWindowHostView*
ApplicationWindowHostViewChildFrame::GetRootApplicationWindowHostView() const {
  return frame_connector_ ? frame_connector_->GetRootApplicationWindowHostView()
                          : nullptr;
}

bool ApplicationWindowHostViewChildFrame::CanBecomeVisible() {
  if (!frame_connector_)
    return true;

  if (frame_connector_->IsHidden())
    return false;

  ApplicationWindowHostView* parent_view = GetParentView();
  if (!parent_view || !parent_view->IsApplicationWindowHostViewChildFrame()) {
    // Root frame does not have a CSS visibility property.
    return true;
  }

  return static_cast<ApplicationWindowHostViewChildFrame*>(parent_view)
      ->CanBecomeVisible();
}

void ApplicationWindowHostViewChildFrame::OnResizeDueToAutoResizeComplete(
    viz::LocalSurfaceId local_surface_id) {
  if (frame_connector_)
    frame_connector_->ResizeDueToAutoResize(local_surface_id);
}

void ApplicationWindowHostViewChildFrame::DidNavigate() {
  host()->SynchronizeVisualProperties();
}

}  // namespace host
