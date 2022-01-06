// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_window_host_view.h"

#include "base/bind.h"
#include "base/logging.h"
#include "base/unguessable_token.h"
#include "build/build_config.h"
#include "components/viz/host/host_frame_sink_manager.h"
#include "components/viz/service/frame_sinks/frame_sink_manager_impl.h"
#include "components/viz/service/surfaces/surface_hittest.h"
#include "core/host/accessibility/browser_accessibility_manager.h"
#include "core/host/compositor/surface_utils.h"
#include "core/host/gpu/gpu_data_manager_impl.h"
#include "core/host/application/display_util.h"
#include "core/host/application/input/synthetic_gesture_target_base.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_window_host_delegate.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view_observer.h"
#include "core/host/application/text_input_manager.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/content_features.h"
#include "ui/base/layout.h"
#include "ui/base/ui_base_types.h"
#include "ui/display/screen.h"
#include "ui/events/event.h"
#include "ui/gfx/geometry/dip_util.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/size_f.h"

#if defined(USE_AURA)
#include "base/unguessable_token.h"
#include "core/shared/common/application_window_tree_client_factory.mojom.h"
#endif

namespace host {

ApplicationWindowHostView::ApplicationWindowHostView(ApplicationWindowHost* host)
    : host_(host),
      is_fullscreen_(false),
      popup_type_(blink::kWebPopupTypeNone),
      current_device_scale_factor_(0),
      current_display_rotation_(display::Display::ROTATE_0),
      text_input_manager_(nullptr),
      wheel_scroll_latching_enabled_(base::FeatureList::IsEnabled(
          features::kTouchpadAndWheelScrollLatching)),
      web_contents_accessibility_(nullptr),
      is_currently_scrolling_viewport_(false),
      renderer_frame_number_(0),
      weak_factory_(this) {
  host_->render_frame_metadata_provider()->AddObserver(this);
}

ApplicationWindowHostView::~ApplicationWindowHostView() {
  DCHECK(!keyboard_locked_);
  DCHECK(!mouse_locked_);
  // We call this here to guarantee that observers are notified before we go
  // away. However, some subclasses may wish to call this earlier in their
  // shutdown process, e.g. to force removal from
  // ApplicationWindowHostInputEventRouter's surface map before relinquishing a
  // host pointer, as in ApplicationWindowHostViewGuest. There is no harm in calling
  // NotifyObserversAboutShutdown() twice, as the observers are required to
  // de-register on the first call, and so the second call does nothing.
  NotifyObserversAboutShutdown();
  // If we have a live reference to |text_input_manager_|, we should unregister
  // so that the |text_input_manager_| will free its state.
  if (text_input_manager_)
    text_input_manager_->Unregister(this);
  if (host_)
    host_->render_frame_metadata_provider()->RemoveObserver(this);
}

ApplicationWindowHost* ApplicationWindowHostView::GetFocusedWidget() const {
  return host();// && host()->delegate()
             //? host()->delegate()->GetFocusedApplicationWindowHost(host())
             //: nullptr;
}

ApplicationWindowHost* ApplicationWindowHostView::GetApplicationWindowHost() const {
  return host();
}

void ApplicationWindowHostView::NotifyObserversAboutShutdown() {
  // Note: ApplicationWindowHostInputEventRouter is an observer, and uses the
  // following notification to remove this view from its surface owners map.
  for (auto& observer : observers_)
    observer.OnApplicationWindowHostViewDestroyed(this);
  // All observers are required to disconnect after they are notified.
  DCHECK(!observers_.might_have_observers());
}

bool ApplicationWindowHostView::OnMessageReceived(const IPC::Message& msg){
  //DLOG(INFO) << "ApplicationWindowHostView::OnMessageReceived: theres nothing here";
  return false;
}

void ApplicationWindowHostView::OnRenderFrameMetadataChanged() {
  is_scroll_offset_at_top_ = host_->render_frame_metadata_provider()
                                 ->LastRenderFrameMetadata()
                                 .is_scroll_offset_at_top;
}

void ApplicationWindowHostView::OnRenderFrameSubmission() {
 
}

void ApplicationWindowHostView::SetBackgroundColor(SkColor color) {
  DCHECK(SkColorGetA(color) == SK_AlphaOPAQUE ||
         SkColorGetA(color) == SK_AlphaTRANSPARENT);
  if (default_background_color_ == color)
    return;

  bool opaque = default_background_color_
                    ? SkColorGetA(*default_background_color_)
                    : SK_AlphaOPAQUE;
  default_background_color_ = color;
  UpdateBackgroundColor();
  if (opaque != (SkColorGetA(color) == SK_AlphaOPAQUE))
    host()->SetBackgroundOpaque(SkColorGetA(color) == SK_AlphaOPAQUE);
}

base::Optional<SkColor> ApplicationWindowHostView::GetBackgroundColor() const {
  if (content_background_color_)
    return content_background_color_;
  return default_background_color_;
}

void ApplicationWindowHostView::SetContentBackgroundColor(SkColor color) {
  if (content_background_color_ == color)
    return;

  content_background_color_ = color;
  UpdateBackgroundColor();
}

//void ApplicationWindowHostView::SetBackgroundColorToDefault() {
//  SetBackgroundColor(SK_ColorTRANSPARENT);
//}

gfx::Size ApplicationWindowHostView::GetCompositorViewportPixelSize() const {
  return gfx::ScaleToCeiledSize(GetRequestedApplicationSize(),
                                GetDeviceScaleFactor());
}

bool ApplicationWindowHostView::DoBrowserControlsShrinkBlinkSize() const {
  return false;
}

float ApplicationWindowHostView::GetTopControlsHeight() const {
  return 0.f;
}

void ApplicationWindowHostView::SelectionBoundsChanged(
    common::mojom::SelectionBoundsParamsPtr params) {
#if !defined(OS_ANDROID)
  if (GetTextInputManager())
    GetTextInputManager()->SelectionBoundsChanged(this, std::move(params));
#else
  NOTREACHED() << "Selection bounds should be routed through the compositor.";
#endif
}

float ApplicationWindowHostView::GetBottomControlsHeight() const {
  return 0.f;
}

int ApplicationWindowHostView::GetMouseWheelMinimumGranularity() const {
  // Most platforms can specify the floating-point delta in the wheel event so
  // they don't have a minimum granularity. Android is currently the only
  // platform that overrides this.
  return 0;
}

void ApplicationWindowHostView::SelectionChanged(const base::string16& text,
                                                size_t offset,
                                                const gfx::Range& range) {
  if (GetTextInputManager())
    GetTextInputManager()->SelectionChanged(this, text, offset, range);
}

gfx::Size ApplicationWindowHostView::GetRequestedApplicationSize() const {
  return GetViewBounds().size();
}

uint32_t ApplicationWindowHostView::GetCaptureSequenceNumber() const {
  // TODO(vmpstr): Implement this for overrides other than aura and child frame.
  NOTIMPLEMENTED_LOG_ONCE();
  return 0u;
}

ui::TextInputClient* ApplicationWindowHostView::GetTextInputClient() {
  NOTREACHED();
  return nullptr;
}

void ApplicationWindowHostView::SetIsInVR(bool is_in_vr) {
  NOTIMPLEMENTED_LOG_ONCE();
}

bool ApplicationWindowHostView::IsInVR() const {
  return false;
}

viz::FrameSinkId ApplicationWindowHostView::GetRootFrameSinkId() {
  return viz::FrameSinkId();
}

bool ApplicationWindowHostView::IsSurfaceAvailableForCopy() const {
  return false;
}

void ApplicationWindowHostView::CopyFromSurface(
    const gfx::Rect& src_rect,
    const gfx::Size& output_size,
    base::OnceCallback<void(const SkBitmap&)> callback) {
  NOTIMPLEMENTED_LOG_ONCE();
  std::move(callback).Run(SkBitmap());
}

viz::mojom::FrameSinkVideoCapturerPtr
ApplicationWindowHostView::CreateVideoCapturer() {
  viz::mojom::FrameSinkVideoCapturerPtr video_capturer;
  GetHostFrameSinkManager()->CreateVideoCapturer(
      mojo::MakeRequest(&video_capturer));
  video_capturer->ChangeTarget(GetFrameSinkId());
  return video_capturer;
}

base::string16 ApplicationWindowHostView::GetSelectedText() {
  if (!GetTextInputManager())
    return base::string16();
  return GetTextInputManager()->GetTextSelection(this)->selected_text();
}

bool ApplicationWindowHostView::IsMouseLocked() {
  return mouse_locked_;
}

bool ApplicationWindowHostView::LockKeyboard(
    base::Optional<base::flat_set<int>> keys) {
  NOTIMPLEMENTED_LOG_ONCE();
  return false;
}

void ApplicationWindowHostView::UnlockKeyboard() {
  NOTIMPLEMENTED_LOG_ONCE();
}

bool ApplicationWindowHostView::IsKeyboardLocked() {
  return keyboard_locked_;
}

common::InputEventAckState ApplicationWindowHostView::FilterInputEvent(
    const blink::WebInputEvent& input_event) {
  // By default, input events are simply forwarded to the renderer.
  //DLOG(INFO) << "ApplicationWindowHostView::FilterInputEvent";
  return common::INPUT_EVENT_ACK_STATE_NOT_CONSUMED;
}

common::InputEventAckState ApplicationWindowHostView::FilterChildGestureEvent(
    const blink::WebGestureEvent& gesture_event) {
  // By default, do nothing with the child's gesture events.
  return common::INPUT_EVENT_ACK_STATE_NOT_CONSUMED;
}

void ApplicationWindowHostView::WheelEventAck(
    const blink::WebMouseWheelEvent& event,
    common::InputEventAckState ack_result) {
}

void ApplicationWindowHostView::GestureEventAck(
    const blink::WebGestureEvent& event,
    common::InputEventAckState ack_result) {
}

void ApplicationWindowHostView::SetPopupType(blink::WebPopupType popup_type) {
  popup_type_ = popup_type;
}

blink::WebPopupType ApplicationWindowHostView::GetPopupType() {
  return popup_type_;
}

//BrowserAccessibilityManager*
//ApplicationWindowHostView::CreateAccessibilityManager(
    //BrowserAccessibilityDelegate* delegate, bool for_root_frame) {
  //NOTREACHED();
  //return nullptr;
//}

void ApplicationWindowHostView::AccessibilityShowMenu(const gfx::Point& point) {
  if (host())
    host()->ShowContextMenuAtPoint(point, ui::MENU_SOURCE_NONE);
}

gfx::Point ApplicationWindowHostView::AccessibilityOriginInScreen(
    const gfx::Rect& bounds) {
  return bounds.origin();
}

gfx::AcceleratedWidget
    ApplicationWindowHostView::AccessibilityGetAcceleratedWidget() {
  return gfx::kNullAcceleratedWidget;
}

gfx::NativeViewAccessible
    ApplicationWindowHostView::AccessibilityGetNativeViewAccessible() {
  return nullptr;
}

void ApplicationWindowHostView::UpdateScreenInfo(gfx::NativeView view) {
  if (host() && host()->delegate())
    host()->delegate()->SendScreenRects();

  if (HasDisplayPropertyChanged(view) && host()) {
    OnSynchronizedDisplayPropertiesChanged();
    host()->NotifyScreenInfoChanged();
  }
}

bool ApplicationWindowHostView::HasDisplayPropertyChanged(gfx::NativeView view) {
  display::Display display =
      display::Screen::GetScreen()->GetDisplayNearestView(view);
  if (current_display_area_ == display.work_area() &&
      current_device_scale_factor_ == display.device_scale_factor() &&
      current_display_rotation_ == display.rotation() &&
      current_display_color_space_ == display.color_space()) {
    return false;
  }

  current_display_area_ = display.work_area();
  current_device_scale_factor_ = display.device_scale_factor();
  current_display_rotation_ = display.rotation();
  current_display_color_space_ = display.color_space();
  return true;
}

void ApplicationWindowHostView::DidUnregisterFromTextInputManager(
    TextInputManager* text_input_manager) {
  DCHECK(text_input_manager && text_input_manager_ == text_input_manager);

  text_input_manager_ = nullptr;
}

void ApplicationWindowHostView::EnableAutoResize(const gfx::Size& min_size,
                                                const gfx::Size& max_size) {
  host()->SetAutoResize(true, min_size, max_size);
  host()->SynchronizeVisualProperties();
}

void ApplicationWindowHostView::DisableAutoResize(const gfx::Size& new_size) {
  if (!new_size.IsEmpty())
    SetSize(new_size);
  // This clears the cached value in the WebContents, so that OOPIFs will
  // stop using it.
  if (host()->delegate())
    host()->delegate()->ResetAutoResizeSize();
  host()->SetAutoResize(false, gfx::Size(), gfx::Size());
  host()->SynchronizeVisualProperties();
}

bool ApplicationWindowHostView::IsScrollOffsetAtTop() const {
  return is_scroll_offset_at_top_;
}

viz::ScopedSurfaceIdAllocator ApplicationWindowHostView::ResizeDueToAutoResize(
    const gfx::Size& new_size,
    const viz::LocalSurfaceId& local_surface_id) {
  // This doesn't suppress allocation. Derived classes that need suppression
  // should override this function.
  return viz::ScopedSurfaceIdAllocator(base::DoNothing());
}

bool ApplicationWindowHostView::IsLocalSurfaceIdAllocationSuppressed() const {
  return false;
}

base::WeakPtr<ApplicationWindowHostView> ApplicationWindowHostView::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

std::unique_ptr<SyntheticGestureTarget>
ApplicationWindowHostView::CreateSyntheticGestureTarget() {
  return std::unique_ptr<SyntheticGestureTarget>(
      new SyntheticGestureTargetBase(host()));
}

void ApplicationWindowHostView::FocusedNodeTouched(
    bool editable) {
  DVLOG(1) << "FocusedNodeTouched: " << editable;
}

void ApplicationWindowHostView::GetScreenInfo(common::ScreenInfo* screen_info) const {
  DisplayUtil::GetNativeViewScreenInfo(screen_info, GetNativeView());
}

float ApplicationWindowHostView::GetDeviceScaleFactor() const {
  common::ScreenInfo screen_info;
  GetScreenInfo(&screen_info);
  return screen_info.device_scale_factor;
}

uint32_t ApplicationWindowHostView::ApplicationFrameNumber() {
  return renderer_frame_number_;
}

void ApplicationWindowHostView::DidReceiveApplicationFrame() {
  ++renderer_frame_number_;
}

void ApplicationWindowHostView::ShowDisambiguationPopup(
    const gfx::Rect& rect_pixels,
    const SkBitmap& zoomed_bitmap) {
  NOTIMPLEMENTED_LOG_ONCE();
}

gfx::Size ApplicationWindowHostView::GetVisibleViewportSize() const {
  return GetViewBounds().size();
}

void ApplicationWindowHostView::SetInsets(const gfx::Insets& insets) {
  NOTIMPLEMENTED_LOG_ONCE();
}

void ApplicationWindowHostView::DisplayCursor(const common::WebCursor& cursor) {
  return;
}

CursorManager* ApplicationWindowHostView::GetCursorManager() {
  return nullptr;
}

void ApplicationWindowHostView::OnDidNavigateMainFrameToNewPage() {
}

void ApplicationWindowHostView::OnFrameTokenChangedForView(
    uint32_t frame_token) {
  if (host())
    host()->DidProcessFrame(frame_token);
}

viz::FrameSinkId ApplicationWindowHostView::GetFrameSinkId() {
  return viz::FrameSinkId();
}

viz::LocalSurfaceId ApplicationWindowHostView::GetLocalSurfaceId() const {
  return viz::LocalSurfaceId();
}

viz::FrameSinkId ApplicationWindowHostView::FrameSinkIdAtPoint(
    viz::SurfaceHittestDelegate* delegate,
    const gfx::PointF& point,
    gfx::PointF* transformed_point,
    bool* out_query_renderer) {
  float device_scale_factor = ui::GetScaleFactorForNativeView(GetNativeView());
  DCHECK(device_scale_factor != 0.0f);

  // The surface hittest happens in device pixels, so we need to convert the
  // |point| from DIPs to pixels before hittesting.
  gfx::PointF point_in_pixels =
      gfx::ConvertPointToPixel(device_scale_factor, point);
  viz::SurfaceId surface_id = GetCurrentSurfaceId();
  if (!surface_id.is_valid()) {
    return GetFrameSinkId();
  }
  viz::SurfaceHittest hittest(delegate,
                              GetFrameSinkManager()->surface_manager());
  gfx::Transform target_transform;
  viz::SurfaceId target_local_surface_id = hittest.GetTargetSurfaceAtPoint(
      surface_id, gfx::ToFlooredPoint(point_in_pixels), &target_transform,
      out_query_renderer);
  *transformed_point = point_in_pixels;
  if (target_local_surface_id.is_valid()) {
    target_transform.TransformPoint(transformed_point);
  }
  *transformed_point =
      gfx::ConvertPointToDIP(device_scale_factor, *transformed_point);
  // It is possible that the renderer has not yet produced a surface, in which
  // case we return our current FrameSinkId.
  auto frame_sink_id = target_local_surface_id.frame_sink_id();
  return frame_sink_id.is_valid() ? frame_sink_id : GetFrameSinkId();
}

void ApplicationWindowHostView::ProcessMouseEvent(
    const blink::WebMouseEvent& event,
    const ui::LatencyInfo& latency) {
  PreProcessMouseEvent(event);
  host()->ForwardMouseEventWithLatencyInfo(event, latency);
}

void ApplicationWindowHostView::ProcessMouseWheelEvent(
    const blink::WebMouseWheelEvent& event,
    const ui::LatencyInfo& latency) {
  host()->ForwardWheelEventWithLatencyInfo(event, latency);
}

void ApplicationWindowHostView::ProcessTouchEvent(
    const blink::WebTouchEvent& event,
    const ui::LatencyInfo& latency) {
  PreProcessTouchEvent(event);
  host()->ForwardTouchEventWithLatencyInfo(event, latency);
}

void ApplicationWindowHostView::ProcessGestureEvent(
    const blink::WebGestureEvent& event,
    const ui::LatencyInfo& latency) {
  host()->ForwardGestureEventWithLatencyInfo(event, latency);
}

gfx::PointF ApplicationWindowHostView::TransformPointToRootCoordSpaceF(
    const gfx::PointF& point) {
  return point;
}

gfx::PointF ApplicationWindowHostView::TransformRootPointToViewCoordSpace(
    const gfx::PointF& point) {
  return point;
}

bool ApplicationWindowHostView::TransformPointToLocalCoordSpace(
    const gfx::PointF& point,
    const viz::SurfaceId& original_surface,
    gfx::PointF* transformed_point) {
  *transformed_point = point;
  return true;
}

bool ApplicationWindowHostView::TransformPointToCoordSpaceForView(
    const gfx::PointF& point,
    ApplicationWindowHostView* target_view,
    gfx::PointF* transformed_point) {
  NOTREACHED();
  return true;
}

bool ApplicationWindowHostView::IsApplicationWindowHostViewGuest() {
  return false;
}

bool ApplicationWindowHostView::IsApplicationWindowHostViewChildFrame() {
  return false;
}

bool ApplicationWindowHostView::HasSize() const {
  return true;
}

void ApplicationWindowHostView::Destroy() {
  if (host_) {
    host_->render_frame_metadata_provider()->RemoveObserver(this);
    host_ = nullptr;
  }
}

void ApplicationWindowHostView::TextInputStateChanged(
    const common::TextInputState& text_input_state) {
  if (GetTextInputManager()) {
    ////DLOG(INFO) << "ApplicationWindowHostView::TextInputStateChanged: TextInputManager()->UpdateTextInputState(" << text_input_state.value << ")";
    GetTextInputManager()->UpdateTextInputState(this, text_input_state);
  } else {
    //DLOG(INFO) << "ApplicationWindowHostView::TextInputStateChanged: BAD. no TextInputManager :(";
  }
}

void ApplicationWindowHostView::ImeCancelComposition() {
  if (GetTextInputManager())
    GetTextInputManager()->ImeCancelComposition(this);
}

void ApplicationWindowHostView::ImeCompositionRangeChanged(
    const gfx::Range& range,
    const std::vector<gfx::Rect>& character_bounds) {
  if (GetTextInputManager()) {
    GetTextInputManager()->ImeCompositionRangeChanged(this, range,
                                                      character_bounds);
  }
}

TextInputManager* ApplicationWindowHostView::GetTextInputManager() {
  if (text_input_manager_)
    return text_input_manager_;

  if (!host() || !host()->delegate())
    return nullptr;

  // This RWHV needs to be registered with the TextInputManager so that the
  // TextInputManager starts tracking its state, and observing its lifetime.
  text_input_manager_ = host()->delegate()->GetTextInputManager();
  if (text_input_manager_)
    text_input_manager_->Register(this);

  return text_input_manager_;
}

void ApplicationWindowHostView::AddObserver(
    ApplicationWindowHostViewObserver* observer) {
  observers_.AddObserver(observer);
}

void ApplicationWindowHostView::RemoveObserver(
    ApplicationWindowHostViewObserver* observer) {
  observers_.RemoveObserver(observer);
}

TouchSelectionControllerClientManager*
ApplicationWindowHostView::GetTouchSelectionControllerClientManager() {
  return nullptr;
}

#if defined(USE_AURA)
void ApplicationWindowHostView::EmbedChildFrameRendererWindowTreeClient(
    ApplicationWindowHostView* root_view,
    int routing_id,
    ui::mojom::WindowTreeClientPtr app_window_tree_client) {
  ApplicationWindowHost* application_window_host = GetApplicationWindowHost();
  if (!application_window_host)
    return;
  const int embed_id = ++next_embed_id_;
  pending_embeds_[routing_id] = embed_id;
  root_view->ScheduleEmbed(
      std::move(app_window_tree_client),
      base::BindOnce(&ApplicationWindowHostView::OnDidScheduleEmbed,
                     GetWeakPtr(), routing_id, embed_id));
}

void ApplicationWindowHostView::OnChildFrameDestroyed(int routing_id) {
  pending_embeds_.erase(routing_id);
  // Tests may not create |render_widget_window_tree_client_| (tests don't
  // necessarily create ApplicationWindowHostViewAura).
  if (application_window_tree_client_)
    application_window_tree_client_->DestroyFrame(routing_id);
}
#endif

#if defined(USE_AURA)
void ApplicationWindowHostView::OnDidScheduleEmbed(
    int routing_id,
    int embed_id,
    const base::UnguessableToken& token) {
  auto iter = pending_embeds_.find(routing_id);
  if (iter == pending_embeds_.end() || iter->second != embed_id)
    return;
  pending_embeds_.erase(iter);
  // Tests may not create |render_widget_window_tree_client_| (tests don't
  // necessarily create ApplicationWindowHostViewAura).
  if (application_window_tree_client_)
    application_window_tree_client_->Embed(routing_id, token);
}

void ApplicationWindowHostView::ScheduleEmbed(
    ui::mojom::WindowTreeClientPtr client,
    base::OnceCallback<void(const base::UnguessableToken&)> callback) {
  NOTREACHED();
}

ui::mojom::WindowTreeClientPtr
ApplicationWindowHostView::GetWindowTreeClientFromRenderer() {
  // NOTE: this function may be called multiple times.
  ApplicationWindowHost* application_window_host = GetApplicationWindowHost();
  common::mojom::ApplicationWindowTreeClientFactoryPtr factory;
  common::BindInterface(application_window_host->GetProcess(), &factory);

  ui::mojom::WindowTreeClientPtr window_tree_client;
  factory->CreateWindowTreeClientForApplicationWindow(
      application_window_host->GetRoutingID(),
      mojo::MakeRequest(&window_tree_client),
      mojo::MakeRequest(&application_window_tree_client_));
  return window_tree_client;
}

#endif

#if defined(OS_MACOSX)
bool ApplicationWindowHostView::ShouldContinueToPauseForFrame() {
  return false;
}
#endif

void ApplicationWindowHostView::DidNavigate() {
  if (host())
    host()->SynchronizeVisualProperties();
}

}  // namespace host
