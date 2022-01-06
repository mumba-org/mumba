// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_window_host_view_mac.h"

#import <Carbon/Carbon.h>

#include <limits>
#include <utility>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/mac/mac_util.h"
#include "base/mac/scoped_cftyperef.h"
#include "base/macros.h"
#include "base/strings/sys_string_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "core/host/accessibility/browser_accessibility_manager_mac.h"
#include "core/host/application/cursor_manager.h"
#import "core/host/renderer_host/input/synthetic_gesture_target_mac.h"
#include "core/host/application/input/web_input_event_builders_mac.h"
#include "core/host/application/application_window_host_delegate.h"
#include "core/host/application/application_window_host_impl.h"
#include "core/host/application/render_widget_helper.h"
#include "core/host/application/application_window_host_input_event_router.h"
#import "core/host/renderer_host/application_window_host_ns_view_bridge.h"
#import "core/host/renderer_host/application_window_host_view_cocoa.h"
#import "core/host/renderer_host/text_input_client_mac.h"
#include "core/common/text_input_state.h"
#include "core/common/view_messages.h"
#include "core/host/application_contents.h"
#include "core/host/browser_plugin_guest_manager.h"
#include "core/host/application/native_web_keyboard_event.h"
#include "core/host/application_window_host.h"
#include "core/host/web_contents.h"
#include "skia/ext/platform_canvas.h"
#include "skia/ext/skia_utils_mac.h"
#include "third_party/blink/public/platform/web_input_event.h"
#import "ui/base/clipboard/clipboard_util_mac.h"
#include "ui/base/cocoa/animation_utils.h"
#include "ui/base/cocoa/cocoa_base_utils.h"
#import "ui/base/cocoa/secure_password_input.h"
#include "ui/base/cocoa/text_services_context_menu.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "ui/gfx/geometry/dip_util.h"
#include "ui/gfx/mac/coordinate_conversion.h"
#include "ui/gl/gl_switches.h"

using blink::WebInputEvent;
using blink::WebMouseEvent;
using blink::WebGestureEvent;

namespace host {

////////////////////////////////////////////////////////////////////////////////
// BrowserCompositorMacClient, public:

SkColor ApplicationWindowHostViewMac::BrowserCompositorMacGetGutterColor() const {
  // When making an element on the page fullscreen the element's background
  // may not match the page's, so use black as the gutter color to avoid
  // flashes of brighter colors during the transition.
  if (host()->delegate() && host()->delegate()->IsFullscreenForCurrentTab()) {
    return SK_ColorBLACK;
  }
  return last_frame_root_background_color_;
}

void ApplicationWindowHostViewMac::BrowserCompositorMacOnBeginFrame(
    base::TimeTicks frame_time) {
  // ProgressFling must get called for middle click autoscroll fling on Mac.
  if (host())
    host()->ProgressFling(frame_time);
  UpdateNeedsBeginFramesInternal();
}

void ApplicationWindowHostViewMac::OnFrameTokenChanged(uint32_t frame_token) {
  OnFrameTokenChangedForView(frame_token);
}

void ApplicationWindowHostViewMac::DidReceiveFirstFrameAfterNavigation() {
  host()->DidReceiveFirstFrameAfterNavigation();
}

void ApplicationWindowHostViewMac::DestroyCompositorForShutdown() {
  // When ApplicationWindowHostViewMac was owned by an NSView, this function was
  // necessary to ensure that the ui::Compositor did not outlive the
  // infrastructure that was needed to support it.
  // https://crbug.com/805726
  Destroy();
}

void ApplicationWindowHostViewMac::SynchronizeVisualProperties() {
  host()->SynchronizeVisualProperties();
}

////////////////////////////////////////////////////////////////////////////////
// AcceleratedWidgetMacNSView, public:

NSView* ApplicationWindowHostViewMac::AcceleratedWidgetGetNSView() const {
  return cocoa_view();
}

void ApplicationWindowHostViewMac::AcceleratedWidgetGetVSyncParameters(
    base::TimeTicks* timebase, base::TimeDelta* interval) const {
  if (display_link_ &&
      display_link_->GetVSyncParameters(timebase, interval))
    return;
  *timebase = base::TimeTicks();
  *interval = base::TimeDelta();
}

void ApplicationWindowHostViewMac::AcceleratedWidgetSwapCompleted() {
  // Set the background color for the root layer from the frame that just
  // swapped. See ApplicationWindowHostViewAura for more details. Note that this is
  // done only after the swap has completed, so that the background is not set
  // before the frame is up.
  SetBackgroundLayerColor(last_frame_root_background_color_);

  if (display_link_)
    display_link_->NotifyCurrentTime(base::TimeTicks::Now());
}

///////////////////////////////////////////////////////////////////////////////
// ApplicationWindowHostViewMac, public:

ApplicationWindowHostViewMac::ApplicationWindowHostViewMac(ApplicationWindowHost* widget,
                                                 bool is_guest_view_hack)
    : ApplicationWindowHostView(widget),
      page_at_minimum_scale_(true),
      mouse_wheel_phase_handler_(this),
      is_loading_(false),
      allow_pause_for_resize_or_repaint_(true),
      is_guest_view_hack_(is_guest_view_hack),
      weak_factory_(this) {
  // The NSView is on the other side of |ns_view_bridge_|.
  ns_view_bridge_ = ApplicationWindowHostNSViewBridge::Create(this);

  // Guess that the initial screen we will be on is the screen of the current
  // window (since that's the best guess that we have, and is usually right).
  // https://crbug.com/357443
  display_ =
      display::Screen::GetScreen()->GetDisplayNearestWindow([NSApp keyWindow]);

  viz::FrameSinkId frame_sink_id = is_guest_view_hack_
                                       ? AllocateFrameSinkIdForGuestViewHack()
                                       : host()->GetFrameSinkId();

  browser_compositor_.reset(
      new BrowserCompositorMac(this, this, host()->is_hidden(),
                               [cocoa_view() window], display_, frame_sink_id));

  if (!is_guest_view_hack_)
    host()->SetView(this);

  // Let the page-level input event router know about our surface ID
  // namespace for surface-based hit testing.
  if (host()->delegate() && host()->delegate()->GetInputEventRouter()) {
    host()->delegate()->GetInputEventRouter()->AddFrameSinkIdOwner(
        GetFrameSinkId(), this);
  }

  RenderViewHost* rvh = RenderViewHost::From(host());
  bool needs_begin_frames = true;

  if (rvh) {
    // TODO(mostynb): actually use prefs.  Landing this as a separate CL
    // first to rebaseline some unreliable layout tests.
    ignore_result(rvh->GetWebkitPreferences());
    needs_begin_frames = !rvh->GetDelegate()->IsNeverVisible();
  }

  cursor_manager_.reset(new CursorManager(this));

  if (GetTextInputManager())
    GetTextInputManager()->AddObserver(this);

  // Because of the way Mac pumps messages during resize, SetNeedsBeginFrame
  // messages are not delayed on Mac.  This leads to creation-time raciness
  // where renderer sends a SetNeedsBeginFrame(true) before the renderer host is
  // created to receive it.
  //
  // Any renderer that will produce frames needs to have begin frames sent to
  // it. So unless it is never visible, start this value at true here to avoid
  // startup raciness and decrease latency.
  needs_begin_frames_ = needs_begin_frames;
  UpdateNeedsBeginFramesInternal();
}

ApplicationWindowHostViewMac::~ApplicationWindowHostViewMac() {
}

ApplicationWindowHostViewCocoa* ApplicationWindowHostViewMac::cocoa_view() const {
  return ns_view_bridge_->GetApplicationWindowHostViewCocoa();
}

void ApplicationWindowHostViewMac::SetDelegate(
    NSObject<ApplicationWindowHostViewMacDelegate>* delegate) {
  [cocoa_view() setResponderDelegate:delegate];
}

void ApplicationWindowHostViewMac::SetAllowPauseForResizeOrRepaint(bool allow) {
  allow_pause_for_resize_or_repaint_ = allow;
}

ui::TextInputType ApplicationWindowHostViewMac::GetTextInputType() {
  if (!GetActiveWidget())
    return ui::TEXT_INPUT_TYPE_NONE;
  return text_input_manager_->GetTextInputState()->type;
}

ApplicationWindowHost* ApplicationWindowHostViewMac::GetActiveWidget() {
  return text_input_manager_ ? text_input_manager_->GetActiveWidget() : nullptr;
}

const TextInputManager::CompositionRangeInfo*
ApplicationWindowHostViewMac::GetCompositionRangeInfo() {
  return text_input_manager_ ? text_input_manager_->GetCompositionRangeInfo()
                             : nullptr;
}

const TextInputManager::TextSelection*
ApplicationWindowHostViewMac::GetTextSelection() {
  return text_input_manager_ ? text_input_manager_->GetTextSelection(
                                   GetFocusedViewForTextSelection())
                             : nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// ApplicationWindowHostViewMac, ApplicationWindowHostView implementation:

void ApplicationWindowHostViewMac::InitAsChild(
    gfx::NativeView parent_view) {
}

void ApplicationWindowHostViewMac::InitAsPopup(
    ApplicationWindowHostView* parent_host_view,
    const gfx::Rect& pos) {
  // This path is used by the time/date picker.
  ns_view_bridge_->InitAsPopup(pos, popup_type_);
}

void ApplicationWindowHostViewMac::InitAsFullscreen(
    ApplicationWindowHostView* reference_host_view) {
  // This path appears never to be reached.
  NOTREACHED();
}

void ApplicationWindowHostViewMac::UpdateDisplayVSyncParameters() {
  if (!host() || !display_link_.get())
    return;

  if (!display_link_->GetVSyncParameters(&vsync_timebase_, &vsync_interval_)) {
    vsync_timebase_ = base::TimeTicks();
    vsync_interval_ = base::TimeDelta();
    return;
  }

  browser_compositor_->UpdateVSyncParameters(vsync_timebase_, vsync_interval_);
}

ApplicationWindowHostView*
    ApplicationWindowHostViewMac::GetFocusedViewForTextSelection() {
  // We obtain the TextSelection from focused RWH which is obtained from the
  // frame tree. BrowserPlugin-based guests' RWH is not part of the frame tree
  // and the focused RWH will be that of the embedder which is incorrect. In
  // this case we should use TextSelection for |this| since RWHV for guest
  // forwards text selection information to its platform view.
  return is_guest_view_hack_ ? this : GetFocusedWidget()
                                          ? GetFocusedWidget()->GetView()
                                          : nullptr;
}

ApplicationWindowHostDelegate*
ApplicationWindowHostViewMac::GetFocusedApplicationWindowHostDelegate() {
  if (auto* focused_widget = GetFocusedWidget())
    return focused_widget->delegate();
  return host()->delegate();
}

ApplicationWindowHost* ApplicationWindowHostViewMac::GetWidgetForKeyboardEvent() {
  DCHECK(in_keyboard_event_);
  return ApplicationWindowHost::FromID(keyboard_event_widget_process_id_,
                                      keyboard_event_widget_routing_id_);
}

ApplicationWindowHost* ApplicationWindowHostViewMac::GetWidgetForIme() {
  if (in_keyboard_event_)
    return GetWidgetForKeyboardEvent();
  return GetActiveWidget();
}

void ApplicationWindowHostViewMac::UpdateNSViewAndDisplayProperties() {
  static bool is_vsync_disabled =
      base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kDisableGpuVsync);
  if (!is_vsync_disabled) {
    display_link_ = ui::DisplayLinkMac::GetForDisplay(display_.id());
    if (!display_link_.get()) {
      // Note that on some headless systems, the display link will fail to be
      // created, so this should not be a fatal error.
      LOG(ERROR) << "Failed to create display link.";
    }
  }

  // During auto-resize it is the responsibility of the caller to ensure that
  // the NSView and ApplicationWindowHost are kept in sync.
  if (host()->auto_resize_enabled())
    return;

  if (host()->delegate())
    host()->delegate()->SendScreenRects();
  else
    host()->SendScreenRects();

  // ApplicationWindowHost will query BrowserCompositorMac for the dimensions
  // to send to the renderer, so it is required that BrowserCompositorMac be
  // updated first. Only notify ApplicationWindowHost of the update if any
  // properties it will query have changed.
  if (browser_compositor_->UpdateNSViewAndDisplay(
          view_bounds_in_window_dip_.size(), display_)) {
    host()->NotifyScreenInfoChanged();
  }
}

void ApplicationWindowHostViewMac::GetScreenInfo(ScreenInfo* screen_info) const {
  browser_compositor_->GetRendererScreenInfo(screen_info);
}

void ApplicationWindowHostViewMac::Show() {
  is_visible_ = true;
  ns_view_bridge_->SetVisible(is_visible_);
  browser_compositor_->SetApplicationWindowHostIsHidden(false);

  ui::LatencyInfo renderer_latency_info;
  renderer_latency_info.AddLatencyNumber(ui::TAB_SHOW_COMPONENT,
                                         host()->GetLatencyComponentId(), 0);
  renderer_latency_info.set_trace_id(++tab_show_sequence_);
  host()->WasShown(renderer_latency_info);
  TRACE_EVENT_ASYNC_BEGIN0("latency", "TabSwitching::Latency",
                           tab_show_sequence_);

  // If there is not a frame being currently drawn, kick one, so that the below
  // pause will have a frame to wait on.
  host()->ScheduleComposite();
  PauseForPendingResizeOrRepaintsAndDraw();
}

void ApplicationWindowHostViewMac::Hide() {
  is_visible_ = false;
  ns_view_bridge_->SetVisible(is_visible_);
  host()->WasHidden();
  browser_compositor_->SetApplicationWindowHostIsHidden(true);
}

void ApplicationWindowHostViewMac::WasUnOccluded() {
  browser_compositor_->SetApplicationWindowHostIsHidden(false);
  host()->WasShown(ui::LatencyInfo());
}

void ApplicationWindowHostViewMac::WasOccluded() {
  host()->WasHidden();
  browser_compositor_->SetApplicationWindowHostIsHidden(true);
}

void ApplicationWindowHostViewMac::SetSize(const gfx::Size& size) {
  gfx::Rect rect = GetViewBounds();
  rect.set_size(size);
  SetBounds(rect);
}

void ApplicationWindowHostViewMac::SetBounds(const gfx::Rect& rect) {
  ns_view_bridge_->SetBounds(rect);
}

gfx::NativeView ApplicationWindowHostViewMac::GetNativeView() const {
  return cocoa_view();
}

gfx::NativeViewAccessible ApplicationWindowHostViewMac::GetNativeViewAccessible() {
  return cocoa_view();
}

void ApplicationWindowHostViewMac::Focus() {
  ns_view_bridge_->MakeFirstResponder();
}

bool ApplicationWindowHostViewMac::HasFocus() const {
  return is_first_responder_;
}

bool ApplicationWindowHostViewMac::IsSurfaceAvailableForCopy() const {
  return browser_compositor_->GetDelegatedFrameHost()
      ->CanCopyFromCompositingSurface();
}

bool ApplicationWindowHostViewMac::IsShowing() {
  return is_visible_;
}

gfx::Rect ApplicationWindowHostViewMac::GetViewBounds() const {
  return view_bounds_in_window_dip_ +
         window_frame_in_screen_dip_.OffsetFromOrigin();
}

void ApplicationWindowHostViewMac::UpdateCursor(const WebCursor& cursor) {
  GetCursorManager()->UpdateCursor(this, cursor);
}

void ApplicationWindowHostViewMac::DisplayCursor(const WebCursor& cursor) {
  ns_view_bridge_->DisplayCursor(cursor);
}

CursorManager* ApplicationWindowHostViewMac::GetCursorManager() {
  return cursor_manager_.get();
}

void ApplicationWindowHostViewMac::SetIsLoading(bool is_loading) {
  is_loading_ = is_loading;
  // If we ever decide to show the waiting cursor while the page is loading
  // like Chrome does on Windows, call |UpdateCursor()| here.
}

void ApplicationWindowHostViewMac::OnUpdateTextInputStateCalled(
    TextInputManager* text_input_manager,
    ApplicationWindowHostView* updated_view,
    bool did_update_state) {
  if (!did_update_state)
    return;

  // |updated_view| is the last view to change its TextInputState which can be
  // used to start/stop monitoring composition info when it has a focused
  // editable text input field.
  ApplicationWindowHost* widget_host =
      ApplicationWindowHost::From(updated_view->GetApplicationWindowHost());

  // We might end up here when |updated_view| has had active TextInputState and
  // then got destroyed. In that case, |updated_view->GetApplicationWindowHost()|
  // returns nullptr.
  if (!widget_host)
    return;

  // Set the monitor state based on the text input focus state.
  const bool has_focus = HasFocus();
  const TextInputState* state = text_input_manager->GetTextInputState();
  bool need_monitor_composition =
      has_focus && state && state->type != ui::TEXT_INPUT_TYPE_NONE;

  widget_host->RequestCompositionUpdates(false /* immediate_request */,
                                         need_monitor_composition);

  if (has_focus) {
    SetTextInputActive(true);

    // Let AppKit cache the new input context to make IMEs happy.
    // See http://crbug.com/73039.
    [NSApp updateWindows];
  }
}

void ApplicationWindowHostViewMac::OnImeCancelComposition(
    TextInputManager* text_input_manager,
    ApplicationWindowHostView* updated_view) {
  ns_view_bridge_->CancelComposition();
}

void ApplicationWindowHostViewMac::OnImeCompositionRangeChanged(
    TextInputManager* text_input_manager,
    ApplicationWindowHostView* updated_view) {
  const TextInputManager::CompositionRangeInfo* info =
      GetCompositionRangeInfo();
  if (!info)
    return;
  // The RangeChanged message is only sent with valid values. The current
  // caret position (start == end) will be sent if there is no IME range.
  ns_view_bridge_->SetCompositionRangeInfo(info->range);
}

void ApplicationWindowHostViewMac::OnSelectionBoundsChanged(
    TextInputManager* text_input_manager,
    ApplicationWindowHostView* updated_view) {
  DCHECK_EQ(GetTextInputManager(), text_input_manager);

  // The rest of the code is to support the Mac Zoom feature tracking the
  // text caret; we can skip it if that feature is not currently enabled.
  if (!UAZoomEnabled())
    return;

  ApplicationWindowHostView* focused_view = GetFocusedViewForTextSelection();
  if (!focused_view)
    return;

  const TextInputManager::SelectionRegion* region =
      GetTextInputManager()->GetSelectionRegion(focused_view);
  if (!region)
    return;

  // Create a rectangle for the edge of the selection focus, which will be
  // the same as the caret position if the selection is collapsed. That's
  // what we want to try to keep centered on-screen if possible.
  gfx::Rect gfx_caret_rect(region->focus.edge_top_rounded().x(),
                           region->focus.edge_top_rounded().y(),
                           1, region->focus.GetHeight());
  gfx_caret_rect += view_bounds_in_window_dip_.OffsetFromOrigin();
  gfx_caret_rect += window_frame_in_screen_dip_.OffsetFromOrigin();

  // Note that UAZoomChangeFocus wants unflipped screen coordinates.
  NSRect caret_rect = NSRectFromCGRect(gfx_caret_rect.ToCGRect());
  UAZoomChangeFocus(&caret_rect, &caret_rect, kUAZoomFocusTypeInsertionPoint);
}

void ApplicationWindowHostViewMac::OnTextSelectionChanged(
    TextInputManager* text_input_manager,
    ApplicationWindowHostView* updated_view) {
  DCHECK_EQ(GetTextInputManager(), text_input_manager);

  const TextInputManager::TextSelection* selection = GetTextSelection();
  if (!selection)
    return;
  ns_view_bridge_->SetTextSelection(selection->text(), selection->offset(),
                                    selection->range());
}

void ApplicationWindowHostViewMac::OnRenderFrameMetadataChanged() {
  last_frame_root_background_color_ = host()
                                          ->render_frame_metadata_provider()
                                          ->LastRenderFrameMetadata()
                                          .root_background_color;
  ApplicationWindowHostView::OnRenderFrameMetadataChanged();
}

void ApplicationWindowHostViewMac::RenderProcessGone(base::TerminationStatus status,
                                                int error_code) {
  Destroy();
}

void ApplicationWindowHostViewMac::Destroy() {
  // Unlock the mouse in the NSView's process before destroying our bridge to
  // it.
  if (mouse_locked_) {
    mouse_locked_ = false;
    ns_view_bridge_->SetCursorLocked(false);
  }

  // Destroy the brige to the NSView. Note that the NSView on the other side
  // of |ns_view_bridge_| may outlive us due to other retains.
  ns_view_bridge_.reset();

  // Delete the delegated frame state, which will reach back into
  // host().
  browser_compositor_.reset();

  // Make sure none of our observers send events for us to process after
  // we release host().
  NotifyObserversAboutShutdown();

  if (text_input_manager_)
    text_input_manager_->RemoveObserver(this);

  mouse_wheel_phase_handler_.IgnorePendingWheelEndEvent();

  // The call to the base class will set host() to nullptr.
  ApplicationWindowHostView::Destroy();

  delete this;
}

void ApplicationWindowHostViewMac::SetTooltipText(
    const base::string16& tooltip_text) {
  GetCursorManager()->SetTooltipTextForView(this, tooltip_text);
}

void ApplicationWindowHostViewMac::DisplayTooltipText(
    const base::string16& tooltip_text) {
  ns_view_bridge_->SetTooltipText(tooltip_text);
}

viz::ScopedSurfaceIdAllocator ApplicationWindowHostViewMac::ResizeDueToAutoResize(
    const gfx::Size& new_size,
    const viz::LocalSurfaceId& child_local_surface_id) {
  base::OnceCallback<void()> allocation_task = base::BindOnce(
      &ApplicationWindowHostViewMac::OnResizeDueToAutoResizeComplete,
      weak_factory_.GetWeakPtr(), new_size, child_local_surface_id);
  return browser_compositor_->GetScopedRendererSurfaceIdAllocator(
      std::move(allocation_task));
}

void ApplicationWindowHostViewMac::DidNavigate() {
  browser_compositor_->DidNavigate();
}

gfx::Size ApplicationWindowHostViewMac::GetRequestedRendererSize() const {
  return browser_compositor_->GetRendererSize();
}

namespace {

// A helper function for CombineTextNodesAndMakeCallback() below. It would
// ordinarily be a helper lambda in that class method, but it processes a tree
// and needs to be recursive, and that's crazy difficult to do with a lambda.
// TODO(avi): Move this to be a lambda when P0839R0 lands in C++.
void AddTextNodesToVector(const ui::AXNode* node,
                          std::vector<base::string16>* strings) {
  const ui::AXNodeData& node_data = node->data();

  if (node_data.role == ax::mojom::Role::kStaticText) {
    if (node_data.HasStringAttribute(ax::mojom::StringAttribute::kName)) {
      strings->emplace_back(
          node_data.GetString16Attribute(ax::mojom::StringAttribute::kName));
    }
    return;
  }

  for (const auto* child : node->children())
    AddTextNodesToVector(child, strings);
}

using SpeechCallback = base::OnceCallback<void(const base::string16&)>;
void CombineTextNodesAndMakeCallback(SpeechCallback callback,
                                     const ui::AXTreeUpdate& update) {
  std::vector<base::string16> text_node_contents;
  text_node_contents.reserve(update.nodes.size());

  ui::AXTree tree(update);

  AddTextNodesToVector(tree.root(), &text_node_contents);

  std::move(callback).Run(
      base::JoinString(text_node_contents, base::ASCIIToUTF16("\n")));
}

}  // namespace

void ApplicationWindowHostViewMac::GetPageTextForSpeech(SpeechCallback callback) {
  // Note that the WebContents::RequestAXTreeSnapshot() call has a limit on the
  // number of nodes returned. For large pages, this call might hit that limit.
  // This is a reasonable thing. The "Start Speaking" call dates back to the
  // earliest days of the Mac, before accessibility. It was designed to show off
  // the speech capabilities of the Mac, which is fine, but is mostly
  // inapplicable nowadays. Is it useful to have the Mac read megabytes of text
  // with zero control over positioning, with no fast-forward or rewind? What
  // does it even mean to read a Web 2.0 dynamic, AJAXy page aloud from
  // beginning to end?
  //
  // If this is an issue, please file a bug explaining the situation and how the
  // limits of this feature affect you in the real world.

  GetWebContents()->RequestAXTreeSnapshot(
      base::BindOnce(CombineTextNodesAndMakeCallback, std::move(callback)),
      ui::AXMode::kWebContents);
}

void ApplicationWindowHostViewMac::SpeakSelection() {
  const TextInputManager::TextSelection* selection = GetTextSelection();
  if (selection && !selection->selected_text().empty()) {
    ui::TextServicesContextMenu::SpeakText(selection->selected_text());
    return;
  }

  // With no selection, speak an approximation of the entire contents of the
  // page.
  GetPageTextForSpeech(base::BindOnce(ui::TextServicesContextMenu::SpeakText));
}

//
// ApplicationWindowHostViewCocoa uses the stored selection text,
// which implements NSServicesRequests protocol.
//

void ApplicationWindowHostViewMac::SetShowingContextMenu(bool showing) {
  ns_view_bridge_->SetShowingContextMenu(showing);
}

void ApplicationWindowHostViewMac::CopyFromSurface(
    const gfx::Rect& src_subrect,
    const gfx::Size& dst_size,
    base::OnceCallback<void(const SkBitmap&)> callback) {
  browser_compositor_->GetDelegatedFrameHost()->CopyFromCompositingSurface(
      src_subrect, dst_size, std::move(callback));
}

void ApplicationWindowHostViewMac::EnsureSurfaceSynchronizedForLayoutTest() {
  // TODO(vmpstr): Figure out what needs to be done here.
}

void ApplicationWindowHostViewMac::SetNeedsBeginFrames(bool needs_begin_frames) {
  needs_begin_frames_ = needs_begin_frames;
  UpdateNeedsBeginFramesInternal();
}

void ApplicationWindowHostViewMac::UpdateNeedsBeginFramesInternal() {
  browser_compositor_->SetNeedsBeginFrames(needs_begin_frames_);
}

void ApplicationWindowHostViewMac::OnResizeDueToAutoResizeComplete(
    const gfx::Size& new_size,
    const viz::LocalSurfaceId& child_allocated_local_surface_id) {
  browser_compositor_->UpdateRendererLocalSurfaceIdFromChild(
      child_allocated_local_surface_id);
  browser_compositor_->UpdateForAutoResize(new_size);
}

void ApplicationWindowHostViewMac::SetWantsAnimateOnlyBeginFrames() {
  browser_compositor_->SetWantsAnimateOnlyBeginFrames();
}

void ApplicationWindowHostViewMac::TakeFallbackContentFrom(
    ApplicationWindowHostView* view) {
  DCHECK(!static_cast<ApplicationWindowHostView*>(view)
              ->IsApplicationWindowHostViewChildFrame());
  DCHECK(!static_cast<ApplicationWindowHostView*>(view)
              ->IsApplicationWindowHostViewGuest());
  ApplicationWindowHostViewMac* view_mac =
      static_cast<ApplicationWindowHostViewMac*>(view);
  ScopedCAActionDisabler disabler;
  SetBackgroundColor(view_mac->background_color());
  browser_compositor_->TakeFallbackContentFrom(
      view_mac->browser_compositor_.get());
}

bool ApplicationWindowHostViewMac::GetLineBreakIndex(
    const std::vector<gfx::Rect>& bounds,
    const gfx::Range& range,
    size_t* line_break_point) {
  DCHECK(line_break_point);
  if (range.start() >= bounds.size() || range.is_reversed() || range.is_empty())
    return false;

  // We can't check line breaking completely from only rectangle array. Thus we
  // assume the line breaking as the next character's y offset is larger than
  // a threshold. Currently the threshold is determined as minimum y offset plus
  // 75% of maximum height.
  // TODO(nona): Check the threshold is reliable or not.
  // TODO(nona): Bidi support.
  const size_t loop_end_idx =
      std::min(bounds.size(), static_cast<size_t>(range.end()));
  int max_height = 0;
  int min_y_offset = std::numeric_limits<int32_t>::max();
  for (size_t idx = range.start(); idx < loop_end_idx; ++idx) {
    max_height = std::max(max_height, bounds[idx].height());
    min_y_offset = std::min(min_y_offset, bounds[idx].y());
  }
  int line_break_threshold = min_y_offset + (max_height * 3 / 4);
  for (size_t idx = range.start(); idx < loop_end_idx; ++idx) {
    if (bounds[idx].y() > line_break_threshold) {
      *line_break_point = idx;
      return true;
    }
  }
  return false;
}

gfx::Rect ApplicationWindowHostViewMac::GetFirstRectForCompositionRange(
    const gfx::Range& range,
    gfx::Range* actual_range) {
  const TextInputManager::CompositionRangeInfo* composition_info =
      GetCompositionRangeInfo();
  if (!composition_info)
    return gfx::Rect();

  DCHECK(actual_range);
  DCHECK(!composition_info->character_bounds.empty());
  DCHECK(range.start() <= composition_info->character_bounds.size());
  DCHECK(range.end() <= composition_info->character_bounds.size());

  if (range.is_empty()) {
    *actual_range = range;
    if (range.start() == composition_info->character_bounds.size()) {
      return gfx::Rect(
          composition_info->character_bounds[range.start() - 1].right(),
          composition_info->character_bounds[range.start() - 1].y(), 0,
          composition_info->character_bounds[range.start() - 1].height());
    } else {
      return gfx::Rect(
          composition_info->character_bounds[range.start()].x(),
          composition_info->character_bounds[range.start()].y(), 0,
          composition_info->character_bounds[range.start()].height());
    }
  }

  size_t end_idx;
  if (!GetLineBreakIndex(composition_info->character_bounds, range, &end_idx)) {
    end_idx = range.end();
  }
  *actual_range = gfx::Range(range.start(), end_idx);
  gfx::Rect rect = composition_info->character_bounds[range.start()];
  for (size_t i = range.start() + 1; i < end_idx; ++i) {
    rect.Union(composition_info->character_bounds[i]);
  }
  return rect;
}

gfx::Range ApplicationWindowHostViewMac::ConvertCharacterRangeToCompositionRange(
    const gfx::Range& request_range) {
  const TextInputManager::CompositionRangeInfo* composition_info =
      GetCompositionRangeInfo();
  if (!composition_info)
    return gfx::Range::InvalidRange();

  if (composition_info->range.is_empty())
    return gfx::Range::InvalidRange();

  if (composition_info->range.is_reversed())
    return gfx::Range::InvalidRange();

  if (request_range.start() < composition_info->range.start() ||
      request_range.start() > composition_info->range.end() ||
      request_range.end() > composition_info->range.end()) {
    return gfx::Range::InvalidRange();
  }

  return gfx::Range(request_range.start() - composition_info->range.start(),
                    request_range.end() - composition_info->range.start());
}

WebContents* ApplicationWindowHostViewMac::GetWebContents() {
  return WebContents::FromRenderViewHost(RenderViewHost::From(host()));
}

bool ApplicationWindowHostViewMac::GetCachedFirstRectForCharacterRange(
    const gfx::Range& requested_range,
    gfx::Rect* rect,
    gfx::Range* actual_range) {
  if (!GetTextInputManager())
    return false;

  DCHECK(rect);
  // This exists to make IMEs more responsive, see http://crbug.com/115920
  TRACE_EVENT0("browser",
               "ApplicationWindowHostViewMac::GetFirstRectForCharacterRange");

  const TextInputManager::TextSelection* selection = GetTextSelection();
  if (!selection)
    return false;

  // If requested range is same as caret location, we can just return it.
  if (selection->range().is_empty() && requested_range == selection->range()) {
    DCHECK(GetFocusedWidget());
    if (actual_range)
      *actual_range = requested_range;
    *rect = GetTextInputManager()
                ->GetSelectionRegion(GetFocusedWidget()->GetView())
                ->caret_rect;
    return true;
  }

  const TextInputManager::CompositionRangeInfo* composition_info =
      GetCompositionRangeInfo();
  if (!composition_info || composition_info->range.is_empty()) {
    if (!selection->range().Contains(requested_range))
      return false;
    DCHECK(GetFocusedWidget());
    if (actual_range)
      *actual_range = selection->range();
    *rect = GetTextInputManager()
                ->GetSelectionRegion(GetFocusedWidget()->GetView())
                ->first_selection_rect;
    return true;
  }

  const gfx::Range request_range_in_composition =
      ConvertCharacterRangeToCompositionRange(requested_range);
  if (request_range_in_composition == gfx::Range::InvalidRange())
    return false;

  // If firstRectForCharacterRange in WebFrame is failed in renderer,
  // ImeCompositionRangeChanged will be sent with empty vector.
  if (!composition_info || composition_info->character_bounds.empty())
    return false;
  DCHECK_EQ(composition_info->character_bounds.size(),
            composition_info->range.length());

  gfx::Range ui_actual_range;
  *rect = GetFirstRectForCompositionRange(request_range_in_composition,
                                          &ui_actual_range);
  if (actual_range) {
    *actual_range =
        gfx::Range(composition_info->range.start() + ui_actual_range.start(),
                   composition_info->range.start() + ui_actual_range.end());
  }
  return true;
}

bool ApplicationWindowHostViewMac::ShouldContinueToPauseForFrame() {
  return browser_compositor_->ShouldContinueToPauseForFrame();
}

void ApplicationWindowHostViewMac::FocusedNodeChanged(
    bool is_editable_node,
    const gfx::Rect& node_bounds_in_screen) {
  ns_view_bridge_->CancelComposition();

  // If the Mac Zoom feature is enabled, update it with the bounds of the
  // current focused node so that it can ensure that it's scrolled into view.
  // Don't do anything if it's an editable node, as this will be handled by
  // OnSelectionBoundsChanged instead.
  if (UAZoomEnabled() && !is_editable_node) {
    NSRect bounds = NSRectFromCGRect(node_bounds_in_screen.ToCGRect());
    UAZoomChangeFocus(&bounds, NULL, kUAZoomFocusTypeOther);
  }
}

void ApplicationWindowHostViewMac::DidCreateNewRendererCompositorFrameSink(
    viz::mojom::CompositorFrameSinkClient* renderer_compositor_frame_sink) {
  browser_compositor_->DidCreateNewRendererCompositorFrameSink(
      renderer_compositor_frame_sink);
}

void ApplicationWindowHostViewMac::SubmitCompositorFrame(
    const viz::LocalSurfaceId& local_surface_id,
    viz::CompositorFrame frame,
    viz::mojom::HitTestRegionListPtr hit_test_region_list) {
  TRACE_EVENT0("browser", "ApplicationWindowHostViewMac::OnSwapCompositorFrame");

  page_at_minimum_scale_ =
      frame.metadata.page_scale_factor == frame.metadata.min_page_scale_factor;

  browser_compositor_->GetDelegatedFrameHost()->SubmitCompositorFrame(
      local_surface_id, std::move(frame), std::move(hit_test_region_list));

  UpdateDisplayVSyncParameters();
}

void ApplicationWindowHostViewMac::OnDidNotProduceFrame(
    const viz::BeginFrameAck& ack) {
  browser_compositor_->OnDidNotProduceFrame(ack);
}

void ApplicationWindowHostViewMac::ClearCompositorFrame() {
  browser_compositor_->ClearCompositorFrame();
}

gfx::Vector2d ApplicationWindowHostViewMac::GetOffsetFromRootSurface() {
  return gfx::Vector2d();
}

gfx::Rect ApplicationWindowHostViewMac::GetBoundsInRootWindow() {
  return window_frame_in_screen_dip_;
}

bool ApplicationWindowHostViewMac::LockMouse() {
  if (mouse_locked_)
    return true;

  mouse_locked_ = true;

  // Lock position of mouse cursor and hide it.
  ns_view_bridge_->SetCursorLocked(true);

  // Clear the tooltip window.
  ns_view_bridge_->SetTooltipText(base::string16());

  return true;
}

void ApplicationWindowHostViewMac::UnlockMouse() {
  if (!mouse_locked_)
    return;
  mouse_locked_ = false;
  ns_view_bridge_->SetCursorLocked(false);

  if (host())
    host()->LostMouseLock();
}

bool ApplicationWindowHostViewMac::LockKeyboard(
    base::Optional<base::flat_set<int>> keys) {
  is_keyboard_locked_ = true;
  ns_view_bridge_->LockKeyboard(std::move(keys));
  return true;
}

void ApplicationWindowHostViewMac::UnlockKeyboard() {
  if (!is_keyboard_locked_)
    return;

  is_keyboard_locked_ = false;
  ns_view_bridge_->UnlockKeyboard();
}

bool ApplicationWindowHostViewMac::IsKeyboardLocked() {
  return is_keyboard_locked_;
}

void ApplicationWindowHostViewMac::GestureEventAck(const WebGestureEvent& event,
                                              common::InputEventAckState ack_result) {
  bool consumed = ack_result == INPUT_EVENT_ACK_STATE_CONSUMED;
  switch (event.GetType()) {
    case WebInputEvent::kGestureScrollBegin:
    case WebInputEvent::kGestureScrollUpdate:
    case WebInputEvent::kGestureScrollEnd:
      [cocoa_view() processedGestureScrollEvent:event consumed:consumed];
      return;
    default:
      break;
  }
  mouse_wheel_phase_handler_.GestureEventAck(event, ack_result);
}

void ApplicationWindowHostViewMac::DidOverscroll(
    const ui::DidOverscrollParams& params) {
  [cocoa_view() processedOverscroll:params];
}

std::unique_ptr<SyntheticGestureTarget>
ApplicationWindowHostViewMac::CreateSyntheticGestureTarget() {
  ApplicationWindowHost* host =
      ApplicationWindowHost::From(GetApplicationWindowHost());
  return std::unique_ptr<SyntheticGestureTarget>(
      new SyntheticGestureTargetMac(host, cocoa_view()));
}

viz::LocalSurfaceId ApplicationWindowHostViewMac::GetLocalSurfaceId() const {
  return browser_compositor_->GetRendererLocalSurfaceId();
}

viz::FrameSinkId ApplicationWindowHostViewMac::GetFrameSinkId() {
  return browser_compositor_->GetDelegatedFrameHost()->frame_sink_id();
}

bool ApplicationWindowHostViewMac::ShouldRouteEvent(
    const WebInputEvent& event) const {
  // See also ApplicationWindowHostViewAura::ShouldRouteEvent.
  // TODO(wjmaclean): Update this function if ApplicationWindowHostViewMac implements
  // OnTouchEvent(), to match what we are doing in ApplicationWindowHostViewAura.
  DCHECK(WebInputEvent::IsMouseEventType(event.GetType()) ||
         event.GetType() == WebInputEvent::kMouseWheel ||
         WebInputEvent::IsPinchGestureEventType(event.GetType()));
  return host()->delegate() && host()->delegate()->GetInputEventRouter();
}

void ApplicationWindowHostViewMac::SendGesturePinchEvent(WebGestureEvent* event) {
  DCHECK(WebInputEvent::IsPinchGestureEventType(event->GetType()));
  if (ShouldRouteEvent(*event)) {
    DCHECK(event->SourceDevice() ==
           blink::WebGestureDevice::kWebGestureDeviceTouchpad);
    host()->delegate()->GetInputEventRouter()->RouteGestureEvent(
        this, event, ui::LatencyInfo(ui::SourceEventType::WHEEL));
    return;
  }
  host()->ForwardGestureEvent(*event);
}

bool ApplicationWindowHostViewMac::TransformPointToLocalCoordSpace(
    const gfx::PointF& point,
    const viz::SurfaceId& original_surface,
    gfx::PointF* transformed_point) {
  // Transformations use physical pixels rather than DIP, so conversion
  // is necessary.
  float scale_factor = display_.device_scale_factor();
  gfx::PointF point_in_pixels = gfx::ConvertPointToPixel(scale_factor, point);
  if (!browser_compositor_->GetDelegatedFrameHost()
           ->TransformPointToLocalCoordSpace(point_in_pixels, original_surface,
                                             transformed_point))
    return false;
  *transformed_point = gfx::ConvertPointToDIP(scale_factor, *transformed_point);
  return true;
}

bool ApplicationWindowHostViewMac::TransformPointToCoordSpaceForView(
    const gfx::PointF& point,
    ApplicationWindowHostView* target_view,
    gfx::PointF* transformed_point) {
  if (target_view == this) {
    *transformed_point = point;
    return true;
  }

  return browser_compositor_->GetDelegatedFrameHost()
      ->TransformPointToCoordSpaceForView(point, target_view,
                                          transformed_point);
}

viz::FrameSinkId ApplicationWindowHostViewMac::GetRootFrameSinkId() {
  return browser_compositor_->GetRootFrameSinkId();
}

viz::SurfaceId ApplicationWindowHostViewMac::GetCurrentSurfaceId() const {
  return browser_compositor_->GetDelegatedFrameHost()->GetCurrentSurfaceId();
}

bool ApplicationWindowHostViewMac::Send(IPC::Message* message) {
  if (host())
    return host()->Send(message);
  delete message;
  return false;
}

void ApplicationWindowHostViewMac::ShutdownHost() {
  weak_factory_.InvalidateWeakPtrs();
  host()->ShutdownAndDestroyWidget(true);
  // Do not touch any members at this point, |this| has been deleted.
}

void ApplicationWindowHostViewMac::SetActive(bool active) {
  if (host()) {
    host()->SetActive(active);
    if (active) {
      if (HasFocus())
        host()->Focus();
    } else {
      host()->Blur();
    }
  }
  if (HasFocus())
    SetTextInputActive(active);
  if (!active)
    UnlockMouse();
}

void ApplicationWindowHostViewMac::ShowDefinitionForSelection() {
  // This will round-trip to the NSView to determine the selection range.
  ns_view_bridge_->ShowDictionaryOverlayForSelection();
}

void ApplicationWindowHostViewMac::SetBackgroundColor(SkColor color) {
  // This is called by the embedding code prior to the first frame appearing,
  // to set a reasonable color to show before the web content generates its
  // first frame. This will be overridden by the web contents.
  SetBackgroundLayerColor(color);
  browser_compositor_->SetBackgroundColor(color);

  DCHECK(SkColorGetA(color) == SK_AlphaOPAQUE ||
         SkColorGetA(color) == SK_AlphaTRANSPARENT);
  bool opaque = SkColorGetA(color) == SK_AlphaOPAQUE;
  if (background_is_opaque_ != opaque) {
    background_is_opaque_ = opaque;
    if (host())
      host()->SetBackgroundOpaque(opaque);
  }
}

SkColor ApplicationWindowHostViewMac::background_color() const {
  // This is used to specify a color to temporarily show while waiting for web
  // content. This should never return transparent, since that will cause bugs
  // where views are initialized as having a transparent background
  // inappropriately.
  // https://crbug.com/735407
  if (background_layer_color_ == SK_ColorTRANSPARENT)
    return SK_ColorWHITE;
  return background_layer_color_;
}

void ApplicationWindowHostViewMac::SetBackgroundLayerColor(SkColor color) {
  if (color == background_layer_color_)
    return;
  background_layer_color_ = color;
  ns_view_bridge_->SetBackgroundColor(color);
}

BrowserAccessibilityManager*
    ApplicationWindowHostViewMac::CreateAccessibilityManager(
        BrowserAccessibilityDelegate* delegate, bool for_root_frame) {
  return new AccessibilityManagerMac(
      AccessibilityManagerMac::GetEmptyDocument(), delegate);
}

gfx::Point ApplicationWindowHostViewMac::AccessibilityOriginInScreen(
    const gfx::Rect& bounds) {
  NSPoint origin = NSMakePoint(bounds.x(), bounds.y());
  NSSize size = NSMakeSize(bounds.width(), bounds.height());
  origin.y = NSHeight([cocoa_view() bounds]) - origin.y;
  NSPoint originInWindow = [cocoa_view() convertPoint:origin toView:nil];
  NSPoint originInScreen =
      ui::ConvertPointFromWindowToScreen([cocoa_view() window], originInWindow);
  originInScreen.y = originInScreen.y - size.height;
  return gfx::Point(originInScreen.x, originInScreen.y);
}

gfx::AcceleratedWidget
ApplicationWindowHostViewMac::AccessibilityGetAcceleratedWidget() {
  return browser_compositor_->GetAcceleratedWidget();
}

void ApplicationWindowHostViewMac::SetTextInputActive(bool active) {
  const bool should_enable_password_input =
      active && GetTextInputType() == ui::TEXT_INPUT_TYPE_PASSWORD;
  if (should_enable_password_input)
    password_input_enabler_.reset(new ui::ScopedPasswordInputEnabler());
  else
    password_input_enabler_.reset();
}

void ApplicationWindowHostViewMac::PauseForPendingResizeOrRepaintsAndDraw() {
  if (!host() || !browser_compositor_ || host()->is_hidden()) {
    return;
  }

  // Pausing for one view prevents others from receiving frames.
  // This may lead to large delays, causing overlaps. See crbug.com/352020.
  if (!allow_pause_for_resize_or_repaint_)
    return;

  // Wait for a frame of the right size to come in.
  browser_compositor_->BeginPauseForFrame(host()->auto_resize_enabled());
  host()->PauseForPendingResizeOrRepaints();
  browser_compositor_->EndPauseForFrame();
}

// static
viz::FrameSinkId
ApplicationWindowHostViewMac::AllocateFrameSinkIdForGuestViewHack() {
  return ImageTransportFactory::GetInstance()
      ->GetContextFactoryPrivate()
      ->AllocateFrameSinkId();
}

///////////////////////////////////////////////////////////////////////////////
// ApplicationWindowHostNSViewClient implementation:

BrowserAccessibilityManager*
ApplicationWindowHostViewMac::GetRootAccessibilityManager() {
  return host()->GetRootAccessibilityManager();
}

void ApplicationWindowHostViewMac::OnNSViewSyncIsRenderViewHost(
    bool* is_render_view) {
  *is_render_view = RenderViewHost::From(host()) != nullptr;
}

void ApplicationWindowHostViewMac::OnNSViewRequestShutdown() {
  if (!weak_factory_.HasWeakPtrs()) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(&ApplicationWindowHostViewMac::ShutdownHost,
                                  weak_factory_.GetWeakPtr()));
  }
}

void ApplicationWindowHostViewMac::OnNSViewIsFirstResponderChanged(
    bool is_first_responder) {
  if (is_first_responder_ == is_first_responder)
    return;
  is_first_responder_ = is_first_responder;
  if (is_first_responder_) {
    host()->GotFocus();
    SetTextInputActive(true);
  } else {
    SetTextInputActive(false);
    host()->LostFocus();
  }
}

void ApplicationWindowHostViewMac::OnNSViewWindowIsKeyChanged(bool is_key) {
  SetActive(is_key);
}

void ApplicationWindowHostViewMac::OnNSViewBoundsInWindowChanged(
    const gfx::Rect& view_bounds_in_window_dip,
    bool attached_to_window) {
  bool view_size_changed =
      view_bounds_in_window_dip_.size() != view_bounds_in_window_dip.size();

  browser_compositor_->SetNSViewAttachedToWindow(attached_to_window);

  if (attached_to_window) {
    view_bounds_in_window_dip_ = view_bounds_in_window_dip;
  } else {
    // If not attached to a window, do not update the bounds origin (since it is
    // meaningless, and the last value is the best guess at the next meaningful
    // value).
    view_bounds_in_window_dip_.set_size(view_bounds_in_window_dip.size());
  }

  if (view_size_changed) {
    UpdateNSViewAndDisplayProperties();
    // Wait for the frame that WasResize might have requested. If the view is
    // being made visible at a new size, then this call will have no effect
    // because the view widget is still hidden, and the pause call in WasShown
    // will have this effect for us.
    PauseForPendingResizeOrRepaintsAndDraw();
  }
}

void ApplicationWindowHostViewMac::OnNSViewWindowFrameInScreenChanged(
    const gfx::Rect& window_frame_in_screen_dip) {
  window_frame_in_screen_dip_ = window_frame_in_screen_dip;
}

void ApplicationWindowHostViewMac::OnNSViewDisplayChanged(
    const display::Display& display) {
  display_ = display;
  UpdateNSViewAndDisplayProperties();
}

void ApplicationWindowHostViewMac::OnNSViewBeginKeyboardEvent() {
  DCHECK(!in_keyboard_event_);
  in_keyboard_event_ = true;
  ApplicationWindowHost* widget_host = host();
  if (widget_host && widget_host->delegate()) {
    widget_host =
        widget_host->delegate()->GetFocusedApplicationWindowHost(widget_host);
  }
  if (widget_host) {
    keyboard_event_widget_process_id_ = widget_host->GetProcess()->GetID();
    keyboard_event_widget_routing_id_ = widget_host->GetRoutingID();
  }
}

void ApplicationWindowHostViewMac::OnNSViewEndKeyboardEvent() {
  in_keyboard_event_ = false;
  keyboard_event_widget_process_id_ = 0;
  keyboard_event_widget_routing_id_ = 0;
}

void ApplicationWindowHostViewMac::OnNSViewForwardKeyboardEvent(
    const NativeWebKeyboardEvent& key_event,
    const ui::LatencyInfo& latency_info) {
  if (auto* widget_host = GetWidgetForKeyboardEvent()) {
    widget_host->ForwardKeyboardEventWithLatencyInfo(key_event, latency_info);
  }
}

void ApplicationWindowHostViewMac::OnNSViewForwardKeyboardEventWithCommands(
    const NativeWebKeyboardEvent& key_event,
    const ui::LatencyInfo& latency_info,
    const std::vector<EditCommand>& commands) {
  if (auto* widget_host = GetWidgetForKeyboardEvent()) {
    widget_host->ForwardKeyboardEventWithCommands(key_event, latency_info,
                                                  &commands);
  }
}

void ApplicationWindowHostViewMac::OnNSViewRouteOrProcessMouseEvent(
    const blink::WebMouseEvent& const_web_event) {
  blink::WebMouseEvent web_event = const_web_event;
  ui::LatencyInfo latency_info(ui::SourceEventType::OTHER);
  latency_info.AddLatencyNumber(ui::INPUT_EVENT_LATENCY_UI_COMPONENT, 0, 0);
  if (ShouldRouteEvent(web_event)) {
    host()->delegate()->GetInputEventRouter()->RouteMouseEvent(this, &web_event,
                                                               latency_info);
  } else {
    ProcessMouseEvent(web_event, latency_info);
  }
}

void ApplicationWindowHostViewMac::OnNSViewRouteOrProcessWheelEvent(
    const blink::WebMouseWheelEvent& const_web_event) {
  blink::WebMouseWheelEvent web_event = const_web_event;
  ui::LatencyInfo latency_info(ui::SourceEventType::WHEEL);
  latency_info.AddLatencyNumber(ui::INPUT_EVENT_LATENCY_UI_COMPONENT, 0, 0);
  if (wheel_scroll_latching_enabled()) {
    mouse_wheel_phase_handler_.AddPhaseIfNeededAndScheduleEndEvent(
        web_event, ShouldRouteEvent(web_event));
    if (web_event.phase == blink::WebMouseWheelEvent::kPhaseEnded) {
      // A wheel end event is scheduled and will get dispatched if momentum
      // phase doesn't start in 100ms. Don't sent the wheel end event
      // immediately.
      return;
    }
  }
  if (ShouldRouteEvent(web_event)) {
    host()->delegate()->GetInputEventRouter()->RouteMouseWheelEvent(
        this, &web_event, latency_info);
  } else {
    ProcessMouseWheelEvent(web_event, latency_info);
  }
}

void ApplicationWindowHostViewMac::OnNSViewForwardMouseEvent(
    const blink::WebMouseEvent& web_event) {
  if (host())
    host()->ForwardMouseEvent(web_event);

  if (web_event.GetType() == WebInputEvent::kMouseLeave)
    ns_view_bridge_->SetTooltipText(base::string16());
}

void ApplicationWindowHostViewMac::OnNSViewForwardWheelEvent(
    const blink::WebMouseWheelEvent& const_web_event) {
  blink::WebMouseWheelEvent web_event = const_web_event;
  if (wheel_scroll_latching_enabled()) {
    mouse_wheel_phase_handler_.AddPhaseIfNeededAndScheduleEndEvent(web_event,
                                                                   false);
  } else {
    ui::LatencyInfo latency_info(ui::SourceEventType::WHEEL);
    latency_info.AddLatencyNumber(ui::INPUT_EVENT_LATENCY_UI_COMPONENT, 0, 0);
    host()->ForwardWheelEventWithLatencyInfo(web_event, latency_info);
  }
}

void ApplicationWindowHostViewMac::OnNSViewGestureBegin(
    blink::WebGestureEvent begin_event) {
  gesture_begin_event_.reset(new WebGestureEvent(begin_event));

  // If the page is at the minimum zoom level, require a threshold be reached
  // before the pinch has an effect.
  if (page_at_minimum_scale_) {
    pinch_has_reached_zoom_threshold_ = false;
    pinch_unused_amount_ = 1;
  }
}

void ApplicationWindowHostViewMac::OnNSViewGestureUpdate(
    blink::WebGestureEvent update_event) {
  // If, due to nesting of multiple gestures (e.g, from multiple touch
  // devices), the beginning of the gesture has been lost, skip the remainder
  // of the gesture.
  if (!gesture_begin_event_)
    return;

  if (!pinch_has_reached_zoom_threshold_) {
    pinch_unused_amount_ *= update_event.data.pinch_update.scale;
    if (pinch_unused_amount_ < 0.667 || pinch_unused_amount_ > 1.5)
      pinch_has_reached_zoom_threshold_ = true;
  }

  // Send a GesturePinchBegin event if none has been sent yet.
  if (!gesture_begin_pinch_sent_) {
    if (wheel_scroll_latching_enabled()) {
      // Before starting a pinch sequence, send the pending wheel end event to
      // finish scrolling.
      mouse_wheel_phase_handler_.DispatchPendingWheelEndEvent();
    }
    WebGestureEvent begin_event(*gesture_begin_event_);
    begin_event.SetType(WebInputEvent::kGesturePinchBegin);
    begin_event.SetSourceDevice(
        blink::WebGestureDevice::kWebGestureDeviceTouchpad);
    SendGesturePinchEvent(&begin_event);
    gesture_begin_pinch_sent_ = YES;
  }

  // Send a GesturePinchUpdate event.
  update_event.data.pinch_update.zoom_disabled =
      !pinch_has_reached_zoom_threshold_;
  SendGesturePinchEvent(&update_event);
}

void ApplicationWindowHostViewMac::OnNSViewGestureEnd(
    blink::WebGestureEvent end_event) {
  gesture_begin_event_.reset();
  if (gesture_begin_pinch_sent_) {
    SendGesturePinchEvent(&end_event);
    gesture_begin_pinch_sent_ = false;
  }
}

void ApplicationWindowHostViewMac::OnNSViewSmartMagnify(
    const blink::WebGestureEvent& smart_magnify_event) {
  host()->ForwardGestureEvent(smart_magnify_event);
}

void ApplicationWindowHostViewMac::OnNSViewImeSetComposition(
    const base::string16& text,
    const std::vector<ui::ImeTextSpan>& ime_text_spans,
    const gfx::Range& replacement_range,
    int selection_start,
    int selection_end) {
  if (auto* widget_host = GetWidgetForIme()) {
    widget_host->ImeSetComposition(text, ime_text_spans, replacement_range,
                                   selection_start, selection_end);
  }
}

void ApplicationWindowHostViewMac::OnNSViewImeCommitText(
    const base::string16& text,
    const gfx::Range& replacement_range) {
  if (auto* widget_host = GetWidgetForIme()) {
    widget_host->ImeCommitText(text, std::vector<ui::ImeTextSpan>(),
                               replacement_range, 0);
  }
}

void ApplicationWindowHostViewMac::OnNSViewImeFinishComposingText() {
  if (auto* widget_host = GetWidgetForIme()) {
    widget_host->ImeFinishComposingText(false);
  }
}

void ApplicationWindowHostViewMac::OnNSViewImeCancelComposition() {
  if (auto* widget_host = GetWidgetForIme()) {
    widget_host->ImeCancelComposition();
  }
}

void ApplicationWindowHostViewMac::OnNSViewLookUpDictionaryOverlayFromRange(
    const gfx::Range& range) {
  content::ApplicationWindowHostView* focused_view =
      GetFocusedViewForTextSelection();
  if (!focused_view)
    return;

  ApplicationWindowHost* widget_host =
      ApplicationWindowHost::From(focused_view->GetApplicationWindowHost());
  if (!widget_host)
    return;

  int32_t target_widget_process_id = widget_host->GetProcess()->GetID();
  int32_t target_widget_routing_id = widget_host->GetRoutingID();
  TextInputClientMac::GetInstance()->GetStringFromRange(
      widget_host, range,
      base::BindOnce(&ApplicationWindowHostViewMac::OnGotStringForDictionaryOverlay,
                     weak_factory_.GetWeakPtr(), target_widget_process_id,
                     target_widget_routing_id));
}

void ApplicationWindowHostViewMac::OnNSViewLookUpDictionaryOverlayAtPoint(
    const gfx::PointF& root_point) {
  if (!host() || !host()->delegate() ||
      !host()->delegate()->GetInputEventRouter())
    return;

  gfx::PointF transformed_point;
  ApplicationWindowHost* widget_host =
      host()->delegate()->GetInputEventRouter()->GetApplicationWindowHostAtPoint(
          this, root_point, &transformed_point);
  if (!widget_host)
    return;

  int32_t target_widget_process_id = widget_host->GetProcess()->GetID();
  int32_t target_widget_routing_id = widget_host->GetRoutingID();
  TextInputClientMac::GetInstance()->GetStringAtPoint(
      widget_host, gfx::ToFlooredPoint(transformed_point),
      base::BindOnce(&ApplicationWindowHostViewMac::OnGotStringForDictionaryOverlay,
                     weak_factory_.GetWeakPtr(), target_widget_process_id,
                     target_widget_routing_id));
}

void ApplicationWindowHostViewMac::OnNSViewSyncGetTextInputType(
    ui::TextInputType* text_input_type) {
  *text_input_type = GetTextInputType();
}

void ApplicationWindowHostViewMac::OnNSViewSyncGetCharacterIndexAtPoint(
    const gfx::PointF& root_point,
    uint32_t* index) {
  *index = UINT32_MAX;

  if (!host() || !host()->delegate() ||
      !host()->delegate()->GetInputEventRouter())
    return;

  gfx::PointF transformed_point;
  ApplicationWindowHost* widget_host =
      host()->delegate()->GetInputEventRouter()->GetApplicationWindowHostAtPoint(
          this, root_point, &transformed_point);
  if (!widget_host)
    return;

  *index = TextInputClientMac::GetInstance()->GetCharacterIndexAtPoint(
      widget_host, gfx::ToFlooredPoint(transformed_point));
}

void ApplicationWindowHostViewMac::OnNSViewSyncGetFirstRectForRange(
    const gfx::Range& requested_range,
    gfx::Rect* rect,
    gfx::Range* actual_range,
    bool* success) {
  if (!GetFocusedWidget()) {
    *success = false;
    return;
  }
  *success = true;
  if (!GetCachedFirstRectForCharacterRange(requested_range, rect,
                                           actual_range)) {
    *rect = TextInputClientMac::GetInstance()->GetFirstRectForRange(
        GetFocusedWidget(), requested_range);
    // TODO(thakis): Pipe |actualRange| through TextInputClientMac machinery.
    *actual_range = requested_range;
  }
}

void ApplicationWindowHostViewMac::OnNSViewExecuteEditCommand(
    const std::string& command) {
  if (host()->delegate()) {
    host()->delegate()->ExecuteEditCommand(command, base::nullopt);
  }
}

void ApplicationWindowHostViewMac::OnNSViewUndo() {
  WebContents* web_contents = GetWebContents();
  if (web_contents)
    web_contents->Undo();
}

void ApplicationWindowHostViewMac::OnNSViewRedo() {
  WebContents* web_contents = GetWebContents();
  if (web_contents)
    web_contents->Redo();
}

void ApplicationWindowHostViewMac::OnNSViewCut() {
  if (auto* delegate = GetFocusedApplicationWindowHostDelegate()) {
    delegate->Cut();
  }
}

void ApplicationWindowHostViewMac::OnNSViewCopy() {
  if (auto* delegate = GetFocusedApplicationWindowHostDelegate()) {
    delegate->Copy();
  }
}

void ApplicationWindowHostViewMac::OnNSViewCopyToFindPboard() {
  WebContents* web_contents = GetWebContents();
  if (web_contents)
    web_contents->CopyToFindPboard();
}

void ApplicationWindowHostViewMac::OnNSViewPaste() {
  if (auto* delegate = GetFocusedApplicationWindowHostDelegate()) {
    delegate->Paste();
  }
}

void ApplicationWindowHostViewMac::OnNSViewPasteAndMatchStyle() {
  WebContents* web_contents = GetWebContents();
  if (web_contents)
    web_contents->PasteAndMatchStyle();
}

void ApplicationWindowHostViewMac::OnNSViewSelectAll() {
  if (auto* delegate = GetFocusedApplicationWindowHostDelegate()) {
    delegate->SelectAll();
  }
}

void ApplicationWindowHostViewMac::OnNSViewSyncIsSpeaking(bool* is_speaking) {
  *is_speaking = ui::TextServicesContextMenu::IsSpeaking();
}

void ApplicationWindowHostViewMac::OnNSViewSpeakSelection() {
  ApplicationWindowHostView* target = this;
  WebContents* web_contents = GetWebContents();
  if (web_contents) {
    content::BrowserPluginGuestManager* guest_manager =
        web_contents->GetApplicationContents()->GetGuestManager();
    if (guest_manager) {
      content::WebContents* guest =
          guest_manager->GetFullPageGuest(web_contents);
      if (guest) {
        target = guest->GetApplicationWindowHostView();
      }
    }
  }
  target->SpeakSelection();
}

void ApplicationWindowHostViewMac::OnNSViewStopSpeaking() {
  ui::TextServicesContextMenu::StopSpeaking();
}

void ApplicationWindowHostViewMac::OnGotStringForDictionaryOverlay(
    int32_t target_widget_process_id,
    int32_t target_widget_routing_id,
    const mac::AttributedStringCoder::EncodedString& encoded_string,
    gfx::Point baseline_point) {
  if (encoded_string.string().empty()) {
    // The PDF plugin does not support getting the attributed string at point.
    // Until it does, use NSPerformService(), which opens Dictionary.app.
    // TODO(shuchen): Support GetStringAtPoint() & GetStringFromRange() for PDF.
    // https://crbug.com/152438
    // This often just opens a blank dictionary, not the definition of |string|.
    // https://crbug.com/830047
    // This path will be taken, inappropriately, when a lookup gesture was
    // performed at a location that doesn't have text, but some text is
    // selected.
    // https://crbug.com/830906
    if (auto* selection = GetTextSelection()) {
      const base::string16& selected_text = selection->selected_text();
      NSString* ns_selected_text = base::SysUTF16ToNSString(selected_text);
      if ([ns_selected_text length] == 0)
        return;
      scoped_refptr<ui::UniquePasteboard> pasteboard = new ui::UniquePasteboard;
      NSArray* types = [NSArray arrayWithObject:NSStringPboardType];
      [pasteboard->get() declareTypes:types owner:nil];
      if ([pasteboard->get() setString:ns_selected_text
                               forType:NSStringPboardType]) {
        NSPerformService(@"Look Up in Dictionary", pasteboard->get());
      }
    }
  } else {
    // By the time we get here |widget_host| might have been destroyed.
    // https://crbug.com/737032
    auto* widget_host = content::ApplicationWindowHost::FromID(
        target_widget_process_id, target_widget_routing_id);
    if (widget_host) {
      if (auto* rwhv = widget_host->GetView())
        baseline_point = rwhv->TransformPointToRootCoordSpace(baseline_point);
    }
    ns_view_bridge_->ShowDictionaryOverlay(encoded_string, baseline_point);
  }
}

Class GetApplicationWindowHostViewCocoaClassForTesting() {
  return [ApplicationWindowHostViewCocoa class];
}

}  // namespace host
