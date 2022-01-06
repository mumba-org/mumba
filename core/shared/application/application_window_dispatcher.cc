// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/application_window_dispatcher.h"

#define INSIDE_BLINK 1

#include "base/strings/utf_string_conversions.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/child_url_loader_factory_bundle.h"
#include "core/shared/common/media/media_player_delegate_messages.h"
#include "cc/trees/swap_promise.h"
#include "cc/trees/latency_info_swap_promise.h"
#include "cc/trees/latency_info_swap_promise_monitor.h"
#include "cc/trees/layer_tree_host.h"
#include "third_party/blink/renderer/platform/scheduler/child/task_runner_impl.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_widget.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "runtime/MumbaShims/CompositorHelper.h"

namespace application {

// WARNING: this is a redecl.. we need to create a internal
// header at least to stop doing this

typedef void(*CLayerTreeHostRequestPresentationCallback)(void *peer, int64_t, int64_t, uint32_t);

struct _LayerTreeHost {
 std::unique_ptr<cc::LayerTreeHost> handle;
 cc::LayerTreeHost* raw;
 std::unique_ptr<CompositorLayerTreeHostClient> client;
 bool owned;
 CLayerTreeHostRequestPresentationCallback request_presentation_callback;
 void* request_presentation_state;

 _LayerTreeHost(std::unique_ptr<cc::LayerTreeHost> ptr, std::unique_ptr<CompositorLayerTreeHostClient> cli):
    handle(std::move(ptr)),
    client(std::move(cli)),
    owned(true),
    request_presentation_callback(nullptr),
    request_presentation_state(nullptr) {}

 _LayerTreeHost(cc::LayerTreeHost* ptr): raw(ptr), owned(false), request_presentation_callback(nullptr), request_presentation_state(nullptr) {}

 void OnRequestPresentation(base::TimeTicks a, base::TimeDelta b, uint32_t c) {
   if (request_presentation_callback) {
     request_presentation_callback(request_presentation_state, a.ToInternalValue(), b.InMilliseconds(), c);
   }
 }

};

ApplicationWindowDispatcher::ApplicationWindowDispatcher(
  ApplicationThread* thread,
  CWindowCallbacks handler, 
  void* instance): 
 main_thread_(thread),
 handler_(std::move(handler)),
 instance_(instance),
 window_binding_(this),
 window_input_binding_(this) {//,
// frame_input_binding_(this) {

}

ApplicationWindowDispatcher::~ApplicationWindowDispatcher() {
  
}

void ApplicationWindowDispatcher::BindApplicationWindow(
  common::mojom::ApplicationWindowAssociatedRequest request) {
  //DLOG(INFO) << "BindApplicationWindow";
  window_binding_.Bind(std::move(request));
}

void ApplicationWindowDispatcher::AddObserver(ApplicationWindowDispatcherObserver* observer) {
  observers_.AddObserver(observer);
  //observer->RegisterMojoInterfaces(main_thread()->GetAssociatedInterfaceRegistry());
}

void ApplicationWindowDispatcher::RemoveObserver(ApplicationWindowDispatcherObserver* observer) {
  //observer->UnregisterMojoInterfaces(main_thread()->GetAssociatedInterfaceRegistry());
  observers_.RemoveObserver(observer);
}

// void ApplicationWindowDispatcher::BindSourceInfo(
//     const service_manager::BindSourceInfo& host_info) {
//   //DLOG(INFO) << "ApplicationWindowDispatcher::BindSourceInfo: setting host_info";
//   host_info_ = host_info;
// }

void ApplicationWindowDispatcher::BindWindowInputHandler(common::mojom::WindowInputHandlerAssociatedRequest request) {
  //DLOG(INFO) << "BindWindowInputHandler";
  window_input_binding_.Bind(std::move(request));
}

// void ApplicationWindowDispatcher::BindFrameInputHandler(common::mojom::FrameInputHandlerAssociatedRequest request) {
//   frame_input_binding_.Bind(std::move(request));
// }

void ApplicationWindowDispatcher::SetPageScale(float page_scale_factor) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetPageScaleImpl, base::Unretained(this), page_scale_factor));
}
void ApplicationWindowDispatcher::SetInitialFocus(bool reverse) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetInitialFocusImpl, base::Unretained(this), reverse));
}

void ApplicationWindowDispatcher::UpdateTargetURLAck() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::UpdateTargetURLAckImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::UpdateWebPreferences(const common::WebPreferences& preferences) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::UpdateWebPreferencesImpl, base::Unretained(this), preferences));
}

void ApplicationWindowDispatcher::ClosePage() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ClosePageImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::MoveOrResizeStarted() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::MoveOrResizeStartedImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::SetBackgroundOpaque(bool opaque) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetBackgroundOpaqueImpl, base::Unretained(this), opaque));
}

void ApplicationWindowDispatcher::EnablePreferredSizeChangedMode() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::EnablePreferredSizeChangedModeImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::DisableScrollbarsForSmallWindows(const gfx::Size& disable_scrollbar_size_limit) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DisableScrollbarsForSmallWindowsImpl, base::Unretained(this), disable_scrollbar_size_limit));
}

void ApplicationWindowDispatcher::SetRendererPrefs(const common::RendererPreferences& prefs) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetRendererPrefsImpl, base::Unretained(this), prefs));
}
void ApplicationWindowDispatcher::SetActive(bool active) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetActiveImpl, base::Unretained(this), active));
}
void ApplicationWindowDispatcher::ForceRedraw(const ui::LatencyInfo& latency_info) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ForceRedrawImpl, base::Unretained(this), latency_info));
}
void ApplicationWindowDispatcher::SelectWordAroundCaret() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SelectWordAroundCaretImpl, base::Unretained(this)));
}
void ApplicationWindowDispatcher::UpdateWindowScreenRect(const gfx::Rect& window_screen_rect) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::UpdateWindowScreenRectImpl, base::Unretained(this), window_screen_rect));
}
void ApplicationWindowDispatcher::SetZoomLevel(double zoom_level) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetZoomLevelImpl, base::Unretained(this), zoom_level));
}
void ApplicationWindowDispatcher::PageWasHidden() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::PageWasHiddenImpl, base::Unretained(this)));
}
void ApplicationWindowDispatcher::PageWasShown() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::PageWasShownImpl, base::Unretained(this)));
}
void ApplicationWindowDispatcher::SetHistoryOffsetAndLength(int32_t history_offset, int32_t history_length) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetHistoryOffsetAndLengthImpl, base::Unretained(this), history_offset, history_length));
}
void ApplicationWindowDispatcher::AudioStateChanged(bool is_audio_playing) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::AudioStateChangedImpl, base::Unretained(this), is_audio_playing));
}
void ApplicationWindowDispatcher::PausePageScheduledTasks(bool pause) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::PausePageScheduledTasksImpl, base::Unretained(this), pause));
}

void ApplicationWindowDispatcher::UpdateScreenInfo(const common::ScreenInfo& screen_info) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::UpdateScreenInfoImpl, base::Unretained(this), screen_info));
}
void ApplicationWindowDispatcher::FreezePage() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::FreezePageImpl, base::Unretained(this)));
}
void ApplicationWindowDispatcher::ShowContextMenu(common::mojom::MenuSourceType type, const gfx::Point& location) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ShowContextMenuImpl, base::Unretained(this), type, location));
}

void ApplicationWindowDispatcher::Close() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CloseImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::WasHidden() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::WasHiddenImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::WasShown(bool needs_repainting, const ui::LatencyInfo& latency_info) {
   //main_thread_->main_thread_runner()->PostTask(
   // FROM_HERE, 
   // base::BindOnce(&ApplicationWindowDispatcher::WasShownImpl, base::Unretained(this), needs_repainting, latency_info));
  WasShownImpl(needs_repainting, latency_info);
}

void ApplicationWindowDispatcher::Repaint(const gfx::Size& size) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::Repaint, base::Unretained(this), size));
}

void ApplicationWindowDispatcher::SetTextDirection(base::i18n::TextDirection direction) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetTextDirectionImpl, base::Unretained(this), direction));
}

void ApplicationWindowDispatcher::MoveAck() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::MoveAckImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::UpdateScreenRects(const gfx::Rect& view_screen_rect, const gfx::Rect& window_screen_rect) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::UpdateScreenRectsImpl, base::Unretained(this), view_screen_rect, window_screen_rect));
}

void ApplicationWindowDispatcher::SetViewportIntersection(const gfx::Rect& intersection, const gfx::Rect& visible_rect) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetViewportIntersectionImpl, base::Unretained(this), intersection, visible_rect));
}

void ApplicationWindowDispatcher::SetIsInert(bool inert) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetIsInertImpl, base::Unretained(this), inert));
}

void ApplicationWindowDispatcher::UpdateRenderThrottlingStatus(bool is_throttled, bool subtree_throttled) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::UpdateRenderThrottlingStatusImpl, base::Unretained(this), is_throttled, subtree_throttled));
}

void ApplicationWindowDispatcher::DragTargetDragEnter(const std::vector<common::DropDataMetadata>& drop_data,
                         const gfx::PointF& client_pt,
                         const gfx::PointF& screen_pt,
                         blink::WebDragOperation ops_allowed,
                         int32_t key_modifiers) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DragTargetDragEnterImpl, base::Unretained(this), drop_data, client_pt, screen_pt, ops_allowed, key_modifiers));
}

void ApplicationWindowDispatcher::DragTargetDragOver(const gfx::PointF& client_pt,
                        const gfx::PointF& screen_pt,
                        blink::WebDragOperation ops_allowed,
                        int32_t key_modifiers) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DragTargetDragOverImpl, base::Unretained(this), client_pt, screen_pt, ops_allowed, key_modifiers));
}

void ApplicationWindowDispatcher::DragTargetDragLeave(const gfx::PointF& client_point, const gfx::PointF& screen_point) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DragTargetDragLeaveImpl, base::Unretained(this), client_point, screen_point)); 
}

void ApplicationWindowDispatcher::DragTargetDrop(const common::DropData& drop_data,
                    const gfx::PointF& client_pt,
                    const gfx::PointF& screen_pt,
                    int32_t key_modifiers) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DragTargetDropImpl, base::Unretained(this), drop_data, client_pt, screen_pt, key_modifiers));
}

void ApplicationWindowDispatcher::DragSourceEnded(const gfx::PointF& client_pt,
                     const gfx::PointF& screen_pt,
                     blink::WebDragOperation drag_operations) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DragSourceEndedImpl, base::Unretained(this), client_pt, screen_pt, drag_operations));
}

void ApplicationWindowDispatcher::DragSourceSystemDragEnded() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DragSourceSystemDragEndedImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::SynchronizeVisualProperties(const common::VisualProperties& params) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SynchronizeVisualPropertiesImpl, base::Unretained(this), params));
}

void ApplicationWindowDispatcher::MediaPlayerActionAt(const gfx::Point& location, blink::WebMediaPlayerAction action) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::MediaPlayerActionAtImpl, base::Unretained(this), location, action));
}

void ApplicationWindowDispatcher::SetFocusedWindow() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetFocusedWindowImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::LockMouseAck(bool succeeded) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::LockMouseAckImpl, base::Unretained(this), succeeded));
}

void ApplicationWindowDispatcher::MouseLockLost() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::MouseLockLostImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::SetupWindowInputHandler(common::mojom::WindowInputHandlerRequest request, common::mojom::WindowInputHandlerHostPtr host) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetupWindowInputHandlerImpl, base::Unretained(this), base::Passed(std::move(request)), base::Passed(std::move(host))));
}

void ApplicationWindowDispatcher::SwapOut(int32_t window_id, bool is_loading) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SwapOutImpl, base::Unretained(this), window_id, is_loading));
}
void ApplicationWindowDispatcher::GetWebApplicationInfo(GetWebApplicationInfoCallback callback) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::GetWebApplicationInfoImpl, base::Unretained(this), base::Passed(std::move(callback))));
}

void ApplicationWindowDispatcher::IntrinsicSizingInfoOfChildChanged(const gfx::SizeF& size, const gfx::SizeF& aspect_ratio, bool has_width, bool has_height) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::IntrinsicSizingInfoOfChildChangedImpl, base::Unretained(this), size, aspect_ratio, has_width, has_height));
}

void ApplicationWindowDispatcher::BeforeUnload(bool is_reload) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::BeforeUnloadImpl, base::Unretained(this), is_reload));
}

void ApplicationWindowDispatcher::ViewChanged(const base::Optional<viz::FrameSinkId>& frame_sink_id) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ViewChangedImpl, base::Unretained(this), frame_sink_id));
}

void ApplicationWindowDispatcher::SetChildFrameSurface(const viz::SurfaceInfo& surface_info) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetChildFrameSurfaceImpl, base::Unretained(this), surface_info));
}

void ApplicationWindowDispatcher::ChildFrameProcessGone() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ChildFrameProcessGoneImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::SwapIn() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SwapInImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::FrameDelete() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::FrameDeleteImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::Stop() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::StopImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::DroppedNavigation() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DroppedNavigationImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::DidStartLoading() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DidStartLoadingImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::DidStopLoading() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DidStopLoadingImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::Collapse(bool collapsed) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CollapseImpl, base::Unretained(this), collapsed));
}

void ApplicationWindowDispatcher::WillEnterFullscreen() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::WillEnterFullscreenImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::EnableAutoResize(const gfx::Size& min_size, const gfx::Size& max_size) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::EnableAutoResizeImpl, base::Unretained(this), min_size, max_size));
}

void ApplicationWindowDispatcher::DisableAutoResize() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DisableAutoResizeImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::ContextMenuClosed() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ContextMenuClosedImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::CustomContextMenuAction(uint32_t action) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CustomContextMenuActionImpl, base::Unretained(this), action));
}

void ApplicationWindowDispatcher::VisualStateRequest(uint64_t id) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::VisualStateRequestImpl, base::Unretained(this), id));
}

void ApplicationWindowDispatcher::DispatchLoad() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DispatchLoadImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::Reload(bool bypass_cache) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ReloadImpl, base::Unretained(this), bypass_cache));
}

void ApplicationWindowDispatcher::ReloadLoFiImages() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ReloadLoFiImagesImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::SnapshotAccessibilityTree() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SnapshotAccessibilityTreeImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::UpdateOpener(int32_t opener_routing_id) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::UpdateOpenerImpl, base::Unretained(this), opener_routing_id));
}

void ApplicationWindowDispatcher::SetFocusedFrame() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetFocusedFrameImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::CheckCompleted() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CheckCompletedImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::PostMessageEvent() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::PostMessageEventImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::NotifyUserActivation() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::NotifyUserActivationImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::DidUpdateOrigin(const GURL& origin) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DidUpdateOriginImpl, base::Unretained(this), origin));
}

void ApplicationWindowDispatcher::CopyImageAt(float x, float y) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CopyImageAtImpl, base::Unretained(this), x, y));
}

void ApplicationWindowDispatcher::SaveImageAt(float x, float y) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SaveImageAtImpl, base::Unretained(this), x, y));
}

void ApplicationWindowDispatcher::ScrollRectToVisible(const gfx::Rect& rect_to_scroll) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ScrollRectToVisibleImpl, base::Unretained(this), rect_to_scroll));
}

void ApplicationWindowDispatcher::TextSurroundingSelectionRequest(uint32_t max_length) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::TextSurroundingSelectionRequestImpl, base::Unretained(this), max_length));
}

void ApplicationWindowDispatcher::AdvanceFocus(::common::mojom::FocusType type, int32_t source_routing_id) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::AdvanceFocusImpl, base::Unretained(this), type, source_routing_id));
}

void ApplicationWindowDispatcher::AdvanceFocusInForm(::common::mojom::FocusType type) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::AdvanceFocusInFormImpl, base::Unretained(this), type));
}

void ApplicationWindowDispatcher::Find(int32_t request_id, const base::string16& search_text, ::common::mojom::FindOptionsPtr options) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::FindImpl, base::Unretained(this),
      request_id, search_text, base::Passed(std::move(options))));
}

void ApplicationWindowDispatcher::ClearActiveFindMatch() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ClearActiveFindMatchImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::StopFinding(::common::mojom::StopFindAction action) {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::StopFindingImpl, base::Unretained(this), action));
}

void ApplicationWindowDispatcher::ClearFocusedElement() {
   main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ClearFocusedElementImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::SetOverlayRoutingToken(const base::UnguessableToken& token) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetOverlayRoutingTokenImpl, base::Unretained(this), token));
}

void ApplicationWindowDispatcher::OnNetworkConnectionChanged(
    net::NetworkChangeNotifier::ConnectionType type,
    double max_bandwidth_mbps) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::OnNetworkConnectionChangedImpl, base::Unretained(this), type, max_bandwidth_mbps)); 
}

void ApplicationWindowDispatcher::SetFocus(bool focused) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetFocusImpl, base::Unretained(this), focused));
}

void ApplicationWindowDispatcher::MouseCaptureLost() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::MouseCaptureLostImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::SetEditCommandsForNextKeyEvent(const std::vector<common::EditCommand>& commands) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetEditCommandsForNextKeyEventImpl, base::Unretained(this), commands));
}

void ApplicationWindowDispatcher::CursorVisibilityChanged(bool visible) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CursorVisibilityChangedImpl, base::Unretained(this), visible)); 
}

void ApplicationWindowDispatcher::ImeSetComposition(
  const base::string16& text, 
  const std::vector<ui::ImeTextSpan>& ime_text_spans, 
  const gfx::Range& range, 
  int32_t start, 
  int32_t end) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ImeSetCompositionImpl, 
      base::Unretained(this), 
      text,
      ime_text_spans,
      range,
      start,
      end)); 
}

void ApplicationWindowDispatcher::ImeCommitText(
  const base::string16& text, 
  const std::vector<ui::ImeTextSpan>& ime_text_spans, 
  const gfx::Range& range,
  int32_t relative_cursor_position) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ImeCommitTextImpl, 
      base::Unretained(this), 
      text,
      ime_text_spans,
      range,
      relative_cursor_position));
}

void ApplicationWindowDispatcher::ImeFinishComposingText(bool keep_selection) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ImeFinishComposingTextImpl, base::Unretained(this), keep_selection));
}

void ApplicationWindowDispatcher::RequestTextInputStateUpdate() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::RequestTextInputStateUpdateImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::RequestCompositionUpdates(bool immediate_request, bool monitor_request) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::RequestCompositionUpdatesImpl, base::Unretained(this), immediate_request, monitor_request));
} 

void ApplicationWindowDispatcher::DispatchEvent(std::unique_ptr<common::InputEvent> event, DispatchEventCallback callback)  {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowDispatcher::DispatchEventImpl, 
      base::Unretained(this), 
      base::Passed(std::move(event)), 
      base::Passed(std::move(callback))));
}

void ApplicationWindowDispatcher::DispatchNonBlockingEvent(std::unique_ptr<common::InputEvent> event) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DispatchNonBlockingEventImpl, base::Unretained(this), base::Passed(std::move(event))));
}

void ApplicationWindowDispatcher::SetCompositionFromExistingText(int32_t start, int32_t end, const std::vector<ui::ImeTextSpan>& ime_text_spans) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetCompositionFromExistingTextImpl, base::Unretained(this), start, end, ime_text_spans));
}

void ApplicationWindowDispatcher::ExtendSelectionAndDelete(int32_t before, int32_t after) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ExtendSelectionAndDeleteImpl, base::Unretained(this), before, after));
}

void ApplicationWindowDispatcher::DeleteSurroundingText(int32_t before, int32_t after) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DeleteSurroundingTextImpl, base::Unretained(this), before, after));
} 

void ApplicationWindowDispatcher::DeleteSurroundingTextInCodePoints(int32_t before, int32_t after) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DeleteSurroundingTextInCodePointsImpl, base::Unretained(this), before, after));
}

void ApplicationWindowDispatcher::SetEditableSelectionOffsets(int32_t start, int32_t end) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SetEditableSelectionOffsetsImpl, base::Unretained(this), start, end));
}

void ApplicationWindowDispatcher::ExecuteEditCommand(const std::string& command, const base::Optional<base::string16>& value) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ExecuteEditCommandImpl, base::Unretained(this), command, value));
}

void ApplicationWindowDispatcher::Undo() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::UndoImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::Redo() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::RedoImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::Cut() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CutImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::Copy() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CopyImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::CopyToFindPboard() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CopyToFindPboardImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::Paste() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::PasteImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::PasteAndMatchStyle() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::PasteAndMatchStyleImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::Delete() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::DeleteImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::SelectAll() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SelectAllImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::CollapseSelection() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CollapseSelectionImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::Replace(const base::string16& word) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ReplaceImpl, base::Unretained(this), word));
}

void ApplicationWindowDispatcher::ReplaceMisspelling(const base::string16& word) { 
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ReplaceMisspellingImpl, base::Unretained(this), word));
}

void ApplicationWindowDispatcher::SelectRange(const gfx::Point& base, const gfx::Point& extent) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::SelectRangeImpl, base::Unretained(this), base, extent));
}

void ApplicationWindowDispatcher::AdjustSelectionByCharacterOffset(int32_t start, int32_t end, ::blink::mojom::SelectionMenuBehavior behavior) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::AdjustSelectionByCharacterOffsetImpl, base::Unretained(this), start, end, behavior));
}

void ApplicationWindowDispatcher::MoveRangeSelectionExtent(const gfx::Point& extent) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::MoveRangeSelectionExtentImpl, base::Unretained(this), extent));
}

void ApplicationWindowDispatcher::ScrollFocusedEditableNodeIntoRect(const gfx::Rect& rect) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::ScrollFocusedEditableNodeIntoRectImpl, base::Unretained(this), rect));
}

void ApplicationWindowDispatcher::MoveCaret(const gfx::Point& point) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::MoveCaretImpl, base::Unretained(this), point));
}

void ApplicationWindowDispatcher::CommitNavigation(common::mojom::CommitNavigationParamsPtr params, std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories, common::mojom::ControllerServiceWorkerInfoPtr controller_service_worker) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CommitNavigationImpl, 
      base::Unretained(this),
      base::Passed(std::move(params)),
      base::Passed(std::move(subresource_loader_factories)))); 
}

void ApplicationWindowDispatcher::CommitSameDocumentNavigation(common::mojom::CommitNavigationParamsPtr params, std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories, common::mojom::ControllerServiceWorkerInfoPtr controller_service_worker, CommitSameDocumentNavigationCallback callback) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CommitSameDocumentNavigationImpl, 
      base::Unretained(this), base::Passed(std::move(params)), base::Passed(std::move(subresource_loader_factories)), base::Passed(std::move(callback)))); 
}

void ApplicationWindowDispatcher::CommitFailedNavigation() {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::CommitFailedNavigationImpl, base::Unretained(this)));
}

void ApplicationWindowDispatcher::GetWindowInputHandler(common::mojom::WindowInputHandlerAssociatedRequest interface_request, common::mojom::WindowInputHandlerHostPtr host) {
  main_thread_->main_thread_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowDispatcher::GetWindowInputHandlerImpl, base::Unretained(this), base::Passed(std::move(interface_request)), base::Passed(std::move(host)))); 
}

void ApplicationWindowDispatcher::SetPageScaleImpl(float page_scale_factor) {
  //DLOG(INFO) << "SetPageScale";
  handler_.SetPageScale(instance_, page_scale_factor);
}

void ApplicationWindowDispatcher::SetInitialFocusImpl(bool reverse) {
  //DLOG(INFO) << "SetInitialFocus";
  handler_.SetInitialFocus(instance_, reverse);
}

void ApplicationWindowDispatcher::UpdateTargetURLAckImpl() {
  //DLOG(INFO) << "UpdateTargetURLAck";
  handler_.UpdateTargetURLAck(instance_);
}

void ApplicationWindowDispatcher::UpdateWebPreferencesImpl(const common::WebPreferences& preferences) {
  //DLOG(INFO) << "UpdateWebPreferences";
  handler_.UpdateWebPreferences(instance_, nullptr);//preferences);
}

void ApplicationWindowDispatcher::ClosePageImpl() {
  //DLOG(INFO) << "ClosePage";
  handler_.ClosePage(instance_);
}

void ApplicationWindowDispatcher::MoveOrResizeStartedImpl() {
  //DLOG(INFO) << "MoveOrResizeStarted";
  handler_.MoveOrResizeStarted(instance_);
}

void ApplicationWindowDispatcher::SetBackgroundOpaqueImpl(bool opaque) {
  //DLOG(INFO) << "SetBackgroundOpaque";
  handler_.SetBackgroundOpaque(instance_, opaque);
}

void ApplicationWindowDispatcher::EnablePreferredSizeChangedModeImpl() {
  //DLOG(INFO) << "EnablePreferredSizeChangedMode";
  handler_.EnablePreferredSizeChangedMode(instance_);
}

void ApplicationWindowDispatcher::DisableScrollbarsForSmallWindowsImpl(const gfx::Size& disable_scrollbar_size_limit) {
  //DLOG(INFO) << "DisableScrollbarsForSmallWindows";
  handler_.DisableScrollbarsForSmallWindows(instance_, disable_scrollbar_size_limit.width(), disable_scrollbar_size_limit.height());
}

void ApplicationWindowDispatcher::SetRendererPrefsImpl(const common::RendererPreferences& prefs) {
  //DLOG(INFO) << "SetRendererPrefs";
  handler_.SetRendererPrefs(instance_, nullptr);//prefs);
}

void ApplicationWindowDispatcher::SetActiveImpl(bool active) {
  //DLOG(INFO) << "SetActive";
  handler_.SetActive(instance_, active);
}

void ApplicationWindowDispatcher::ForceRedrawImpl(const ui::LatencyInfo& latency_info) {
  //DLOG(INFO) << "ForceRedrawImpl";
  int component_types[latency_info.latency_components().size()];
  int64_t event_time[latency_info.latency_components().size()];
  
  size_t index = 0;
  for (auto it = latency_info.latency_components().begin(); it != latency_info.latency_components().end(); ++it) {
    component_types[index] = static_cast<int>(it->first);
    event_time[index] = it->second.ToInternalValue();
    index++;
  }
  
  handler_.ForceRedraw(
    instance_, 
    latency_info.trace_name().c_str(), 
    latency_info.trace_id(),
    latency_info.ukm_source_id(),
    latency_info.coalesced(),
    latency_info.began(),
    latency_info.terminated(),
    latency_info.source_event_type(),
    latency_info.scroll_update_delta(),
    latency_info.predicted_scroll_update_delta(),
    latency_info.latency_components().size(),
    component_types,
    event_time);
}

void ApplicationWindowDispatcher::SelectWordAroundCaretImpl() {
  //DLOG(INFO) << "SelectWordAroundCaret";
  handler_.SelectWordAroundCaret(instance_);
}

void ApplicationWindowDispatcher::UpdateWindowScreenRectImpl(const gfx::Rect& rect) {
  handler_.UpdateWindowScreenRect(instance_, rect.x(), rect.y(), rect.width(), rect.height());
}

void ApplicationWindowDispatcher::SetZoomLevelImpl(double zoom_level) {
  //DLOG(INFO) << "SetZoomLevel";
  handler_.SetZoomLevel(instance_, zoom_level); 
}

void ApplicationWindowDispatcher::PageWasHiddenImpl() {
  handler_.PageWasHidden(instance_);
}

void ApplicationWindowDispatcher::PageWasShownImpl() {
  handler_.PageWasShown(instance_);
} 

void ApplicationWindowDispatcher::SetHistoryOffsetAndLengthImpl(int32_t history_offset, int32_t history_length) {
  //DLOG(INFO) << "SetHistoryOffsetAndLength";
  handler_.SetHistoryOffsetAndLength(instance_, history_offset, history_length);
}

void ApplicationWindowDispatcher::AudioStateChangedImpl(bool is_audio_playing) {
  //DLOG(INFO) << "AudioStateChanged";
  handler_.AudioStateChanged(instance_, is_audio_playing);
}

void ApplicationWindowDispatcher::PausePageScheduledTasksImpl(bool pause) {
  //DLOG(INFO) << "PausePageScheduledTasks";
  handler_.PausePageScheduledTasks(instance_, pause); 
}

void ApplicationWindowDispatcher::UpdateScreenInfoImpl(const common::ScreenInfo& screen_info) {
  handler_.UpdateScreenInfo(instance_, 
    screen_info.device_scale_factor, 
    screen_info.depth, 
    screen_info.depth_per_component, 
    screen_info.is_monochrome, 
    screen_info.rect.x(), screen_info.rect.y(), screen_info.rect.width(), screen_info.rect.height(),
    screen_info.available_rect.x(), screen_info.available_rect.y(), screen_info.available_rect.width(), screen_info.available_rect.height(),
    screen_info.orientation_type, screen_info.orientation_angle);
}

void ApplicationWindowDispatcher::FreezePageImpl() {
  //DLOG(INFO) << "FreezePage";
  handler_.FreezePage(instance_); 
}

void ApplicationWindowDispatcher::ShowContextMenuImpl(common::mojom::MenuSourceType type, const gfx::Point& location) {
  //DLOG(INFO) << "ShowContextMenu";
  handler_.ShowContextMenu(instance_, static_cast<int>(type), location.x(), location.y()); 
}

void ApplicationWindowDispatcher::CloseImpl() {
  //DLOG(INFO) << "Close";
  handler_.Close(instance_);  
}

void ApplicationWindowDispatcher::SynchronizeVisualPropertiesImpl(const common::VisualProperties& params) {
  handler_.SynchronizeVisualProperties(instance_,
    /*
     SurfaceId
    */
     params.local_surface_id->parent_sequence_number(),
     params.local_surface_id->child_sequence_number(),
     params.local_surface_id->embed_token().GetHighForSerialization(), 
     params.local_surface_id->embed_token().GetLowForSerialization(),
    /*
     ScreenInfo
    */
     params.screen_info.device_scale_factor,
     static_cast<uint8_t>(params.screen_info.color_space.primaries()),
     static_cast<uint8_t>(params.screen_info.color_space.transfer()),
     static_cast<uint8_t>(params.screen_info.color_space.matrix()),
     static_cast<uint8_t>(params.screen_info.color_space.range()),
     params.screen_info.color_space.icc_profile(),
     params.screen_info.depth,
     params.screen_info.depth_per_component,
     params.screen_info.is_monochrome,
     params.screen_info.rect.x(),
     params.screen_info.rect.y(),
     params.screen_info.rect.width(),
     params.screen_info.rect.height(),
     params.screen_info.available_rect.x(),
     params.screen_info.available_rect.y(),
     params.screen_info.available_rect.width(),
     params.screen_info.available_rect.height(),
     params.screen_info.orientation_type,
     params.screen_info.orientation_angle,
     params.auto_resize_enabled, 
     params.min_size_for_auto_resize.width(), 
     params.min_size_for_auto_resize.height(), 
     params.max_size_for_auto_resize.width(), 
     params.max_size_for_auto_resize.height(),
     params.new_size.width(),
     params.new_size.height(),
     params.compositor_viewport_pixel_size.width(),
     params.compositor_viewport_pixel_size.height(),
     params.visible_viewport_size.width(),
     params.visible_viewport_size.height(),
     params.capture_sequence_number);
}

void ApplicationWindowDispatcher::WasHiddenImpl() {
  //DLOG(INFO) << "WasHidden";
  handler_.WasHidden(instance_);
}

void ApplicationWindowDispatcher::WasShownImpl(bool needs_repainting, const ui::LatencyInfo& latency_info) {
  //DLOG(INFO) << "WasShownImpl";
  int component_types[latency_info.latency_components().size()];
  int64_t event_time[latency_info.latency_components().size()];
  
  size_t index = 0;
  for (auto it = latency_info.latency_components().begin(); it != latency_info.latency_components().end(); ++it) { 
    component_types[index] = static_cast<int>(it->first);
    event_time[index] = it->second.ToInternalValue();
    index++;
  }

  handler_.WasShown(
    instance_, 
    needs_repainting,
    latency_info.trace_name().c_str(), 
    latency_info.trace_id(),
    latency_info.ukm_source_id(),
    latency_info.coalesced(),
    latency_info.began(),
    latency_info.terminated(),
    latency_info.source_event_type(),
    latency_info.scroll_update_delta(),
    latency_info.predicted_scroll_update_delta(),
    latency_info.latency_components().size(),
    component_types,
    event_time);
 
  if (!needs_repainting) {
    return;
  }
  _LayerTreeHost* layer_tree_host_wrapper = reinterpret_cast<_LayerTreeHost *>(handler_.GetLayerTreeHost(instance_));

  if (!layer_tree_host_wrapper) {
    return;
  }

  ui::LatencyInfo cloned(latency_info);
  std::unique_ptr<cc::LatencyInfoSwapPromiseMonitor> swap_promise = 
  std::make_unique<cc::LatencyInfoSwapPromiseMonitor>(&cloned, layer_tree_host_wrapper->handle->GetSwapPromiseManager(), nullptr);
  layer_tree_host_wrapper->handle->SetNeedsAnimate();  
}

void ApplicationWindowDispatcher::RepaintImpl(const gfx::Size& size) {
  //DLOG(INFO) << "Repaint";
  handler_.Repaint(instance_, size.width(), size.height());
}

void ApplicationWindowDispatcher::SetTextDirectionImpl(base::i18n::TextDirection direction) {
  //DLOG(INFO) << "SetTextDirection";
  handler_.SetTextDirection(instance_, direction);
}

void ApplicationWindowDispatcher::MoveAckImpl() {
  //DLOG(INFO) << "MoveAck";
  handler_.MoveAck(instance_);
}

void ApplicationWindowDispatcher::UpdateScreenRectsImpl(const gfx::Rect& view_screen_rect, const gfx::Rect& window_screen_rect) {
  handler_.UpdateScreenRects(
    instance_,
    view_screen_rect.x(),
    view_screen_rect.y(),
    view_screen_rect.width(),
    view_screen_rect.height(),
    window_screen_rect.x(),
    window_screen_rect.y(),
    window_screen_rect.width(),
    window_screen_rect.height());
}

void ApplicationWindowDispatcher::SetViewportIntersectionImpl(const gfx::Rect& intersection, const gfx::Rect& visible_rect) {
  //DLOG(INFO) << "SetViewportIntersection";
  handler_.UpdateScreenRects(
    instance_,
    intersection.x(),
    intersection.y(),
    intersection.width(),
    intersection.height(),
    visible_rect.x(),
    visible_rect.y(),
    visible_rect.width(),
    visible_rect.height());
}

void ApplicationWindowDispatcher::SetIsInertImpl(bool inert) {
  //DLOG(INFO) << "SetIsInert";
  handler_.SetIsInert(
    instance_,
    inert);
}

void ApplicationWindowDispatcher::UpdateRenderThrottlingStatusImpl(bool is_throttled, bool subtree_throttled) {
  //DLOG(INFO) << "FreezePage";
  handler_.UpdateRenderThrottlingStatus(
    instance_,
    is_throttled,
    subtree_throttled);
}

void ApplicationWindowDispatcher::DragTargetDragEnterImpl(
    const std::vector<common::DropDataMetadata>& drop_data,
    const gfx::PointF& client_pt,
    const gfx::PointF& screen_pt,
    blink::WebDragOperation ops_allowed,
    int32_t key_modifiers) {
  //DLOG(INFO) << "DragTargetDragEnter";

  int drop_data_kind[drop_data.size()];
  const char* drop_data_mime[drop_data.size()];
  
  // we need this because of the lifetime.. or else drop_data_mime char* pointer
  // will point to a temp inside of a for loop that is gone by the time it reads it
  std::vector<std::string> drop_data_mime_str;

  const char* drop_data_filename[drop_data.size()];
  const char* drop_data_file_system_url[drop_data.size()];
                              
  for (size_t i = 0; i < drop_data.size(); ++i) {
    drop_data_kind[i] = static_cast<int>(drop_data[i].kind);
    drop_data_mime_str.push_back(base::UTF16ToASCII(drop_data[i].mime_type));
    drop_data_mime[i] = drop_data_mime_str[i].c_str();
    drop_data_filename[i] = drop_data[i].filename.value().c_str();
    drop_data_file_system_url[i] = drop_data[i].file_system_url.spec().c_str();
  }

  // Note: lifetime issues.. its only safe to consume the values inside of the
  // callback.. if theres a need to extend, theres a need of copy on the consumer side
  handler_.DragTargetDragEnter(
    instance_,
    drop_data.size(),
    drop_data_kind,
    drop_data_mime,
    drop_data_filename,
    drop_data_file_system_url,
    client_pt.x(), client_pt.y(),
    screen_pt.x(), screen_pt.y(),
    static_cast<int>(ops_allowed),
    key_modifiers);
}

void ApplicationWindowDispatcher::DragTargetDragOverImpl(const gfx::PointF& client_pt,
                        const gfx::PointF& screen_pt,
                        blink::WebDragOperation ops_allowed,
                        int32_t key_modifiers) {
  //DLOG(INFO) << "DragTargetDragOver";
  handler_.DragTargetDragOver(
    instance_,
    client_pt.x(), client_pt.y(),
    screen_pt.x(), screen_pt.y(),
    static_cast<int>(ops_allowed),
    key_modifiers);
}

void ApplicationWindowDispatcher::DragTargetDragLeaveImpl(const gfx::PointF& client_pt, const gfx::PointF& screen_pt) {
  //DLOG(INFO) << "DragTargetDragLeave";
  handler_.DragTargetDragLeave(
    instance_,
    client_pt.x(), client_pt.y(),
    screen_pt.x(), screen_pt.y());
}

void ApplicationWindowDispatcher::DragTargetDropImpl(
  const common::DropData& drop_data,
  const gfx::PointF& client_pt,
  const gfx::PointF& screen_pt,
  int32_t key_modifiers) {
  //DLOG(INFO) << "DragTargetDrop";
  std::string utf8_url_title = base::UTF16ToASCII(drop_data.url_title);
  std::string utf8_download_metadata = base::UTF16ToASCII(drop_data.download_metadata);

  const char* filenames[drop_data.filenames.size()];
  const char* file_mimes[drop_data.file_mime_types.size()];

  for (size_t i = 0; i < drop_data.filenames.size(); i++) {
     filenames[i] = drop_data.filenames[i].path.value().c_str();
  }

  for (size_t i = 0; i < drop_data.file_mime_types.size(); i++) {
    // pass the casted utf16 value 
    file_mimes[i] = reinterpret_cast<const char *>(drop_data.file_mime_types[i].data());//base::UTF16ToASCII(drop_data.file_mime_types[i]).c_str()
  }

  const char* files_url[drop_data.file_system_files.size()];
  const char* files_filesystem_id[drop_data.file_system_files.size()];
  int files_size[drop_data.file_system_files.size()]; 
  for (size_t i = 0; i < drop_data.file_system_files.size(); i++) {
    files_url[i] = drop_data.file_system_files[i].url.spec().c_str();
    files_size[i] = drop_data.file_system_files[i].size;
    files_filesystem_id[i] = drop_data.file_system_files[i].filesystem_id.c_str();
  }

  const char* drop_data_custom_data_keys[drop_data.custom_data.size()];
  const char* drop_data_custom_data_values[drop_data.custom_data.size()];

  int i = 0;
  for (auto it = drop_data.custom_data.begin(); it != drop_data.custom_data.end(); ++it) {
    drop_data_custom_data_keys[i] = reinterpret_cast<const char *>(it->first.c_str());
    drop_data_custom_data_values[i] = reinterpret_cast<const char *>(it->second.c_str());
    i++;
  }

  handler_.DragTargetDrop(
    instance_,
    drop_data.view_id,
    drop_data.did_originate_from_renderer,
    drop_data.url.spec().c_str(),
    utf8_url_title.c_str(),
    utf8_download_metadata.c_str(),
    drop_data.filenames.size(),
    filenames,
    drop_data.file_mime_types.size(),
    file_mimes,
    reinterpret_cast<const char *>(drop_data.filesystem_id.data()),
    drop_data.file_system_files.size(),
    files_url, 
    files_size,
    files_filesystem_id,
    reinterpret_cast<const char *>(drop_data.text.string().data()),
    reinterpret_cast<const char *>(drop_data.html.string().data()),
    drop_data.html_base_url.spec().c_str(),
    drop_data.file_contents.c_str(),
    drop_data.file_contents_source_url.spec().c_str(),
    drop_data.file_contents_filename_extension.c_str(),
    drop_data.file_contents_content_disposition.c_str(),
    drop_data.custom_data.size(),
    drop_data_custom_data_keys,
    drop_data_custom_data_values,
    client_pt.x(), client_pt.y(),
    screen_pt.x(), screen_pt.y(), 
    key_modifiers);
}

void ApplicationWindowDispatcher::DragSourceEndedImpl(const gfx::PointF& client_pt,
                     const gfx::PointF& screen_pt,
                     blink::WebDragOperation drag_operations) {
  //DLOG(INFO) << "DragSourceEnded";
  handler_.DragSourceEnded(instance_, client_pt.x(), client_pt.y(),
    screen_pt.x(), screen_pt.y(), static_cast<int>(drag_operations));
}

void ApplicationWindowDispatcher::DragSourceSystemDragEndedImpl() {
  //DLOG(INFO) << "DragSourceSystemDragEnded";
  handler_.DragSourceSystemDragEnded(instance_);
}

void ApplicationWindowDispatcher::MediaPlayerActionAtImpl(const gfx::Point& location, blink::WebMediaPlayerAction action) {
  //DLOG(INFO) << "MediaPlayerActionAt";
  handler_.MediaPlayerActionAt(instance_, location.x(), location.y(), static_cast<int>(action.type), action.enable ? 1 : 0); 
}

void ApplicationWindowDispatcher::SetFocusedWindowImpl() {
  //DLOG(INFO) << "SetFocusedWindow";
  handler_.SetFocusedWindow(instance_); 
}

void ApplicationWindowDispatcher::LockMouseAckImpl(bool succeeded) {
  //DLOG(INFO) << "LockMouseAck";
  handler_.LockMouseAck(instance_, succeeded);
}

void ApplicationWindowDispatcher::MouseLockLostImpl() {
  //DLOG(INFO) << "MouseLockLost";
  handler_.MouseLockLost(instance_); 
}

void ApplicationWindowDispatcher::SetupWindowInputHandlerImpl(common::mojom::WindowInputHandlerRequest request, common::mojom::WindowInputHandlerHostPtr host) {
  //DLOG(INFO) << "SetupWindowInputHandler";
  //handler_.SetupWindowInputHandler(instance_, request, host.get());
}

void ApplicationWindowDispatcher::CopyImageAtImpl(float x, float y) {
  //DLOG(INFO) << "CopyImageAt";
  handler_.CopyImageAt(instance_, x, y);
}

void ApplicationWindowDispatcher::SaveImageAtImpl(float x, float y) {
  //DLOG(INFO) << "SaveImageAt";
  handler_.SaveImageAt(instance_, x, y);
}

void ApplicationWindowDispatcher::SwapOutImpl(int32_t window_id, bool is_loading) {
  handler_.SwapOut(instance_, window_id, is_loading ? 1 : 0);
}

void ApplicationWindowDispatcher::SetFocusImpl(bool focused) {
  //DLOG(INFO) << "SetFocus";
  handler_.SetFocus(instance_, focused ? 1 : 0); 
}

void ApplicationWindowDispatcher::MouseCaptureLostImpl() {
  //DLOG(INFO) << "MouseCaptureLost";
  handler_.MouseCaptureLost(instance_);
}

void ApplicationWindowDispatcher::SetEditCommandsForNextKeyEventImpl(const std::vector<common::EditCommand>& commands) {
  //DLOG(INFO) << "SetEditCommandsForNextKeyEvent";
  const char* edit_cmd_name[commands.size()];
  const char* edit_cmd_value[commands.size()];

  for (size_t i = 0; i < commands.size(); i++) {
    edit_cmd_name[i] = commands[i].name.c_str();
    edit_cmd_value[i] = commands[i].value.c_str();
  }
    
  handler_.SetEditCommandsForNextKeyEvent(
    instance_,
    edit_cmd_name,
    edit_cmd_value,    
    commands.size());
}

void ApplicationWindowDispatcher::CursorVisibilityChangedImpl(bool visible) {
  //DLOG(INFO) << "CursorVisibilityChanged";
  handler_.CursorVisibilityChanged(instance_, visible ? 1 : 0);
}

void ApplicationWindowDispatcher::ImeSetCompositionImpl(
  const base::string16& text, 
  const std::vector<ui::ImeTextSpan>& ime_text_spans, 
  const gfx::Range& range, 
  int32_t start, 
  int32_t end) {
  //DLOG(INFO) << "ImeSetComposition";
  int tspan_type[ime_text_spans.size()];
  uint32_t tspan_start_offset[ime_text_spans.size()];
  uint32_t tspan_end_offset[ime_text_spans.size()];
  int tspan_underline_color[ime_text_spans.size()];
  int tspan_thickness[ime_text_spans.size()];
  int tspan_background_color[ime_text_spans.size()];

  for (size_t i = 0; i < ime_text_spans.size(); i++) {
    tspan_type[i] = static_cast<int>(ime_text_spans[i].type);
    tspan_start_offset[i] = ime_text_spans[i].start_offset;
    tspan_end_offset[i] = ime_text_spans[i].end_offset;
    tspan_underline_color[i] = ime_text_spans[i].underline_color;
    tspan_thickness[i] = static_cast<int>(ime_text_spans[i].thickness);
    tspan_background_color[i] = ime_text_spans[i].background_color;
  }
  
  handler_.ImeSetComposition(instance_, 
    text.data(),
    tspan_type,
    tspan_start_offset,
    tspan_end_offset,
    tspan_underline_color,
    tspan_thickness,
    tspan_background_color,
    ime_text_spans.size(),
    range.start(),
    range.end(),
    start,
    end);
}

void ApplicationWindowDispatcher::ImeCommitTextImpl(
  const base::string16& text, 
  const std::vector<ui::ImeTextSpan>& ime_text_spans, 
  const gfx::Range& range,
  int32_t relative_cursor_position) {
  //DLOG(INFO) << "ImeCommitText";
  int tspan_type[ime_text_spans.size()];
  uint32_t tspan_start_offset[ime_text_spans.size()];
  uint32_t tspan_end_offset[ime_text_spans.size()];
  int tspan_underline_color[ime_text_spans.size()];
  int tspan_thickness[ime_text_spans.size()];
  int tspan_background_color[ime_text_spans.size()];

  for (size_t i = 0; i < ime_text_spans.size(); i++) {
    tspan_type[i] = static_cast<int>(ime_text_spans[i].type);
    tspan_start_offset[i] = ime_text_spans[i].start_offset;
    tspan_end_offset[i] = ime_text_spans[i].end_offset;
    tspan_underline_color[i] = ime_text_spans[i].underline_color;
    tspan_thickness[i] = static_cast<int>(ime_text_spans[i].thickness);
    tspan_background_color[i] = ime_text_spans[i].background_color;
  }
  
  handler_.ImeCommitText(instance_, 
    text.data(),
    tspan_type,
    tspan_start_offset,
    tspan_end_offset,
    tspan_underline_color,
    tspan_thickness,
    tspan_background_color,
    ime_text_spans.size(),
    range.start(),
    range.end(),
    relative_cursor_position);
}

void ApplicationWindowDispatcher::ImeFinishComposingTextImpl(bool keep_selection) {
  //DLOG(INFO) << "ImeFinishComposingText";
  handler_.ImeFinishComposingText(instance_, keep_selection ? 1 : 0);
}

void ApplicationWindowDispatcher::RequestTextInputStateUpdateImpl() {
  //DLOG(INFO) << "RequestTextInputStateUpdate";
  handler_.RequestTextInputStateUpdate(instance_);
}

void ApplicationWindowDispatcher::RequestCompositionUpdatesImpl(bool immediate_request, bool monitor_request) {
  //DLOG(INFO) << "RequestCompositionUpdates";
  handler_.RequestCompositionUpdates(instance_, immediate_request ? 1 : 0, monitor_request ? 1 : 0);
} 

void ApplicationWindowDispatcher::DispatchEventImpl(std::unique_ptr<common::InputEvent> event, DispatchEventCallback callback)  {
  std::unique_ptr<cc::LatencyInfoSwapPromiseMonitor> swap_promise;
  ui::LatencyInfo latency_info(event->latency_info);
  latency_info.AddLatencyNumber(
      ui::LatencyComponentType::INPUT_EVENT_LATENCY_RENDERER_MAIN_COMPONENT);
  _LayerTreeHost* layer_tree_host_wrapper = reinterpret_cast<_LayerTreeHost *>(handler_.GetLayerTreeHost(instance_));
  if (layer_tree_host_wrapper) {
    swap_promise = std::make_unique<cc::LatencyInfoSwapPromiseMonitor>(&latency_info, layer_tree_host_wrapper->handle->GetSwapPromiseManager(), nullptr);
  }
  common::InputEventAckState state = static_cast<common::InputEventAckState>(handler_.DispatchEvent(instance_, event->web_event.get()));
  std::move(callback).Run(common::InputEventAckSource::MAIN_THREAD, 
                          latency_info,
                          state,
                          base::nullopt,
                          base::nullopt);
}

void ApplicationWindowDispatcher::DispatchNonBlockingEventImpl(std::unique_ptr<common::InputEvent> event) {
  //DLOG(INFO) << "DispatchNonBlockingEvent";
  handler_.DispatchNonBlockingEvent(instance_, event->web_event.get());
}

void ApplicationWindowDispatcher::SetCompositionFromExistingTextImpl(int32_t start, int32_t end, const std::vector<ui::ImeTextSpan>& ime_text_spans) {
  //DLOG(INFO) << "SetCompositionFromExistingText";
  int tspan_type[ime_text_spans.size()];
  uint32_t tspan_start_offset[ime_text_spans.size()];
  uint32_t tspan_end_offset[ime_text_spans.size()];
  int tspan_underline_color[ime_text_spans.size()];
  int tspan_thickness[ime_text_spans.size()];
  int tspan_background_color[ime_text_spans.size()];

  for (size_t i = 0; i < ime_text_spans.size(); i++) {
    tspan_type[i] = static_cast<int>(ime_text_spans[i].type);
    tspan_start_offset[i] = ime_text_spans[i].start_offset;
    tspan_end_offset[i] = ime_text_spans[i].end_offset;
    tspan_underline_color[i] = ime_text_spans[i].underline_color;
    tspan_thickness[i] = static_cast<int>(ime_text_spans[i].thickness);
    tspan_background_color[i] = ime_text_spans[i].background_color;
  }

  handler_.SetCompositionFromExistingText(instance_, 
    start, 
    end,
    tspan_type,
    tspan_start_offset,
    tspan_end_offset,
    tspan_underline_color,
    tspan_thickness,
    tspan_background_color,
    ime_text_spans.size());
}

void ApplicationWindowDispatcher::ExtendSelectionAndDeleteImpl(int32_t before, int32_t after) {
  //DLOG(INFO) << "ExtendSelectionAndDelete";
  handler_.ExtendSelectionAndDelete(instance_, before, after);
}

void ApplicationWindowDispatcher::DeleteSurroundingTextImpl(int32_t before, int32_t after) {
  //DLOG(INFO) << "DeleteSurroundingText";
  handler_.DeleteSurroundingText(instance_, before, after);
} 

void ApplicationWindowDispatcher::DeleteSurroundingTextInCodePointsImpl(int32_t before, int32_t after) {
  //DLOG(INFO) << "DeleteSurroundingTextInCodePoints";
  handler_.DeleteSurroundingTextInCodePoints(instance_, before, after);
}

void ApplicationWindowDispatcher::SetEditableSelectionOffsetsImpl(int32_t start, int32_t end) {
  //DLOG(INFO) << "SetEditableSelectionOffsets";
  handler_.SetEditableSelectionOffsets(instance_, start, end);
}

void ApplicationWindowDispatcher::ExecuteEditCommandImpl(const std::string& command, const base::Optional<base::string16>& value) {
  //DLOG(INFO) << "ExecuteEditCommand";
  handler_.ExecuteEditCommand(instance_, command.c_str(), value ? value->data() : nullptr);
}

void ApplicationWindowDispatcher::UndoImpl() {
  //DLOG(INFO) << "Undo";
  handler_.Undo(instance_);
}

void ApplicationWindowDispatcher::RedoImpl() {
  //DLOG(INFO) << "Redo";
  handler_.Redo(instance_);
}

void ApplicationWindowDispatcher::CutImpl() {
  //DLOG(INFO) << "Cut";
  handler_.Cut(instance_); 
}

void ApplicationWindowDispatcher::CopyImpl() {
  //DLOG(INFO) << "Copy";
  handler_.Copy(instance_); 
}

void ApplicationWindowDispatcher::CopyToFindPboardImpl() {
  //DLOG(INFO) << "CopyToFindPboard";
  handler_.CopyToFindPboard(instance_); 
}

void ApplicationWindowDispatcher::PasteImpl() {
  //DLOG(INFO) << "Paste";
  handler_.Paste(instance_); 
}

void ApplicationWindowDispatcher::PasteAndMatchStyleImpl() {
  //DLOG(INFO) << "PasteAndMatchStyle";
  handler_.PasteAndMatchStyle(instance_); 
}

void ApplicationWindowDispatcher::DeleteImpl() {
  //DLOG(INFO) << "Delete";
  handler_.Delete(instance_);
}

void ApplicationWindowDispatcher::SelectAllImpl() {
  //DLOG(INFO) << "SelectAll";
  handler_.SelectAll(instance_);
}

void ApplicationWindowDispatcher::CollapseSelectionImpl() {
  //DLOG(INFO) << "CollapseSelection";
  handler_.CollapseSelection(instance_);
}

void ApplicationWindowDispatcher::ReplaceImpl(const base::string16& word) {
  //DLOG(INFO) << "Replace";
  handler_.Replace(instance_, word.data());
}

void ApplicationWindowDispatcher::ReplaceMisspellingImpl(const base::string16& word) { 
  //DLOG(INFO) << "ReplaceMisspelling";
  handler_.ReplaceMisspelling(instance_, word.data());
}

void ApplicationWindowDispatcher::SelectRangeImpl(const gfx::Point& base, const gfx::Point& extent) {
  //DLOG(INFO) << "SelectRange";
  handler_.SelectRange(instance_, base.x(), base.y(), extent.x(), extent.y());
}

void ApplicationWindowDispatcher::AdjustSelectionByCharacterOffsetImpl(int32_t start, int32_t end, ::blink::mojom::SelectionMenuBehavior behavior) {
  //DLOG(INFO) << "AdjustSelectionByCharacterOffset";
  handler_.AdjustSelectionByCharacterOffset(instance_, start, end, static_cast<int>(behavior));
}

void ApplicationWindowDispatcher::MoveRangeSelectionExtentImpl(const gfx::Point& extent) {
  //DLOG(INFO) << "MoveRangeSelectionExtent";
  handler_.MoveRangeSelectionExtent(instance_, extent.x(), extent.y());
}

void ApplicationWindowDispatcher::ScrollFocusedEditableNodeIntoRectImpl(const gfx::Rect& rect) {
  //DLOG(INFO) << "ScrollFocusedEditableNodeIntoRect";
  handler_.ScrollFocusedEditableNodeIntoRect(instance_, rect.x(), rect.y(), rect.width(), rect.height());
}

void ApplicationWindowDispatcher::MoveCaretImpl(const gfx::Point& point) {
  //DLOG(INFO) << "MoveCaret";
  handler_.MoveCaret(instance_, point.x(), point.y());
}

void ApplicationWindowDispatcher::CommitNavigationImpl(common::mojom::CommitNavigationParamsPtr params, std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories) {
  //blink::TaskRunnerImpl::Create(LoadingTaskQueue(), blink::TaskType::kInternalLoading);
  // GetTaskRunner(blink::TaskType::kInternalLoading)
  loader_factories_ = base::MakeRefCounted<application::HostChildURLLoaderFactoryBundle>(
    // TODO: this is not supposed to be like this.. and maybe it will block
    // the main thread somehow..
    application::ApplicationThread::current()->main_thread_runner());

  loader_factories_->Update(
        std::make_unique<application::ChildURLLoaderFactoryBundleInfo>(std::move(subresource_loader_factories)),
        base::nullopt);

  handler_.CommitNavigation(instance_, params->url.c_str(), params->keep_alive ? 1 : 0, params->provider_id, params->route_id);
}

void ApplicationWindowDispatcher::CommitSameDocumentNavigationImpl(common::mojom::CommitNavigationParamsPtr params, std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories, CommitSameDocumentNavigationCallback callback) {
  //DLOG(INFO) << "CommitSameDocumentNavigation";
  blink::mojom::CommitResult commit_status = static_cast<blink::mojom::CommitResult>(handler_.CommitSameDocumentNavigation(instance_, params->url.c_str(), params->keep_alive ? 1 : 0, params->provider_id, params->route_id));
  std::move(callback).Run(commit_status);
}

void ApplicationWindowDispatcher::CommitFailedNavigationImpl() {
  //DLOG(INFO) << "CommitFailedNavigation";
  handler_.CommitFailedNavigation(instance_);
}

void ApplicationWindowDispatcher::GetWindowInputHandlerImpl(common::mojom::WindowInputHandlerAssociatedRequest interface_request, common::mojom::WindowInputHandlerHostPtr host) {
  //DLOG(INFO) << "GetWindowInputHandler";
}

void ApplicationWindowDispatcher::IntrinsicSizingInfoOfChildChangedImpl(const gfx::SizeF& size, const gfx::SizeF& aspect_ratio, bool has_width, bool has_height) {
  //DLOG(INFO) << "IntrinsicSizingInfoOfChildChanged";
  handler_.IntrinsicSizingInfoOfChildChanged(instance_, size.width(), size.height(), aspect_ratio.width(), aspect_ratio.height(), has_width, has_height);
}

void ApplicationWindowDispatcher::BeforeUnloadImpl(bool is_reload) {
  //DLOG(INFO) << "BeforeUnload";
  handler_.BeforeUnload(instance_, is_reload);
}

void ApplicationWindowDispatcher::ViewChangedImpl(const base::Optional<viz::FrameSinkId>& frame_sink_id) {
  //DLOG(INFO) << "ViewChanged";
  uint32_t frame_sink_id_client_id = frame_sink_id.has_value() ? frame_sink_id->client_id() : 0;
  uint32_t frame_sink_id_sink_id = frame_sink_id.has_value() ? frame_sink_id->sink_id(): 0;

  handler_.ViewChanged(instance_, frame_sink_id.has_value(), frame_sink_id_client_id, frame_sink_id_sink_id);
}

void ApplicationWindowDispatcher::SetChildFrameSurfaceImpl(const viz::SurfaceInfo& surface_info) {
  //DLOG(INFO) << "SetChildFrameSurface";
  handler_.SetChildFrameSurface(
    instance_,
    surface_info.id().frame_sink_id().client_id(),
    surface_info.id().frame_sink_id().sink_id(),
    surface_info.id().local_surface_id().parent_sequence_number(),
    surface_info.id().local_surface_id().child_sequence_number(),
    surface_info.id().local_surface_id().embed_token().GetHighForSerialization(),
    surface_info.id().local_surface_id().embed_token().GetLowForSerialization(),
    surface_info.device_scale_factor(),
    surface_info.size_in_pixels().width(),
    surface_info.size_in_pixels().height());
}

void ApplicationWindowDispatcher::ChildFrameProcessGoneImpl() {
  //DLOG(INFO) << "ChildFrameProcessGone";
  handler_.ChildFrameProcessGone(instance_);
}

void ApplicationWindowDispatcher::SwapInImpl() {
  //DLOG(INFO) << "SwapIn";
  handler_.SwapIn(instance_);
}

void ApplicationWindowDispatcher::FrameDeleteImpl() {
  //DLOG(INFO) << "FrameDelete";
  handler_.FrameDelete(instance_);
}

void ApplicationWindowDispatcher::StopImpl() {
  //DLOG(INFO) << "Stop";
  handler_.Stop(instance_);
}

void ApplicationWindowDispatcher::DroppedNavigationImpl() {
  //DLOG(INFO) << "DroppedNavigation";
  handler_.DroppedNavigation(instance_);
}

void ApplicationWindowDispatcher::DidStartLoadingImpl() {
  //DLOG(INFO) << "DidStartLoading";
  handler_.DidStartLoading(instance_);
}

void ApplicationWindowDispatcher::DidStopLoadingImpl() {
  //DLOG(INFO) << "DidStopLoading";
  handler_.DidStopLoading(instance_);
}

void ApplicationWindowDispatcher::CollapseImpl(bool collapsed) {
  //DLOG(INFO) << "Collapse";
  handler_.Collapse(instance_, collapsed);
}

void ApplicationWindowDispatcher::WillEnterFullscreenImpl() {
  //DLOG(INFO) << "WillEnterFullscreen";
  handler_.WillEnterFullscreen(instance_);
}

void ApplicationWindowDispatcher::EnableAutoResizeImpl(const gfx::Size& min_size, const gfx::Size& max_size) {
  //DLOG(INFO) << "EnableAutoResize";
  handler_.EnableAutoResize(instance_, min_size.width(), min_size.height(), max_size.width(), max_size.height());
}

void ApplicationWindowDispatcher::DisableAutoResizeImpl() {
  //DLOG(INFO) << "DisableAutoResize";
  handler_.DisableAutoResize(instance_);
}

void ApplicationWindowDispatcher::ContextMenuClosedImpl() {
  //DLOG(INFO) << "ContextMenuClosed";
  handler_.ContextMenuClosed(instance_);
}

void ApplicationWindowDispatcher::CustomContextMenuActionImpl(uint32_t action) {
  //DLOG(INFO) << "CustomContextMenuAction";
  handler_.CustomContextMenuAction(instance_, action);
}

void ApplicationWindowDispatcher::VisualStateRequestImpl(uint64_t id) {
  //DLOG(INFO) << "VisualStateRequest";
  handler_.VisualStateRequest(instance_, id);
}

void ApplicationWindowDispatcher::DispatchLoadImpl() {
  //DLOG(INFO) << "DispatchLoad";
  handler_.DispatchLoad(instance_);
}

void ApplicationWindowDispatcher::ReloadImpl(bool bypass_cache) {
  //DLOG(INFO) << "Reload";
  handler_.Reload(instance_, bypass_cache ? 1 : 0);
}

void ApplicationWindowDispatcher::ReloadLoFiImagesImpl() {
  //DLOG(INFO) << "ReloadLoFiImages";
  handler_.ReloadLoFiImages(instance_);
}

void ApplicationWindowDispatcher::SnapshotAccessibilityTreeImpl() {
  //DLOG(INFO) << "SnapshotAccessibilityTree";
  handler_.SnapshotAccessibilityTree(instance_);
}

void ApplicationWindowDispatcher::UpdateOpenerImpl(int32_t opener_routing_id) {
  //DLOG(INFO) << "UpdateOpener";
  handler_.UpdateOpener(instance_, opener_routing_id);
}

void ApplicationWindowDispatcher::SetFocusedFrameImpl() {
  //DLOG(INFO) << "SetFocusedFrame";
  handler_.SetFocusedFrame(instance_);
}

void ApplicationWindowDispatcher::CheckCompletedImpl() {
  //DLOG(INFO) << "CheckCompleted";
  handler_.CheckCompleted(instance_);
}

void ApplicationWindowDispatcher::PostMessageEventImpl() {
  //DLOG(INFO) << "PostMessageEvent";
  handler_.PostMessageEvent(instance_);
}

void ApplicationWindowDispatcher::NotifyUserActivationImpl() {
  //DLOG(INFO) << "NotifyUserActivation";
  handler_.NotifyUserActivation(instance_);
}

void ApplicationWindowDispatcher::DidUpdateOriginImpl(const GURL& origin) {
  //DLOG(INFO) << "DidUpdateOrigin";
  handler_.DidUpdateOrigin(instance_, origin.spec().c_str());
}

void ApplicationWindowDispatcher::ScrollRectToVisibleImpl(const gfx::Rect& rect_to_scroll) {
  //DLOG(INFO) << "ScrollRectToVisible";
  handler_.ScrollRectToVisible(instance_, rect_to_scroll.x(), rect_to_scroll.y(), rect_to_scroll.width(), rect_to_scroll.height());
}

void ApplicationWindowDispatcher::TextSurroundingSelectionRequestImpl(uint32_t max_length) {
  //DLOG(INFO) << "TextSurroundingSelectionRequest";
  handler_.TextSurroundingSelectionRequest(instance_, max_length);
}

void ApplicationWindowDispatcher::AdvanceFocusImpl(::common::mojom::FocusType type, int32_t source_routing_id) {
  //DLOG(INFO) << "AdvanceFocus";
  handler_.AdvanceFocus(instance_, static_cast<int>(type), source_routing_id);
}

void ApplicationWindowDispatcher::AdvanceFocusInFormImpl(::common::mojom::FocusType type) {
  //DLOG(INFO) << "AdvanceFocusInForm";
  handler_.AdvanceFocusInForm(instance_, static_cast<int>(type));
}

void ApplicationWindowDispatcher::FindImpl(int32_t request_id, const base::string16& search_text, ::common::mojom::FindOptionsPtr options) {
  //DLOG(INFO) << "Find";
  handler_.Find(instance_, 
    request_id,
    search_text.data(),   
    options->forward,
    options->match_case,
    options->find_next,
    options->word_start,
    options->medial_capital_as_word_start,
    options->force);
}

void ApplicationWindowDispatcher::ClearActiveFindMatchImpl() {
  //DLOG(INFO) << "ClearActiveFindMatch";
  handler_.ClearActiveFindMatch(instance_);
}

void ApplicationWindowDispatcher::StopFindingImpl(::common::mojom::StopFindAction action) {
  //DLOG(INFO) << "StopFinding";
  handler_.StopFinding(instance_, static_cast<int>(action));
}

void ApplicationWindowDispatcher::ClearFocusedElementImpl() {
  //DLOG(INFO) << "ClearFocusedElement";
  handler_.ClearFocusedElement(instance_);
}

void ApplicationWindowDispatcher::SetOverlayRoutingTokenImpl(const base::UnguessableToken& token) {
  //DLOG(INFO) << "SetOverlayRoutingToken";
  handler_.SetOverlayRoutingToken(instance_, token.GetHighForSerialization(), token.GetLowForSerialization());
}

void ApplicationWindowDispatcher::OnNetworkConnectionChangedImpl(
    net::NetworkChangeNotifier::ConnectionType type,
    double max_bandwidth_mbps) {
  //DLOG(INFO) << "ApplicationWindowDispatcher::OnNetworkConnectionChanged: type: " << type << " mbps: " << max_bandwidth_mbps;
  handler_.OnNetworkConnectionChanged(instance_, static_cast<int>(type), max_bandwidth_mbps);
}

void* ApplicationWindowDispatcher::CreateURLLoader(void* request, struct CBlinkPlatformCallbacks* cbs) {
  return handler_.CreateURLLoader(instance_, request, cbs);
}

int ApplicationWindowDispatcher::CountResponseHandler() {
  return handler_.CountResponseHandler(instance_);
}

void* ApplicationWindowDispatcher::GetResponseHandlerAt(int index, struct CResponseHandler* cbs) {
  return handler_.GetResponseHandlerAt(instance_, index, cbs);
}

void* ApplicationWindowDispatcher::GetServiceWorkerContextClientState() {
  return handler_.GetServiceWorkerContextClientState(instance_);
}

ServiceWorkerContextClientCallbacks ApplicationWindowDispatcher::GetServiceWorkerContextClientCallbacks() {
  return handler_.GetServiceWorkerContextClientCallbacks(instance_);
}

void ApplicationWindowDispatcher::GetWebApplicationInfoImpl(GetWebApplicationInfoCallback callback) {
  common::WebApplicationInfo info;
  std::move(callback).Run(info);
}

cc::LayerTreeHost* ApplicationWindowDispatcher::layer_tree_host() const {
  return reinterpret_cast<cc::LayerTreeHost *>(handler_.GetLayerTreeHost(instance_));
}

blink::WebFrame* ApplicationWindowDispatcher::GetMainWebFrame() const {
  void* ptr = handler_.GetMainWebFrame(instance_);
  if (ptr == nullptr) {
    return nullptr;
  }
  return reinterpret_cast<blink::WebFrame *>(ptr); 
}

blink::WebFrame* ApplicationWindowDispatcher::GetWebFrame(int id) const {
  void* ptr = handler_.GetWebFrame(instance_, id);
  if (ptr == nullptr) {
    return nullptr;
  }
  return reinterpret_cast<blink::WebFrame *>(ptr);
}

blink::WebWidget* ApplicationWindowDispatcher::GetWebWidget() const {
  void* ptr = handler_.GetWebWidget(instance_);
  if (ptr == nullptr) {
    return nullptr;
  }
  return reinterpret_cast<blink::WebWidget *>(ptr);
}

blink::WebViewClient* ApplicationWindowDispatcher::GetWebViewClient() const {
  void* ptr = handler_.GetWebViewClient(instance_);
  if (ptr == nullptr) {
    return nullptr;
  }
  return reinterpret_cast<blink::WebViewClient *>(ptr);
}

blink::WebScreenInfo ApplicationWindowDispatcher::GetScreenInfo() {
  blink::WebViewClient* client = GetWebViewClient();
  DCHECK(client);
  return client->GetScreenInfo();
}

void ApplicationWindowDispatcher::ApplicationProcessGone(int32_t status, int32_t exit_code) {
  window_host_interface_->ApplicationProcessGone(status, exit_code);
}

void ApplicationWindowDispatcher::HittestData(const viz::SurfaceId& surface_id, bool ignored_for_hittest) {
  window_host_interface_->HittestData(surface_id, ignored_for_hittest);
}

void ApplicationWindowDispatcher::CloseHost() {
  window_host_interface_->Close();
}

void ApplicationWindowDispatcher::CloseAck() {
  window_host_interface_->CloseAck();
}

void ApplicationWindowDispatcher::UpdateScreenRectsAck() {
  window_host_interface_->UpdateScreenRectsAck();
}

void ApplicationWindowDispatcher::RequestMove(const gfx::Rect& position) {
  window_host_interface_->RequestMove(position);
}

void ApplicationWindowDispatcher::SetTooltipText(const base::string16& text, base::i18n::TextDirection direction) {
  window_host_interface_->SetTooltipText(text, direction);
}

void ApplicationWindowDispatcher::ResizeOrRepaintACK(const gfx::Size& view_size, int32_t flags, const base::Optional<viz::LocalSurfaceId>& local_surface_id) {
  window_host_interface_->ResizeOrRepaintACK(view_size, flags, local_surface_id);
}

void ApplicationWindowDispatcher::SetCursor(const common::WebCursor& cursor) {
  window_host_interface_->SetCursor(cursor);
}

void ApplicationWindowDispatcher::AutoscrollStart(const gfx::PointF& start) {
  window_host_interface_->AutoscrollStart(start);
}

void ApplicationWindowDispatcher::AutoscrollFling(const gfx::Vector2dF& velocity) {
  window_host_interface_->AutoscrollFling(velocity);
}

void ApplicationWindowDispatcher::AutoscrollEnd() {
  window_host_interface_->AutoscrollEnd();
}

void ApplicationWindowDispatcher::TextInputStateChanged(const common::TextInputState& text_input_state) {
  window_host_interface_->TextInputStateChanged(text_input_state);
}

void ApplicationWindowDispatcher::LockMouse(bool user_gesture, bool privileged) {
  window_host_interface_->LockMouse(user_gesture, privileged);
}

void ApplicationWindowDispatcher::UnlockMouse() {
  window_host_interface_->UnlockMouse();
}

void ApplicationWindowDispatcher::SelectionBoundsChanged(common::mojom::SelectionBoundsParamsPtr params) {
  window_host_interface_->SelectionBoundsChanged(std::move(params));
}

void ApplicationWindowDispatcher::FocusedNodeTouched(bool editable) {
  window_host_interface_->FocusedNodeTouched(editable);
}

void ApplicationWindowDispatcher::StartDragging(const common::DropData& drop_data, blink::WebDragOperation ops_allowed, const SkBitmap& image, const gfx::Vector2d& image_offset, const common::DragEventSourceInfo& event_info) {
  window_host_interface_->StartDragging(drop_data, ops_allowed, image, image_offset, event_info);
}

void ApplicationWindowDispatcher::UpdateDragCursor(blink::WebDragOperation drag_operation) {
  window_host_interface_->UpdateDragCursor(drag_operation);
}

void ApplicationWindowDispatcher::FrameSwapMessagesReceived(uint32_t frame_token) {
  window_host_interface_->FrameSwapMessagesReceived(frame_token);
}

void ApplicationWindowDispatcher::ShowWindow(int32_t route_id, const gfx::Rect& initial_rect) {
  window_host_interface_->ShowWindow(route_id, initial_rect);
}

void ApplicationWindowDispatcher::ShowFullscreenWindow(int32_t route_id) {
  window_host_interface_->ShowFullscreenWindow(route_id);
}

void ApplicationWindowDispatcher::UpdateTargetURL(const std::string& url) {
  window_host_interface_->UpdateTargetURL(url);
}

void ApplicationWindowDispatcher::DocumentAvailableInMainFrame(bool uses_temporary_zoom_level) {
  window_host_interface_->DocumentAvailableInMainFrame(uses_temporary_zoom_level);
}

void ApplicationWindowDispatcher::DidContentsPreferredSizeChange(const gfx::Size& pref_size) {
  window_host_interface_->DidContentsPreferredSizeChange(pref_size);
}

void ApplicationWindowDispatcher::RouteCloseEvent() {
  window_host_interface_->RouteCloseEvent();
}

void ApplicationWindowDispatcher::TakeFocus(bool reverse) {
  window_host_interface_->TakeFocus(reverse); 
}

void ApplicationWindowDispatcher::ClosePageACK() {
  window_host_interface_->ClosePageACK();
}

void ApplicationWindowDispatcher::Focus() {
  window_host_interface_->Focus();
}

void ApplicationWindowDispatcher::DidChangeOpener(int opener) {
  window_host_interface_->DidChangeOpener(opener);
}

void ApplicationWindowDispatcher::DetachFrame(int id) {
  window_host_interface_->Detach(id);
}

bool ApplicationWindowDispatcher::CreateNewWindowOnHost(common::mojom::CreateNewWindowParamsPtr params) {
  common::mojom::CreateNewWindowStatus out_status; 
  common::mojom::CreateNewWindowReplyPtr out_reply;
  return window_host_interface_->CreateNewWindowOnHost(std::move(params), &out_status, &out_reply);
}

void ApplicationWindowDispatcher::DidCommitProvisionalLoad(common::mojom::DidCommitProvisionalLoadParamsPtr params, service_manager::mojom::InterfaceProviderRequest interface_provider_request) {
  window_host_interface_->DidCommitProvisionalLoad(std::move(params), std::move(interface_provider_request));
}

void ApplicationWindowDispatcher::DidCommitSameDocumentNavigation(common::mojom::DidCommitProvisionalLoadParamsPtr params) {
  window_host_interface_->DidCommitSameDocumentNavigation(std::move(params)); 
}

void ApplicationWindowDispatcher::BeginNavigation(const std::string& url) {
  window_host_interface_->BeginNavigation(url);
}

void ApplicationWindowDispatcher::DidChangeName(const std::string& name, const std::string& unique_name) {
  window_host_interface_->DidChangeName(name, unique_name);
}

void ApplicationWindowDispatcher::FrameSizeChanged(const gfx::Size& size) {
  window_host_interface_->FrameSizeChanged(size);
}

void ApplicationWindowDispatcher::OnUpdatePictureInPictureSurfaceId(const viz::SurfaceId& surface_id, const gfx::Size& natural_size) {
  window_host_interface_->OnUpdatePictureInPictureSurfaceId(surface_id, natural_size);
}

void ApplicationWindowDispatcher::OnExitPictureInPicture() {
  window_host_interface_->OnExitPictureInPicture();
}

void ApplicationWindowDispatcher::OnSwappedOut() {
  window_host_interface_->OnSwappedOut(); 
}

void ApplicationWindowDispatcher::SwapOutAck() {
  window_host_interface_->SwapOutAck(); 
}

void ApplicationWindowDispatcher::SelectWordAroundCaretAck(bool did_select, int start, int end) {
  window_host_interface_->SelectWordAroundCaretAck(did_select, start, end); 
}

//void ApplicationWindowDispatcher::Detach() {
//  window_host_interface_->Detach();
//}

void ApplicationWindowDispatcher::FrameFocused() {
  window_host_interface_->FrameFocused();
}

void ApplicationWindowDispatcher::DidStartProvisionalLoad(const GURL& url, const std::vector<GURL>& redirect_chain, base::TimeTicks navigation_start) {
  window_host_interface_->DidStartProvisionalLoad(url, redirect_chain, navigation_start);
}

void ApplicationWindowDispatcher::DidFailProvisionalLoadWithError(int32_t error_code, const base::string16& error_description, const GURL& url) {
  window_host_interface_->DidFailProvisionalLoadWithError(error_code, error_description, url);
}

void ApplicationWindowDispatcher::DidFinishDocumentLoad() {
  window_host_interface_->DidFinishDocumentLoad();
}

void ApplicationWindowDispatcher::DidFailLoadWithError(const GURL& url, int32_t error_code, const base::string16& error_description) {
  window_host_interface_->DidFailLoadWithError(url, error_code, error_description);
}

void ApplicationWindowDispatcher::DidStartLoading(bool to_different_document) {
  window_host_interface_->DidStartLoading(to_different_document);
}

void ApplicationWindowDispatcher::SendDidStopLoading() {
  window_host_interface_->DidStopLoading();
}

void ApplicationWindowDispatcher::SendRequestOverlayRoutingToken() {
  window_host_interface_->RequestOverlayRoutingToken();
}

void ApplicationWindowDispatcher::UpdateState(::common::mojom::PageStatePtr state) {
  window_host_interface_->UpdateState(std::move(state));
}

void ApplicationWindowDispatcher::DidChangeLoadProgress(double load_progress) {
  window_host_interface_->DidChangeLoadProgress(load_progress);
}

void ApplicationWindowDispatcher::OpenURL(const GURL& url) {
  window_host_interface_->OpenURL(url);
}

void ApplicationWindowDispatcher::DidFinishLoad(const GURL& url) {
  window_host_interface_->DidFinishLoad(url);
}

void ApplicationWindowDispatcher::DocumentOnLoadCompleted(base::TimeTicks timestamp) {
  window_host_interface_->DocumentOnLoadCompleted(timestamp);
}

void ApplicationWindowDispatcher::DidAccessInitialDocument() {
  window_host_interface_->DidAccessInitialDocument();
}

void ApplicationWindowDispatcher::UpdateTitle(const base::string16& title, base::i18n::TextDirection direction) {
  window_host_interface_->UpdateTitle(title, direction);
}

void ApplicationWindowDispatcher::BeforeUnloadAck(bool proceed, base::TimeTicks start_time, base::TimeTicks end_time) {
  window_host_interface_->BeforeUnloadAck(proceed, start_time, end_time);
}

void ApplicationWindowDispatcher::SynchronizeVisualProperties(const viz::SurfaceId& surface_id, const common::ScreenInfo& screen_info, bool auto_resize_enabled, const gfx::Size& min_size_for_auto_resize, const gfx::Size& max_size_for_auto_resize, const gfx::Rect& screen_space_rect, const gfx::Size& local_frame_size, int32_t capture_sequence_number) {
  window_host_interface_->SynchronizeVisualProperties(
    surface_id, 
    screen_info, 
    auto_resize_enabled, 
    min_size_for_auto_resize, 
    max_size_for_auto_resize, 
    screen_space_rect, 
    local_frame_size, 
    capture_sequence_number);
}

void ApplicationWindowDispatcher::UpdateViewportIntersection(const gfx::Rect& viewport_intersection, const gfx::Rect& compositor_visible_rect) {
  window_host_interface_->UpdateViewportIntersection(
    viewport_intersection, 
    compositor_visible_rect);
}

void ApplicationWindowDispatcher::VisibilityChanged(bool visible) {
  window_host_interface_->VisibilityChanged(visible);
}

void ApplicationWindowDispatcher::SendUpdateRenderThrottlingStatus(bool is_throttled, bool subtree_throttled) {
  window_host_interface_->UpdateRenderThrottlingStatus(is_throttled, subtree_throttled);
}

void ApplicationWindowDispatcher::SetHasReceivedUserGesture() {
  window_host_interface_->SetHasReceivedUserGesture();
}

void ApplicationWindowDispatcher::SetHasReceivedUserGestureBeforeNavigation(bool value) {
  window_host_interface_->SetHasReceivedUserGestureBeforeNavigation(value);
}

void ApplicationWindowDispatcher::ContextMenu() {
  window_host_interface_->ContextMenu();
}

void ApplicationWindowDispatcher::SelectionChanged(const base::string16& selection, uint32_t offset, const gfx::Range& range) {
  window_host_interface_->SelectionChanged(selection, offset, range);
}

void ApplicationWindowDispatcher::VisualStateResponse(uint64_t id) {
  window_host_interface_->VisualStateResponse(id);
}

void ApplicationWindowDispatcher::EnterFullscreen() {
  window_host_interface_->EnterFullscreen();
}

void ApplicationWindowDispatcher::ExitFullscreen() {
  window_host_interface_->ExitFullscreen();
}

void ApplicationWindowDispatcher::SendDispatchLoad() {
  window_host_interface_->DispatchLoad();
}

void ApplicationWindowDispatcher::SendCheckCompleted() {
  window_host_interface_->CheckCompleted();
}

void ApplicationWindowDispatcher::UpdateFaviconURL(const std::vector<GURL>& favicons) {
  window_host_interface_->UpdateFaviconURL(favicons);
}

void ApplicationWindowDispatcher::ScrollRectToVisibleInParentFrame(const gfx::Rect& rect_to_scroll) {
  window_host_interface_->ScrollRectToVisibleInParentFrame(rect_to_scroll);
}

void ApplicationWindowDispatcher::FrameDidCallFocus() {
  window_host_interface_->FrameDidCallFocus();
}

void ApplicationWindowDispatcher::TextSurroundingSelectionResponse(
  const base::string16& content,
  uint32_t start_offset, 
  uint32_t end_offset) {

  window_host_interface_->TextSurroundingSelectionResponse(content, start_offset, end_offset); 
}

void ApplicationWindowDispatcher::GetInterface(
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  
  auto* registry = ApplicationThread::current()->registry();
  //DCHECK(registry);
  registry->TryBindInterface(interface_name, &interface_pipe);
  for (auto& observer : observers_) {
    observer.OnInterfaceRequestForFrame(interface_name, &interface_pipe);
    if (!interface_pipe.is_valid())
      return;
  }
}

void ApplicationWindowDispatcher::GetInterfaceProvider(::service_manager::mojom::InterfaceProviderRequest interfaces) {
  //DLOG(INFO) << "ApplicationWindowDispatcher::GetInterfaceProvider";
  ApplicationThread* thread = ApplicationThread::current();
  service_manager::Connector* connector = thread->GetConnector();
  service_manager::mojom::InterfaceProviderPtr provider;
  
  service_manager::mojom::InterfaceProviderRequest 
      remote_interface_provider_request = mojo::MakeRequest(&provider);
  interface_provider_bindings_.AddBinding(this, std::move(remote_interface_provider_request));//mojo::MakeRequest(&provider));
  connector->FilterInterfaces(common::mojom::kNavigation_FrameSpec,
                              service_manager::Identity("host"), std::move(interfaces),
                              std::move(provider));
}

void ApplicationWindowDispatcher::AttachSynchronousCompositor(
  common::mojom::SynchronousCompositorControlHostPtr control_host, 
  common::mojom::SynchronousCompositorHostAssociatedPtrInfo host, 
  common::mojom::SynchronousCompositorAssociatedRequest compositor_request) {
  LOG(ERROR) << "ApplicationWindowDispatcher::AttachSynchronousCompositor: not emented";
}

void ApplicationWindowDispatcher::CancelTouchTimeout() {
  window_input_host_interface_->CancelTouchTimeout();
}

void ApplicationWindowDispatcher::SetWhiteListedTouchAction(
  cc::TouchAction touch_action,
  uint32_t unique_touch_event_id,
  common::InputEventAckState state) {
 window_input_host_interface_->SetWhiteListedTouchAction(touch_action, unique_touch_event_id, state);
}

void ApplicationWindowDispatcher::DidOverscroll(const ui::DidOverscrollParams& params) {
  window_input_host_interface_->DidOverscroll(params);
}

void ApplicationWindowDispatcher::DidStopFlinging() {
  window_input_host_interface_->DidStopFlinging();
}

void ApplicationWindowDispatcher::DidStartScrollingViewport() {
  window_input_host_interface_->DidStartScrollingViewport();
}

void ApplicationWindowDispatcher::ImeCancelComposition() {
  window_input_host_interface_->ImeCancelComposition();
}

void ApplicationWindowDispatcher::ImeCompositionRangeChanged(const gfx::Range& range, const std::vector<gfx::Rect>& bounds) {
  window_input_host_interface_->ImeCompositionRangeChanged(range, bounds);
}

void ApplicationWindowDispatcher::HasTouchEventHandlers(bool has_handlers) {
  window_input_host_interface_->HasTouchEventHandlers(has_handlers);
}

void ApplicationWindowDispatcher::WindowCreatedAck() {
  window_host_interface_->WindowCreatedAck();
}

void ApplicationWindowDispatcher::LayerTreeFrameSinkInitialized() {
  window_host_interface_->LayerTreeFrameSinkInitialized();
}

int ApplicationWindowDispatcher::GenerateRoutingID() {
  int32_t routing_id = MSG_ROUTING_NONE;
  window_host_interface_->GenerateRoutingID(&routing_id);
  return routing_id;
}

void ApplicationWindowDispatcher::OnMediaDestroyed(int delegate_id) {
  main_thread_->Send(new MediaPlayerDelegateHostMsg_OnMediaDestroyed(0, delegate_id));
}

void ApplicationWindowDispatcher::OnMediaPaused(int delegate_id,
                                                int reached_end_of_stream) {
  main_thread_->Send(new MediaPlayerDelegateHostMsg_OnMediaPaused(0, delegate_id, reached_end_of_stream != 0));
}

void ApplicationWindowDispatcher::OnMediaPlaying(
  int delegate_id, 
  int has_video,
  int has_audio,
  int is_remote,
  int content_type) {
  main_thread_->Send(new MediaPlayerDelegateHostMsg_OnMediaPlaying(
    0, 
    delegate_id, 
    has_video != 0,
    has_audio != 0,
    is_remote != 0,
    static_cast<media::MediaContentType>(content_type)));
}

void ApplicationWindowDispatcher::OnMediaMutedStatusChanged(int delegate_id,
    int muted) {
  main_thread_->Send(new MediaPlayerDelegateHostMsg_OnMutedStatusChanged(0, delegate_id, muted != 0));
}

void ApplicationWindowDispatcher::OnMediaEffectivelyFullscreenChanged(
  int delegate_id,
  int fullscreen_status) {
  main_thread_->Send(new MediaPlayerDelegateHostMsg_OnMediaEffectivelyFullscreenChanged(
    0, 
    delegate_id, 
    static_cast<blink::WebFullscreenVideoStatus>(fullscreen_status)));
}

void ApplicationWindowDispatcher::OnMediaSizeChanged(int delegate_id, int sw, int sh) {
  main_thread_->Send(new MediaPlayerDelegateHostMsg_OnMediaSizeChanged(
    0, delegate_id, gfx::Size(sw, sh)));
}

void ApplicationWindowDispatcher::OnPictureInPictureSourceChanged(int delegate_id) {
  main_thread_->Send(new MediaPlayerDelegateHostMsg_OnPictureInPictureSourceChanged(
    0, delegate_id));
}

void ApplicationWindowDispatcher::OnPictureInPictureModeEnded(int delegate_id) {
  main_thread_->Send(new MediaPlayerDelegateHostMsg_OnPictureInPictureModeEnded(0, delegate_id));
}

void ApplicationWindowDispatcher::OnWebFrameCreated(blink::WebLocalFrame* frame, bool is_main) {
  main_thread_->OnWebFrameCreated(frame, is_main);
}

}