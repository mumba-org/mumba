// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_APPLICATION_WINDOW_DISPATCHER_H_
#define MUMBA_APPLICATION_APPLICATION_WINDOW_DISPATCHER_H_

#include "base/macros.h"

#include "base/observer_list.h"
#include "core/shared/common/drag_event_source_info.h"
#include "core/shared/common/drop_data.h"
#include "core/shared/common/mojom/application_types.mojom.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/shared/common/input/input_handler.mojom.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "core/shared/application/child_url_loader_factory_bundle.h"
#include "services/service_manager/public/mojom/interface_provider.mojom.h"
#include "runtime/MumbaShims/ApplicationHandler.h"
#include "third_party/blink/public/platform/web_screen_info.h"

namespace cc {
class LayerTreeHost;  
}

namespace blink {
class WebFrame;
class WebLocalFrame;
class WebWidget;
class WebViewClient;
}

namespace application {
class ApplicationThread;
class ApplicationWindowDispatcher;
class ApplicationWindowDispatcherObserver;
class ChildURLLoaderFactoryBundle;

// Implementation of the application process side of the ApplicationWindow
class CONTENT_EXPORT ApplicationWindowDispatcher : public common::mojom::ApplicationWindow,
                                                   public common::mojom::WindowInputHandler,
                                                   public service_manager::mojom::InterfaceProvider {
public:
  ApplicationWindowDispatcher(ApplicationThread* thread, CWindowCallbacks handler, void* instance);
  ~ApplicationWindowDispatcher() override;

  void BindApplicationWindow(
    common::mojom::ApplicationWindowAssociatedRequest request);

  void BindWindowInputHandler(common::mojom::WindowInputHandlerAssociatedRequest request);
  //void BindFrameInputHandler(common::mojom::FrameInputHandlerAssociatedRequest request);

  common::mojom::ApplicationWindowHost* application_window_host() const {
    return window_host_interface_.get();
  }

  common::mojom::WindowInputHandlerHost* window_input_host() const {
    return window_input_host_interface_.get();
  }

  ApplicationThread* main_thread() const {
    return main_thread_;
  }

  cc::LayerTreeHost* layer_tree_host() const;

  blink::WebFrame* GetMainWebFrame() const;
  blink::WebFrame* GetWebFrame(int id) const;
  blink::WebWidget* GetWebWidget() const;
  blink::WebViewClient* GetWebViewClient() const;
  blink::WebScreenInfo GetScreenInfo();

  scoped_refptr<application::ChildURLLoaderFactoryBundle> loader_factories() const {
    return loader_factories_;
  }

  void AddObserver(ApplicationWindowDispatcherObserver* observer);
  void RemoveObserver(ApplicationWindowDispatcherObserver* observer);

  //void set_main_thread(ApplicationThread* main_thread) {
  //  main_thread_ = main_thread;
  //}

  void SetPageScale(float page_scale_factor) override;
  void SetInitialFocus(bool reverse) override;
  void UpdateTargetURLAck() override;
  void UpdateWebPreferences(const common::WebPreferences& preferences) override;
  void ClosePage() override;
  void MoveOrResizeStarted() override;
  void SetBackgroundOpaque(bool opaque) override;
  void EnablePreferredSizeChangedMode() override;
  void DisableScrollbarsForSmallWindows(const gfx::Size& disable_scrollbar_size_limit) override;
  void SetRendererPrefs(const common::RendererPreferences& prefs) override;
  void SetActive(bool active) override;
  void ForceRedraw(const ui::LatencyInfo& latency_info) override;
  void SelectWordAroundCaret() override;
  void UpdateWindowScreenRect(const gfx::Rect& window_screen_rect) override;
  void SetZoomLevel(double zoom_level) override;
  void PageWasHidden() override;
  void PageWasShown() override;
  void SetHistoryOffsetAndLength(int32_t history_offset, int32_t history_length) override;
  void AudioStateChanged(bool is_audio_playing) override;
  void PausePageScheduledTasks(bool pause) override;
  void UpdateScreenInfo(const common::ScreenInfo& screen_info) override;
  void FreezePage() override;
  void ShowContextMenu(common::mojom::MenuSourceType type, const gfx::Point& location) override;
  void Close() override;
  void SynchronizeVisualProperties(const common::VisualProperties& params) override;
  void WasHidden() override;
  void WasShown(bool needs_repainting, const ui::LatencyInfo& latency_info) override;
  void Repaint(const gfx::Size& size) override;
  void SetTextDirection(base::i18n::TextDirection direction) override;
  void MoveAck() override;
  void UpdateScreenRects(const gfx::Rect& view_screen_rect, const gfx::Rect& window_screen_rect) override;
  void SetViewportIntersection(const gfx::Rect& intersection, const gfx::Rect& visible_rect) override;
  void SetIsInert(bool inert) override;
  void UpdateRenderThrottlingStatus(bool is_throttled, bool subtree_throttled) override;
  void DragTargetDragEnter(const std::vector<common::DropDataMetadata>& drop_data,
                           const gfx::PointF& client_pt,
                           const gfx::PointF& screen_pt,
                           blink::WebDragOperation ops_allowed,
                           int32_t key_modifiers) override;
  void DragTargetDragOver(const gfx::PointF& client_pt,
                          const gfx::PointF& screen_pt,
                          blink::WebDragOperation ops_allowed,
                          int32_t key_modifiers) override;
  void DragTargetDragLeave(const gfx::PointF& client_point, const gfx::PointF& screen_point) override;
  void DragTargetDrop(const common::DropData& drop_data,
                      const gfx::PointF& client_pt,
                      const gfx::PointF& screen_pt,
                      int32_t key_modifiers) override;
  void DragSourceEnded(const gfx::PointF& client_pt,
                       const gfx::PointF& screen_pt,
                       blink::WebDragOperation drag_operations) override;

  void DragSourceSystemDragEnded() override;
  void MediaPlayerActionAt(const gfx::Point& location, blink::WebMediaPlayerAction action) override;
  void SetFocusedWindow() override;
  void LockMouseAck(bool succeeded) override;
  void MouseLockLost() override;
  void SetupWindowInputHandler(common::mojom::WindowInputHandlerRequest request, common::mojom::WindowInputHandlerHostPtr host) override;
  void SwapOut(int32_t window_id, bool is_loading) override;
  void GetWebApplicationInfo(GetWebApplicationInfoCallback callback) override;

  void IntrinsicSizingInfoOfChildChanged(const gfx::SizeF& size, const gfx::SizeF& aspect_ratio, bool has_width, bool has_height) override;
  void BeforeUnload(bool is_reload) override;
  void ViewChanged(const base::Optional<viz::FrameSinkId>& frame_sink_id) override;
  void SetChildFrameSurface(const viz::SurfaceInfo& surface_info) override;
  void ChildFrameProcessGone() override;
  void SwapIn() override;
  void FrameDelete() override;
  void Stop() override;
  void DroppedNavigation() override;
  void DidStartLoading() override;
  void DidStopLoading() override;
  void Collapse(bool collapsed) override;
  void WillEnterFullscreen() override;
  void EnableAutoResize(const gfx::Size& min_size, const gfx::Size& max_size) override;
  void DisableAutoResize() override;
  void ContextMenuClosed() override;
  void CustomContextMenuAction(uint32_t action) override;
  void VisualStateRequest(uint64_t id) override;
  void DispatchLoad() override;
  void Reload(bool bypass_cache) override;
  void ReloadLoFiImages() override;
  void SnapshotAccessibilityTree() override;
  void UpdateOpener(int32_t opener_routing_id) override;
  void SetFocusedFrame() override;
  void CheckCompleted() override;
  void PostMessageEvent() override;
  void NotifyUserActivation() override;
  void DidUpdateOrigin(const GURL& origin) override;
  void CopyImageAt(float x, float y) override;
  void SaveImageAt(float x, float y) override;
  void ScrollRectToVisible(const gfx::Rect& rect_to_scroll) override;
  void TextSurroundingSelectionRequest(uint32_t max_length) override;
  void AdvanceFocus(::common::mojom::FocusType type, int32_t source_routing_id) override;
  void AdvanceFocusInForm(::common::mojom::FocusType type) override;
  void Find(int32_t request_id, const base::string16& search_text, ::common::mojom::FindOptionsPtr options) override;
  void ClearActiveFindMatch() override;
  void StopFinding(::common::mojom::StopFindAction action) override;
  void ClearFocusedElement() override;
  void SetOverlayRoutingToken(const base::UnguessableToken& token) override;
  void GetInterfaceProvider(::service_manager::mojom::InterfaceProviderRequest interfaces) override;
  void GetInterface(const std::string& interface_name,
                    mojo::ScopedMessagePipeHandle interface_pipe) override;
  void OnNetworkConnectionChanged(
      net::NetworkChangeNotifier::ConnectionType type,
      double max_bandwidth_mbps) override;
  
  // calling WindowHost

  void ApplicationProcessGone(int32_t status, int32_t exit_code);
  void HittestData(const viz::SurfaceId& surface_id, bool ignored_for_hittest);
  void CloseHost();
  void CloseAck();
  void UpdateScreenRectsAck();
  void RequestMove(const gfx::Rect& position);
  void SetTooltipText(const base::string16& text, base::i18n::TextDirection direction);
  void ResizeOrRepaintACK(const gfx::Size& view_size, int32_t flags, const base::Optional<viz::LocalSurfaceId>& local_surface_id);
  void SetCursor(const common::WebCursor& cursor);
  void AutoscrollStart(const gfx::PointF& start);
  void AutoscrollFling(const gfx::Vector2dF& velocity);
  void AutoscrollEnd();
  void TextInputStateChanged(const common::TextInputState& text_input_state);
  void LockMouse(bool user_gesture, bool privileged);
  void UnlockMouse();
  void SelectionBoundsChanged(common::mojom::SelectionBoundsParamsPtr params);
  void FocusedNodeTouched(bool editable);
  void StartDragging(const common::DropData& drop_data, blink::WebDragOperation ops_allowed, const SkBitmap& image, const gfx::Vector2d& image_offset, const common::DragEventSourceInfo& event_info);
  void UpdateDragCursor(blink::WebDragOperation drag_operation);
  void FrameSwapMessagesReceived(uint32_t frame_token);
  void ShowWindow(int32_t route_id, const gfx::Rect& initial_rect);
  void ShowFullscreenWindow(int32_t route_id);
  void UpdateTargetURL(const std::string& url);
  void DocumentAvailableInMainFrame(bool uses_temporary_zoom_level);
  void DidContentsPreferredSizeChange(const gfx::Size& pref_size);
  void RouteCloseEvent();
  void TakeFocus(bool reverse);
  void ClosePageACK();
  void Focus();
  bool CreateNewWindowOnHost(common::mojom::CreateNewWindowParamsPtr params);
  void DidCommitProvisionalLoad(common::mojom::DidCommitProvisionalLoadParamsPtr params, service_manager::mojom::InterfaceProviderRequest interface_provider_request);
  void DidCommitSameDocumentNavigation(common::mojom::DidCommitProvisionalLoadParamsPtr params);
  void BeginNavigation(const std::string& url);
  void DidChangeName(const std::string& name, const std::string& unique_name);
  void FrameSizeChanged(const gfx::Size& size);
  void OnUpdatePictureInPictureSurfaceId(const viz::SurfaceId& surface_id, const gfx::Size& natural_size);
  void OnExitPictureInPicture();
  void OnSwappedOut();
  void SwapOutAck();
  void SelectWordAroundCaretAck(bool did_select, int start, int end);
  int GenerateRoutingID();

  //void Detach();
  void FrameFocused();
  void DidStartProvisionalLoad(const GURL& url, const std::vector<GURL>& redirect_chain, base::TimeTicks navigation_start);
  void DidFailProvisionalLoadWithError(int32_t error_code, const base::string16& error_description, const GURL& url);
  void DidFinishDocumentLoad();
  void DidFailLoadWithError(const GURL& url, int32_t error_code, const base::string16& error_description);
  void DidStartLoading(bool to_different_document);
  void SendDidStopLoading();
  void SendRequestOverlayRoutingToken();
  void UpdateState(::common::mojom::PageStatePtr state);
  void DidChangeLoadProgress(double load_progress);
  void OpenURL(const GURL& url);
  void DidFinishLoad(const GURL& url);
  void DocumentOnLoadCompleted(base::TimeTicks timestamp);
  void DidAccessInitialDocument();
  void UpdateTitle(const base::string16& title, base::i18n::TextDirection direction);
  void BeforeUnloadAck(bool proceed, base::TimeTicks start_time, base::TimeTicks end_time);
  void SynchronizeVisualProperties(const viz::SurfaceId& surface_id, const common::ScreenInfo& screen_info, bool auto_resize_enabled, const gfx::Size& min_size_for_auto_resize, const gfx::Size& max_size_for_auto_resize, const gfx::Rect& screen_space_rect, const gfx::Size& local_frame_size, int32_t capture_sequence_number);
  void UpdateViewportIntersection(const gfx::Rect& viewport_intersection, const gfx::Rect& compositor_visible_rect);
  void VisibilityChanged(bool visible);
  void SendUpdateRenderThrottlingStatus(bool is_throttled, bool subtree_throttled);
  void SetHasReceivedUserGesture();
  void SetHasReceivedUserGestureBeforeNavigation(bool value);
  void ContextMenu();
  void SelectionChanged(const base::string16& selection, uint32_t offset, const gfx::Range& range);
  void VisualStateResponse(uint64_t id);
  void EnterFullscreen();
  void ExitFullscreen();
  void SendDispatchLoad();
  void SendCheckCompleted();
  void UpdateFaviconURL(const std::vector<GURL>& favicons);
  void ScrollRectToVisibleInParentFrame(const gfx::Rect& rect_to_scroll);
  void FrameDidCallFocus();
  void TextSurroundingSelectionResponse(const base::string16& content,
    uint32_t start_offset, 
    uint32_t end_offset);
  
  void DidChangeOpener(int opener);
  void DetachFrame(int id);
  void WindowCreatedAck();
  void LayerTreeFrameSinkInitialized();

  void OnMediaDestroyed(int delegate_id);
  void OnMediaPaused(int delegate_id, int reached_end_of_stream);
  void OnMediaPlaying(int delegate_id, 
    int has_video,
    int has_audio,
    int is_remote,
    int content_type);
  void OnMediaMutedStatusChanged(int delegate_id, int muted);
  void OnMediaEffectivelyFullscreenChanged(int delegate_id, int fullscreen_status);
  void OnMediaSizeChanged(int delegate_id, int sw, int sh);
  void OnPictureInPictureSourceChanged(int delegate_id);
  void OnPictureInPictureModeEnded(int delegate_id);

  // WindowInputHandler
  void SetFocus(bool focused) override;
  void MouseCaptureLost() override;
  void SetEditCommandsForNextKeyEvent(const std::vector<common::EditCommand>& commands) override;
  void CursorVisibilityChanged(bool visible) override;
  void ImeSetComposition(const base::string16& text, 
                         const std::vector<ui::ImeTextSpan>& ime_text_spans, 
                         const gfx::Range& range, 
                         int32_t start, 
                         int32_t end) override;
  void ImeCommitText(
    const base::string16& text, 
    const std::vector<ui::ImeTextSpan>& ime_text_spans, 
    const gfx::Range& range,
    int32_t relative_cursor_position) override;

  void ImeFinishComposingText(bool keep_selection) override;
  void RequestTextInputStateUpdate() override;
  void RequestCompositionUpdates(bool immediate_request, bool monitor_request) override;
  void DispatchEvent(std::unique_ptr<common::InputEvent> event, DispatchEventCallback callback) override;
  void DispatchNonBlockingEvent(std::unique_ptr<common::InputEvent> event) override;
  void AttachSynchronousCompositor(
    common::mojom::SynchronousCompositorControlHostPtr control_host, 
    common::mojom::SynchronousCompositorHostAssociatedPtrInfo host, 
    common::mojom::SynchronousCompositorAssociatedRequest compositor_request) override;

  // calling on WindowInputHandlerHost

  void CancelTouchTimeout();
  void SetWhiteListedTouchAction(cc::TouchAction touch_action,
                                 uint32_t unique_touch_event_id,
                                 common::InputEventAckState state);
  void DidOverscroll(const ui::DidOverscrollParams& params);
  void DidStopFlinging();
  void DidStartScrollingViewport();
  void ImeCancelComposition();
  void ImeCompositionRangeChanged(const gfx::Range& range, const std::vector<gfx::Rect>& bounds);
  void HasTouchEventHandlers(bool has_handlers);

  // FrameInputHandler
  void SetCompositionFromExistingText(int32_t start, int32_t end, const std::vector<ui::ImeTextSpan>& ime_text_spans) override;
  void ExtendSelectionAndDelete(int32_t before, int32_t after) override;
  void DeleteSurroundingText(int32_t before, int32_t after) override;
  void DeleteSurroundingTextInCodePoints(int32_t before, int32_t after) override;
  void SetEditableSelectionOffsets(int32_t start, int32_t end) override;
  void ExecuteEditCommand(const std::string& command, const base::Optional<base::string16>& value) override;
  void Undo() override;
  void Redo() override;
  void Cut() override;
  void Copy() override;
  void CopyToFindPboard() override;
  void Paste() override;
  void PasteAndMatchStyle() override;
  void Delete() override;
  void SelectAll() override;
  void CollapseSelection() override;
  void Replace(const base::string16& word) override;
  void ReplaceMisspelling(const base::string16& word) override;
  void SelectRange(const gfx::Point& base, const gfx::Point& extent) override;
  void AdjustSelectionByCharacterOffset(int32_t start, int32_t end, ::blink::mojom::SelectionMenuBehavior behavior) override;
  void MoveRangeSelectionExtent(const gfx::Point& extent) override;
  void ScrollFocusedEditableNodeIntoRect(const gfx::Rect& rect) override;
  void MoveCaret(const gfx::Point& point) override;
  void GetWindowInputHandler(common::mojom::WindowInputHandlerAssociatedRequest interface_request, common::mojom::WindowInputHandlerHostPtr host) override;
  void CommitNavigation(common::mojom::CommitNavigationParamsPtr params, std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories, common::mojom::ControllerServiceWorkerInfoPtr controller_service_worker) override;
  void CommitSameDocumentNavigation(common::mojom::CommitNavigationParamsPtr params, std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories, common::mojom::ControllerServiceWorkerInfoPtr controller_service_worker, CommitSameDocumentNavigationCallback callback) override;
  void CommitFailedNavigation() override;

  void* CreateURLLoader(void* request, struct CBlinkPlatformCallbacks* cbs);
  int CountResponseHandler();
  void* GetResponseHandlerAt(int index, struct CResponseHandler* cbs);
  void* GetServiceWorkerContextClientState(); 
  ServiceWorkerContextClientCallbacks GetServiceWorkerContextClientCallbacks();
  void OnWebFrameCreated(blink::WebLocalFrame* frame, bool is_main);
  
private:
  
  void SetPageScaleImpl(float page_scale_factor);
  void SetInitialFocusImpl(bool reverse);
  void UpdateTargetURLAckImpl();
  void UpdateWebPreferencesImpl(const common::WebPreferences& preferences);
  void ClosePageImpl();
  void MoveOrResizeStartedImpl();
  void SetBackgroundOpaqueImpl(bool opaque);
  void EnablePreferredSizeChangedModeImpl();
  void DisableScrollbarsForSmallWindowsImpl(const gfx::Size& disable_scrollbar_size_limit);
  void SetRendererPrefsImpl(const common::RendererPreferences& prefs);
  void SetActiveImpl(bool active);
  void ForceRedrawImpl(const ui::LatencyInfo& latency_info);
  void SelectWordAroundCaretImpl();
  void UpdateWindowScreenRectImpl(const gfx::Rect& window_screen_rect);
  void SetZoomLevelImpl(double zoom_level);
  void PageWasHiddenImpl();
  void PageWasShownImpl();
  void SetHistoryOffsetAndLengthImpl(int32_t history_offset, int32_t history_length);
  void AudioStateChangedImpl(bool is_audio_playing);
  void PausePageScheduledTasksImpl(bool pause);
  void UpdateScreenInfoImpl(const common::ScreenInfo& screen_info);
  void FreezePageImpl();
  void ShowContextMenuImpl(common::mojom::MenuSourceType type, const gfx::Point& location);
  void CloseImpl();
  void SynchronizeVisualPropertiesImpl(const common::VisualProperties& params);
  void WasHiddenImpl();
  void WasShownImpl(bool needs_repainting, const ui::LatencyInfo& latency_info);
  void RepaintImpl(const gfx::Size& size);
  void SetTextDirectionImpl(base::i18n::TextDirection direction);
  void MoveAckImpl();
  void UpdateScreenRectsImpl(const gfx::Rect& view_screen_rect, const gfx::Rect& window_screen_rect);
  void SetViewportIntersectionImpl(const gfx::Rect& intersection, const gfx::Rect& visible_rect);
  void SetIsInertImpl(bool inert);
  void UpdateRenderThrottlingStatusImpl(bool is_throttled, bool subtree_throttled);
  void DragTargetDragEnterImpl(const std::vector<common::DropDataMetadata>& drop_data,
                           const gfx::PointF& client_pt,
                           const gfx::PointF& screen_pt,
                           blink::WebDragOperation ops_allowed,
                           int32_t key_modifiers);
  void DragTargetDragOverImpl(const gfx::PointF& client_pt,
                          const gfx::PointF& screen_pt,
                          blink::WebDragOperation ops_allowed,
                          int32_t key_modifiers);
  void DragTargetDragLeaveImpl(const gfx::PointF& client_point, const gfx::PointF& screen_point);
  void DragTargetDropImpl(const common::DropData& drop_data,
                      const gfx::PointF& client_pt,
                      const gfx::PointF& screen_pt,
                      int32_t key_modifiers);
  void DragSourceEndedImpl(const gfx::PointF& client_pt,
                       const gfx::PointF& screen_pt,
                       blink::WebDragOperation drag_operations);

  void DragSourceSystemDragEndedImpl();
  void MediaPlayerActionAtImpl(const gfx::Point& location, blink::WebMediaPlayerAction action);
  void SetFocusedWindowImpl();
  void LockMouseAckImpl(bool succeeded);
  void MouseLockLostImpl();
  void SetupWindowInputHandlerImpl(common::mojom::WindowInputHandlerRequest request, common::mojom::WindowInputHandlerHostPtr host);
  void SwapOutImpl(int32_t window_id, bool is_loading);
  void GetWebApplicationInfoImpl(GetWebApplicationInfoCallback callback);

  void IntrinsicSizingInfoOfChildChangedImpl(const gfx::SizeF& size, const gfx::SizeF& aspect_ratio, bool has_width, bool has_height);
  void BeforeUnloadImpl(bool is_reload);
  void ViewChangedImpl(const base::Optional<viz::FrameSinkId>& frame_sink_id);
  void SetChildFrameSurfaceImpl(const viz::SurfaceInfo& surface_info);
  void ChildFrameProcessGoneImpl();
  void SwapInImpl();
  void FrameDeleteImpl();
  void StopImpl();
  void DroppedNavigationImpl();
  void DidStartLoadingImpl();
  void DidStopLoadingImpl();
  void CollapseImpl(bool collapsed);
  void WillEnterFullscreenImpl();
  void EnableAutoResizeImpl(const gfx::Size& min_size, const gfx::Size& max_size);
  void DisableAutoResizeImpl();
  void ContextMenuClosedImpl();
  void CustomContextMenuActionImpl(uint32_t action);
  void VisualStateRequestImpl(uint64_t id);
  void DispatchLoadImpl();
  void ReloadImpl(bool bypass_cache);
  void ReloadLoFiImagesImpl();
  void SnapshotAccessibilityTreeImpl();
  void UpdateOpenerImpl(int32_t opener_routing_id);
  void SetFocusedFrameImpl();
  void CheckCompletedImpl();
  void PostMessageEventImpl();
  void NotifyUserActivationImpl();
  void DidUpdateOriginImpl(const GURL& origin);
  void CopyImageAtImpl(float x, float y);
  void SaveImageAtImpl(float x, float y);
  void ScrollRectToVisibleImpl(const gfx::Rect& rect_to_scroll);
  void TextSurroundingSelectionRequestImpl(uint32_t max_length);
  void AdvanceFocusImpl(::common::mojom::FocusType type, int32_t source_routing_id);
  void AdvanceFocusInFormImpl(::common::mojom::FocusType type);
  void FindImpl(int32_t request_id, const base::string16& search_text, ::common::mojom::FindOptionsPtr options);
  void ClearActiveFindMatchImpl();
  void StopFindingImpl(::common::mojom::StopFindAction action);
  void ClearFocusedElementImpl();
  void SetOverlayRoutingTokenImpl(const base::UnguessableToken& token);
  void OnNetworkConnectionChangedImpl(
    net::NetworkChangeNotifier::ConnectionType type,
    double max_bandwidth_mbps);

  void SetFocusImpl(bool focused);
  void MouseCaptureLostImpl();
  void SetEditCommandsForNextKeyEventImpl(const std::vector<common::EditCommand>& commands);
  void CursorVisibilityChangedImpl(bool visible);
  void ImeSetCompositionImpl(const base::string16& text, 
                         const std::vector<ui::ImeTextSpan>& ime_text_spans, 
                         const gfx::Range& range, 
                         int32_t start, 
                         int32_t end);
  void ImeCommitTextImpl(
    const base::string16& text, 
    const std::vector<ui::ImeTextSpan>& ime_text_spans, 
    const gfx::Range& range,
    int32_t relative_cursor_position);

  void ImeFinishComposingTextImpl(bool keep_selection);
  void RequestTextInputStateUpdateImpl();
  void RequestCompositionUpdatesImpl(bool immediate_request, bool monitor_request);
  void DispatchEventImpl(std::unique_ptr<common::InputEvent> event, DispatchEventCallback callback);
  void DispatchNonBlockingEventImpl(std::unique_ptr<common::InputEvent> event);
  void SetCompositionFromExistingTextImpl(int32_t start, int32_t end, const std::vector<ui::ImeTextSpan>& ime_text_spans);
  void ExtendSelectionAndDeleteImpl(int32_t before, int32_t after);
  void DeleteSurroundingTextImpl(int32_t before, int32_t after);
  void DeleteSurroundingTextInCodePointsImpl(int32_t before, int32_t after);
  void SetEditableSelectionOffsetsImpl(int32_t start, int32_t end);
  void ExecuteEditCommandImpl(const std::string& command, const base::Optional<base::string16>& value);
  void UndoImpl();
  void RedoImpl();
  void CutImpl();
  void CopyImpl();
  void CopyToFindPboardImpl();
  void PasteImpl();
  void PasteAndMatchStyleImpl();
  void DeleteImpl();
  void SelectAllImpl();
  void CollapseSelectionImpl();
  void ReplaceImpl(const base::string16& word);
  void ReplaceMisspellingImpl(const base::string16& word);
  void SelectRangeImpl(const gfx::Point& base, const gfx::Point& extent);
  void AdjustSelectionByCharacterOffsetImpl(int32_t start, int32_t end, ::blink::mojom::SelectionMenuBehavior behavior);
  void MoveRangeSelectionExtentImpl(const gfx::Point& extent);
  void ScrollFocusedEditableNodeIntoRectImpl(const gfx::Rect& rect);
  void MoveCaretImpl(const gfx::Point& point);
  void GetWindowInputHandlerImpl(common::mojom::WindowInputHandlerAssociatedRequest interface_request, common::mojom::WindowInputHandlerHostPtr host);
  void CommitNavigationImpl(common::mojom::CommitNavigationParamsPtr params, std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories);
  void CommitSameDocumentNavigationImpl(common::mojom::CommitNavigationParamsPtr params, std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories, CommitSameDocumentNavigationCallback callback);
  void CommitFailedNavigationImpl();
 

  friend class ApplicationThread;

  ApplicationThread* main_thread_;
  CWindowCallbacks handler_;
  void* instance_;

  scoped_refptr<application::ChildURLLoaderFactoryBundle> loader_factories_;

  mojo::AssociatedBinding<common::mojom::ApplicationWindow> window_binding_;
  mojo::AssociatedBinding<common::mojom::WindowInputHandler> window_input_binding_;
  //mojo::AssociatedBinding<common::mojom::FrameInputHandler> frame_input_binding_;

  common::mojom::ApplicationWindowHostAssociatedPtr window_host_interface_;
  common::mojom::WindowInputHandlerHostAssociatedPtr window_input_host_interface_;
  
  //service_manager::BindSourceInfo host_info_;
  mojo::BindingSet<service_manager::mojom::InterfaceProvider> interface_provider_bindings_;
  
  base::ObserverList<ApplicationWindowDispatcherObserver> observers_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationWindowDispatcher);  
};

class ApplicationWindowDispatcherObserver {
public:
  ApplicationWindowDispatcherObserver(ApplicationWindowDispatcher* dispatcher):
   dispatcher_(dispatcher) {
    dispatcher_->AddObserver(this);
  }
  
  virtual ~ApplicationWindowDispatcherObserver(){
    dispatcher_->RemoveObserver(this);
  }

  ApplicationWindowDispatcher* dispatcher() const {
    return dispatcher_;
  }

  ApplicationThread* application_thread() const {
    return dispatcher_->main_thread();
  }

  cc::LayerTreeHost* layer_tree_host() const {
    return dispatcher_->layer_tree_host();
  }

  blink::WebFrame* GetMainWebFrame() const {
    return dispatcher_->GetMainWebFrame();
  }

  blink::WebFrame* GetWebFrame(int id) const {
    return dispatcher_->GetWebFrame(id); 
  }

  virtual void OnInterfaceRequestForFrame(
    const std::string& interface_name, 
    mojo::ScopedMessagePipeHandle* handle) {}

private:
  ApplicationWindowDispatcher* dispatcher_;
};

}

#endif