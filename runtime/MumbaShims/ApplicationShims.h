// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_APPLICATION_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_APPLICATION_SHIMS_H_

#include "Globals.h"
#include "SkiaShims.h"
#include "ApplicationHandler.h"

typedef void* ApplicationInstanceRef;
typedef void* WindowRef;
typedef void* LayerRef;
typedef void* LayerTreeHostRef;
typedef void* SwapPromiseRef;

EXPORT ApplicationInstanceRef _ApplicationInstanceCreate(
  void* instance_state,
  int argc, 
  const char** argv,
  void* window_state, 
  struct CWindowCallbacks window_callbacks,
  struct CApplicationCallbacks app_callbacks);
EXPORT void _ApplicationInstanceDestroy(ApplicationInstanceRef instance);
EXPORT void _ApplicationInstanceRunLoop(ApplicationInstanceRef instance);
EXPORT void _ApplicationInstanceExitLoop(ApplicationInstanceRef instance);
EXPORT void _ApplicationInstanceAddRefProcess(ApplicationInstanceRef instance);
EXPORT void _ApplicationInstanceReleaseProcess(ApplicationInstanceRef instance);
EXPORT int32_t _ApplicationInstanceGetApplicationProcessHostId(ApplicationInstanceRef instance);
EXPORT int32_t _ApplicationInstanceGetApplicationWindowHostId(ApplicationInstanceRef instance);
EXPORT int32_t _ApplicationInstanceGetRoutingId(ApplicationInstanceRef instance);
EXPORT char* _ApplicationInstanceGetInitialUrl(ApplicationInstanceRef instance, int* size);
EXPORT int _ApplicationInstanceIsHeadless(ApplicationInstanceRef instance);
EXPORT ApplicationInstanceRef _ApplicationInstanceGetCurrent();
EXPORT void _ApplicationInstanceSetColorSpace(
  ApplicationInstanceRef instance,
  uint8_t primaries,
  uint8_t transfer,
  uint8_t matrix,
  uint8_t range,
  int64_t icc_profile);
EXPORT void _ApplicationInstanceWindowHidden(ApplicationInstanceRef instance);
EXPORT void _ApplicationInstanceWindowCreated(ApplicationInstanceRef instance);
EXPORT void _ApplicationInstanceWindowRestored(ApplicationInstanceRef instance);
EXPORT void _ApplicationInstanceRequestNewLayerTreeFrameSink(
  ApplicationInstanceRef instance,
  LayerTreeHostRef layer_tree_host,
  void* state,
  void(*cb)(void*, void*));

EXPORT SwapPromiseRef _ApplicationInstanceQueueVisualStateResponse(ApplicationInstanceRef reference, int32_t source_frame_number, uint64_t id);
EXPORT void _ApplicationInstanceSendWindowCreatedAck(ApplicationInstanceRef instance);

EXPORT WindowRef _WindowCreate(ApplicationInstanceRef instance);
EXPORT void _WindowDestroy(WindowRef state);
EXPORT void _WindowApplicationProcessGone(WindowRef state, int status, int exit_code);
EXPORT void _WindowHittestData(WindowRef state, /* surface_id */ uint32_t sid_client_id, uint32_t sid_sink_id, uint32_t sid_parent, uint32_t sid_child, uint64_t sid_token_high, uint64_t sid_token_low /* end surface_id*/, int ignored_for_hittest);
EXPORT void _WindowClose(WindowRef state);
EXPORT void _WindowSetTextureLayerForCanvas(WindowRef state, const char* target, LayerRef texture_layer);
EXPORT void _WindowUpdateState(WindowRef state);
EXPORT void _WindowUpdateScreenRectsAck(WindowRef state);
EXPORT void _WindowRequestMove(WindowRef state, int px, int py, int pw, int ph);
EXPORT void _WindowSetTooltipText(WindowRef state, const char* text, int text_direction);
EXPORT void _WindowResizeOrRepaintACK(WindowRef state, int view_width, int view_height, int flags, int optional_local_surface_is_set,/* surface_id */ uint32_t sid_parent, uint32_t sid_child, uint64_t sid_token_high, uint64_t sid_token_low /* end surface_id*/);  
EXPORT void _WindowSetCursor(WindowRef state, int type, int hotspot_x, int hotspot_y, float scale, ImageRef custom_data);
EXPORT void _WindowAutoscrollStart(WindowRef state, float px, float py);
EXPORT void _WindowAutoscrollFling(WindowRef state, float vx, float vy);  
EXPORT void _WindowAutoscrollEnd(WindowRef state);  
EXPORT void _WindowTextInputStateChanged(WindowRef state,
  int type, 
  int mode, 
  int flags,
  const char* value, 
  int selection_start, 
  int selection_end, 
  int composition_start, 
  int composition_end, 
  int can_compose_inline, 
  int show_ime_if_needed, 
  int reply_to_request);
EXPORT void _WindowLockMouse(WindowRef state, int user_gesture, int privileged);
EXPORT void _WindowUnlockMouse(WindowRef state);
EXPORT void _WindowSelectionBoundsChanged(WindowRef state,
  int ax, int ay, int aw, int ah,
  int anchor_text_dir,
  int fx, int fy, int fw, int fh,
  int focus_text_dir,
  int is_anchor_first);
EXPORT void _WindowFocusedNodeTouched(WindowRef state, int editable);
EXPORT void _WindowStartDragging(WindowRef state, 
  int view_id,
  const char* url,
  const char* url_title,
  const char* download_metadata, 
  int ops_allowed, 
  BitmapRef image, 
  int offset_x, 
  int offset_y, 
  int ev_loc_x, 
  int ev_loc_y,
  int event_source);
EXPORT void _WindowUpdateDragCursor(WindowRef state, int drag_operation);
EXPORT void _WindowFrameSwapMessagesReceived(WindowRef state, uint32_t frame_token);
EXPORT void _WindowShowWindow(WindowRef state, int route_id, int x, int y, int w, int h);
EXPORT void _WindowShowFullscreenWindow(WindowRef state, int route_id);
EXPORT void _WindowUpdateTargetURL(WindowRef state, const char* url);
EXPORT void _WindowDocumentAvailableInMainFrame(WindowRef state, int uses_temporary_zoom_level);
EXPORT void _WindowDidContentsPreferredSizeChange(WindowRef state, int x, int y);
EXPORT void _WindowRouteCloseEvent(WindowRef state);
EXPORT void _WindowTakeFocus(WindowRef state, int reverse);
EXPORT void _WindowLayerTreeFrameSinkInitialized(WindowRef state);
EXPORT void _WindowClosePageACK(WindowRef state);
EXPORT void _WindowFocus(WindowRef state);
EXPORT void _WindowCreateNewWindowOnHost(WindowRef state, 
  int user_gesture,
  int window_container_type,
  const char* window_name,
  int opener_suppressed,
  int window_disposition,
  const char* target_url,
  int window_id,
  int swapped_out,
  int hidden,
  int never_visible,
  int enable_auto_resize,
  int sw,
  int sh,
  float zoom_level,
  float window_features_x,
  float window_features_y,
  float window_features_w,
  float window_features_h);
EXPORT void _WindowDidCommitProvisionalLoad(WindowRef state, 
  int http_status_code, 
  int url_is_unreachable, 
  const char* method);
EXPORT void _WindowDidCommitSameDocumentNavigation(WindowRef state);
EXPORT void _WindowBeginNavigation(WindowRef state, const char* url);
EXPORT void _WindowDidChangeName(WindowRef state, const char* name);
EXPORT void _WindowDidChangeOpener(WindowRef state, int opener);
EXPORT void _WindowDetachFrame(WindowRef state, int id);
EXPORT void _WindowFrameSizeChanged(WindowRef state, int x, int y); 
EXPORT void _WindowOnUpdatePictureInPictureSurfaceId(WindowRef state, /* surface_id */ uint32_t sid_client_id, uint32_t sid_sink_id, uint32_t sid_parent, uint32_t sid_child, uint64_t sid_token_high, uint64_t sid_token_low /* end surface_id*/, int sx, int sy);
EXPORT void _WindowOnExitPictureInPicture(WindowRef state);
EXPORT void _WindowOnSwappedOut(WindowRef state);

EXPORT void _WindowCancelTouchTimeout(WindowRef state);
EXPORT void _WindowSetWhiteListedTouchAction(
    WindowRef state,
    int touch_action,
    uint32_t unique_touch_event_id,
    int input_event_state);
EXPORT void _WindowDidOverscroll(
  WindowRef state,
  float accumulated_overscroll_x,
  float accumulated_overscroll_y,
  float latest_overscroll_delta_x,
  float latest_overscroll_delta_y,
  float current_fling_velocity_x,
  float current_fling_velocity_y,
  float causal_event_viewport_point_x,
  float causal_event_viewport_point_y,
  int overscroll_behavior_x,
  int overscroll_behavior_y);
EXPORT void _WindowDidStopFlinging(WindowRef state);
EXPORT void _WindowDidStartScrollingViewport(WindowRef state);
EXPORT void _WindowImeCancelComposition(WindowRef state);
EXPORT void _WindowImeCompositionRangeChanged(
  WindowRef state,
  uint32_t range_start, 
  uint32_t range_end,
  int* bounds_x,
  int* bounds_y,
  int* bounds_w,
  int* bounds_h,
  int bounds_count);
EXPORT void _WindowHasTouchEventHandlers(WindowRef state, int has_handlers);
EXPORT void _WindowSelectWordAroundCaretAck(WindowRef state, int did_select, int start, int end);
EXPORT void _WindowSwapOutAck(WindowRef state);
//EXPORT void _WindowDetach(WindowRef state);
EXPORT void _WindowFrameFocused(WindowRef state);
EXPORT void _WindowDidStartProvisionalLoad(WindowRef state, const char* url, int64_t navigation_start);
EXPORT void _WindowDidFailProvisionalLoadWithError(WindowRef state, int32_t error_code, const uint16_t* error_description, const char* url);
EXPORT void _WindowDidFinishDocumentLoad(WindowRef state);
EXPORT void _WindowDidFailLoadWithError(WindowRef state, const char* url, int32_t error_code, const uint16_t* error_description);
EXPORT void _WindowDidStartLoading(WindowRef state, int to_different_document);
EXPORT void _WindowSendDidStopLoading(WindowRef state);
//EXPORT void _WindowUpdateState(::common::mojom::PageStatePtr state);
EXPORT void _WindowDidChangeLoadProgress(WindowRef state, double load_progress);
EXPORT void _WindowOpenURL(WindowRef state, const char* url);
EXPORT void _WindowDidFinishLoad(WindowRef state, const char* url);
EXPORT void _WindowDocumentOnLoadCompleted(WindowRef state, int64_t timestamp);
EXPORT void _WindowDidAccessInitialDocument(WindowRef state);
EXPORT void _WindowUpdateTitle(WindowRef state, const int8_t* title, int title_len, int text_direction);
EXPORT void _WindowBeforeUnloadAck(WindowRef state, int proceed, int64_t start_ticks, int64_t end_ticks);
EXPORT void _WindowSynchronizeVisualProperties(
  WindowRef state,
  /*
   SurfaceId
  */
  uint32_t surface_id_client_id,
  uint32_t surface_id_sink_id, 
  uint32_t surface_id_parent_sequence_number,
  uint32_t surface_id_child_sequence_number,
  uint64_t surface_id_token_high, 
  uint64_t surface_id_token_low,
  /*
   ScreenInfo
  */
   float screen_info_device_scale_factor,
   int screen_info_primaries,
   int screen_info_transfer,
   int screen_info_matrix,
   int screen_info_range,
   int64_t screen_info_icc_profile,
   uint32_t screen_info_depth,
   uint32_t screen_info_depth_per_component,
   int screen_info_is_monochrome,
   int screen_info_rect_x,
   int screen_info_rect_y,
   int screen_info_rect_w,
   int screen_info_rect_h,
   int screen_info_available_rect_x,
   int screen_info_available_rect_y,
   int screen_info_available_rect_w,
   int screen_info_available_rect_h,
   int screen_info_orientation_type,
   uint16_t screen_info_orientation_angle,
   int auto_resize_enabled, 
   int min_size_for_auto_resize_w, 
   int min_size_for_auto_resize_h, 
   int max_size_for_auto_resize_w, 
   int max_size_for_auto_resize_h,
   int screen_space_rect_x, 
   int screen_space_rect_y,
   int screen_space_rect_w,
   int screen_space_rect_h,   
   int local_frame_size_w,
   int local_frame_size_h,
   int32_t capture_sequence_number);
EXPORT void _WindowUpdateViewportIntersection(
  WindowRef state, 
  int intersection_x, 
  int intersection_y, 
  int intersection_w, 
  int intersection_h, 
  int visible_x, 
  int visible_y, 
  int visible_w, 
  int visible_h);
EXPORT void _WindowVisibilityChanged(WindowRef state, int visible);
EXPORT void _WindowSendUpdateRenderThrottlingStatus(WindowRef state, int is_throttled, int subtree_throttled);
EXPORT void _WindowSetHasReceivedUserGesture(WindowRef state);
EXPORT void _WindowSetHasReceivedUserGestureBeforeNavigation(WindowRef state,int value);
EXPORT void _WindowContextMenu(WindowRef state);
EXPORT void _WindowSelectionChanged(WindowRef state, const uint16_t* selection, uint32_t offset, int range_start, int range_end);
EXPORT void _WindowVisualStateResponse(WindowRef state, uint64_t id);
EXPORT void _WindowEnterFullscreen(WindowRef state);
EXPORT void _WindowExitFullscreen(WindowRef state);
EXPORT void _WindowSendDispatchLoad(WindowRef state);
EXPORT void _WindowSendCheckCompleted(WindowRef state);
EXPORT void _WindowUpdateFaviconURL(WindowRef state, const char** favicons_url, int favicon_count);
EXPORT void _WindowScrollRectToVisibleInParentFrame(WindowRef state, int rect_x, int rect_y, int rect_w, int rect_h);
EXPORT void _WindowFrameDidCallFocus(WindowRef state);
EXPORT void _WindowTextSurroundingSelectionResponse(
  WindowRef state,
  const uint16_t* content,
  uint32_t start_offset, 
  uint32_t end_offset);

EXPORT void _WindowCloseAck(WindowRef state);

EXPORT void _WindowSendOnMediaDestroyed(WindowRef state, int delegate_id);
EXPORT void _WindowSendOnMediaPaused(WindowRef state, int delegate_id, int reached_end_of_stream);
EXPORT void _WindowSendOnMediaPlaying(WindowRef state, 
  int delegate_id, 
  int has_video,
  int has_audio,
  int is_remote,
  int content_type);
EXPORT void _WindowSendOnMediaMutedStatusChanged(WindowRef state, int delegate_id, int muted);
EXPORT void _WindowSendOnMediaEffectivelyFullscreenChanged(WindowRef state, int delegate_id, int fullscreen_status);
EXPORT void _WindowSendOnMediaSizeChanged(WindowRef state, int delegate_id, int sw, int sh);
EXPORT void _WindowSendOnPictureInPictureSourceChanged(WindowRef state, int delegate_id);
EXPORT void _WindowSendOnPictureInPictureModeEnded(WindowRef state, int delegate_id);
EXPORT void _WindowOnWebFrameCreated(WindowRef state, WebFrameRef frame, int is_main);

#endif