// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_APPLICATION_HANDLER_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_APPLICATION_HANDLER_H_

typedef void* LayerTreeHostRef;
typedef void* WebURLResponseRef;
typedef void* WebFrameRef;
typedef void* WebWidgetRef;
typedef void* WebViewClientRef;

#include "WebDefinitions.h"

struct CWindowCallbacks {
  void (*SetPageScale)(void* state, float page_scale_factor);
  void (*SetInitialFocus)(void* state, int reverse);
  void (*UpdateTargetURLAck)(void* state);
  void (*UpdateWebPreferences)(void* state, void* web_preferences);
  void (*ClosePage)(void* state);
  void (*MoveOrResizeStarted)(void* state);
  void (*SetBackgroundOpaque)(void* state, int opaque);
  void (*EnablePreferredSizeChangedMode)(void* state);
  void (*DisableScrollbarsForSmallWindows)(void* state, int width, int height);
  void (*SetRendererPrefs)(void* state, void* prefs);
  void (*SetActive)(void* state, int active);
  void (*ForceRedraw)(void* state,
     const char* trace_name,
     int64_t trace_id,
     int ukm_source_id,
     int coalesced,
     int began,
     int terminated,
     int source_event_type,
     float scroll_update_delta,
     float predicted_scroll_update_delta,
     size_t latency_components_size,
     int component_types[],
     int64_t info_event_time[]);
  void (*SelectWordAroundCaret)(void* state);
  void (*UpdateWindowScreenRect)(void* state, int rx, int ry, int rw, int rh);
  void (*SetZoomLevel)(void* state, double zoom_level);
  void (*PageWasHidden)(void* state);
  void (*PageWasShown)(void* state);
  void (*SetHistoryOffsetAndLength)(void* state, int32_t history_offset, int32_t history_length);
  void (*AudioStateChanged)(void* state, int is_audio_playing);
  void (*PausePageScheduledTasks)(void* state, int pause);
  void (*UpdateScreenInfo)(
    void* state, 
    float device_scale_factor, 
    // no colorspace for now, defaults to SRGB
    // int color_space, 
    uint32_t depth, uint32_t depth_per_component, 
    int is_monochrome, 
    int rx, int ry, int rw, int rh,
    int avrx, int avry, int avrw, int avrh,
    int orientation_type, uint16_t orientation_angle);
  void (*FreezePage)(void* state);
  void (*ShowContextMenu)(void* state, int type, int px, int py);
  void (*Close)(void* state);
  void (*SynchronizeVisualProperties)(
     void* state, 
     uint32_t surface_id_parent_sequence_number,
     uint32_t surface_id_child_sequence_number,
     uint64_t surface_id_token_high, 
     uint64_t surface_id_token_low,
     float screen_info_device_scale_factor,
     uint8_t screen_info_color_space_primaries,
     uint8_t screen_info_color_space_transfer,
     uint8_t screen_info_color_space_matrix,
     uint8_t screen_info_color_space_range,
     int64_t screen_info_color_space_icc_profile,
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
     int new_size_w, 
     int new_size_h,
     int compositor_viewport_size_w,
     int compositor_viewport_size_h,   
     int visible_viewport_size_w,
     int visible_viewport_size_h,
     int32_t capture_sequence_number);
  void (*WasHidden)(void* state);
  void (*WasShown)(void* state, 
     int needs_repainting,
     const char* trace_name,
     int64_t trace_id,
     int ukm_source_id,
     int coalesced,
     int began,
     int terminated,
     int source_event_type,
     float scroll_update_delta,
     float predicted_scroll_update_delta,
     size_t latency_components_size,
     int component_types[],
     int64_t event_time[]);
  void (*Repaint)(void* state, int w, int h);
  void (*SetTextDirection)(void* state, int direction);
  void (*MoveAck)(void* state);
  void (*UpdateScreenRects)(void* state, int vx, int vy, int vw, int vh, int wx, int wy, int ww, int wh);
  void (*SetViewportIntersection)(void* state, int ix, int iy, int iw, int ih, int vx, int vy, int vw, int vh);
  void (*SetIsInert)(void* state, int inert);
  void (*UpdateRenderThrottlingStatus)(void* state, int is_throttled, int subtree_throttled);
  void (*DragTargetDragEnter)(void* state,
                              size_t drop_data_size, 
                              int* drop_data_kind,
                              const char** drop_data_mime,
                              const char** drop_data_filename,
                              const char** drop_data_file_system_url,
                              float cx, float cy,
                              float sx, float sy,
                              int ops_allowed,
                              int32_t key_modifiers);
  
  void (*DragTargetDragOver)(void* state, 
                             float cx, float cy,
                             float sx, float sy,
                             int ops_allowed,
                             int32_t key_modifiers);
  void (*DragTargetDragLeave)(void* state, float cx, float cy, float sx, float sy);
  void (*DragTargetDrop)( void* state, 
                          int drop_data_view_id,
                          int drop_data_did_originate_from_renderer,
                          const char* drop_data_url_string,
                          const char* drop_data_url_title,
                          const char* drop_data_download_metadata,
                          int drop_data_filenames_size,
                          const char** drop_data_filenames,
                          int drop_data_file_mime_types_size,
                          const char** drop_data_file_mime_types,
                          const char* drop_data_filesystem_id,
                          int drop_data_file_system_files_count,
                          const char** drop_data_file_system_files_url,
                          int* drop_data_file_system_files_filesize,
                          const char** drop_data_file_system_files_filesystem_id,
                          const char* drop_data_text,
                          const char* drop_data_html,
                          const char* drop_data_html_base_url,
                          const char* drop_data_file_contents,
                          const char* drop_data_file_contents_source_url,
                          const char* drop_data_file_contents_filename_extension,
                          const char* drop_data_file_contents_content_disposition,
                          int drop_data_custom_data_size,
                          const char** drop_data_custom_data_keys,
                          const char** drop_data_custom_data_values,
                          float cx, float cy,
                          float sx, float sy,
                          int32_t key_modifiers);
  void (*DragSourceEnded)(void* state, float cx, float cy,
                          float px, float py, int drag_operations);
  void (*DragSourceSystemDragEnded)(void* state);
  void (*MediaPlayerActionAt)(void* state, int px, int py, int action, int enable);
  void (*SetFocusedWindow)(void* state);
  void (*LockMouseAck)(void* state, int succeeded);
  void (*MouseLockLost)(void* state);
  void (*CopyImageAt)(void* state, float x, float y);
  void (*SaveImageAt)(void* state, float x, float y);
  void (*SwapOut)(void* state, int32_t window_id, int is_loading);

  // InputHandler

  void (*SetFocus)(void* state, int focused);
  void (*MouseCaptureLost)(void* state);
  void (*SetEditCommandsForNextKeyEvent)(
    void* state, 
    const char** edit_cmd_name,
    const char** edit_cmd_value,
    int edit_cmd_count);
  void (*CursorVisibilityChanged)(void* state, int visible);
  void (*ImeSetComposition)(void* state, 
    const uint16_t* text, 
    int* tspan_type,
    uint32_t* tspan_start_offset,
    uint32_t* tspan_end_offset,
    int* tspan_underline_color,
    int* tspan_thickness,
    int* tspan_background_color,
    int tspan_count,
    uint32_t range_start, 
    uint32_t range_end,
    int32_t start, 
    int32_t end);

  void (*ImeCommitText)(
    void* state,
    const uint16_t* text,
    int* tspan_type,
    uint32_t* tspan_start_offset,
    uint32_t* tspan_end_offset,
    int* tspan_underline_color,
    int* tspan_thickness,
    int* tspan_background_color,
    int tspan_count,
    uint32_t range_start, 
    uint32_t range_end,
    int32_t relative_cursor_position);

  void (*ImeFinishComposingText)(void* state, int keep_selection);
  void (*RequestTextInputStateUpdate)(void* state);
  void (*RequestCompositionUpdates)(void* state, int immediate_request, int monitor_request);
  int (*DispatchEvent)(void* state, void* input_event);
  void (*DispatchNonBlockingEvent)(void* state, void* input_event);
  //void (*AttachSynchronousCompositor)(
  //  void* state,
  //  common::mojom::SynchronousCompositorControlHostPtr control_host, 
  //  common::mojom::SynchronousCompositorHostAssociatedPtrInfo host, 
  //  common::mojom::SynchronousCompositorAssociatedRequest compositor_request);

  // FrameInputHandler

  void (*SetCompositionFromExistingText)(void* state, int32_t start, int32_t end,
    int* tspan_type,
    uint32_t* tspan_start_offset,
    uint32_t* tspan_end_offset,
    int* tspan_underline_color,
    int* tspan_thickness,
    int* tspan_background_color,
    int tspan_count);
  void (*ExtendSelectionAndDelete)(void* state, int32_t before, int32_t after);
  void (*DeleteSurroundingText)(void* state, int32_t before, int32_t after);
  void (*DeleteSurroundingTextInCodePoints)(void* state, int32_t before, int32_t after);
  void (*SetEditableSelectionOffsets)(void* state, int32_t start, int32_t end);
  void (*ExecuteEditCommand)(void* state, const char* command, const uint16_t* value);
  void (*Undo)(void* state);
  void (*Redo)(void* state);
  void (*Cut)(void* state);
  void (*Copy)(void* state);
  void (*CopyToFindPboard)(void* state);
  void (*Paste)(void* state);
  void (*PasteAndMatchStyle)(void* state);
  void (*Delete)(void* state);
  void (*SelectAll)(void* state);
  void (*CollapseSelection)(void* state);
  void (*Replace)(void* state, const uint16_t* word);
  void (*ReplaceMisspelling)(void* state, const uint16_t* word);
  void (*SelectRange)(void* state, int base_x, int base_y, int extent_x, int extent_y);
  void (*AdjustSelectionByCharacterOffset)(void* state, int32_t start, int32_t end, int select_menu_behavior);
  void (*MoveRangeSelectionExtent)(void* state, int extent_x, int extent_y);
  void (*ScrollFocusedEditableNodeIntoRect)(void* state, int rx,int ry,int rw,int rh);
  void (*MoveCaret)(void* state, int px, int py);
  //void (*GetWindowInputHandler)(common::mojom::WindowInputHandlerAssociatedRequest interface_request, common::mojom::WindowInputHandlerHostPtr host);
  void (*IntrinsicSizingInfoOfChildChanged)(void* state, float size_w, float size_h, float aspect_ratio_w, float aspect_ratio_h, int has_width, int has_height);
  void (*BeforeUnload)(void* state, int is_reload);
  void (*ViewChanged)(void* state, int has_frame_sink_id, uint32_t frame_sink_id_client_id, uint32_t frame_sink_id_route_id);
  void (*SetChildFrameSurface)(void* state, 
                               uint32_t surface_info_client_id, 
                               uint32_t surface_info_sink_id,
                               uint32_t surface_info_parent_sequence_number,
                               uint32_t surface_info_child_sequence_number,
                               uint64_t surface_info_token_high, 
                               uint64_t surface_info_token_low,
                               float device_scale_factor,
                               int size_width,
                               int size_height);
  void (*ChildFrameProcessGone)(void* state);
  void (*SwapIn)(void* state);
  void (*FrameDelete)(void* state);
  void (*Stop)(void* state);
  void (*DroppedNavigation)(void* state);
  void (*DidStartLoading)(void* state);
  void (*DidStopLoading)(void* state);
  void (*Collapse)(void* state, int collapsed);
  void (*WillEnterFullscreen)(void* state);
  void (*EnableAutoResize)(void* state, int min_size_w, int min_size_h, int max_size_w, int max_size_h);
  void (*DisableAutoResize)(void* state);
  void (*ContextMenuClosed)(void* state);
  void (*CustomContextMenuAction)(void* state, uint32_t action);
  void (*VisualStateRequest)(void* state, uint64_t id);
  void (*DispatchLoad)(void* state);
  void (*Reload)(void* state, int bypass_cache);
  void (*ReloadLoFiImages)(void* state);
  void (*SnapshotAccessibilityTree)(void* state);
  void (*UpdateOpener)(void* state, int32_t opener_routing_id);
  void (*SetFocusedFrame)(void* state);
  void (*CheckCompleted)(void* state);
  void (*PostMessageEvent)(void* state);
  void (*NotifyUserActivation)(void* state);
  void (*DidUpdateOrigin)(void* state, const char* origin);
  void (*ScrollRectToVisible)(void* state, int rect_to_scroll_x, int rect_to_scroll_y, int rect_to_scroll_w, int rect_to_scroll_h);
  void (*TextSurroundingSelectionRequest)(void* state, uint32_t max_len);
  void (*AdvanceFocus)(void* state, int type, int32_t source_routing_id);
  void (*AdvanceFocusInForm)(void* state, int type);
  void (*Find)(
    void* state, 
    int32_t request_id,
    const uint16_t* search_text, 
    int forward,
    int match_case,
    int find_next,
    int word_start,
    int medial_capital_as_word_start,
    int force);
  void (*ClearActiveFindMatch)(void* state);
  void (*StopFinding)(void* state, int stop_find_action);
  void (*ClearFocusedElement)(void* state);
  void (*SetOverlayRoutingToken)(void* state, uint64_t token_high, uint64_t token_low);
  void (*OnNetworkConnectionChanged)(void* state, int connection_type, double max_bandwidth_mbps);
  void (*CommitNavigation)(void* state, const char* url, int keep_alive, int32_t provider_id, int route_id);
  int (*CommitSameDocumentNavigation)(void* state, const char* url, int keep_alive, int32_t provider_id, int route_id);
  void (*CommitFailedNavigation)(void* state);
  LayerTreeHostRef (*GetLayerTreeHost)(void* state);
  WebFrameRef (*GetMainWebFrame)(void* state);
  WebFrameRef (*GetWebFrame)(void* state, int id);
  WebWidgetRef (*GetWebWidget)(void* state);
  WebViewClientRef (*GetWebViewClient)(void* state);
  void* (*CreateURLLoader)(void* state, void* request, struct CBlinkPlatformCallbacks* cbs);
  int (*CountResponseHandler)(void* state);
  void* (*GetResponseHandlerAt)(void* state, int index, struct CResponseHandler* cbs);
  void* (*GetServiceWorkerContextClientState)(void* state); 
  ServiceWorkerContextClientCallbacks (*GetServiceWorkerContextClientCallbacks)(void* state);
};

struct CApplicationCallbacks {
  void (*CreateNewWindow)(void* state,
     uint32_t surface_id_parent_sequence_number,
     uint32_t surface_id_child_sequence_number,
     uint64_t surface_id_token_high, 
     uint64_t surface_id_token_low,
     float screen_info_device_scale_factor,
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
     int new_size_w, 
     int new_size_h,
     int compositor_viewport_size_w,
     int compositor_viewport_size_h,   
     int visible_viewport_size_w,
     int visible_viewport_size_h,
     int32_t capture_sequence_number);
  void (*OnExternalTextureLayerRequested)(void* state);
};

struct CBlinkPlatformCallbacks {
  void (*URLLoaderLoadAsynchronously)(void* state);
  void (*URLLoaderLoadSynchronously)(void* state);
  void (*URLLoaderCancel)(void* state);
  void (*URLLoaderSetDefersLoading)(void* state, int defers);
  void (*URLLoaderDidChangePriority)(void* state);
};

struct CResponseHandler {
  const char* (*GetName)(void* state);
  int (*WillHandleResponse)(void* state, WebURLResponseRef web_url_response);
  int (*OnDataAvailable)(void* state, const char* input, int input_len);
  int (*OnFinishLoading)(void* state, int error_code, int total_transfer_size);
  void (*GetResult)(void* state, char** output, int* output_len);
};

struct WebMediaPlayerDelegateCallbacks {
  int (*IsFrameHidden)(void* state);
  int (*IsFrameClosed)(void* state);
  int (*AddObserver)(void* state, void* observer);
  void (*RemoveObserver)(void* state, int player_id);
  void (*DidPlay)(void* state,
                  int player_id,
                  int has_video,
                  int has_audio,
                  int media_content_type);
  void (*DidPause)(void* state, int player_id);
  void (*DidPlayerSizeChange)(void* state, int delegate_id, int sw, int wh);
  void (*DidPlayerMutedStatusChange)(void* state, int delegate_id, int muted);
  void (*DidPictureInPictureSourceChange)(void* state, int delegate_id);
  void (*DidPictureInPictureModeEnd)(void* state, int delegate_id);
  void (*PlayerGone)(void* state, int player_id);
  void (*SetIdle)(void* state, int player_id, int is_idle);
  int (*IsIdle)(void* state, int player_id);
  void (*ClearStaleFlag)(void* state, int player_id);
  int (*IsStale)(void* state, int player_id);
  void (*SetIsEffectivelyFullscreen)(
      void* state,
      int player_id,
      int fullscreen_video_status);
  void (*OnPictureInPictureSurfaceIdUpdated)(
        void* state,
        int delegate_id,
        uint32_t surface_id_client_id,
        uint32_t surface_id_sink_id, 
        uint32_t surface_id_parent_sequence_number,
        uint32_t surface_id_child_sequence_number,
        uint64_t surface_id_token_high, 
        uint64_t surface_id_token_low,
        int width,
        int height);
  void (*OnExitPictureInPicture)(void* state, int delegate_id);
  void (*OnMediaDelegatePause)(void* state, int player_id);
  void (*OnMediaDelegatePlay)(void* state, int player_id);
  void (*OnMediaDelegateSeekForward)(
    void* state, 
    int player_id,
    int64_t seek_milliseconds);
  void (*OnMediaDelegateSeekBackward)(
    void* state, 
    int player_id,
    int64_t seek_milliseconds);
  void (*OnMediaDelegateSuspendAllMediaPlayers)(void* state);
  void (*OnMediaDelegateVolumeMultiplierUpdate)(
    void* state, 
    int player_id,
    double multiplier);
 void (*OnMediaDelegateBecamePersistentVideo)(
    void* state,
    int player_id,
    int value);
 void (*OnPictureInPictureModeEnded)(
    void* state,
    int player_id);
};

#endif
