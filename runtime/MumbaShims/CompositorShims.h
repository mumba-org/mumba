// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_OMPOSITOR_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_OMPOSITOR_SHIMS_H_

#include "Globals.h"
#include "CompositorCallbacks.h"
#include "CompositorFrameSinkCallbacks.h"
#include "SkiaShims.h"

#if defined(OS_LINUX)
typedef unsigned long XID;
//#include "X11Shims.h"
#elif defined(OS_WIN)
//#include <windows.h>
typedef void* HWND;
#endif

/* LayerTree */

typedef void* LayerTreeHostRef;
typedef void* LayerRef;
typedef void* LayerTreeRef;
typedef void* LayerTreeMutatorRef;
typedef void* AnimationHostRef;
typedef void* AnimationTimelineRef;

//typedef void* AnimationRegistrarRef;
typedef void* SwapPromiseMonitorRef;
typedef void* SwapPromiseRef;
typedef void* PropertyTreesRef;
typedef void* OutputSurfaceRef;
typedef void* AnimationEventRef;
typedef void* CopyOutputRequestRef;
//typedef void* LayerAnimationEventObserverRef;
//typedef void* LayerAnimationControllerRef;
typedef void* AnimationRef;
typedef void* AnimationCurveRef;
typedef void* CompositorFrameRef;
typedef void* ContextProviderRef;
typedef void* DisplayItemListRef;

typedef void* TransferableResourceRef;

//typedef void* DisplayItemRef;
typedef void* PaintRecordRef;
typedef void* PathEffectRef;
typedef void* PaintShaderRef;
typedef void* PaintFlagsRef;
typedef void* PaintFilterRef;

typedef void* KeyframeEffectRef;
typedef void* KeyframeModelRef;
typedef void* ElementAnimationsRef;
typedef void* KeyframeEffectListRef;
typedef void* AnimationEventsRef;
typedef void* AnimationEventRef;
typedef int64_t (*AnimationTimeProviderCallback)(void *state, KeyframeModelRef model);

typedef void* TransformOperationsRef;
typedef void* TransformOperationRef;

typedef void* FilterOperationRef;
typedef void* FilterOperationsRef;

typedef void* InputHandlerRef;

typedef void* LayerTreeFrameSinkRef;
typedef void* FrameSinkManagerRef;
typedef void* HostFrameSinkManagerRef;
typedef void* DisplayRef;
typedef void* BeginFrameSourceRef;
typedef void* FrameSwapMessageQueueRef;

typedef void* InProcessContextProviderRef;

struct HostFrameSinkClientCallbacks;

const int DidNotSwapReasonSwapFails       = 0;
const int DidNotSwapReasonCommitFails     = 1;
const int DidNotSwapReasonCommitNoUpdate  = 2;
const int DidNotSwapReasonActivationFails = 3;

const int AnimationEventTypeStarted        = 0;
const int AnimationEventTypeFinished       = 1;
const int AnimationEventTypeAborted        = 2;
const int AnimationEventTypePropertyUpdate = 3;

const int AnimationTargetPropertyTransform = 0;
const int AnimationTargetPropertyOpacity = 1;
const int AnimationTargetPropertyFilter = 2;
const int AnimationTargetPropertyScrollOffset = 3;
const int AnimationTargetPropertyBackgroundColor = 4;

const int SelectionBoundTypeLeft = 0;
const int SelectionBoundTypeRight = 1;
const int SelectionBoundTypeCenter = 2;
const int SelectionBoundTypeEmpty = 3;

const int TopControlsStateShown = 1;
const int TopControlsStateHidden = 2;
const int TopControlsStateBoth = 3;

const int LayerTreeTypeActive = 0;
const int LayerTreeTypePending = 1;

const int TransferModeClear = 0;
const int TransferModeSrc = 1;
const int TransferModeDst = 2;
const int TransferModeSrcOver = 3;
const int TransferModeDstOver = 4;
const int TransferModeSrcIn = 5;
const int TransferModeDstIn = 6;
const int TransferModeSrcOut = 7;
const int TransferModeDstOut = 8;
const int TransferModeSrcATop = 9;
const int TransferModeDstATop = 10;
const int TransferModeXor = 11;
const int TransferModePlus = 12;
const int TransferModeModulate = 13;
const int TransferModeScreen = 14;
const int TransferModeOverlay = 15;
const int TransferModeDarken = 16;
const int TransferModeLighten = 17;
const int TransferModeColorDodge = 18;
const int TransferModeColorBurn = 19;
const int TransferModeHardLight = 20;
const int TransferModeSoftLight = 21;
const int TransferModeDifference = 22;
const int TransferModeExclusion = 23;
const int TransferModeMultiply = 24;
const int TransferModeHue = 25;
const int TransferModeSaturation = 26;
const int TransferModeColor = 27;
const int TransferModeLuminosity = 28;

const int ScrollBlocksOnNone = 0x0;
const int ScrollBlocksOnStartTouch = 0x1;
const int ScrollBlocksOnWheelEvent = 0x2;
const int ScrollBlocksOnScrollEvent = 0x4;

const int OutputSurfaceTypeDirect = 0;

// const int DisplayItemTypeClip = 0;
// const int DisplayItemTypeEndClip = 1;
// const int DisplayItemTypeClipPath = 2;
// const int DisplayItemTypeEndClipPath = 3;
// const int DisplayItemTypeCompositing = 4;
// const int DisplayItemTypeEndCompositing = 5;
// const int DisplayItemTypeFilter = 6;
// const int DisplayItemTypeEndFilter = 7;
// const int DisplayItemTypeDrawing = 8;
// const int DisplayItemTypeFloatClip = 9;
// const int DisplayItemTypeEndFloatClip = 10;
// const int DisplayItemTypeTransform = 11;
// const int DisplayItemTypeEndTransform = 12;

// KeyframeModel
const int RunStateWaitingForTargetAvailability = 0;
const int RunStateWaitingForDeletion = 1;
const int RunStateStarting = 2;
const int RunStateRunning = 3;
const int RunStatePaused = 4;
const int RunStateFinished = 5;
const int RunStateAborted = 6;
const int RunStateAbortedButNeedsCompletion = 7;
// KeyframeModel
const int DirectionNormal = 0;
const int DirectionReverse = 1;
const int DirectionAlternateNormal = 2;
const int DirectionAlternateReverse = 3;
// KeyframeModel
const int FillModeNone = 0;
const int FillModeForwards = 1;
const int FillModeBackwards = 2;
const int FillModeBoth = 3;
const int FillModeAuto = 4;

// DisplayListUsageHint
const int DisplayListUsageHintTopLevelDisplayItemList = 0;
const int DisplayListUsageHintToBeReleasedAsPaintOpBuffer = 1;

// helpers
//EXPORT void _AnimationRegistrarDestroy(AnimationRegistrarRef handle);
EXPORT void _PropertyTreesDestroy(PropertyTreesRef handle);

// DisplayItem

// TODO: i know they are ref_counted but how can we garantee
// they wont leak? only seting their handles to nil in the swift code
// will suffice?
// EXPORT DisplayItemRef _DisplayItemClipCreate();
// EXPORT DisplayItemRef _DisplayItemEndClipCreate();
// EXPORT DisplayItemRef _DisplayItemClipPathCreate();
// EXPORT DisplayItemRef _DisplayItemEndClipPathCreate();
// EXPORT DisplayItemRef _DisplayItemCompositingCreate();
// EXPORT DisplayItemRef _DisplayItemEndCompositingCreate();
// EXPORT DisplayItemRef _DisplayItemFilterCreate();
// EXPORT DisplayItemRef _DisplayItemEndFilterCreate();
// EXPORT DisplayItemRef _DisplayItemDrawingCreate();
// EXPORT DisplayItemRef _DisplayItemFloatClipCreate();
// EXPORT DisplayItemRef _DisplayItemEndFloatClipCreate();
// EXPORT DisplayItemRef _DisplayItemTransformCreate();
// EXPORT DisplayItemRef _DisplayItemEndTransformCreate();

// EXPORT void _ClipDisplayItemSetNew(DisplayItemRef handle, int cx, int cy, int cw, int ch);
// EXPORT void _ClipPathDisplayItemSetNew(DisplayItemRef handle, PathRef path, int clip_op, int antialias);
// EXPORT void _CompositingDisplayItemSetNew(DisplayItemRef handle, uint8_t alpha, int blend_mode, int* bx, int* by, int* bw, int* bh, ColorFilterRef filter);
// EXPORT void _DrawingDisplayItemSetNew(DisplayItemRef handle, PictureRef picture);
// EXPORT void _FilterDisplayItemSetNew(DisplayItemRef handle, float rx, float ry, float rw, float rh);
// EXPORT void _FloatClipDisplayItemSetNew(DisplayItemRef handle, float rx, float ry, float rw, float rh);
// EXPORT void _TransformDisplayItemSetNew(DisplayItemRef handle,
//   double col1row1, double col2row1,
//   double col3row1, double col4row1,
//   double col1row2, double col2row2,
//   double col3row2, double col4row2,
//   double col1row3, double col2row3,
//   double col3row3, double col4row3,
//   double col1row4, double col2row4,
//   double col3row4, double col4row4);

EXPORT void _CompositorInitialize(int single_threaded);

EXPORT PaintShaderRef _PaintShaderCreateColor(int r, int g, int b, int a);

EXPORT PaintShaderRef _PaintShaderCreateLinearGradient(
      const float* px,
      const float* py,
      const int* inputColors,
      const float* pos,
      int count,
      int shader_tile_mode);

EXPORT PaintShaderRef _PaintShaderCreateRadialGradient(
      float center_x,
      float center_y,
      float radius,
      int* r,
      int* g,
      int* b,
      int* a,
      float* pos,
      int color_count,
      int shader_tile_mode);

EXPORT PaintShaderRef _PaintShaderCreateTwoPointConicalGradient(
      float start_x,
      float start_y,
      float start_radius,
      float end_x,
      float end_y,
      float end_radius,
      int* r,
      int* g,
      int* b,
      int* a,
      float* pos,
      int color_count,
      int shader_tile_mode);

EXPORT PaintShaderRef _PaintShaderCreateSweepGradient(
      float cx,
      float cy,
      int* r,
      int* g,
      int* b,
      int* a,
      float* pos,
      int color_count,
      int shader_tile_mode,
      float start_degrees,
      float end_degrees);

EXPORT PaintShaderRef _PaintShaderCreateImage(
  ImageRef image,
  int shader_tile_mode_x,
  int shader_tile_mode_y,
  // local_matrix
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2);

EXPORT PaintShaderRef _PaintShaderCreateImageFromBitmap(
  BitmapRef bitmap,
  int shader_tile_mode_x,
  int shader_tile_mode_y,
  // local_matrix
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2);

EXPORT PaintShaderRef _PaintShaderCreatePaintRecord(
      PaintRecordRef record,
      float tile_x,
      float tile_y,
      float tile_w,
      float tile_h,
      int shader_tile_mode_x,
      int shader_tile_mode_y,
      // local_matrix
      double scale_x,
      double skew_x,
      double trans_x,
      double skew_y,
      double scale_y,
      double trans_y,
      double persp0,
      double persp1,
      double persp2);

EXPORT void _PaintShaderDestroy(PaintShaderRef shader);

// PaintFlags

EXPORT PaintFlagsRef _PaintFlagsCreate();
EXPORT void _PaintFlagsDestroy(PaintFlagsRef flags);
EXPORT PaintRef _PaintFlagsToSkiaPaint(PaintFlagsRef flags);
EXPORT int _PaintFlagsIsSimpleOpacity(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetStyleFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetBlendModeFlag(PaintFlagsRef flags);
EXPORT uint8_t _PaintFlagsGetAlphaFlag(PaintFlagsRef flags);
EXPORT void _PaintFlagsGetColorFlag(PaintFlagsRef flags, uint8_t* r, uint8_t* g, uint8_t* b, uint8_t* a);
EXPORT int _PaintFlagsGetAntiAliasFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetVerticalTextFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetSubpixelTextFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetLCDRenderTextFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetHintingFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetAutohintedFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetDitherFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetTextEncodingFlag(PaintFlagsRef flags);
EXPORT float _PaintFlagsGetTextSizeFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetFilterQualityFlag(PaintFlagsRef flags);
EXPORT float _PaintFlagsGetStrokeWidthFlag(PaintFlagsRef flags);
EXPORT float _PaintFlagsGetStrokeMiterFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetStrokeCapFlag(PaintFlagsRef flags);
EXPORT int _PaintFlagsGetStrokeJoinFlag(PaintFlagsRef flags);
EXPORT TypefaceRef _PaintFlagsGetTypefaceFlag(PaintFlagsRef flags);
EXPORT ColorFilterRef _PaintFlagsGetColorFilterFlag(PaintFlagsRef flags);
EXPORT MaskFilterRef _PaintFlagsGetMaskFilterFlag(PaintFlagsRef flags);
EXPORT PaintShaderRef _PaintFlagsGetShaderFlag(PaintFlagsRef flags);
EXPORT PathEffectRef _PaintFlagsGetPathEffectFlag(PaintFlagsRef flags);
EXPORT PaintFilterRef _PaintFlagsGetImageFilterFlag(PaintFlagsRef flags);
EXPORT DrawLooperRef _PaintFlagsGetLooperFlag(PaintFlagsRef flags);

EXPORT void _PaintFlagsSetStyleFlag(PaintFlagsRef flags, int style);
EXPORT void _PaintFlagsSetBlendModeFlag(PaintFlagsRef flags, int blend_mode);
EXPORT void _PaintFlagsSetAlphaFlag(PaintFlagsRef flags, uint8_t alpha);
EXPORT void _PaintFlagsSetColorFlag(PaintFlagsRef flags, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
EXPORT void _PaintFlagsSetAntiAliasFlag(PaintFlagsRef flags, int aa);
EXPORT void _PaintFlagsSetVerticalTextFlag(PaintFlagsRef flags, int vertical);
EXPORT void _PaintFlagsSetSubpixelTextFlag(PaintFlagsRef flags, int subpixel_text);
EXPORT void _PaintFlagsSetLCDRenderTextFlag(PaintFlagsRef flags, int lcd_text);
EXPORT void _PaintFlagsSetHintingFlag(PaintFlagsRef flags, int hinting);
EXPORT void _PaintFlagsSetAutohintedFlag(PaintFlagsRef flags, int use_auto_hinter);
EXPORT void _PaintFlagsSetDitherFlag(PaintFlagsRef flags, int dither);
EXPORT void _PaintFlagsSetTextEncodingFlag(PaintFlagsRef flags, int encoding);
EXPORT void _PaintFlagsSetTextSizeFlag(PaintFlagsRef flags, float text_size);
EXPORT void _PaintFlagsSetFilterQualityFlag(PaintFlagsRef flags, int quality);
EXPORT void _PaintFlagsSetStrokeWidthFlag(PaintFlagsRef flags, float width);
EXPORT void _PaintFlagsSetStrokeMiterFlag(PaintFlagsRef flags, float miter);
EXPORT void _PaintFlagsSetStrokeCapFlag(PaintFlagsRef flags, int cap);
EXPORT void _PaintFlagsSetStrokeJoinFlag(PaintFlagsRef flags, int join);
EXPORT void _PaintFlagsSetTypefaceFlag(PaintFlagsRef flags, TypefaceRef typeface);
EXPORT void _PaintFlagsSetColorFilterFlag(PaintFlagsRef flags, ColorFilterRef color_filter);
EXPORT void _PaintFlagsSetMaskFilterFlag(PaintFlagsRef flags, MaskFilterRef mask);
EXPORT void _PaintFlagsSetShaderFlag(PaintFlagsRef flags, PaintShaderRef shader);
EXPORT void _PaintFlagsSetPathEffectFlag(PaintFlagsRef flags, PathEffectRef effect);
EXPORT void _PaintFlagsSetImageFilterFlag(PaintFlagsRef flags, PaintFilterRef filter);
EXPORT void _PaintFlagsSetLooperFlag(PaintFlagsRef flags, DrawLooperRef looper);

// DisplayItemList

EXPORT DisplayItemListRef _DisplayItemListCreate(int display_list_usage_hint);
EXPORT void _DisplayItemListDestroy(DisplayItemListRef list);

//EXPORT DisplayItemRef _DisplayItemListCreateAndAppendItem(DisplayItemListRef list, int type);
EXPORT int _DisplayItemListTotalOpCount(DisplayItemListRef list);
EXPORT void _DisplayItemListStartPaint(DisplayItemListRef list);
EXPORT void _DisplayItemListEndPaintOfPairedBegin(DisplayItemListRef list);
EXPORT void _DisplayItemListEndPaintOfPairedBeginWithRect(DisplayItemListRef list, int rx, int ry, int rw, int rh);
EXPORT void _DisplayItemListEndPaintOfPairedEnd(DisplayItemListRef list);
EXPORT void _DisplayItemListEndPaintOfUnpaired(DisplayItemListRef list, int rx, int ry, int rw, int rh);
EXPORT void _DisplayItemListFinalize(DisplayItemListRef list);
EXPORT PaintRecordRef _DisplayItemListReleaseAsRecord(DisplayItemListRef list);
// DisplayList Push Ops
EXPORT void _DisplayItemListPushClipPath(DisplayItemListRef list, PathRef path, int clip_op, int antialias);
EXPORT void _DisplayItemListPushClipRect(DisplayItemListRef list, float rx, float ry, float rw, float rh, int clip_op, int antialias);
EXPORT void _DisplayItemListPushClipRRect(DisplayItemListRef list, float x, float y, float w, float h, int clip_op, int antialias);
EXPORT void _DisplayItemListPushConcat(DisplayItemListRef list, 
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2);
EXPORT void _DisplayItemListPushCustomData(DisplayItemListRef list, uint32_t id);
EXPORT void _DisplayItemListPushDrawColor(DisplayItemListRef list, int r, int g , int b, int a, int blend_mode);
EXPORT void _DisplayItemListPushDrawDRRect(DisplayItemListRef list, float ix, float iy, float iw, float ih, float ox, float oy, float ow, float oh, PaintFlagsRef flags);          
EXPORT void _DisplayItemListPushDrawBitmap(DisplayItemListRef list, BitmapRef bitmap, float left, float top, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushDrawImage(DisplayItemListRef list, ImageRef image, float left, float top, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushDrawImageRect(DisplayItemListRef list, ImageRef image, float sx, float sy, float sw, float sh, float dx, float dy, float dw, float dh, int paint_canvas_src_rect_constraint, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushDrawIRect(DisplayItemListRef list, int x, int y, int w, int h, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushDrawLine(DisplayItemListRef list, float x0, float y0, float x1, float y1, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushDrawOval(DisplayItemListRef list, float x, float y, float w, float h, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushDrawPath(DisplayItemListRef list, PathRef path, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushDrawRecord(DisplayItemListRef list, PaintRecordRef record);
EXPORT void _DisplayItemListPushDrawRect(DisplayItemListRef list, float x, float y, float w, float h, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushDrawRRect(DisplayItemListRef list, float x, float y, float w, float h, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushDrawTextBlob(DisplayItemListRef list, PaintTextBlobRef blob, float x, float y, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushNoop(DisplayItemListRef list);
EXPORT void _DisplayItemListPushRestore(DisplayItemListRef list);

EXPORT void _DisplayItemListPushRotate(DisplayItemListRef list, float degrees);
EXPORT void _DisplayItemListPushSave(DisplayItemListRef list);

EXPORT void _DisplayItemListPushSaveLayer(DisplayItemListRef list, PaintFlagsRef flags);
EXPORT void _DisplayItemListPushSaveLayerBounds(DisplayItemListRef list, 
  float x, 
  float y, 
  float w, 
  float h, 
  PaintFlagsRef flags);

EXPORT void _DisplayItemListPushSaveLayerAlpha(DisplayItemListRef list, 
  uint8_t alpha, 
  int preserve_lcd_text_requests);

EXPORT void _DisplayItemListPushSaveLayerAlphaBounds(DisplayItemListRef list,
  float x, 
  float y, 
  float w, 
  float h,
  uint8_t alpha, 
  int preserve_lcd_text_requests);


EXPORT void _DisplayItemListPushScale(DisplayItemListRef list, float x, float y);
EXPORT void _DisplayItemListPushSetMatrix(DisplayItemListRef list,
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2);

EXPORT void _DisplayItemListPushTranslate(DisplayItemListRef list, float x, float y);

EXPORT void _DisplayItemImageRasterWithFlags();
EXPORT void _DisplayItemImageRectRasterWithFlags();

EXPORT void _PaintRecordPlayback(PaintRecordRef handle, CanvasRef canvas); 
EXPORT void _PaintRecordPlaybackParams(PaintRecordRef handle, CanvasRef canvas, MatrixRef mat); 
EXPORT void _PaintRecordDestroy(PaintRecordRef handle);

// OutputSurface
EXPORT OutputSurfaceRef _OutputSurfaceCreate(ContextProviderRef provider, ContextProviderRef worker);
EXPORT void _OutputSurfaceDestroy(OutputSurfaceRef handle);
//EXPORT int _OutputSurfaceBindToClient(OutputSurfaceRef handle);
//EXPORT void _OutputSurfaceDetachFromClient(OutputSurfaceRef handle);
EXPORT void _OutputSurfaceEnsureBackbuffer(OutputSurfaceRef handle);
EXPORT void _OutputSurfaceDiscardBackbuffer(OutputSurfaceRef handle);
EXPORT void _OutputSurfaceReshape(OutputSurfaceRef handle,
 int width, int height, float scaleFactor, int has_alpha, int use_stencil);
//EXPORT void _OutputSurfaceSurfaceSize(OutputSurfaceRef handle, int* width, int* height);
//EXPORT float _OutputSurfaceDeviceScaleFactor(OutputSurfaceRef handle);
//EXPORT void _OutputSurfaceForceReclaimResources(OutputSurfaceRef handle);
EXPORT void _OutputSurfaceBindFramebuffer(OutputSurfaceRef handle);
//EXPORT void _OutputSurfaceOnSwapBuffersComplete(OutputSurfaceRef handle);
//EXPORT void _OutputSurfaceUpdateSmoothnessTakesPriority(OutputSurfaceRef handle, int preferSmoothness);
//EXPORT int _OutputSurfaceHasClient(OutputSurfaceRef handle);
EXPORT void _OutputSurfaceGetOverlayCandidateValidator(OutputSurfaceRef handle);
EXPORT int _OutputSurfaceIsDisplayedAsOverlayPlane(OutputSurfaceRef handle);
EXPORT uint32_t _OutputSurfaceGetOverlayTextureId(OutputSurfaceRef handle);
//EXPORT void _OutputSurfaceDidLoseOutputSurface(OutputSurfaceRef handle);
//EXPORT void _OutputSurfaceSetMemoryPolicy(OutputSurfaceRef handle);
//EXPORT void _OutputSurfaceInvalidate(OutputSurfaceRef handle);
//EXPORT void _OutputSurfaceSetWorkerContextShouldAggressivelyFreeResources(OutputSurfaceRef handle, int isVisible);
EXPORT int _OutputSurfaceSurfaceIsSuspendForRecycle(OutputSurfaceRef handle);
EXPORT void _DirectOutputSurfaceSwapBuffers(OutputSurfaceRef handle, CompositorFrameRef frame);

// ContextProvider
EXPORT ContextProviderRef _ContextProviderCreate(
  int alphaSize,
  int blueSize,
  int greenSize,
  int redSize,
  int depthSize,
  int stencilSize,
  int samples,
  int sampleBuffers,
  int bufferPreserved,
  int bindGeneratesResource,
  int failIfMajorPerfCaveat,
  int loseContextWhenOutOfMemory,
  int contextType,
#if defined(OS_LINUX)
  XID widget,
#elif defined(OS_WIN)
  HWND widget,
#endif
  int offscreen);

EXPORT void _ContextProviderDestroy(ContextProviderRef provider);
EXPORT int _ContextProviderBindToCurrentThread(ContextProviderRef provider);
//EXPORT void _ContextProviderDetachFromThread(ContextProviderRef provider);
//EXPORT void _ContextProviderInvalidateGrContext(ContextProviderRef provider, uint32_t state);
//EXPORT void _ContextProviderDeleteCachedResources(ContextProviderRef provider);
//EXPORT void _ContextProviderSetupLock(ContextProviderRef provider);

// CompositorFrame
CompositorFrameRef _CompositorFrameCreate();
EXPORT void _CompositorFrameDestroy(CompositorFrameRef frame);
EXPORT void _CompositorFrameSetMetadata(CompositorFrameRef frame);

EXPORT LayerTreeHostRef _LayerTreeHostCreate(
  void* payload, 
  AnimationHostRef animator_host,
  CLayerTreeHostSingleThreadClientCbs callbacks,
  int /*bool*/ is_single_threaded,
  int /*bool*/ single_thread_proxy_scheduler,
  int /*bool*/ main_frame_before_activation_enabled,
  int /*bool*/ using_synchronous_renderer_compositor,
  int /*bool*/ enable_early_damage_check,
  int damaged_frame_limit,
  int /*bool*/ enable_latency_recovery,
  int /*bool*/ can_use_lcd_text,
  int /*bool*/ gpu_rasterization_forced,
  int gpu_rasterization_msaa_sample_count,
  float gpu_rasterization_skewport_target_time_in_seconds,
  int /*bool*/ create_low_res_tiling,
  int /*bool*/ use_stream_video_draw_quad,
  int64_t scrollbar_fade_delay,
  int64_t scrollbar_fade_duration,
  int64_t scrollbar_thinning_duration,
  int /*bool*/ scrollbar_flash_after_any_scroll_update,
  int /*bool*/ scrollbar_flash_when_mouse_enter,
  uint8_t solid_color_scrollbar_color_a,
  uint8_t solid_color_scrollbar_color_r,
  uint8_t solid_color_scrollbar_color_g,
  uint8_t solid_color_scrollbar_color_b,
  int /*bool*/ timeout_and_draw_when_animation_checkerboards,
  int /*bool*/ layer_transforms_should_scale_layer_contents,
  int /*bool*/ layers_always_allowed_lcd_text,
  float minimum_contents_scale,
  float low_res_contents_scale_factor,
  float top_controls_show_threshold,
  float top_controls_hide_threshold,
  double background_animation_rate,
  int default_tile_size_width,
  int default_tile_size_height,
  int max_untiled_layer_size_width,
  int max_untiled_layer_size_height,
  int max_gpu_raster_tile_size_width,
  int max_gpu_raster_tile_size_height,
  int minimum_occlusion_tracking_size_width,
  int minimum_occlusion_tracking_size_height,
  int tiling_interest_area_padding,
  float skewport_target_time_in_seconds,
  int skewport_extrapolation_limit_in_screen_pixels,
  int max_memory_for_prepaint_percentage,
  int /*bool*/ use_zero_copy,
  int /*bool*/ use_partial_raster,
  int /*bool*/ enable_elastic_overscroll,
  int /*bool*/ ignore_root_layer_flings,
  int scheduled_raster_task_limit,
  int /*bool*/ use_occlusion_for_tile_prioritization,
  int /*bool*/ use_layer_lists,
  int max_staging_buffer_usage_in_bytes,
  //ManagedMemoryPolicy memory_policy,
  int memory_policy_bytes_limit_when_visible,
  int memory_policy_priority_cutoff_when_visible,
  int decoded_image_working_set_budget_bytes,
  int max_preraster_distance_in_screen_pixels,
  int /*bool*/ use_rgba_4444,
  int /*bool*/ unpremultiply_and_dither_low_bit_depth_tiles,
  int /*bool*/ enable_mask_tiling,
  int /*bool*/ enable_checker_imaging,
  int min_image_bytes_to_checker,
  int /*bool*/ only_checker_images_with_gpu_raster,
  int /*bool*/ enable_surface_synchronization,
  int /*bool*/ is_layer_tree_for_subframe,
  int /*bool*/ disallow_non_exact_resource_reuse,
  int /*bool*/ wait_for_all_pipeline_stages_before_draw,
  int /*bool*/ commit_to_active_tree,
  int /*bool*/ enable_oop_rasterization,
  int /*bool*/ enable_image_animation_resync,
  int /*bool*/ enable_edge_anti_aliasing,
  int /*bool*/ always_request_presentation_time,
  int /*bool*/ use_painted_device_scale_factor);

//EXPORT LayerTreeHostRef _LayerTreeHostCreateSingleThreaded(
//  void* payload, 
//  AnimationHostRef animator_host,
//  CLayerTreeHostSingleThreadClientCbs callbacks);
EXPORT void _LayerTreeHostDestroy(LayerTreeHostRef tree);
//EXPORT void _LayerTreeHostSetClientPeer(LayerTreeHostRef tree, void* payload);
EXPORT void _LayerTreeHostWillBeginMainFrame(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostDidBeginMainFrame(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostBeginMainFrame(LayerTreeHostRef tree, 
  uint64_t source_id, uint64_t sequence_number, double frame_time, 
  double deadline, double interval);
EXPORT void _LayerTreeHostBeginMainFrameNotExpectedSoon(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostAnimateLayers(LayerTreeHostRef tree, double monotonic_frame_begin_time);
EXPORT void _LayerTreeHostDidStopFlinging(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostRequestMainFrameUpdate(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostFinishCommitOnImplThread(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostWillCommit(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostCommitComplete(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostReleaseLayerTreeFrameSink(LayerTreeHostRef tree);
typedef void(*CLayerTreeHostRequestPresentationCallback)(void *peer, int64_t, int64_t, uint32_t);

EXPORT void _LayerTreeHostRequestPresentationTimeForNextFrame(LayerTreeHostRef tree, void *peer, CLayerTreeHostRequestPresentationCallback cb);
//EXPORT void _LayerTreeHostSetOutputSurface(LayerTreeHostRef tree, OutputSurfaceRef output_surface);
// EXPORT OutputSurfaceRef _LayerTreeHostReleaseOutputSurface(LayerTreeHostRef tree);
// EXPORT void _LayerTreeHostRequestNewOutputSurface(LayerTreeHostRef tree);
// EXPORT void _LayerTreeHostDidInitializeOutputSurface(LayerTreeHostRef tree);
// EXPORT void _LayerTreeHostDidFailToInitializeOutputSurface(LayerTreeHostRef tree);
// EXPORT void _LayerTreeHostDidLoseOutputSurface(LayerTreeHostRef tree);
// EXPORT int  _LayerTreeHostOutputSurfaceLost(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostDidCommitAndDrawFrame(LayerTreeHostRef tree);
//EXPORT void _LayerTreeHostDidCompleteSwapBuffers(LayerTreeHostRef tree);
EXPORT int _LayerTreeHostUpdateLayers(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostDidCompletePageScaleAnimation(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostNotifyInputThrottledUntilCommit(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostLayoutAndUpdateLayers(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostComposite(LayerTreeHostRef tree, int64_t frame_begin_time, int raster);
//EXPORT void _LayerTreeHostFinishAllRendering(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostGetDeviceViewportSize(LayerTreeHostRef tree, int* w, int* h);
EXPORT void _LayerTreeHostSetViewportSizeAndScale(LayerTreeHostRef tree, 
   int w, int h, float scale,
   uint32_t lsid_parent,
   uint32_t lsid_child,
   uint64_t lsid_token_high,
   uint64_t lsid_token_low);
EXPORT float _LayerTreeHostGetRecordingScaleFactor(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetRecordingScaleFactor(LayerTreeHostRef tree, float factor);
EXPORT void _LayerTreeHostSetDeferCommits(LayerTreeHostRef tree, int defer_commits);
EXPORT int  _LayerTreeHostSourceFrameNumber(LayerTreeHostRef tree);
// EXPORT int  _LayerTreeHostMetaInformationSequenceNumber(LayerTreeHostRef tree);
// EXPORT void _LayerTreeHostIncrementMetaInformationSequenceNumber(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetNeedsDisplayOnAllLayers(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetNeedsAnimate(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetNeedsUpdateLayers(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetNeedsCommit(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetNeedsCommitWithForcedRedraw(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetNeedsFullTreeSync(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostGetViewportVisibleRect(LayerTreeHostRef tree, int* x, int* y, int* width, int* height);
EXPORT void _LayerTreeHostSetViewportVisibleRect(LayerTreeHostRef tree, int x, int y, int width, int height);
EXPORT int _LayerTreeHostHasPendingPageScaleAnimation(LayerTreeHostRef tree);
//EXPORT void _LayerTreeHostSetNeedsMetaInfoRecomputation(LayerTreeHostRef tree, int needs_meta_info_recomputation);
//EXPORT void _LayerTreeHostSetNeedsRedraw(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetNeedsRedrawRect(LayerTreeHostRef tree, int x, int y, int width, int height);
EXPORT int  _LayerTreeHostCommitRequested(LayerTreeHostRef tree);
//EXPORT int  _LayerTreeHostBeginMainFrameRequested(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetNextCommitWaitsForActivation(LayerTreeHostRef tree);
//EXPORT void _LayerTreeHostSetNextCommitForcesRedraw(LayerTreeHostRef tree);
//EXPORT void _LayerTreeHostSetAnimationEvents(LayerTreeHostRef tree, AnimationEventRef* events, int event_count);
EXPORT void _LayerTreeHostSetRootLayer(LayerTreeHostRef tree, LayerRef root);
EXPORT LayerRef _LayerTreeHostRootLayer(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostClearRootLayer(LayerTreeHostRef tree);
EXPORT LayerRef _LayerTreeHostOverscrollElasticityLayer(LayerTreeHostRef tree);
EXPORT LayerRef _LayerTreeHostPageScaleLayer(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostRegisterViewportLayers(LayerTreeHostRef tree,
                            LayerRef overscroll_elasticity_layer,
                            LayerRef page_scale_layer,
                            LayerRef inner_viewport_container_layer,
                            LayerRef outer_viewport_container_layer,
                            LayerRef inner_viewport_scroll_layer,
                            LayerRef outer_viewport_scroll_layer);
EXPORT LayerRef _LayerTreeHostInnerViewportScrollLayer(LayerTreeHostRef tree);
EXPORT LayerRef _LayerTreeHostOuterViewportScrollLayer(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostRegisterSelection(LayerTreeHostRef tree,
  int s1_boundtype,
  int s1_edgetop_x,
  int s1_edgetop_y,
  int s1_edgebottom_x,
  int s1_edgebottom_y,
  int s1_layerid,
  int s1_hidden,
  int s2_boundtype,
  int s2_edgetop_x,
  int s2_edgetop_y,
  int s2_edgebottom_x,
  int s2_edgebottom_y,
  int s2_layerid,
  int s2_hidden);//,
  //int is_editable,
  //int is_empty_text_form_control);
EXPORT void _LayerTreeHostSetLayerTreeMutator(LayerTreeHostRef tree, LayerTreeMutatorRef mutator);
EXPORT void _LayerTreeHostSetNeedsRecalculateRasterScales(LayerTreeHostRef tree);
EXPORT int  _LayerTreeHostHasGpuRasterizationTrigger(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetHasGpuRasterizationTrigger(LayerTreeHostRef tree, int has_gpu_rasterization_trigger);
//EXPORT void _LayerTreeHostSetTopControlsHeight(LayerTreeHostRef tree, float height, int shrink);
//EXPORT void _LayerTreeHostSetTopControlsShownRatio(LayerTreeHostRef tree, float ratio);
EXPORT void _LayerTreeHostDeviceViewportSize(LayerTreeHostRef tree, int* width, int* height);
//EXPORT void _LayerTreeHostSetViewportSize(LayerTreeHostRef tree, int width, int height);
//EXPORT void _LayerTreeHostApplyPageScaleDeltaFromImplSide(LayerTreeHostRef tree, float page_scale_delta);
EXPORT void _LayerTreeHostSetPageScaleFactorAndLimits(LayerTreeHostRef tree,
                                 float page_scale_factor,
                                 float min_page_scale_factor,
                                 float max_page_scale_factor);
EXPORT float _LayerTreeHostPageScaleFactor(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostElasticOverscroll(LayerTreeHostRef tree, float* x, float* y);
EXPORT void _LayerTreeHostSetBackgroundColor(LayerTreeHostRef tree, uint8_t a, uint8_t r, uint8_t g, uint8_t b);
EXPORT void _LayerTreeHostBackgroundColor(LayerTreeHostRef tree, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b);
//EXPORT void _LayerTreeHostSetHasTransparentBackground(LayerTreeHostRef tree, int transparent);
EXPORT void _LayerTreeHostSetVisible(LayerTreeHostRef tree, int visible);
EXPORT int  _LayerTreeHostIsVisible(LayerTreeHostRef tree);
//EXPORT void _LayerTreeHostSetThrottleFrameProduction(LayerTreeHostRef tree, int throttle);
EXPORT void _LayerTreeHostStartPageScaleAnimation(LayerTreeHostRef tree,
                               int offset_x,
                               int offset_y,
                               int use_anchor,
                               float scale,
                               double duration);
EXPORT void _LayerTreeHostApplyScrollAndScale(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetTransform(LayerTreeHostRef tree,
            double col1row1, double col2row1,
            double col3row1, double col4row1,
            double col1row2, double col2row2,
            double col3row2, double col4row2,
            double col1row3, double col2row3,
            double col3row3, double col4row3,
            double col1row4, double col2row4,
            double col3row4, double col4row4);
//EXPORT void _LayerTreeHostSetDeviceScaleFactor(LayerTreeHostRef tree, float scale);
EXPORT float _LayerTreeHostDeviceScaleFactor(LayerTreeHostRef tree);
//EXPORT void _LayerTreeHostSetPaintedDeviceScaleFactor(LayerTreeHostRef tree, float painted_device_scale_factor);
//EXPORT void _LayerTreeHostUpdateTopControlsState(LayerTreeHostRef tree, int top_controls_state_constraints, int top_controls_state_current, int animate);
//EXPORT AnimationRegistrarRef _LayerTreeHostAnimationRegistrar(LayerTreeHostRef tree);
EXPORT int _LayerTreeHostInPaintLayerContents(LayerTreeHostRef tree);
EXPORT AnimationHostRef _LayerTreeHostAnimationHost(LayerTreeHostRef tree);
//EXPORT int _LayerTreeHostUsingSharedMemoryResources(LayerTreeHostRef tree);
EXPORT int _LayerTreeHostId(LayerTreeHostRef tree);
//EXPORT void _LayerTreeHostInsertSwapPromiseMonitor(LayerTreeHostRef tree, SwapPromiseMonitorRef monitor);
//EXPORT void _LayerTreeHostRemoveSwapPromiseMonitor(LayerTreeHostRef tree, SwapPromiseMonitorRef monitor);
EXPORT void _LayerTreeHostQueueSwapPromise(LayerTreeHostRef tree, SwapPromiseRef swap_promise);
EXPORT void _LayerTreeHostQueueImageDecode(LayerTreeHostRef tree, void* peer, ImageRef image, void(*callback)(void*, int));
//EXPORT void _LayerTreeHostBreakSwapPromises(LayerTreeHostRef tree, int DidNotSwapReason);
EXPORT size_t _LayerTreeHostNumQueuedSwapPromises(LayerTreeHostRef tree);
//EXPORT void _LayerTreeHostSetSurfaceIdNamespace(LayerTreeHostRef tree, uint32_t id_namespace);
//EXPORT void _LayerTreeHostCreateSurfaceSequence(LayerTreeHostRef tree, uint32_t* id_namespace, uint32_t* sequence);
//EXPORT void _LayerTreeHostSetChildrenNeedBeginFrames(LayerTreeHostRef tree, int children_need_begin_frames);
// EXPORT void _LayerTreeHostSendBeginFramesToChildren(LayerTreeHostRef tree, 
//   uint64_t source_id,
//   uint64_t sequence_number,
//   double frame_time, 
//   double deadline, 
//   double interval);

EXPORT void _LayerTreeHostRequestBeginMainFrameNotExpected(LayerTreeHostRef reference, int new_state);
EXPORT int _LayerTreeHostGetHaveScrollEventHandlers(LayerTreeHostRef reference);
EXPORT void _LayerTreeHostSetHaveScrollEventHandlers(LayerTreeHostRef reference, int have);

EXPORT void _LayerTreeHostGetLocalSurfaceId(
        LayerTreeHostRef reference,
        uint32_t* parent,
        uint32_t* child,
        uint64_t* high,
        uint64_t* low);

EXPORT void _LayerTreeHostSetLocalSurfaceId(
        LayerTreeHostRef reference, 
        uint32_t parent,
        uint32_t child,
        uint64_t high,
        uint64_t low);

EXPORT void _LayerTreeHostSetRasterColorSpace(LayerTreeHostRef reference, 
  uint8_t primaries,
  uint8_t transfer,
  uint8_t matrix,
  uint8_t range,
  int64_t icc_profile);
//EXPORT void _LayerTreeHostGetRasterColorSpace(LayerTreeHostRef reference,
//  uint8_t* primaries,
//  uint8_t* transfer,
//  uint8_t* matrix,
//  uint8_t* range);

EXPORT void _LayerTreeHostSetContentSourceId(LayerTreeHostRef reference, uint32_t id);
EXPORT void _LayerTreeHostSetLayerTreeFrameSink(LayerTreeHostRef reference, LayerTreeFrameSinkRef framesink);
EXPORT void _LayerTreeHostQueueSwapPromise(LayerTreeHostRef reference, SwapPromiseRef swap_promise);
EXPORT void _LayerTreeHostSetOverscrollBehavior(LayerTreeHostRef reference, int x_behavior, int y_behavior);

EXPORT PropertyTreesRef _LayerTreeHostPropertyTrees(LayerTreeHostRef tree);
//EXPORT void _LayerTreeHostSetAuthoritativeVsyncInterval(LayerTreeHostRef tree, double interval);
EXPORT LayerRef _LayerTreeHostLayerById(LayerTreeHostRef tree, int id);
//EXPORT int _LayerTreeHostNeedsMetaInfoRecomputation(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostRegisterLayer(LayerTreeHostRef tree, LayerRef layer);
EXPORT void _LayerTreeHostUnregisterLayer(LayerTreeHostRef tree, LayerRef layer);
//EXPORT int _LayerTreeHostIsLayerInTree(LayerTreeHostRef tree, int layer_id, int tree_type);
EXPORT void _LayerTreeHostSetMutatorsNeedCommit(LayerTreeHostRef tree);
EXPORT void _LayerTreeHostSetMutatorsNeedRebuildPropertyTrees(LayerTreeHostRef tree);
// EXPORT void _LayerTreeHostSetLayerFilterMutated(LayerTreeHostRef tree,
//                                                  int layer_id,
//                                                  int tree_type,
//                                                  int* filters);
// EXPORT void _LayerTreeHostSetLayerOpacityMutated(LayerTreeHostRef tree,
//                             int layer_id,
//                             int tree_type,
//                             float opacity);
// EXPORT void _LayerTreeHostSetLayerTransformMutated(LayerTreeHostRef tree,
//                               int layer_id,
//                               int tree_type,
//                               double col1row1, double col2row1,
//                               double col3row1, double col4row1,
//                               double col1row2, double col2row2,
//                               double col3row2, double col4row2,
//                               double col1row3, double col2row3,
//                               double col3row3, double col4row3,
//                               double col1row4, double col2row4,
//                               double col3row4, double col4row4);
// EXPORT void _LayerTreeHostSetLayerScrollOffsetMutated(LayerTreeHostRef tree,
//   int layer_id,
//   int tree_type,
//   double offset_x, double offset_y);
// EXPORT void _LayerTreeHostLayerTransformIsPotentiallyAnimatingChanged(LayerTreeHostRef tree,
//   int layer_id,
//   int tree_type,
//   int is_animating);
EXPORT void _LayerTreeHostScrollOffsetAnimationFinished(LayerTreeHostRef tree);
// EXPORT void _LayerTreeHostGetScrollOffsetForAnimation(LayerTreeHostRef tree, int layer_id, double* x, double* y);
// EXPORT int _LayerTreeHostScrollOffsetAnimationWasInterrupted(LayerTreeHostRef tree, LayerRef layer);
// EXPORT int _LayerTreeHostIsAnimatingFilterProperty(LayerTreeHostRef tree, LayerRef layer);
// EXPORT int _LayerTreeHostIsAnimatingOpacityProperty(LayerTreeHostRef tree, LayerRef layer);
// EXPORT int _LayerTreeHostIsAnimatingTransformProperty(LayerTreeHostRef tree, LayerRef layer);
// EXPORT int _LayerTreeHostHasPotentiallyRunningFilterAnimation(LayerTreeHostRef tree, LayerRef layer);
// EXPORT int _LayerTreeHostHasPotentiallyRunningOpacityAnimation(LayerTreeHostRef tree, LayerRef layer);
// EXPORT int _LayerTreeHostHasPotentiallyRunningTransformAnimation(LayerTreeHostRef tree, LayerRef layer);
//EXPORT int _LayerTreeHostHasOnlyTranslationTransforms(LayerTreeHostRef tree, LayerRef layer);
// int _LayerTreeHostMaximumTargetScale(LayerTreeHostRef tree, LayerRef layer, float* max_scale);
//EXPORT int _LayerTreeHostAnimationStartScale(LayerTreeHostRef tree, LayerRef layer, float* start_scale);
//EXPORT int _LayerTreeHostHasAnyAnimationTargetingProperty(LayerTreeHostRef tree, LayerRef layer, int property);
//EXPORT int _LayerTreeHostAnimationsPreserveAxisAlignment(LayerTreeHostRef tree, LayerRef layer);
//EXPORT int _LayerTreeHostHasAnyAnimation(LayerTreeHostRef tree, LayerRef layer);
//EXPORT int _LayerTreeHostHasActiveAnimation(LayerTreeHostRef tree, LayerRef layer);
EXPORT void _LayerTreeHostSetEventListenerProperties(LayerTreeHostRef reference, int event_class, int event_properties);
EXPORT void _LayerTreeHostRequestNewLocalSurfaceId(LayerTreeHostRef reference);
//EXPORT void _LayerTreeHostDidNavigate(LayerTreeHostRef reference);
EXPORT void _LayerTreeHostClearCachesOnNextCommit(LayerTreeHostRef reference);

// helpers 
EXPORT void _LayerTreeHostHelperSynchronouslyComposite(LayerTreeHostRef reference, int raster, SwapPromiseRef swap_promise);
EXPORT void _LayerTreeHostHelperBeginMainFrame(LayerTreeHostRef reference,
  uint64_t source_id,
  uint64_t sequence_number,
  int64_t frame_time, 
  int64_t deadline, 
  int64_t interval);
EXPORT void _LayerTreeHostHelperBeginMainFrameNotExpectedSoon(LayerTreeHostRef reference);
EXPORT void _LayerTreeHostHelperBeginMainFrameNotExpectedUntil(LayerTreeHostRef reference, int64_t time);
EXPORT void _LayerTreeHostHelperRequestNewLayerTreeFrameSink(LayerTreeHostRef reference, void* peer, void (*callback)(void*));
EXPORT void _LayerTreeHostHelperDidCommitFrameToCompositor(LayerTreeHostRef reference);
//EXPORT void _LayerTreeHostSetRasterColorSpace(LayerTreeHostRef reference, 
//  uint8_t primaries,
//  uint8_t transfer,
//  uint8_t matrix,
//  uint8_t range);

/* Layer */

EXPORT LayerRef _LayerCreateDefault();
EXPORT LayerRef _LayerCreate(int type, void* client, CLayerClientCallbacks cbs);
EXPORT void _LayerDestroy(LayerRef layer);
EXPORT int64_t _LayerId(LayerRef layer);
EXPORT uint64_t _LayerGetElementId(LayerRef layer);
EXPORT void _LayerSetElementId(LayerRef layer, uint64_t id);
EXPORT int64_t _LayerType(LayerRef layer);
EXPORT LayerRef _LayerRootLayer(LayerRef layer);
EXPORT LayerRef _LayerParent(LayerRef layer);
EXPORT void _LayerAddChild(LayerRef layer, LayerRef child);
EXPORT void _LayerInsertChild(LayerRef layer, LayerRef child, int index);
EXPORT void _LayerReplaceChild(LayerRef layer, LayerRef ref, LayerRef repl);
EXPORT void _LayerRemoveFromParent(LayerRef layer);
EXPORT void _LayerRemoveAllChildren(LayerRef layer);
// the children should be of the "owned" type
EXPORT void _LayerSetChildren(LayerRef layer, LayerRef* children, int count);
EXPORT int  _LayerHasAncestor(LayerRef layer, const LayerRef ancestor);
// this is disabled from now
EXPORT void  _LayerChildren(LayerRef layer);
EXPORT void _LayerSetTrilinearFiltering(LayerRef layer, int value);
EXPORT int _LayerGetTrilinearFiltering(LayerRef layer);
EXPORT void _LayerSetCacheRenderSurface(LayerRef layer, int value);
EXPORT int _LayerGetCacheRenderSurface(LayerRef layer);
EXPORT LayerRef _LayerChildAt(LayerRef layer, int index);
EXPORT void _LayerRequestCopyOfOutput(LayerRef layer, CopyOutputRequestRef output_request);
EXPORT int  _LayerHasCopyRequest(LayerRef layer);
EXPORT void _LayerSetBackgroundColor(LayerRef layer, uint8_t a, uint8_t r, uint8_t g, uint8_t b);
EXPORT void _LayerBackgroundColor(LayerRef layer, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b);
EXPORT void _LayerSafeOpaqueBackgroundColor(LayerRef layer, uint8_t* r, uint8_t* g, uint8_t* b);
EXPORT void _LayerSetBounds(LayerRef layer, int width, int height);
EXPORT void _LayerBounds(LayerRef layer, int* width, int* height);
EXPORT void _LayerSetMasksToBounds(LayerRef layer, int masks_to_bounds);
EXPORT int  _LayerMasksToBounds(LayerRef layer);
EXPORT void _LayerSetMaskLayer(LayerRef layer, LayerRef mask);
EXPORT LayerRef _LayerMaskLayer(LayerRef layer);
EXPORT int _LayerDrawsContent(LayerRef layer);
EXPORT void _LayerSetNeedsDisplayRect(LayerRef layer, int x, int y, int width, int height);
EXPORT void _LayerSetNeedsDisplay(LayerRef layer);
EXPORT void _LayerGetVisibleLayerRect(LayerRef layer, int* x, int* y, int* w, int* h);
EXPORT void _LayerSetOpacity(LayerRef layer, float opacity);
EXPORT float _LayerOpacity(LayerRef layer);
EXPORT float _LayerGetEffectiveOpacity(LayerRef layer);
//EXPORT int _LayerOpacityIsAnimating(LayerRef layer);
//EXPORT int _LayerHasPotentiallyRunningOpacityAnimation(LayerRef layer);
EXPORT void _LayerOpacityCanAnimateOnImplThread(LayerRef layer);
EXPORT void _LayerSetBlendMode(LayerRef layer, int blend_mode);
EXPORT int _LayerBlendMode(LayerRef layer);
//EXPORT int _LayerUsesDefaultBlendMode(LayerRef layer);
EXPORT void _LayerSetIsRootForIsolatedGroup(LayerRef layer, int root);
EXPORT int _LayerIsRootForIsolatedGroup(LayerRef layer);
// NOT WORKING
EXPORT void _LayerSetFilters(LayerRef layer, int* filters);
// NOT WORKING
EXPORT void _LayerFilters(LayerRef layer);
//EXPORT int _LayerFilterIsAnimating(LayerRef layer);
EXPORT void _LayerFilterOperations(LayerRef layer);
EXPORT void _LayerSetFilterOperations(LayerRef layer);
//EXPORT int _LayerHasPotentiallyRunningFilterAnimation(LayerRef layer);
// NOT WORKING
EXPORT void _LayerSetBackgroundFilters(LayerRef layer);
// NOT WORKING
EXPORT void _LayerBackgroundFilters(LayerRef layer);
EXPORT void _LayerSetContentsOpaque(LayerRef layer, int contents_opaque);
EXPORT int _LayerContentsOpaque(LayerRef layer);
EXPORT void _LayerSetPosition(LayerRef layer, float x, float y);
EXPORT void _LayerPosition(LayerRef layer, float* x, float* y);
EXPORT void _LayerSetIsContainerForFixedPositionLayers(LayerRef layer, int container_fixed);
EXPORT int _LayerIsContainerForFixedPositionLayers(LayerRef layer);
//EXPORT void _LayerFixedContainerSizeDelta(LayerRef layer, float* x, float* y);
EXPORT void _LayerSetPositionConstraint(LayerRef layer);
EXPORT void _LayerPositionConstraint(LayerRef layer);
EXPORT void _LayerSetTransform(LayerRef layer,
  double col1row1, double col2row1,
  double col3row1, double col4row1,
  double col1row2, double col2row2,
  double col3row2, double col4row2,
  double col1row3, double col2row3,
  double col3row3, double col4row3,
  double col1row4, double col2row4,
  double col3row4, double col4row4);
EXPORT void _LayerTransform(LayerRef layer,
  double* col1row1, double* col2row1,
  double* col3row1, double* col4row1,
  double* col1row2, double* col2row2,
  double* col3row2, double* col4row2,
  double* col1row3, double* col2row3,
  double* col3row3, double* col4row3,
  double* col1row4, double* col2row4,
  double* col3row4, double* col4row4);
//EXPORT int _LayerTransformIsAnimating(LayerRef layer);
//EXPORT int _LayerTransformIsInvertible(LayerRef layer);
//EXPORT int _LayerHasPotentiallyRunningTransformAnimation(LayerRef layer);
//EXPORT int _LayerHasOnlyTranslationTransforms(LayerRef layer);
//EXPORT int _LayerAnimationsPreserveAxisAlignment(LayerRef layer);
//EXPORT int _LayerTransformIsInvertible(LayerRef layer);
//EXPORT int _LayerMaximumTargetScale(LayerRef layer, float* max_scale);
//EXPORT int _LayerAnimationStartScale(LayerRef layer, float* start_scale);
EXPORT void _LayerSetTransformOrigin(LayerRef layer, float x, float y, float z);
EXPORT void _LayerTransformOrigin(LayerRef layer, float* x, float* y, float* z);
//EXPORT int _LayerHasAnyAnimationTargetingProperty(LayerRef layer, int target_property);
//EXPORT int _LayerScrollOffsetAnimationWasInterrupted(LayerRef layer);
EXPORT void _LayerSetScrollParent(LayerRef layer, LayerRef parent);
EXPORT LayerRef _LayerScrollParent(LayerRef layer);
//EXPORT void _LayerAddScrollChild(LayerRef layer, LayerRef child);
//EXPORT void _LayerRemoveScrollChild(LayerRef layer, LayerRef child);
EXPORT void _LayerScrollChildren(LayerRef layer);
EXPORT void _LayerSetClipParent(LayerRef layer, LayerRef ancestor);
EXPORT LayerRef _LayerClipParent(LayerRef layer);
//EXPORT void _LayerAddClipChild(LayerRef layer, LayerRef clip_child);
//EXPORT void _LayerRemoveClipChild(LayerRef layer, LayerRef clip_child);
EXPORT void _LayerClipChildren(LayerRef layer);
// EXPORT void _LayerDrawTransform(LayerRef layer,
//   double* col1row1, double* col2row1,
//   double* col3row1, double* col4row1,
//   double* col1row2, double* col2row2,
//   double* col3row2, double* col4row2,
//   double* col1row3, double* col2row3,
//   double* col3row3, double* col4row3,
//   double* col1row4, double* col2row4,
//   double* col3row4, double* col4row4);
EXPORT void _LayerScreenSpaceTransform(LayerRef layer,
  double* col1row1, double* col2row1,
  double* col3row1, double* col4row1,
  double* col1row2, double* col2row2,
  double* col3row2, double* col4row2,
  double* col1row3, double* col2row3,
  double* col3row3, double* col4row3,
  double* col1row4, double* col2row4,
  double* col3row4, double* col4row4);
EXPORT void _LayerSetNumUnclippedDescendants(LayerRef layer, int descendants);
EXPORT int _LayerNumUnclippedDescendants(LayerRef layer);
EXPORT void _LayerSetScrollOffset(LayerRef layer, float offset_x, float offset_y);
//EXPORT void _LayerSetScrollCompensationAdjustment(LayerRef layer, float offset_x, float offset_y);
//EXPORT void _LayerScrollCompensationAdjustment(LayerRef layer, float* offset_x, float* offset_y);
EXPORT void _LayerScrollOffset(LayerRef layer, float* offset_x, float* offset_y);
EXPORT void _LayerSetScrollOffsetFromImplSide(LayerRef layer, float offset_x, float offset_y);
//EXPORT void _LayerSetScrollClipLayerId(LayerRef layer, int clip_layer_id);
EXPORT int _LayerScrollable(LayerRef layer);
EXPORT void _LayerSetUserScrollable(LayerRef layer, int horizontal, int vertical);
EXPORT int _LayerUserScrollableHorizontal(LayerRef layer);
EXPORT int _LayerUserScrollableVertical(LayerRef layer);
//EXPORT void _LayerSetShouldScrollOnMainThread(LayerRef layer, int should_scroll);
EXPORT int _LayerShouldScrollOnMainThread(LayerRef layer);
//EXPORT void _LayerSetHaveWheelEventHandlers(LayerRef layer, int have_wheel);
//EXPORT int _LayerHaveWheelEventHandlers(LayerRef layer);
//EXPORT void _LayerSetHaveScrollEventHandlers(LayerRef layer, int have_scroll);
//EXPORT int _LayerHaveScrollEventHandlers(LayerRef layer);
EXPORT void _LayerSetNonFastScrollableRegion(LayerRef layer, int x, int y, int width, int height);
EXPORT void _LayerNonFastScrollableRegion(LayerRef layer, int* x, int* y, int* width, int* height);
//EXPORT void _LayerSetTouchEventHandlerRegion(LayerRef layer, int x, int y, int width, int height);
//EXPORT void _LayerTouchEventHandlerRegion(LayerRef layer, int* x, int* y, int* width, int* height);
//EXPORT void _LayerSetScrollBlocksOn(LayerRef layer, int scroll_blocks_on);
//EXPORT int _LayerScrollBlocksOn(LayerRef layer);
EXPORT void _LayerSetDidScrollCallback(LayerRef layer);
EXPORT int _LayerForceRenderSurface(LayerRef layer);
EXPORT void _LayerSetForceRenderSurface(LayerRef layer, int force_render_surface);
//EXPORT void _LayerScrollDelta(LayerRef layer, float* delta_x, float* delta_y);
EXPORT void _LayerCurrentScrollOffset(LayerRef layer, float* offset_x, float* offset_y);
EXPORT void _LayerSetDoubleSided(LayerRef layer, int double_sided);
EXPORT int _LayerDoubleSided(LayerRef layer);
EXPORT void _LayerSetShouldFlattenTransform(LayerRef layer, int should_flatten);
EXPORT int _LayerShouldFlattenTransform(LayerRef layer);
EXPORT int _LayerIs3dSorted(LayerRef layer);
EXPORT void _LayerSetUseParentBackfaceVisibility(LayerRef layer, int parent_backface_visibility);
EXPORT int _LayerUseParentBackfaceVisibility(LayerRef layer);
EXPORT void _LayerSetLayerTreeHost(LayerRef layer, LayerTreeHostRef host);
//EXPORT int _LayerHasDelegatedContent(LayerRef layer);
//EXPORT int _LayerHasContributingDelegatedRenderPasses(LayerRef layer);
EXPORT void _LayerSetIsDrawable(LayerRef layer, int is_drawable);
EXPORT void _LayerSetHideLayerAndSubtree(LayerRef layer, int hide);
EXPORT int _LayerHideLayerAndSubtree(LayerRef layer);
//EXPORT void _LayerSetReplicaLayer(LayerRef layer, LayerRef replica);
//EXPORT LayerRef _LayerReplicaLayer(LayerRef layer);
//EXPORT int _LayerHasMask(LayerRef layer);
//EXPORT int _LayerHasReplica(LayerRef layer);
//EXPORT int _LayerReplicaHasMask(LayerRef layer);
EXPORT int _LayerNumDescendantsThatDrawContent(LayerRef layer);
//EXPORT void _LayerSavePaintProperties(LayerRef layer);
EXPORT int _LayerUpdate(LayerRef layer);
//EXPORT void _LayerSetIsMask(LayerRef layer, int is_mask);
//EXPORT int _LayerIsSuitableForGpuRasterization(LayerRef layer);
EXPORT void _LayerSetLayerClient(LayerRef layer);
EXPORT void _LayerPushPropertiesTo(LayerRef layer, LayerRef other);
EXPORT LayerTreeHostRef _LayerLayerTreeHost(LayerRef layer);
// EXPORT int _LayerAddAnimation(LayerRef layer, AnimationRef animation);
// EXPORT void _LayerPauseAnimation(LayerRef layer, int animation_id, double time_offset);
// EXPORT void _LayerRemoveAnimation(LayerRef layer, int animation_id);
// EXPORT void _LayerRemoveAnimationByProperty(LayerRef layer, int animation_id, int target_property);
// //EXPORT LayerAnimationControllerRef _LayerLayerAnimationController(LayerRef layer);
// EXPORT void _LayerSetLayerAnimationDelegate(LayerRef layer, void* peer, CLayerAnimationDelegateCallbacks delegate);
// EXPORT int _LayerHasActiveAnimation(LayerRef layer);
//EXPORT void _LayerRegisterForAnimations(LayerRef layer, AnimationRegistrarRef registrar);
//EXPORT void _LayerAddLayerAnimationEventObserver(LayerRef layer, LayerAnimationEventObserverRef observer);
//EXPORT void _LayerRemoveLayerAnimationEventObserver(LayerRef layer, LayerAnimationEventObserverRef observer);
EXPORT void _LayerGetPicture(LayerRef layer);
// returning the layer id
EXPORT int _LayerToScrollbarLayer(LayerRef layer);
EXPORT void _LayerPaintProperties(LayerRef layer);
EXPORT void _LayerSetNeedsPushProperties(LayerRef layer);
//EXPORT int _LayerNeedsPushProperties(LayerRef layer);
//EXPORT int _LayerDescendantNeedsPushProperties(LayerRef layer);
EXPORT void _LayerSet3dSortingContextId(LayerRef layer, int id);
EXPORT int _LayerSortingContextId(LayerRef layer);
EXPORT void _LayerSetPropertyTreeSequenceNumber(LayerRef layer, int sequence_number);
EXPORT void _LayerSetTransformTreeIndex(LayerRef layer, int index);
EXPORT int _LayerTransformTreeIndex(LayerRef layer);
EXPORT void _LayerSetClipTreeIndex(LayerRef layer, int index);
EXPORT int _LayerClipTreeIndex(LayerRef layer);
EXPORT void _LayerSetEffectTreeIndex(LayerRef layer, int index);
EXPORT int _LayerEffectTreeIndex(LayerRef layer);
EXPORT void _LayerSetOffsetToTransformParent(LayerRef layer, float offset_x, float offset_y);
EXPORT void _LayerOffsetToTransformParent(LayerRef layer, float* offset_x, float* offset_y);
//EXPORT void _LayerVisibleRectFromPropertyTrees(LayerRef layer, int* x, int* y, int* width, int* height);
//EXPORT void _LayerSetVisibleRectFromPropertyTrees(LayerRef layer, int x, int y, int width, int height);
// EXPORT void _LayerClipRectInTargetSpaceFromPropertyTrees(LayerRef layer, int* x, int* y, int* width, int* height);
// EXPORT void _LayerSetClipRectInTargetSpaceFromPropertyTrees(LayerRef layer, int x, int y, int width, int height);
EXPORT void _LayerSetShouldFlattenTransformFromPropertyTree(LayerRef layer, int should_flatten);
EXPORT int _LayerShouldFlattenTransformFromPropertyTree(LayerRef layer);
//EXPORT void _LayerVisibleLayerRect(LayerRef layer, int* x, int* y, int* width, int* height);
EXPORT void _LayerSetVisibleLayerRect(LayerRef layer, int x, int y, int width, int height);
//EXPORT void _LayerClipRect(LayerRef layer, int* x, int* y, int* width, int* height);
//EXPORT void _LayerSetClipRect(LayerRef layer, int x, int y, int width, int height);
//EXPORT int _LayerHasRenderSurface(LayerRef layer);
EXPORT void _LayerSetFrameTimingRequests(LayerRef layer);
EXPORT void _LayerFrameTimingRequests(LayerRef layer);
EXPORT void _LayerDidBeginTracing(LayerRef layer);
//EXPORT void _LayerSetNumLayerOrDescendantWithCopyRequest(LayerRef layer, int layers);
//EXPORT int _LayerNumLayerOrDescendantsWithCopyRequest(LayerRef layer);
//EXPORT void _LayerSetVisited(LayerRef layer, int visited);
//EXPORT int _LayerVisited(LayerRef layer);
//EXPORT void _LayerSetLayerOrDescendantIsDrawn(LayerRef layer, int is_drawn);
//EXPORT int _LayerLayerOrDescendantIsDrawn(LayerRef layer);
//EXPORT void _LayerSetSortedForRecursion(LayerRef layer, int sorted);
//EXPORT int _LayerSortedForRecursion(LayerRef layer);
//EXPORT void _LayerScrollOffsetForAnimation(LayerRef layer, double* offset_x, double* offset_y);
// NOT WORKING
EXPORT void _LayerOnFilterAnimated(LayerRef layer, int* filters);
// EXPORT void _LayerOnOpacityAnimated(LayerRef layer, float opacity);
// EXPORT void _LayerOnTransformAnimated(LayerRef layer,
//   double col1row1, double col2row1,
//   double col3row1, double col4row1,
//   double col1row2, double col2row2,
//   double col3row2, double col4row2,
//   double col1row3, double col2row3,
//   double col3row3, double col4row3,
//   double col1row4, double col2row4,
//   double col3row4, double col4row4);
// EXPORT void _LayerOnScrollOffsetAnimated(LayerRef layer, double x_offset, double y_offset);
// EXPORT void _LayerOnAnimationWaitingForDeletion(LayerRef layer);
//EXPORT void _LayerOnTransformIsPotentiallyAnimatingChanged(LayerRef layer, int is_animating);
//EXPORT int _LayerIsActive(LayerRef layer);

// TextureLayer

EXPORT int _TextureLayerFlipped(LayerRef reference);
EXPORT void _TextureLayerSetFlipped(LayerRef reference, int flipped);
EXPORT int _TextureLayerIsSnapped(LayerRef reference);
EXPORT void _TextureLayerClearClient(LayerRef reference);
EXPORT void _TextureLayerClearTexture(LayerRef reference);
EXPORT void _TextureLayerSetUV(LayerRef reference, float tlx, float tly, float brx, float bry);
EXPORT void _TextureLayerSetNearestNeighbor(LayerRef reference, int nearest_neighbor);
EXPORT void _TextureLayerSetVertexOpacity(LayerRef reference, float bottom_left, float top_left, float top_right, float bottom_right);
EXPORT void _TextureLayerSetPremultipliedAlpha(LayerRef reference, int premulalpha);
EXPORT void _TextureLayerSetBlendBackgroundColor(LayerRef reference, int blend);
EXPORT void _TextureLayerSetTransferableResource(LayerRef reference, TransferableResourceRef resource);

EXPORT int _InputHandlerGetScrollOffsetForLayer(InputHandlerRef reference, int layerId, float* x, float* y);
EXPORT int _InputHandlerScrollLayerTo(InputHandlerRef reference, int layerId, float offset_x, float offset_y);
// KeyframeModel
EXPORT KeyframeModelRef _KeyframeModelCreate(AnimationCurveRef curve, int id, int group, int property);
EXPORT void _KeyframeModelDestroy(KeyframeModelRef model);
EXPORT int _KeyframeModelIsFinishedAt(KeyframeModelRef model, int64_t monotonic_time);
EXPORT int  _KeyframeModelId(KeyframeModelRef model);
EXPORT int _KeyframeModelGroup(KeyframeModelRef model);
EXPORT int _KeyframeModelTargetProperty(KeyframeModelRef model);
EXPORT int _KeyframeModelRunState(KeyframeModelRef model);
EXPORT void _KeyframeModelSetRunState(KeyframeModelRef model, int run_state, int64_t monotonic_time);
EXPORT double _KeyframeModelIterations(KeyframeModelRef model);
EXPORT void _KeyframeModelSetIterations(KeyframeModelRef model, double iterations);
EXPORT double _KeyframeModelIterationStart(KeyframeModelRef model);
EXPORT void _KeyframeModelSetIterationStart(KeyframeModelRef model, double iteration_start);
EXPORT int64_t _KeyframeModelStartTime(KeyframeModelRef model);
EXPORT void _KeyframeModelSetStartTime(KeyframeModelRef model, int64_t value);
EXPORT int64_t _KeyframeModelTimeOffset(KeyframeModelRef model);
EXPORT void _KeyframeModelSetTimeOffset(KeyframeModelRef model, int64_t value);
EXPORT int _KeyframeModelDirection(KeyframeModelRef model);
EXPORT void _KeyframeModelSetDirection(KeyframeModelRef model, int value);
EXPORT int _KeyframeModelFillMode(KeyframeModelRef model);
EXPORT void _KeyframeModelSetFillMode(KeyframeModelRef model, int value);
EXPORT double _KeyframeModelPlaybackRate(KeyframeModelRef model);
EXPORT void _KeyframeModelSetPlaybackRate(KeyframeModelRef model, double value);
EXPORT AnimationCurveRef _KeyframeModelAnimationCurve(KeyframeModelRef model);
EXPORT int _KeyframeModelNeedsSynchronizedStartTime(KeyframeModelRef model);
EXPORT void _KeyframeModelSetNeedsSynchronizedStartTime(KeyframeModelRef model, int value);
EXPORT int _KeyframeModelReceivedFinishedEvent(KeyframeModelRef model);
EXPORT void _KeyframeModelSetReceivedFinishedEvent(KeyframeModelRef model, int value);
EXPORT int _KeyframeModelIsControllingInstance(KeyframeModelRef model);
EXPORT void _KeyframeModelSetIsControllingInstance(KeyframeModelRef model, int value);
EXPORT int _KeyframeModelIsImplOnly(KeyframeModelRef model);
EXPORT void _KeyframeModelSetIsImplOnly(KeyframeModelRef model, int value);
EXPORT int _KeyframeModelAffectsActiveElements(KeyframeModelRef model);
EXPORT void _KeyframeModelSetAffectsActiveElements(KeyframeModelRef model, int value);
EXPORT int _KeyframeModelAffectsPendingElements(KeyframeModelRef model);
EXPORT void _KeyframeModelSetAffectsPendingElements(KeyframeModelRef model, int value);

EXPORT void _KeyframeEffectDestroy(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectGetId(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectHasBoundElementAnimations(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectGetElementId(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectHasAnyKeyframeModel(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectScrollOffsetAnimationWasInterrupted(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectGetNeedsPushProperties(KeyframeEffectRef reference);
EXPORT void _KeyframeEffectSetNeedsPushProperties(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectAnimationsPreserveAxisAlignment(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectIsTicking(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectHasTickingKeyframeModel(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectTickingKeyframeModelsCount(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectHasNonDeletedKeyframeModel(KeyframeEffectRef reference);
EXPORT void _KeyframeEffectBindElementAnimations(KeyframeEffectRef reference, ElementAnimationsRef elementAnimations);
EXPORT void _KeyframeEffectUnbindElementAnimations(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectHasAttachedElement(KeyframeEffectRef reference);
EXPORT void _KeyframeEffectAttachElement(KeyframeEffectRef reference, int elementId);
EXPORT void _KeyframeEffectDetachElement(KeyframeEffectRef reference);
EXPORT void _KeyframeEffectTick(KeyframeEffectRef reference, int64_t monotonicTime, void* state, AnimationTimeProviderCallback tickProvider);
EXPORT void _KeyframeEffectRemoveFromTicking(KeyframeEffectRef reference);
EXPORT void _KeyframeEffectUpdateState(KeyframeEffectRef reference, int startReadyKeyframeModels, AnimationEventsRef events);
EXPORT void _KeyframeEffectUpdateTickingState(KeyframeEffectRef reference, int type);
EXPORT void _KeyframeEffectAddKeyframeModel(KeyframeEffectRef reference, KeyframeModelRef model);
EXPORT void _KeyframeEffectPauseKeyframeModel(KeyframeEffectRef reference, int id, double timeOffset);
EXPORT void _KeyframeEffectRemoveKeyframeModel(KeyframeEffectRef reference, int id);
EXPORT void _KeyframeEffectAbortKeyframeModel(KeyframeEffectRef reference, int id);
EXPORT void _KeyframeEffectAbortKeyframeModels(KeyframeEffectRef reference, int target, int needsCompletion);
EXPORT void _KeyframeEffectActivateKeyframeEffects(KeyframeEffectRef reference);
EXPORT void _KeyframeEffectActivateKeyframeModelAdded(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectNotifyKeyframeModelStarted(KeyframeEffectRef reference, AnimationEventRef event);
EXPORT int _KeyframeEffectNotifyKeyframeModelFinished(KeyframeEffectRef reference, AnimationEventRef event);
EXPORT void _KeyframeEffectNotifyKeyframeModelTakeover(KeyframeEffectRef reference, AnimationEventRef event);
EXPORT int _KeyframeEffectNotifyKeyframeModelAborted(KeyframeEffectRef reference, AnimationEventRef event);
EXPORT int _KeyframeEffectHasOnlyTranslationTransforms(KeyframeEffectRef reference, int type);
EXPORT int _KeyframeEffectAnimationStartScale(KeyframeEffectRef reference, int type, float* scale);
EXPORT int _KeyframeEffectAnimationsPreserveAxisAlignment(KeyframeEffectRef reference);
EXPORT int _KeyframeEffectMaximumTargetScale(KeyframeEffectRef reference, int type, float* scale);
EXPORT int _KeyframeEffectIsPotentiallyAnimatingProperty(KeyframeEffectRef reference, int targetProperty, int type);
EXPORT int _KeyframeEffectIsCurrentlyAnimatingProperty(KeyframeEffectRef reference, int targetProperty, int type);
EXPORT KeyframeModelRef _KeyframeEffectGetKeyframeModel(KeyframeEffectRef reference, int targetProperty);
EXPORT KeyframeModelRef _KeyframeEffectGetKeyframeModelById(KeyframeEffectRef reference, int keyframeModelId);
EXPORT void _KeyframeEffectGetPropertyAnimationState(KeyframeEffectRef reference, int* pendingStateCurrentlyRunning, int* pendingStatePotentiallyAnimating, int* activeStateCurrentlyRunning , int* activeStatePotentiallyAnimating);
EXPORT void _KeyframeEffectMarkAbortedKeyframeModelsForDeletion(KeyframeEffectRef reference, KeyframeEffectRef effect);
EXPORT void _KeyframeEffectPurgeKeyframeModelsMarkedForDeletion(KeyframeEffectRef reference, int implOnly);
EXPORT void _KeyframeEffectPushNewKeyframeModelsToImplThread(KeyframeEffectRef reference, KeyframeEffectRef effect);
EXPORT void _KeyframeEffectRemoveKeyframeModelsCompletedOnMainThread(KeyframeEffectRef reference, KeyframeEffectRef effect);
EXPORT void _KeyframeEffectPushPropertiesTo(KeyframeEffectRef reference, KeyframeEffectRef effect);
EXPORT void _KeyframeEffectSetAnimation(KeyframeEffectRef reference, AnimationRef animation);

EXPORT void _KeyframeEffectListDestroy(KeyframeEffectListRef reference);

EXPORT void _ElementAnimationsDestroy(ElementAnimationsRef reference);
EXPORT int _ElementAnimationsIsEmpty(ElementAnimationsRef reference);
EXPORT uint64_t _ElementAnimationsGetElementId(ElementAnimationsRef reference);
EXPORT void _ElementAnimationsSetElementId(ElementAnimationsRef reference, uint64_t id);
EXPORT AnimationHostRef _ElementAnimationsGetAnimationHost(ElementAnimationsRef reference);
EXPORT void _ElementAnimationsSetAnimationHost(ElementAnimationsRef reference, AnimationHostRef animHost);
EXPORT void _ElementAnimationsGetScrollOffsetForAnimation(ElementAnimationsRef reference, float* x, float* y);
EXPORT KeyframeEffectListRef _ElementAnimationsKeyframeEffectListGet(ElementAnimationsRef reference);
EXPORT int _ElementAnimationsHasTickingKeyframeEffect(ElementAnimationsRef reference);
EXPORT int _ElementAnimationsHasAnyKeyframeModel(ElementAnimationsRef reference);
EXPORT int _ElementAnimationsHasElementInActiveList(ElementAnimationsRef reference);
EXPORT int _ElementAnimationsHasElementInPendingList(ElementAnimationsRef reference);  
EXPORT int _ElementAnimationsHasElementInAnyList(ElementAnimationsRef reference);
EXPORT int _ElementAnimationsAnimationsPreserveAxisAlignment(ElementAnimationsRef reference);
EXPORT int _ElementAnimationsScrollOffsetAnimationWasInterrupted(ElementAnimationsRef reference);
EXPORT int _ElementAnimationsGetNeedsPushProperties(ElementAnimationsRef reference);
EXPORT void _ElementAnimationsSetNeedsPushProperties(ElementAnimationsRef reference);
EXPORT void _ElementAnimationsInitAffectedElementTypes(ElementAnimationsRef reference);
EXPORT void _ElementAnimationsClearAffectedElementTypes(ElementAnimationsRef reference);
EXPORT void _ElementAnimationsElementRegistered(ElementAnimationsRef reference, uint64_t elementId, int type);
EXPORT void _ElementAnimationsElementUnregistered(ElementAnimationsRef reference, uint64_t elementId, int type);
EXPORT void _ElementAnimationsAddKeyframeEffect(ElementAnimationsRef reference, KeyframeEffectRef effect);
EXPORT void _ElementAnimationsRemoveKeyframeEffect(ElementAnimationsRef reference, KeyframeEffectRef effect);
EXPORT void _ElementAnimationsPushPropertiesTo(ElementAnimationsRef reference, ElementAnimationsRef animations);
EXPORT int _ElementAnimationsHasAnyAnimationTargetingProperty(ElementAnimationsRef reference, int property);
EXPORT int _ElementAnimationsIsPotentiallyAnimatingProperty(ElementAnimationsRef reference, int property, int type);
EXPORT int _ElementAnimationsIsCurrentlyAnimatingProperty(ElementAnimationsRef reference, int property, int type);
EXPORT void  _ElementAnimationsNotifyAnimationStarted(ElementAnimationsRef reference, AnimationEventRef event);
EXPORT void _ElementAnimationsNotifyAnimationFinished(ElementAnimationsRef reference, AnimationEventRef event);
EXPORT void _ElementAnimationsNotifyAnimationAborted(ElementAnimationsRef reference, AnimationEventRef event);
//EXPORT void _ElementAnimationsNotifyAnimationPropertyUpdate(ElementAnimationsRef reference, AnimationEventRef event);
EXPORT void _ElementAnimationsNotifyAnimationTakeover(ElementAnimationsRef reference, AnimationEventRef event);
EXPORT void _ElementAnimationsSetHasElementInActiveList(ElementAnimationsRef reference, int hasElementInActiveList);
EXPORT void _ElementAnimationsSetHasElementInPendingList(ElementAnimationsRef reference, int hasElementInPendingList);
//EXPORT int _ElementAnimationsTransformAnimationBoundsForBox(ElementAnimationsRef reference, 
//  float bx, float by, float bz, float bw, float bh, float bdepth,
//  float* x, float* y, float* z, float* w, float* h, float* depth);
EXPORT int _ElementAnimationsHasOnlyTranslationTransforms(ElementAnimationsRef reference, int type);
EXPORT int _ElementAnimationsAnimationStartScale(ElementAnimationsRef reference, int type, float* scale);
EXPORT int _ElementAnimationsMaximumTargetScale(ElementAnimationsRef reference, int type, float* scale);
EXPORT void _ElementAnimationsUpdateClientAnimationState(ElementAnimationsRef reference);
EXPORT void _ElementAnimationsNotifyClientFloatAnimated(ElementAnimationsRef reference, float opacity, int target, KeyframeModelRef model);  
EXPORT void _ElementAnimationsNotifyClientScrollOffsetAnimated(
    ElementAnimationsRef reference, 
    float scrollOffsetX,
    float scrollOffsetY,
    int target,
    KeyframeModelRef model);

EXPORT PaintTextBlobRef _PaintTextBlobCreate(const uint16_t* glyphs, size_t glyph_count, const float* px, const float* py, int plen, PaintFlagsRef flags);
EXPORT void _PaintTextBlobDestroy(PaintTextBlobRef handle);

EXPORT void _PaintFilterDestroy(PaintFilterRef handle);

// TransformOperations

EXPORT int _TransformOperationGetType(TransformOperationRef handle);

EXPORT TransformOperationsRef _TransformOperationsCreate();
EXPORT void _TransformOperationsDestroy(TransformOperationsRef handle);
EXPORT int _TransformOperationsIsTranslation(TransformOperationsRef handle);
EXPORT int _TransformOperationsPreservesAxisAlignment(TransformOperationsRef handle);
EXPORT int _TransformOperationsIsIdentity(TransformOperationsRef handle);
EXPORT int _TransformOperationsCount(TransformOperationsRef handle);
EXPORT TransformOperationRef _TransformOperationsGet(TransformOperationsRef handle, int index);
EXPORT Matrix44Ref _TransformOperationsApply(TransformOperationsRef handle);
EXPORT TransformOperationsRef _TransformOperationsBlend(TransformOperationsRef handle, TransformOperationsRef other, float progress);
EXPORT int _TransformOperationsMatchesTypes(TransformOperationsRef handle, TransformOperationsRef other);
EXPORT int _TransformOperationsCanBlendWith(TransformOperationsRef handle, TransformOperationsRef other);
EXPORT int _TransformOperationsScaleComponent(TransformOperationsRef handle, float* scale);
EXPORT void _TransformOperationsAppendTranslate(TransformOperationsRef handle, float x, float y, float z);
EXPORT void _TransformOperationsAppendRotate(TransformOperationsRef handle, float x, float y, float z, float degrees);
EXPORT void _TransformOperationsAppendScale(TransformOperationsRef handle, float x, float y, float z);
EXPORT void _TransformOperationsAppendSkew(TransformOperationsRef handle, float x, float y);
EXPORT void _TransformOperationsAppendPerspective(TransformOperationsRef handle, float depth);
EXPORT void _TransformOperationsAppendMatrix(TransformOperationsRef handle, Matrix44Ref matrix);
EXPORT void _TransformOperationsAppendIdentity(TransformOperationsRef handle);
EXPORT void _TransformOperationsAppend(TransformOperationsRef handle, TransformOperationRef op);
EXPORT int _TransformApproximatelyEqual(TransformOperationsRef handle, TransformOperationsRef other, float tolerance);

// AnimationEvents

EXPORT int _AnimationEventGetType(AnimationEventRef handle);
EXPORT uint64_t _AnimationEventGetElementId(AnimationEventRef handle);
EXPORT int _AnimationEventGetGroupId(AnimationEventRef handle);
EXPORT int _AnimationEventGetTargetProperty(AnimationEventRef handle);
EXPORT int64_t _AnimationEventGetMonotonicTime(AnimationEventRef handle);
EXPORT int _AnimationEventIsImplOnly(AnimationEventRef handle);
EXPORT float _AnimationEventGetOpacity(AnimationEventRef handle);
EXPORT Matrix44Ref _AnimationEventGetTransform(AnimationEventRef handle);
EXPORT FilterOperationsRef _AnimationEventGetFilterOperations(AnimationEventRef handle);

EXPORT int _AnimationEventsIsEmpty(AnimationEventsRef handle);

// FilterOperations

EXPORT int _FilterOperationGetType(FilterOperationRef reference);
EXPORT float _FilterOperationGetAmount(FilterOperationRef reference);
EXPORT void _FilterOperationSetAmount(FilterOperationRef reference, float value);
EXPORT float _FilterOperationGetOuterThreshold(FilterOperationRef reference);
EXPORT void _FilterOperationSetOuterThreshold(FilterOperationRef reference, float value);
EXPORT void _FilterOperationGetDropShadowOffset(FilterOperationRef reference, int* x, int* y);
EXPORT void _FilterOperationSetDropShadowOffset(FilterOperationRef reference, int x, int y);
EXPORT void _FilterOperationGetDropShadowColor(FilterOperationRef reference, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b);
EXPORT void _FilterOperationSetDropShadowColor(FilterOperationRef reference, uint8_t a, uint8_t r, uint8_t g, uint8_t b); 
EXPORT PaintFilterRef _FilterOperationGetImageFilter(FilterOperationRef reference);
EXPORT void _FilterOperationSetImageFilter(FilterOperationRef reference, PaintFilterRef filter);
EXPORT void _FilterOperationGetColorMatrix(
  FilterOperationRef reference, 
  int *m0, int *m1, int *m2, int *m3,
  int *m4, int *m5, int *m6, int *m7,
  int *m8, int *m9, int *m10, int *m11,
  int *m12, int *m13, int *m14, int *m15,
  int *m16, int *m17, int *m18, int *m19);

EXPORT void _FilterOperationSetColorMatrix(
    FilterOperationRef reference,
    int m0, int m1, int m2, int m3,
    int m4, int m5, int m6, int m7,
    int m8, int m9, int m10, int m11,
    int m12, int m13, int m14, int m15,
    int m16, int m17, int m18, int m19);

EXPORT int _FilterOperationGetZoomInset(FilterOperationRef reference);
EXPORT void _FilterOperationSetZoomInset(FilterOperationRef reference, int inset);

EXPORT void _FilterOperationGetShape(FilterOperationRef reference, int** x, int** y, int** w, int** h, int* count);
EXPORT void _FilterOperationGetShapeCount(FilterOperationRef reference, int* count);
EXPORT void _FilterOperationGetShapeNoCount(FilterOperationRef reference, int** x, int** y, int** w, int** h);
EXPORT void _FilterOperationSetShape(FilterOperationRef reference, int* x, int* y, int* w, int* h, int count);

EXPORT FilterOperationRef _FilterOperationCreateWithAmount(int type, float amount);
EXPORT FilterOperationRef _FilterOperationCreateWithShape(int type, int* x, int* y, int* w, int* h, int count, float innerThreshold, float outerThreshold);
EXPORT FilterOperationRef _FilterOperationCreateWithOffset(int type, 
  int x, int y, 
  float deviation,
  uint8_t a, uint8_t r, uint8_t g, uint8_t b);
EXPORT FilterOperationRef _FilterOperationCreateWithInset(int type, float amount, int inset);
EXPORT FilterOperationRef _FilterOperationCreateWithMatrix(int type,
  int m0, int m1, int m2, int m3,
  int m4, int m5, int m6, int m7,
  int m8, int m9, int m10, int m11,
  int m12, int m13, int m14, int m15,
  int m16, int m17, int m18, int m19);
EXPORT FilterOperationRef _FilterOperationCreateWithFilter(int type, PaintFilterRef filter);

EXPORT FilterOperationsRef _FilterOperationsCreate();
EXPORT void _FilterOperationsDestroy(FilterOperationsRef reference);
EXPORT int _FilterOperationsGetCount(FilterOperationsRef reference);
EXPORT int _FilterOperationsHasFilterThatMovesPixels(FilterOperationsRef reference);
EXPORT int _FilterOperationsHasFilterThatAffectsOpacity(FilterOperationsRef reference);
EXPORT int _FilterOperationsHasReferenceFilter(FilterOperationsRef reference);
EXPORT FilterOperationRef _FilterOperationsGet(FilterOperationsRef reference, int index);
EXPORT void _FilterOperationsAppend(FilterOperationsRef reference, FilterOperationRef filter);
EXPORT void _FilterOperationsClear(FilterOperationsRef reference);
EXPORT void _FilterOperationsMapRect(FilterOperationsRef reference,
  int rx, int ry, int rw, int rh, 
  float scaleX, float skewX, float transX,
  float skewY, float scaleY, float transY,
  float pers0, float pers1, float pers2,
  int* x, int* y, int* w, int* h);
EXPORT void _FilterOperationsMapRectReverse(FilterOperationsRef reference, 
  int rx, int ry, int rw, int rh, 
  float scaleX, float skewX, float transX,
  float skewY, float scaleY, float transY,
  float pers0, float pers1, float pers2,
  int* x, int* y, int* w, int* h);

EXPORT FilterOperationsRef _FilterOperationsBlend(FilterOperationsRef reference, FilterOperationsRef from, float progress);

typedef struct {
  int64_t (*GetDuration)(void* state);
  float (*GetValue)(void* state, int64_t t);
} FloatAnimationCurveCallbacks;

typedef struct {
  int64_t (*GetDuration)(void* state);
  TransformOperationsRef (*GetValue)(void* state, int64_t t);
  int (*GetAnimatedBoundsForBox)(void* state, 
    float ix, float iy, float iz, float iw, float ih, float id,
    float* ox, float* oy, float* oz, float* ow, float* oh, float* od);
  int (*GetIsTranslation)(void* state);
  int (*GetPreservesAxisAlignment)(void* state);
  int (*GetAnimationStartScale)(void* state, int forward_direction, float* start_scale);
  int (*GetMaximumTargetScale)(void* state, int forward_direction, float* max_scale);
} TransformAnimationCurveCallbacks;

// Animation Curve
EXPORT AnimationCurveRef _AnimationCurveCreateFloatAnimation(void* state, FloatAnimationCurveCallbacks callbacks);
EXPORT AnimationCurveRef _AnimationCurveCreateTransformAnimation(void* state, TransformAnimationCurveCallbacks callbacks);
EXPORT int64_t _AnimationCurveGetDuration(AnimationCurveRef reference);
EXPORT int _AnimationCurveGetType(AnimationCurveRef reference);
EXPORT AnimationCurveRef _AnimationCurveClone(AnimationCurveRef reference);
EXPORT void _AnimationCurveDestroy(AnimationCurveRef reference);

// AnimationHost

EXPORT AnimationHostRef _AnimationHostCreate();
EXPORT void _AnimationHostDestroy(AnimationHostRef handle);
EXPORT void _AnimationHostAddAnimationTimeline(AnimationHostRef handle, AnimationTimelineRef timeline);
EXPORT void _AnimationHostRemoveAnimationTimeline(AnimationHostRef handle, AnimationTimelineRef timeline);
EXPORT AnimationTimelineRef _AnimationHostGetTimelineById(AnimationHostRef handle, int id);
//EXPORT void _AnimationHostClearTimelines(AnimationHostRef handle);
EXPORT void _AnimationHostRegisterKeyframeEffectForElement(AnimationHostRef handle, uint64_t element_id, KeyframeEffectRef effect);
EXPORT void _AnimationHostUnregisterKeyframeEffectForElement(AnimationHostRef handle, uint64_t element_id, KeyframeEffectRef effect);
EXPORT void _AnimationHostSetNeedsCommit(AnimationHostRef handle);
EXPORT void _AnimationHostSetNeedsPushProperties(AnimationHostRef handle);
EXPORT int _AnimationHostGetNeedsPushProperties(AnimationHostRef handle);
EXPORT int _AnimationHostSupportsScrollAnimations(AnimationHostRef handle);

typedef struct {
  void (*NotifyAnimationStarted)(void*, int64_t, int, int);
  void (*NotifyAnimationFinished)(void*, int64_t, int, int);
  void (*NotifyAnimationAborted)(void*, int64_t, int, int);
  void (*NotifyAnimationTakeover)(void*, int64_t, int, int64_t, AnimationCurveRef);
} CAnimationDelegate;

// Animation
EXPORT void _AnimationDestroy(AnimationRef handle);
EXPORT int _AnimationGetId(AnimationRef handle);
EXPORT int _AnimationIsElementAttached(AnimationRef handle, uint64_t id);
EXPORT int _AnimationGetElementIdOfKeyframeEffect(AnimationRef handle, uint64_t keyframe_effect_id, uint64_t* elem_id);
EXPORT AnimationHostRef _AnimationGetAnimationHost(AnimationRef handle);
EXPORT void _AnimationSetAnimationDelegate(AnimationRef handle, void *peer, CAnimationDelegate delegate);
EXPORT void _AnimationSetAnimationHost(AnimationRef handle, AnimationHostRef host);
EXPORT int _AnimationHasAnimationHost(AnimationRef handle);
EXPORT AnimationTimelineRef _AnimationGetAnimationTimeline(AnimationRef handle);
EXPORT void _AnimationSetAnimationTimeline(AnimationRef handle, AnimationTimelineRef timeline);
EXPORT int _AnimationHasElementAnimations(AnimationRef handle);
EXPORT void _AnimationAttachElementForKeyframeEffect(AnimationRef handle, uint64_t element_id, uint64_t keyframe_effect_id);
EXPORT void _AnimationDetachElementForKeyframeEffect(AnimationRef handle, uint64_t element_id, uint64_t keyframe_effect_id);
EXPORT void _AnimationDetachElement(AnimationRef handle);
EXPORT void _AnimationAddKeyframeModelForKeyframeEffect(AnimationRef handle, KeyframeModelRef model, uint64_t keyframe_effect_id);
EXPORT void _AnimationPauseKeyframeModelForKeyframeEffect(AnimationRef handle, int keyframe_model_id, double time_offset, uint64_t keyframe_effect_id);
EXPORT void _AnimationRemoveKeyframeModelForKeyframeEffect(AnimationRef handle, int keyframe_model_id, uint64_t keyframe_effect_id);
EXPORT void _AnimationAbortKeyframeModelForKeyframeEffect(AnimationRef handle, int keyframe_model_id, uint64_t keyframe_effect_id);
EXPORT void _AnimationAbortKeyframeModels(AnimationRef handle, int target_property, int needs_completion);
EXPORT void _AnimationPushPropertiesTo(AnimationRef handle, AnimationRef other);
EXPORT void _AnimationUpdateState(AnimationRef handle, int start_ready_keyframe_models, AnimationEventsRef events);
EXPORT void _AnimationTick(AnimationRef handle, int64_t monotonic_time);
EXPORT void _AnimationAddToTicking(AnimationRef handle);
EXPORT void _AnimationKeyframeModelRemovedFromTicking(AnimationRef handle);
EXPORT void _AnimationNotifyKeyframeModelStarted(AnimationRef handle, AnimationEventRef event);
EXPORT void _AnimationNotifyKeyframeModelFinished(AnimationRef handle, AnimationEventRef event);
EXPORT void _AnimationNotifyKeyframeModelAborted(AnimationRef handle, AnimationEventRef event);
EXPORT void _AnimationNotifyKeyframeModelTakeover(AnimationRef handle, AnimationEventRef event);
EXPORT uint64_t _AnimationTickingKeyframeModelsCount(AnimationRef handle);
EXPORT void _AnimationSetNeedsPushProperties(AnimationRef handle);
EXPORT void _AnimationActivateKeyframeEffects(AnimationRef handle);
EXPORT KeyframeModelRef _AnimationGetKeyframeModelForKeyframeEffect(AnimationRef handle, int target_property, uint64_t keyframe_effect_id);
EXPORT void _AnimationSetNeedsCommit(AnimationRef handle);
EXPORT int _AnimationIsWorkletAnimation(AnimationRef handle);
EXPORT void _AnimationAddKeyframeEffect(AnimationRef handle, KeyframeEffectRef effect);
EXPORT KeyframeEffectRef _AnimationGetKeyframeEffectById(AnimationRef handle, uint64_t keyframe_effect_id);
EXPORT uint64_t _AnimationNextKeyframeEffectId(AnimationRef handle);

// SingleKeyframeEffectAnimation
EXPORT AnimationRef _SingleKeyframeEffectAnimationCreate(int id);
EXPORT uint64_t _SingleKeyframeEffectAnimationGetElementId(AnimationRef handle);
//EXPORT KeyframeEffectRef _SingleKeyframeEffectAnimationGetKeyframeEffect(AnimationRef handle);
EXPORT void _SingleKeyframeEffectAnimationAttachElement(AnimationRef handle, uint64_t id);
EXPORT void _SingleKeyframeEffectAddKeyframeModel(AnimationRef handle, KeyframeModelRef model);
EXPORT void _SingleKeyframeEffectAnimationPauseKeyframeModel(AnimationRef handle, int keyframeModelId, double timeOffset);
EXPORT void _SingleKeyframeEffectAnimationRemoveKeyframeModel(AnimationRef handle, int keyframeModelId);
EXPORT void _SingleKeyframeEffectAnimationAbortKeyframeModel(AnimationRef handle, int keyframeModelId);
EXPORT KeyframeModelRef _SingleKeyframeEffectAnimationGetKeyframeModel(AnimationRef handle, int target_property);

// AnimationTimeline
EXPORT AnimationTimelineRef _AnimationTimelineCreate(int id);
EXPORT void _AnimationTimelineDestroy(AnimationTimelineRef handle);
EXPORT void _AnimationTimelineAttachAnimation(AnimationTimelineRef handle, AnimationRef anim);
EXPORT void _AnimationTimelineDetachAnimation(AnimationTimelineRef handle, AnimationRef anim);

// LayerTreeFrameSink
EXPORT LayerTreeFrameSinkRef _LayerTreeFrameSinkCreateDirect(
  uint32_t frame_sink_client_id, 
  uint32_t frame_sink_sink_id,
  HostFrameSinkManagerRef hostframe_sink_manager,
  FrameSinkManagerRef frame_sink_manager,
  DisplayRef display,
  ContextProviderRef contex_provider);

EXPORT void _LayerTreeFrameSinkDestroy(LayerTreeFrameSinkRef handle);

// HostFrameSinkManager

EXPORT HostFrameSinkManagerRef _HostFrameSinkManagerCreate();

EXPORT void _HostFrameSinkManagerDestroy(HostFrameSinkManagerRef reference);
  
EXPORT void _HostFrameSinkManagerRegisterFrameSinkId(HostFrameSinkManagerRef reference, uint32_t clientId, uint32_t sinkId, void* clientPtr, struct HostFrameSinkClientCallbacks clientCbs);
 
EXPORT void _HostFrameSinkManagerSetFrameSinkDebugLabel(HostFrameSinkManagerRef reference, uint32_t clientId, uint32_t sinkId, const char* labelCstr);
 
EXPORT int _HostFrameSinkManagerRegisterFrameSinkHierarchy(
        HostFrameSinkManagerRef reference, 
        uint32_t parentClientId, uint32_t parentSinkId,
        uint32_t childClientId, uint32_t childSinkId);

EXPORT void _HostFrameSinkManagerUnregisterFrameSinkHierarchy(
          HostFrameSinkManagerRef reference, 
          uint32_t parentClientId, uint32_t parentSinkId,
          uint32_t childClientId, uint32_t childSinkId);
  
EXPORT void _HostFrameSinkManagerInvalidateFrameSinkId(
          HostFrameSinkManagerRef reference, 
          uint32_t clientId, uint32_t sinkId);

EXPORT void _HostFrameSinkManagerSetLocalManager(HostFrameSinkManagerRef reference, FrameSinkManagerRef frameSinkManager);

// FrameSinkManagerImpl
EXPORT FrameSinkManagerRef _FrameSinkManagerImplCreate();
EXPORT void _FrameSinkManagerImplDestroy(FrameSinkManagerRef reference);
EXPORT void _FrameSinkManagerImplRegisterBeginFrameSource(FrameSinkManagerRef reference, BeginFrameSourceRef begin_frame, uint32_t clientId, uint32_t sinkId);
EXPORT void _FrameSinkManagerImplSetLocalClient(FrameSinkManagerRef reference, HostFrameSinkManagerRef hostFrameReference);
// BeginFrame
EXPORT BeginFrameSourceRef _BeginFrameSourceCreateDelayBased(int64_t microseconds);
EXPORT BeginFrameSourceRef _BeginFrameSourceCreateBackToBack();
EXPORT void _BeginFrameSourceDestroy(BeginFrameSourceRef reference);

// Display

EXPORT DisplayRef _DisplayCreate(uint32_t clientId, uint32_t sinkId, OutputSurfaceRef output_surface, BeginFrameSourceRef begin_frame);
EXPORT void _DisplayDestroy(DisplayRef reference);
EXPORT void _DisplaySetVisible(DisplayRef reference, int visible);
EXPORT void _DisplayResize(DisplayRef reference, int w, int h);
EXPORT void _DisplaySetColorMatrix(DisplayRef reference, Matrix44Ref mat);
EXPORT void _DisplaySetColorSpace(DisplayRef reference, int blending_type, int device_type);

// GpuSurface

#if defined(OS_LINUX)
// Off course this is only valid for X11. change it for the others
EXPORT XID _GpuSurfaceTrackerAddSurfaceNativeWidget(XID widget);
#elif defined(OS_WIN)
EXPORT HWND _GpuSurfaceTrackerAddSurfaceNativeWidget(HWND widget);
#endif

EXPORT InProcessContextProviderRef InProcessContextProviderCreate(
#if defined(OS_LINUX)
  XID window,
#elif defined(OS_WIN)
  HWND window,
#endif
  int32_t alpha_size, 
  int32_t blue_size, 
  int32_t green_size, 
  int32_t red_size, 
  int32_t depth_size, 
  int32_t stencil_size, 
  int32_t samples, 
  int32_t sample_buffers);
EXPORT InProcessContextProviderRef InProcessContextProviderCreateOffscreen(
  #if defined(OS_LINUX)
  XID window
#elif defined(OS_WIN)
  HWND window
#endif
);
EXPORT void InProcessContextProviderDestroy(InProcessContextProviderRef provider);
EXPORT void InProcessContextProviderBindToCurrentThread(InProcessContextProviderRef provider);

// CopyOutputRequest

EXPORT CopyOutputRequestRef _CopyOutputRequestCreateWithBitmapRequest(void* state, LayerTreeHostRef tree, void(*callback)(void*, BitmapRef));
EXPORT void _CopyOutputRequestDestroy(CopyOutputRequestRef reference);


EXPORT SwapPromiseRef _SwapPromiseCreateLatency(
        LayerTreeHostRef layer_tree_host,
        int64_t trace_id,
        const char* trace_name,
        int64_t ukm_sourced_id,
        int coalesced,
        int began,
        int terminated,
        int source_event_type,
        float scroll_update_delta,
        float pred_scroll_update_delta,
        int component_count,
        const int* typearr,
        const int64_t* evtarr);//,
        //void* state, 
        //void(*cb)(void*, int, int, double));

EXPORT SwapPromiseRef _SwapPromiseCreateAlwaysDraw(
      LayerTreeHostRef layer_tree_host,
        int64_t trace_id,
        const char* trace_name,
        int64_t ukm_sourced_id,
        int coalesced,
        int began,
        int terminated,
        int source_event_type,
        float scroll_update_delta,
        float pred_scroll_update_delta,
        int component_count,
        const int* typearr,
        const int64_t* evtarr,
        void* state, 
        void(*cb)(void*, int, int, double));

EXPORT SwapPromiseRef _SwapPromiseCreateReportTime(
  LayerTreeHostRef layer_tree_host,
  void* state);

EXPORT void _SwapPromiseDestroy(SwapPromiseRef ref);

EXPORT SwapPromiseMonitorRef _SwapPromiseMonitorCreateLatency(
      LayerTreeHostRef layer_tree_host,
      int64_t trace_id,
      const char* trace_name,
      int64_t ukm_sourced_id,
      int coalesced,
      int began,
      int terminated,
      int source_event_type,
      float scroll_update_delta,
      float pred_scroll_update_delta,
      int component_count,
      const int* typearr,
      const int64_t* evtarr);

EXPORT void _SwapPromiseMonitorDestroy(SwapPromiseMonitorRef ref);

#endif // MUMBA_KIT_RUNTIME_OMPOSITOR_SHIMS_H_

