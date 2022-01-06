// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_SKIA_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_SKIA_SHIMS_H_

#include "Globals.h"

typedef void* CanvasRef;
//typedef void* NoDrawCanvasRef;
typedef void* PathRef;
typedef void* ImageRef;
typedef void* PictureRef;
typedef void* PictureRecorderRef;
typedef void* GrContextRef;
typedef struct GrGLInterface* GrGLInterfaceRef;
typedef void (*GrGLInterfaceCallback)(const struct GrGLInterface* interface);
typedef void* PaintRef;
typedef void* RegionRef;
typedef void* RegionIteratorRef;
typedef void* MatrixRef;
typedef void* Matrix44Ref;
typedef void* ShaderRef;
typedef void* DrawLooperRef;
typedef void* DrawLooperBuilderRef;
typedef void* TypefaceRef;
typedef void* BitmapRef;
typedef void* DrawableRef;
typedef void* DrawFilterRef;
typedef void* MaskFilterRef;
typedef void* ColorFilterRef;
typedef void* PathEffectRef;
typedef void* PaintTextBlobRef;

EXPORT CanvasRef _CanvasCreate();
EXPORT CanvasRef _CanvasCreateWithBitmap(BitmapRef bitmap);
EXPORT void _CanvasDestroy(CanvasRef canvas);
EXPORT void _CanvasFlush(CanvasRef canvas);
EXPORT int _CanvasSave(CanvasRef canvas);
EXPORT void _CanvasRestore(CanvasRef canvas);
EXPORT void _CanvasRestoreToCount(CanvasRef canvas, int count);
EXPORT int _CanvasSaveLayer(CanvasRef canvas, PaintRef paint);
EXPORT int _CanvasSaveLayerRect(CanvasRef canvas, float x, float y, float width, float height, PaintRef paint);
EXPORT int _CanvasSaveLayerAlpha(CanvasRef canvas, uint8_t alpha);
EXPORT int _CanvasSaveLayerAlphaRect(CanvasRef canvas, uint8_t alpha, float x, float y, float width, float height);
EXPORT int _CanvasSaveLayerPreserveLCDTextRequests(CanvasRef canvas, PaintRef paint);
EXPORT int _CanvasSaveLayerPreserveLCDTextRequestsRect(CanvasRef canvas, float x, float y, float width, float height, PaintRef paint);
EXPORT int _CanvasGetSaveCount(CanvasRef canvas);
EXPORT void _CanvasTranslate(CanvasRef canvas, float dx, float dy);
EXPORT void _CanvasScale(CanvasRef canvas, float sx, float sy);
EXPORT void _CanvasRotate(CanvasRef canvas, float degrees);
EXPORT void _CanvasSkew(CanvasRef canvas, float sx, float sy);
EXPORT void _CanvasConcat(CanvasRef canvas,
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2);
EXPORT void _CanvasSetMatrix(CanvasRef canvas,
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2);
EXPORT void _CanvasConcatHandle(CanvasRef canvas, MatrixRef matrix);
EXPORT void _CanvasConcatHandle44(CanvasRef canvas, Matrix44Ref matrix);
EXPORT void _CanvasSetMatrixHandle(CanvasRef canvas, MatrixRef matrix);
EXPORT MatrixRef _CanvasTotalMatrix(CanvasRef canvas);
EXPORT int _CanvasIsClipEmpty(CanvasRef canvas);
EXPORT int _CanvasIsClipRect(CanvasRef canvas);
EXPORT void _CanvasGetDeviceSize(CanvasRef canvas, float* width, float* height);
EXPORT void _CanvasClipRect(CanvasRef canvas, float x, float y, float width, float height, int clip_op, int anti_alias);
EXPORT void _CanvasClipRRect(CanvasRef canvas, float x, float y, float width, float height, int clip_op, int anti_alias);
EXPORT void _CanvasClipPath(CanvasRef canvas, PathRef path, int clip_op, int anti_alias);
EXPORT int _CanvasGetLocalClipBounds(CanvasRef canvas, float* x, float* y, float* width, float* height);
EXPORT int _CanvasGetDeviceClipBounds(CanvasRef canvas, int* x, int* y, int* width, int* height);
EXPORT int _CanvasReadPixelsXY(CanvasRef canvas, BitmapRef bitmap, int x, int y);
EXPORT int _CanvasWritePixels(CanvasRef canvas, BitmapRef bitmap, int x, int y);
EXPORT void _CanvasDrawColor(CanvasRef canvas, uint8_t a, uint8_t r, uint8_t g, uint8_t b, int mode);
EXPORT void _CanvasDrawLine(CanvasRef canvas, float sx, float sy, float dx, float dy, PaintRef paint);
EXPORT void _CanvasDrawPaint(CanvasRef canvas, PaintRef paint);
EXPORT void _CanvasDrawIRect(CanvasRef canvas, int x, int y, int width, int height, PaintRef paint);
EXPORT void _CanvasDrawRect(CanvasRef canvas, float x, float y, float width, float height, PaintRef paint);
EXPORT void _CanvasDrawRoundRect(CanvasRef canvas, float x, float y, float width, float height, float rx, float ry, PaintRef paint);
EXPORT void _CanvasDrawRRect(CanvasRef canvas, float x, float y, float width, float height, PaintRef paint);
EXPORT void _CanvasDrawDRRect(CanvasRef canvas, float ox, float oy, float ow, float oh, float ix, float iy, float iw, float ih, PaintRef paint);
EXPORT void _CanvasDrawOval(CanvasRef canvas, float x, float y, float width, float height, PaintRef paint);
EXPORT void _CanvasDrawCircle(CanvasRef canvas, float x, float y, float radius, PaintRef paint);
EXPORT void _CanvasDrawPath(CanvasRef canvas, PathRef path, PaintRef paint);
EXPORT void _CanvasDrawImage(CanvasRef canvas, ImageRef image, float x, float y, PaintRef paint);
EXPORT void _CanvasDrawImageRect(CanvasRef canvas, ImageRef image, float sx, float sy, float sw, float sh, float dx, float dy, float dw, float dh, PaintRef paint);
EXPORT void _CanvasDrawImageNine(CanvasRef canvas, ImageRef image, float cx, float cy, float cw, float ch, float dx, float dy, float dw, float dh, PaintRef paint);
EXPORT void _CanvasDrawPicture(CanvasRef canvas, PictureRef picture);
EXPORT void _CanvasDrawDrawable(CanvasRef canvas, DrawableRef drawable);
EXPORT void _CanvasDrawDrawableAt(CanvasRef canvas, DrawableRef drawable, float x, float y);

EXPORT void _CanvasDrawVertices(CanvasRef canvas,
    int vertex_mode,
    float* vx,
    float* vy,
    float* tx,
    float* ty,
    int* colors,
    int count,
    int blend_mode,
    int* indices,
    int indices_count,
    PaintRef paint);

EXPORT void _CanvasDrawAtlas(CanvasRef canvas,
    ImageRef atlas,
    float* transform_scale,
    float* transform_radians, 
    float* transform_tx,
    float* transform_ty,
    float* transform_ax,
    float* transform_ay,
    float* rx,
    float* ry,
    float* rw,
    float* rh,
    int* colors,
    int count,  
    int blend_mode,
    float cull_x,
    float cull_y,
    float cull_w,
    float cull_h,
    PaintRef paint);

EXPORT void _CanvasDrawRegion(CanvasRef canvas, RegionRef region, PaintRef paint);
EXPORT void _CanvasDrawText(CanvasRef canvas, const void* ptr, size_t count, float x, float y, PaintRef paint);
EXPORT void _CanvasDrawPosText(CanvasRef canvas, const void* ptr, size_t count, const float* px, const float* py, int plen, PaintRef paint);
EXPORT void _CanvasDrawTextBlob(CanvasRef canvas, PaintTextBlobRef text_blob, float x, float y, PaintRef paint);
EXPORT void _CanvasDrawBitmap(CanvasRef canvas, BitmapRef bitmap, float left, float top, PaintRef paint);
EXPORT void _CanvasDrawBitmapRectSrcDst(CanvasRef canvas, BitmapRef bitmap, float sx, float sy, float sw, float sh, float dx, float dy, float dw, float dh, PaintRef paint);
EXPORT void _CanvasDrawBitmapRectDst(CanvasRef canvas, BitmapRef bitmap, float dx, float dy, float dw, float dh, PaintRef paint);
EXPORT void _CanvasDrawBitmapNine(CanvasRef canvas, BitmapRef bitmap, float cx, float cy, float cw, float ch, float dx, float dy, float dw, float dh, PaintRef paint);

// NoDrawCanvas
EXPORT CanvasRef _NoDrawCanvasCreate(int width, int height);
EXPORT void _NoDrawCanvasResetCanvas(CanvasRef canvas, int width, int height);
//EXPORT void _NoDrawCanvasDestroy(NoDrawCanvasRef canvas);

// Paint

EXPORT PaintRef _PaintCreate();
EXPORT PaintRef _PaintCreateFromOther(PaintRef paint);

EXPORT void _PaintDestroy(PaintRef paint);
EXPORT void _PaintGetColor(PaintRef paint, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b);
EXPORT void _PaintSetColor(PaintRef paint, uint8_t a, uint8_t r, uint8_t g, uint8_t b);
EXPORT uint8_t _PaintGetAlpha(PaintRef handle);
EXPORT void _PaintSetAlpha(PaintRef handle, uint8_t a);

EXPORT uint32_t _PaintGetStyle(PaintRef paint);
EXPORT void _PaintSetStyle(PaintRef paint, uint32_t style);
EXPORT uint32_t _PaintGetBlend(PaintRef paint);
EXPORT void _PaintSetBlend(PaintRef paint, uint32_t blendmode);
EXPORT int _PaintIsAntiAlias(PaintRef paint);
EXPORT void _PaintSetAntiAlias(PaintRef paint, int antialias);

EXPORT int _PaintGetTextSize(PaintRef paint);
EXPORT void _PaintSetTextSize(PaintRef paint, int size);

EXPORT ShaderRef _PaintGetShader(PaintRef paint);
EXPORT void _PaintSetShader(PaintRef paint, ShaderRef shader);

EXPORT DrawLooperRef _PaintGetDrawLooper(PaintRef paint);
EXPORT void _PaintSetDrawLooper(PaintRef paint, DrawLooperRef looper);

EXPORT TypefaceRef _PaintGetTypeface(PaintRef paint);
EXPORT void _PaintSetTypeface(PaintRef paint, TypefaceRef typeface);

EXPORT int _PaintGetStrokeWidth(PaintRef paint);
EXPORT void _PaintSetStrokeWidth(PaintRef paint, int width);

EXPORT int _PaintIsFakeBoldText(PaintRef paint);
EXPORT void _PaintSetIsFakeBoldText(PaintRef paint, int fake);

EXPORT int _PaintIsSubpixelText(PaintRef paint);
EXPORT void _PaintSetIsSubpixelText(PaintRef paint, int subpixel);

EXPORT int _PaintIsLCDRenderText(PaintRef paint);
EXPORT void _PaintSetIsLCDRenderText(PaintRef paint, int lcd);

EXPORT int _PaintIsAutoHinted(PaintRef paint);
EXPORT void _PaintSetIsAutoHinted(PaintRef paint, int autohinted);

EXPORT uint32_t _PaintGetHinting(PaintRef paint);
EXPORT void _PaintSetHinting(PaintRef paint, uint32_t hinting);

EXPORT uint32_t _PaintGetFilterQuality(PaintRef paint);
EXPORT void _PaintSetFilterQuality(PaintRef paint, uint32_t quality);

EXPORT uint32_t _PaintGetTextEncoding(PaintRef paint);
EXPORT void _PaintSetTextEncoding(PaintRef paint, uint32_t encoding);

EXPORT MaskFilterRef _PaintGetMaskFilter(PaintRef paint);
EXPORT void _PaintSetMaskFilter(PaintRef paint, MaskFilterRef filter);
EXPORT ColorFilterRef _PaintGetColorFilter(PaintRef paint);
EXPORT void _PaintSetColorFilter(PaintRef paint, ColorFilterRef filter);

EXPORT PathRef _PathCreate();
EXPORT void _PathDestroy(PathRef path);
EXPORT void _PathSetFillType(PathRef path, int type);
EXPORT int _PathGetFillType(PathRef path);
EXPORT int _PathIsInverseFillType(PathRef path);
EXPORT int _PathIsEmpty(PathRef path);
EXPORT int _PathIsRect(PathRef path, float x, float y, float width, float height);
EXPORT int _PathIsOval(PathRef path, float x, float y, float width, float height);
EXPORT int _PathIsRRect(PathRef path, float x, float y, float width, float height);
EXPORT void _PathMoveTo(PathRef path, float x, float y);
EXPORT void _PathLineTo(PathRef path, float x, float y);
EXPORT void _PathArcTo(PathRef path, float x, float y, float width, float height, double start_angle, double sweep_angle, int force_move_to);
EXPORT void _PathAddRect(PathRef path, float x, float y, float width, float height, int direction);
EXPORT void _PathAddRoundRect(PathRef path, float x, float y, float width, float height, float rx, float ry, int direction);
EXPORT void _PathAddPath(PathRef path, PathRef other, float x, float y);
EXPORT void _PathAddOval(PathRef path, float x, float y, float width, float height);
EXPORT void _PathClose(PathRef path);
EXPORT void _PathReset(PathRef path);
EXPORT int _PathCountPoints(PathRef path);
EXPORT int _PathGetPoint(PathRef path, int index, float* x, float*y);
EXPORT void _PathTransformMatrix44(PathRef path, Matrix44Ref mat, PathRef dest);
EXPORT void _PathTransformMatrix(PathRef path, MatrixRef mat);

EXPORT PictureRef _PictureCreate();
EXPORT int _PictureSuitableForGpuRasterization(PictureRef picture, GrContextRef context);
EXPORT int _PictureApproximateOpCount(PictureRef picture);
EXPORT size_t _PictureApproximateBytesUsed(PictureRef picture);
EXPORT void _PictureDestroy(PictureRef picture);
EXPORT void _PictureGetBounds(PictureRef picture, int* x, int* y, int* w, int* h);
EXPORT int _PictureGetWidth(PictureRef picture);
EXPORT int _PictureGetHeight(PictureRef picture);
EXPORT void _PictureDraw(PictureRef picture, CanvasRef canvas);

// PictureRecorder
EXPORT PictureRecorderRef _PictureRecorderCreate();
EXPORT void _PictureRecorderDestroy(PictureRecorderRef recorder);
EXPORT CanvasRef _PictureRecorderBeginRecording(PictureRecorderRef recorder, int x, int y, int width, int height);
EXPORT CanvasRef _PictureRecorderGetRecordingCanvas(PictureRecorderRef recorder);
EXPORT PictureRef _PictureRecorderFinishRecordingAsPicture(PictureRecorderRef recorder);

EXPORT ImageRef _ImageCreate(float width, float height);
EXPORT ImageRef _ImageCreateFromBitmap(BitmapRef bitmap);
EXPORT ImageRef _ImageCreateFromBytes(
  const void* pixel_data,
  uint32_t width,
  uint32_t height,
  int is_image_bitmap_premultiplied,
  int is_image_bitmap_origin_clean,
  int color_type,
  uint8_t primaries,
  uint8_t transfer,
  uint8_t matrix,
  uint8_t range,
  int64_t icc_profile);
EXPORT ImageRef _ImageCreateFrom1xPNGBytes(const unsigned char* input, size_t input_size);
EXPORT void _ImageDestroy(ImageRef handle);
EXPORT void _ImageGetSize(ImageRef handle, float* width, float* height);
EXPORT int _ImageIsEmpty(ImageRef handle);
EXPORT BitmapRef _ImageGetBitmap(ImageRef handle);

EXPORT GrGLInterfaceRef _CreateCommandBufferSkiaGLBinding();
//EXPORT void _GrGLInterfaceSetCallback(GrGLInterfaceRef handle, GrGLInterfaceCallback callback, const void* callbackData);
//EXPORT void* _GrGLInterfaceGetCallbackData(GrGLInterfaceRef handle);

EXPORT RegionRef _RegionCreate();
EXPORT RegionRef _RegionCreateWithRect(int x, int y, int width, int height);
EXPORT void _RegionBounds(RegionRef handle, int* x, int* y, int* width, int* height);
EXPORT int _RegionEmpty(RegionRef handle);
EXPORT void _RegionDestroy(RegionRef handle);
EXPORT int _RegionContains(RegionRef handle, int x, int y);
EXPORT void _RegionSetRect(RegionRef handle, int x, int y, int width, int height);
EXPORT int _RegionSetPath(RegionRef handle, PathRef mask, RegionRef clip);
EXPORT int _RegionUnionRect(RegionRef handle, int x, int y, int width, int height);
EXPORT int _RegionUnionRegion(RegionRef handle, RegionRef other);
EXPORT void _RegionClear(RegionRef handle);
EXPORT PathRef _RegionGetBoundaryPath(RegionRef handle);

EXPORT RegionIteratorRef _RegionIteratorCreate(RegionRef region);
EXPORT void _RegionIteratorDestroy(RegionIteratorRef handle);
EXPORT int _RegionIteratorIsDone(RegionIteratorRef handle);
EXPORT int _RegionIteratorHasRect(RegionIteratorRef handle);
EXPORT void _RegionIteratorGetRect(RegionIteratorRef handle, int* x, int* y, int* width, int* height);
EXPORT void _RegionIteratorNext(RegionIteratorRef handle);

EXPORT MatrixRef _MatrixCreate();
EXPORT void _MatrixDestroy(MatrixRef handle);
EXPORT double _MatrixGet(MatrixRef handle, int index);
EXPORT void _MatrixSet(MatrixRef handle, int index, double value);

EXPORT void _MatrixToIdentity(MatrixRef handle);
EXPORT void _MatrixPreTranslate(MatrixRef handle, double dx, double dy);
EXPORT void _MatrixPostTranslate(MatrixRef handle, double dx, double dy);
EXPORT void _MatrixTranslate(MatrixRef handle, double x, double y);
EXPORT void _MatrixScale(MatrixRef handle, double x, double y);
EXPORT void _MatrixPreScale(MatrixRef handle, double sx, double sy);
EXPORT void _MatrixPostConcat(MatrixRef handle, MatrixRef matrix);
EXPORT void _MatrixPreConcat(MatrixRef handle, MatrixRef matrix);
EXPORT int _MatrixInvert(MatrixRef handle, MatrixRef matrix);
EXPORT int _MatrixEquals(MatrixRef left, MatrixRef right);
EXPORT int _MatrixNotEquals(MatrixRef left, MatrixRef right);
EXPORT int _MatrixRectStaysRect(MatrixRef handle);


EXPORT Matrix44Ref _Matrix44Create(int is_identity);
EXPORT void _Matrix44Destroy(Matrix44Ref handle);
EXPORT double _Matrix44Get(Matrix44Ref handle, int row, int col);
EXPORT double _Matrix44GetDeterminant(Matrix44Ref handle);
EXPORT void _Matrix44Set(Matrix44Ref handle, int row, int col, double value);
EXPORT void _Matrix44SetRotateDegreesAbout(Matrix44Ref reference, double x, double y, double z, double degrees);
EXPORT int _Matrix44IsIdentity(Matrix44Ref handle);
EXPORT int _Matrix44IsScaleTranslate(Matrix44Ref handle);
EXPORT int _Matrix44IsTranslate(Matrix44Ref handle);
EXPORT void _Matrix44ToIdentity(Matrix44Ref handle);
EXPORT void _Matrix44Transpose(Matrix44Ref handle); 
EXPORT void _Matrix44PreTranslate(Matrix44Ref handle, double dx, double dy, double dz);
EXPORT void _Matrix44PreScale(Matrix44Ref handle, double sx, double sy, double sz);
EXPORT void _Matrix44Set3x3(Matrix44Ref reference, 
  double m00, double m10, double m20, 
  double m01, double m11, double m21, 
  double m02, double m12, double m22);
EXPORT void _Matrix44Scale(Matrix44Ref reference, double x, double y, double z);
EXPORT void _Matrix44Translate(Matrix44Ref reference, double x, double y, double z);
EXPORT void _Matrix44PostConcat(Matrix44Ref handle, Matrix44Ref matrix);
EXPORT void _Matrix44PreConcat(Matrix44Ref handle, Matrix44Ref matrix);
EXPORT int _Matrix44Invert(Matrix44Ref handle, Matrix44Ref matrix);
EXPORT void _Matrix44MapRect(Matrix44Ref handle, int* x, int* y, int* width, int* height);
EXPORT void _Matrix44MapRectf(Matrix44Ref handle, float* x, float* y, float* width, float* height);
EXPORT void _Matrix44MapScalars(Matrix44Ref handle, double* x, double* y, double* z, double* w);
EXPORT void _Matrix44MapScalars2(Matrix44Ref handle, 
  double x0, double y0, double z0, double w0, 
  double* x1, double* y1, double* z1, double* w1);
EXPORT Matrix44Ref _Matrix44Multiply(Matrix44Ref left, Matrix44Ref right);
EXPORT int _Matrix44Equals(Matrix44Ref left, Matrix44Ref right);
EXPORT int _Matrix44NotEquals(Matrix44Ref left, Matrix44Ref right);

EXPORT ShaderRef _ShaderCreateEmpty();
EXPORT ShaderRef _ShaderCreateBitmap(BitmapRef bitmap, int xmode, int ymode, MatrixRef localMatrix);
EXPORT ShaderRef _ShaderCreateColor(uint8_t a, uint8_t r, uint8_t g, uint8_t b);
EXPORT ShaderRef _ShaderCreatePicture(PictureRef picture);
EXPORT ShaderRef _ShaderCreateLocalMatrix();
EXPORT ShaderRef _ShaderCreateGradient();
EXPORT void _ShaderDestroy(ShaderRef handle);

EXPORT DrawLooperRef _DrawLooperCreateBlur(uint8_t a, uint8_t r, uint8_t g, uint8_t b, double sigma, double dx, double dy);
EXPORT DrawLooperRef _DrawLooperCreateLayer();
EXPORT void _DrawLooperDestroy(DrawLooperRef handle);
EXPORT DrawLooperBuilderRef _DrawLooperLayerBuilderCreate();
EXPORT void _DrawLooperLayerBuilderDestroy(DrawLooperBuilderRef handle);
EXPORT PaintRef _DrawLooperLayerBuilderAddLayer(DrawLooperBuilderRef handle, int flags, int colormode, int x, int y, int posttrans);
EXPORT void _DrawLooperLayerBuilderAddLayerXY(DrawLooperBuilderRef handle, int x, int y);
EXPORT PaintRef _DrawLooperLayerBuilderAddLayerOnTop(DrawLooperBuilderRef handle, int flags, int colormode, int x, int y, int posttrans);
EXPORT DrawLooperRef _DrawLooperLayerBuilderDetachLooper(DrawLooperBuilderRef handle);

EXPORT TypefaceRef _TypefaceCreate(const char* name, int bold, int italic);
EXPORT void _TypefaceDestroy(TypefaceRef handle);
EXPORT int _TypefaceIsBold(TypefaceRef handle);
EXPORT int _TypefaceIsItalic(TypefaceRef handle);

EXPORT BitmapRef _BitmapCreate(float width, float height);
EXPORT BitmapRef _BitmapCreateButtonBackground(uint8_t a, uint8_t r, uint8_t g, uint8_t b, BitmapRef image, BitmapRef mask);
EXPORT BitmapRef _BitmapCreateBlendedBitmap(BitmapRef first, BitmapRef second, double alpha);
EXPORT void _BitmapDestroy(BitmapRef handle);
EXPORT float _BitmapGetWidth(BitmapRef handle);
EXPORT float _BitmapGetHeight(BitmapRef handle);
EXPORT void _BitmapGetSize(BitmapRef handle, float* width, float* height);
EXPORT int _BitmapIsImmutable(BitmapRef handle);
EXPORT int _BitmapIsEmpty(BitmapRef handle);
EXPORT int _BitmapIsNull(BitmapRef handle);
EXPORT int _BitmapIsDrawable(BitmapRef handle);
EXPORT void _BitmapSetImmutable(BitmapRef handle);
//EXPORT void _BitmapLockPixels(BitmapRef handle);
//EXPORT void _BitmapUnlockPixels(BitmapRef handle);
EXPORT void _BitmapGetColorAtARGB(BitmapRef handle, float x, float y, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b);
EXPORT int _BitmapGetColorAt(BitmapRef handle, float x, float y);
EXPORT void* _BitmapGetBufferAt(BitmapRef handle, float x, float y, size_t* size);
EXPORT void _BitmapEraseARGB(BitmapRef handle, uint8_t a, uint8_t r, uint8_t g, uint8_t b);
EXPORT void _BitmapAllocatePixels(BitmapRef handle, float width, float height);
EXPORT void _BitmapAllocatePixelsAlpha(BitmapRef handle, float width, float height, int alpha_type);
EXPORT BitmapRef _BitmapExtractSubset(BitmapRef handle, float x, float y, float width, float height);

typedef struct {
 void (*CDrawableOnGetBounds)(void* peer, int *x, int *y, int* w, int* h);
 void (*CDrawableOnDraw)(void* peer, CanvasRef canvas);
 PictureRef (*CDrawableOnNewPictureSnapshot)(void* peer);
} CDrawableCallbacks;


EXPORT DrawableRef _DrawableCreate(void* peer, CDrawableCallbacks callbacks);
EXPORT void _DrawableDestroy(DrawableRef handle);
EXPORT uint32_t _DrawableGetGenerationID(DrawableRef handle);
EXPORT void _DrawableGetBounds(DrawableRef handle, int* x, int* y, int* w, int* h);
EXPORT void _DrawableDraw(DrawableRef handle, CanvasRef canvas);
EXPORT void _DrawableDrawAt(DrawableRef handle, CanvasRef canvas,  int x, int y);
EXPORT PictureRef _DrawableNewPictureSnapshot(DrawableRef handle);
EXPORT void _DrawableNotifyDrawingChanged(DrawableRef handle);

EXPORT MaskFilterRef _MaskFilterCreateBlur(double radius, int style, int flags);
//EXPORT MaskFilterRef _MaskFilterCreateEmboss(double sigma, double x, double y, double z, double ambient, double specular);
EXPORT void _MaskFilterDestroy(MaskFilterRef filter);

EXPORT PathEffectRef _PathEffectCreateDash(const float* intervals, int count, float phase);
EXPORT PathEffectRef _PathEffectCreateSum(PathEffectRef first, PathEffectRef second);
EXPORT PathEffectRef _PathEffectCreateCompose(PathEffectRef outer, PathEffectRef inner);
EXPORT void _PathEffectDestroy(PathEffectRef handle);

// PNGCodec
EXPORT unsigned char* _PNGCodecDecodeAsRawBytes(const unsigned char* input, int input_size, int format, int* size, int* width, int* height);
EXPORT BitmapRef _PNGCodecDecodeAsBitmap(const unsigned char* input, int input_size);
EXPORT ImageRef _PNGCodecDecodeAsImage(const unsigned char* input, int input_size);

#endif
