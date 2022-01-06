// Copyright (c) 2015 Mumba. All rights reserved.public var 
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "SkiaShims.h"

#include "CompositorStructsPrivate.h"
#include "PNGCodec.h"

#include "base/logging.h"
#include "base/memory/ref_counted.h"
//#include "base/memory/scoped_ptr.h"
//#include "gpu/GLES2/gl2extchromium.h"
//#include "skia/ext/refptr.h"
//#include "ui/gl/gl_bindings.h"
#include "ui/gl/extension_set.h"
#include "ui/gl/gl_version_info.h"
#include "ui/gl/init/create_gr_gl_interface.h"
#include "ui/gfx/skbitmap_operations.h"
#include "ui/gfx/color_space.h"
#include "cc/paint/paint_text_blob.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkPicture.h"
#include "third_party/skia/include/core/SkRegion.h"
#include "third_party/skia/include/core/SkMatrix.h"
#include "third_party/skia/include/core/SkColor.h"
#include "third_party/skia/include/core/SkPath.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkShader.h"
#include "third_party/skia/include/core/SkTypeface.h"
#include "third_party/skia/include/utils/SkNoDrawCanvas.h"
#include "third_party/skia/include/core/SkDrawFilter.h"
#include "third_party/skia/include/core/SkColorFilter.h"
#include "third_party/skia/include/core/SkDrawLooper.h"
#include "third_party/skia/include/effects/SkBlurDrawLooper.h"
#include "third_party/skia/include/effects/SkLayerDrawLooper.h"
#include "third_party/skia/include/effects/SkBlurMaskFilter.h"
#include "third_party/skia/include/core/SkDrawable.h"
#include "third_party/skia/include/core/SkPathEffect.h"
#include "third_party/skia/include/effects/SkDashPathEffect.h"
#include "third_party/skia/include/core/SkRSXform.h"
//#include "third_party/skia/include/utils/SkMatrix44.h"
#include "third_party/skia/include/core/SkPictureRecorder.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "third_party/skia/include/core/SkImageInfo.h"
//#include "third_party/khronos/GLES2/gl2.h"
//#include "third_party/khronos/GLES2/gl2ext.h"
#include "third_party/skia/include/gpu/gl/GrGLInterface.h"
#include "third_party/libpng/png.h"

namespace {
  const char* kFallbackFontFamilyName = "sans";
}

// class SkiaNoDrawCanvas {
// public:
//  SkiaNoDrawCanvas(int width, int height): skcanvas_(new SkNoDrawCanvas(width, height)) {}
 
//  SkiaNoDrawCanvas(SkNoDrawCanvas* canvas): skcanvas_(canvas) {
//  }

//  ~SkiaNoDrawCanvas(){}

//  SkNoDrawCanvas* handle() const { return skcanvas_.get(); }

// private:

//  std::unique_ptr<SkNoDrawCanvas> skcanvas_;

//  DISALLOW_COPY_AND_ASSIGN(SkiaNoDrawCanvas);
// };


// Canvas
CanvasRef _CanvasCreate() {
  return new SkiaCanvas();
}

CanvasRef _CanvasCreateWithBitmap(BitmapRef bitmap) {
  return new SkiaCanvas(reinterpret_cast<SkBitmap *>(bitmap));
}

void _CanvasDestroy(CanvasRef canvas) {
  delete reinterpret_cast<SkiaCanvas *>(canvas);
}

void _CanvasFlush(CanvasRef canvas) {
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->flush();
}

int _CanvasSave(CanvasRef canvas) {
  return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->save();
}

void _CanvasRestore(CanvasRef canvas) {
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->restore();
}

void _CanvasRestoreToCount(CanvasRef canvas, int count) {
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->restoreToCount(count);
}

int _CanvasSaveLayer(CanvasRef canvas, PaintRef paint) {
  return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->saveLayer(nullptr, reinterpret_cast<SkPaint *>(paint));
}

int _CanvasSaveLayerRect(CanvasRef canvas, float x, float y, float width, float height, PaintRef paint) {
 SkRect r = SkRect::MakeXYWH(x, y, width, height);
 return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->saveLayer(&r, reinterpret_cast<SkPaint *>(paint));
}

int _CanvasSaveLayerAlpha(CanvasRef canvas, uint8_t alpha) {
 return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->saveLayerAlpha(nullptr, alpha);
}

int _CanvasSaveLayerAlphaRect(CanvasRef canvas, uint8_t alpha, float x, float y, float width, float height) {
 SkRect r = SkRect::MakeXYWH(x, y, width, height);
 return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->saveLayerAlpha(&r, alpha);
}

int _CanvasSaveLayerPreserveLCDTextRequests(CanvasRef canvas, PaintRef paint) {
  return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->saveLayerPreserveLCDTextRequests(nullptr, reinterpret_cast<SkPaint *>(paint));
}

int _CanvasSaveLayerPreserveLCDTextRequestsRect(CanvasRef canvas, float x, float y, float width, float height, PaintRef paint) {
  SkRect r = SkRect::MakeXYWH(x, y, width, height);
  return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->saveLayerPreserveLCDTextRequests(&r, reinterpret_cast<SkPaint *>(paint));
}

int _CanvasGetSaveCount(CanvasRef canvas) {
 return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->getSaveCount();
}

void _CanvasTranslate(CanvasRef canvas, float dx, float dy) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->translate(dx, dy);
}

void _CanvasScale(CanvasRef canvas, float sx, float sy) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->scale(sx, sy);
}

void _CanvasRotate(CanvasRef canvas, float degrees) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->rotate(degrees);
}

void _CanvasSkew(CanvasRef canvas, float sx, float sy) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->skew(sx, sy);
}

void _CanvasConcat(CanvasRef canvas,
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2) {

  SkMatrix mat;
  mat.setAll(scale_x, skew_x, trans_x, skew_y, scale_y, trans_y, persp0, persp1, persp2);
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->concat(mat);
}

void _CanvasSetMatrix(CanvasRef canvas,
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2) {
  SkMatrix mat;
  mat.setAll(scale_x, skew_x, trans_x, skew_y, scale_y, trans_y, persp0, persp1, persp2);
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->setMatrix(mat);
}

void _CanvasConcatHandle(CanvasRef canvas, MatrixRef matrix) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->concat(*reinterpret_cast<SkMatrix *>(matrix));
}

void _CanvasConcatHandle44(CanvasRef canvas, Matrix44Ref matrix) {
 SkMatrix44 * ptr = reinterpret_cast<SkMatrix44 *>(matrix);  
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->concat(*ptr);
}

void _CanvasSetMatrixHandle(CanvasRef canvas, MatrixRef matrix) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->setMatrix(*reinterpret_cast<SkMatrix *>(matrix)); 
}

MatrixRef _CanvasTotalMatrix(CanvasRef canvas) {
 return const_cast<SkMatrix *>(&reinterpret_cast<SkiaCanvas *>(canvas)->handle()->getTotalMatrix());
}

int _CanvasIsClipEmpty(CanvasRef canvas) {
  return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->isClipEmpty() ? 1 : 0;
}

int _CanvasIsClipRect(CanvasRef canvas) {
  return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->isClipRect() ? 1 : 0;
}

void _CanvasClipRect(CanvasRef canvas, float x, float y, float width, float height, int clip_op, int anti_alias) {
 SkRect r = SkRect::MakeXYWH(x, y, width, height);
 SkClipOp op = static_cast<SkClipOp>(clip_op);
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->clipRect(r, op, anti_alias == 1 ? true : false);
}

void _CanvasClipRRect(CanvasRef canvas, float x, float y, float width, float height, int clip_op, int anti_alias) {
 SkRRect r = SkRRect::MakeRect(SkRect::MakeXYWH(x, y, width, height));
 SkClipOp op = static_cast<SkClipOp>(clip_op);
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->clipRRect(r, op, anti_alias == 1 ? true : false);
}

void _CanvasClipPath(CanvasRef canvas, PathRef path, int clip_op, int anti_alias) {
 SkClipOp op = static_cast<SkClipOp>(clip_op);
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->clipPath(reinterpret_cast<SkiaPath *>(path)->ref(), op, anti_alias == 1 ? true : false);
}

int _CanvasGetLocalClipBounds(CanvasRef canvas, float* x, float* y, float* width, float* height) {
 SkRect r = SkRect::MakeEmpty();
 if (reinterpret_cast<SkiaCanvas *>(canvas)->handle()->getLocalClipBounds(&r)) {
   *x = r.x();
   *y = r.y();
   *width = r.width();
   *height = r.height();
   return 1;
 }
 return 0;
}

int _CanvasGetDeviceClipBounds(CanvasRef canvas, int* x, int* y, int* width, int* height) {
 SkIRect r = SkIRect::MakeEmpty();
 if (reinterpret_cast<SkiaCanvas *>(canvas)->handle()->getDeviceClipBounds(&r)) {
   *x = r.x();
   *y = r.y();
   *width = r.width();
   *height = r.height();
   return 1;
 }
 return 0;
}

void _CanvasGetDeviceSize(CanvasRef canvas, float* width, float* height) {
  SkISize size = reinterpret_cast<SkiaCanvas *>(canvas)->handle()->getBaseLayerSize();
  *width = size.width();
  *height = size.height();
}

int _CanvasReadPixelsXY(CanvasRef canvas, BitmapRef bitmap, int x, int y) {
  SkBitmap* bitmap_handle = reinterpret_cast<SkBitmap *>(bitmap);
  return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->readPixels(*bitmap_handle, x, y) ? 1 : 0;
}

// int _CanvasReadPixelsRect(CanvasRef canvas, BitmapRef bitmap, int x, int y, int width, int height) {
//   SkBitmap* bitmap_handle = reinterpret_cast<SkBitmap *>(bitmap);
//   return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->readPixels(SkIRect::MakeXYWH(x, y, width, height), *bitmap_handle) ? 1 : 0; 
// }

int _CanvasWritePixels(CanvasRef canvas, BitmapRef bitmap, int x, int y) {
  return reinterpret_cast<SkiaCanvas *>(canvas)->handle()->writePixels(*reinterpret_cast<SkBitmap *>(bitmap), x, y) ? 1 : 0;
}

void _CanvasDrawColor(CanvasRef canvas, uint8_t a, uint8_t r, uint8_t g, uint8_t b, int mode) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawColor(SkColorSetARGB(a, r, g, b));
}

void _CanvasDrawLine(CanvasRef canvas, float sx, float sy, float dx, float dy, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawLine(sx, sy, dx, dy, *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawPaint(CanvasRef canvas, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawPaint(*reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawRect(CanvasRef canvas, float x, float y, float width, float height, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawRect(SkRect::MakeXYWH(x, y, width, height), *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawIRect(CanvasRef canvas, int x, int y, int width, int height, PaintRef paint) {
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawIRect(SkIRect::MakeXYWH(x, y, width, height), *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawRegion(CanvasRef canvas, RegionRef region, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawRegion(*reinterpret_cast<SkRegion *>(region), *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawRoundRect(CanvasRef canvas, float x, float y, float width, float height, float rx, float ry, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawRoundRect(SkRect::MakeXYWH(x, y, width, height), rx, ry, *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawRRect(CanvasRef canvas, float x, float y, float width, float height, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawRRect(SkRRect::MakeRect(SkRect::MakeXYWH(x, y, width, height)), *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawDRRect(CanvasRef canvas, float ox, float oy, float ow, float oh, float ix, float iy, float iw, float ih, PaintRef paint) {
 SkRRect outer = SkRRect::MakeRect(SkRect::MakeXYWH(ox, oy, ow, oh));
 SkRRect inner = SkRRect::MakeRect(SkRect::MakeXYWH(ix, iy, iw, ih));
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawDRRect(outer, inner, *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawOval(CanvasRef canvas, float x, float y, float width, float height, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawOval(SkRect::MakeXYWH(x, y, width, height), *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawCircle(CanvasRef canvas, float x, float y, float radius, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawCircle(x, y, radius, *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawPath(CanvasRef canvas, PathRef path, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawPath(reinterpret_cast<SkiaPath *>(path)->ref(), *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawImage(CanvasRef canvas, ImageRef image, float x, float y, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawImage(reinterpret_cast<SkiaImage *>(image)->handle(), x, y, reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawImageRect(CanvasRef canvas, ImageRef image, float sx, float sy, float sw, float sh, float dx, float dy, float dw, float dh, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawImageRect(reinterpret_cast<SkiaImage *>(image)->handle(), SkRect::MakeXYWH(sx, sy, sw, sh), SkRect::MakeXYWH(dx, dy, dw, dh), reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawImageNine(CanvasRef canvas, ImageRef image, float cx, float cy, float cw, float ch, float dx, float dy, float dw, float dh, PaintRef paint) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawImageNine(reinterpret_cast<SkiaImage *>(image)->handle(), SkIRect::MakeXYWH(cx, cy, cw, ch), SkRect::MakeXYWH(dx, dy, dw, dh), reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawPicture(CanvasRef canvas, PictureRef picture) {
 sk_sp<SkPicture> pic = reinterpret_cast<SkiaPicture *>(picture)->handle(); 
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawPicture(pic);
}

void _CanvasDrawDrawable(CanvasRef canvas, DrawableRef drawable) {
 reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawDrawable(reinterpret_cast<SkDrawable *>(drawable));
}

void _CanvasDrawDrawableAt(CanvasRef canvas, DrawableRef drawable, float x, float y) {
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawDrawable(reinterpret_cast<SkDrawable *>(drawable), x, y);
}

void _CanvasDrawVertices(CanvasRef canvas, 
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
  PaintRef paint) {
  
  //std::vector<gfx::PointF> tex;
  //std::vector<SkColor> colors_arr;
  //std::vector<int> idx;
  SkPoint positions[count];
  SkPoint textures[count];
  SkColor colors_arr[count];
  uint16_t indices_arr[indices_count];

  for (int i = 0; i < count; ++i) {
    positions[i] = SkPoint{vx[i], vy[i]};
    textures[i] = SkPoint{tx[i], ty[i]};
    colors_arr[i] = static_cast<SkColor>(colors[i]);
  }

  for (int i = 0; i < indices_count; ++i) {
    indices_arr[i] = static_cast<uint16_t>(indices[i]);
  }

  sk_sp<SkVertices> vertices = SkVertices::MakeCopy(
    static_cast<SkVertices::VertexMode>(vertex_mode), 
    count,
    positions,
    textures,
    colors_arr,
    indices_count,
    indices_arr);

  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawVertices(
    vertices,
    static_cast<SkBlendMode>(blend_mode),
    *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawAtlas(CanvasRef canvas,
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
    PaintRef paint) {

  SkRect textures[count];
  SkColor colors_arr[count];
  SkRSXform xform[count];
  SkRect cull{cull_x, cull_y, cull_w, cull_h};

  for (int i = 0; i < count; i++) {
    textures[i] = SkRect{rx[i], ry[i], rw[i], rh[i]};
    colors_arr[i] = colors[i];
    xform[i] = SkRSXform::MakeFromRadians(transform_scale[i], transform_radians[i], transform_tx[i], transform_ty[i],
                                       transform_ax[i], transform_ay[i]);
  }

  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawAtlas(
    reinterpret_cast<SkiaImage *>(atlas)->handle(),
    xform,
    textures,
    colors_arr,
    count,
    static_cast<SkBlendMode>(blend_mode),
    &cull,
    reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawText(CanvasRef canvas, const void* ptr, size_t count, float x, float y, PaintRef paint) {
  //DLOG(INFO) << "_CanvasDrawText (skia)";
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawText(ptr, count, x, y, *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawPosText(CanvasRef canvas, const void* ptr, size_t count, const float* x, const float* y, int plen, PaintRef paint) {
  //DLOG(INFO) << "_CanvasDrawPosText (skia)";
  std::unique_ptr<SkPoint[]> pos(new SkPoint[plen]);
  for (int i = 0; i < plen; ++i) {
    pos[i] = SkPoint::Make(x[i], y[i]);
  }
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawPosText(ptr, count, &(pos.get()[0]), *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawTextBlob(CanvasRef canvas, PaintTextBlobRef text_blob, float x, float y, PaintRef paint) {
  //DLOG(INFO) << "_CanvasDrawTextBlob (skia)";
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawTextBlob(
    reinterpret_cast<PaintTextBlob *>(text_blob)->handle()->ToSkTextBlob(), 
    x,
    y,
    *reinterpret_cast<SkPaint *>(paint));
}

void _CanvasDrawBitmap(CanvasRef canvas, BitmapRef bitmap, float left, float top, PaintRef paint) {
  const SkPaint* skpaint = (paint == nullptr) ? nullptr : reinterpret_cast<const SkPaint *>(paint);
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawBitmap(*reinterpret_cast<SkBitmap *>(bitmap), SkIntToScalar(left), SkIntToScalar(top), skpaint);
}

void _CanvasDrawBitmapRectSrcDst(CanvasRef canvas, BitmapRef bitmap, float sx, float sy, float sw, float sh, float dx, float dy, float dw, float dh, PaintRef paint) {
  const SkPaint* skpaint = (paint == nullptr) ? nullptr : reinterpret_cast<const SkPaint *>(paint);
  SkRect src = SkRect::MakeXYWH(sx, sy, sw, sh);
  SkRect dst = SkRect::MakeXYWH(dx, dy, dw, dh);
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawBitmapRect(*reinterpret_cast<SkBitmap *>(bitmap), src, dst, skpaint);
}

void _CanvasDrawBitmapRectDst(CanvasRef canvas, BitmapRef bitmap, float dx, float dy, float dw, float dh, PaintRef paint) {
  const SkPaint* skpaint = (paint == nullptr) ? nullptr : reinterpret_cast<const SkPaint *>(paint);
  SkRect dst = SkRect::MakeXYWH(dx, dy, dw, dh);
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawBitmapRect(*reinterpret_cast<SkBitmap *>(bitmap), dst, skpaint);
}

void _CanvasDrawBitmapNine(CanvasRef canvas, BitmapRef bitmap, float cx, float cy, float cw, float ch, float dx, float dy, float dw, float dh, PaintRef paint) {
  SkIRect center = SkIRect::MakeXYWH(cx, cy, cw, ch);
  SkRect dst = SkRect::MakeXYWH(dx, dy, dw, dh);
  const SkPaint* skpaint = (paint == nullptr) ? nullptr : reinterpret_cast<const SkPaint *>(paint);
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawBitmapNine(*reinterpret_cast<SkBitmap *>(bitmap), center, dst, skpaint);
}

// void _CanvasSetDrawFilter(CanvasRef canvas, DrawFilterRef filter) {
//  auto* filter_handle = reinterpret_cast<SkiaDrawFilter *>(filter)->handle(); 
//  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->setDrawFilter(filter_handle);
// }

// DrawFilterRef _CanvasGetDrawFilter(CanvasRef canvas) {
//   sk_sp<SkDrawFilter> filter = reinterpret_cast<SkiaCanvas *>(canvas)->handle()->getDrawFilter();
//   return new SkiaDrawFilter(filter.Pass());
// }

CanvasRef _NoDrawCanvasCreate(int width, int height) {
  SkNoDrawCanvas* handle = new SkNoDrawCanvas(width, height);
  return new SkiaCanvas(handle);
}

void _NoDrawCanvasResetCanvas(CanvasRef canvas, int width, int height) {
  reinterpret_cast<SkNoDrawCanvas*>(reinterpret_cast<SkiaCanvas*>(canvas)->handle())->resetCanvas(width, height);
}

// void _NoDrawCanvasDestroy(NoDrawCanvasRef canvas) {
//   delete reinterpret_cast<SkiaNoDrawCanvas*>(canvas);
// }

// Paint
PaintRef _PaintCreate() {
 return new SkPaint();
}

PaintRef _PaintCreateFromOther(PaintRef paint) {
 return new SkPaint(*reinterpret_cast<SkPaint *>(paint));
}

void _PaintDestroy(PaintRef paint) {
 delete reinterpret_cast<SkPaint *>(paint);
}

void _PaintGetColor(PaintRef paint, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b) {
 SkColor color = reinterpret_cast<SkPaint *>(paint)->getColor();
 *a = SkColorGetA(color);
 *r = SkColorGetR(color);
 *g = SkColorGetG(color);
 *b = SkColorGetB(color);
}

void _PaintSetColor(PaintRef paint, uint8_t a, uint8_t r, uint8_t g, uint8_t b) {
 reinterpret_cast<SkPaint *>(paint)->setColor(SkColorSetARGB(a, r, g, b));
}

uint8_t _PaintGetAlpha(PaintRef handle) {
 return reinterpret_cast<SkPaint *>(handle)->getAlpha(); 
}

void _PaintSetAlpha(PaintRef handle, uint8_t a) {
 reinterpret_cast<SkPaint *>(handle)->setAlpha(a);
}

uint32_t _PaintGetStyle(PaintRef paint) {
 uint32_t out = 0;
 SkPaint::Style style = reinterpret_cast<SkPaint *>(paint)->getStyle();
 switch (style) {
  case SkPaint::kFill_Style:
   out = 0;
   break;
  case SkPaint::kStroke_Style:
   out = 1;
   break;
  case SkPaint::kStrokeAndFill_Style:
   out = 2;
   break;
  default:
   out = 0; 
 }
 return out;
}

void _PaintSetStyle(PaintRef paint, uint32_t style) {
 SkPaint::Style instyle;
 
 switch (style) {
  case 0:
   instyle = SkPaint::kFill_Style;
   break;
  case 1:
   instyle = SkPaint::kStroke_Style;
   break;
  case 2:
   instyle = SkPaint::kStrokeAndFill_Style;
   break;
  default:
   instyle = SkPaint::kFill_Style; 
 }

 reinterpret_cast<SkPaint *>(paint)->setStyle(instyle);
}

int _PaintIsAntiAlias(PaintRef paint) {
  return reinterpret_cast<SkPaint *>(paint)->isAntiAlias();
}

void _PaintSetAntiAlias(PaintRef paint, int antialias) {
  reinterpret_cast<SkPaint *>(paint)->setAntiAlias(antialias > 0 ? true : false);
}

uint32_t _PaintGetBlend(PaintRef paint) {
 //SkXfermode::Mode mode;
 SkBlendMode blend = reinterpret_cast<SkPaint *>(paint)->getBlendMode();
 //blend->asMode(&mode);
 return static_cast<uint32_t>(blend);
}

void _PaintSetBlend(PaintRef paint, uint32_t blendmode) {
 //SkBlendMode mode;
//  switch (blendmode) {
//    case 0:
//     mode = SkBlendMode::kClear;
//     break;
//    case 1:
//     mode = SkBlendMode::kSrc;
//     break;
//    case 2:
//     mode = SkBlendMode::kDst;
//     break;
//    case 3:
//     mode = SkBlendMode::kSrcOver;
//     break;
//    case 4:
//     mode = SkBlendMode::kDstOver;
//     break;
//    case 5:
//     mode = SkBlendMode::kSrcIn;
//     break;
//    case 6:
//     mode = SkBlendMode::kDstIn;
//     break;
//    case 7:
//     mode = SkBlendMode::kSrcOut;
//     break;
//    case 8:
//     mode = SkBlendMode::kDstOut;
//     break;
//    case 9:
//     mode = SkBlendMode::kSrcATop;
//     break;
//    case 10:
//     mode = SkBlendMode::kDstATop;
//     break;
//    case 11:
//     mode = SkBlendMode::kXor;
//     break;
//    case 12:
//     mode = SkBlendMode::kPlus;
//     break;
//    case 13:
//     mode = SkBlendMode::kModulate;
//     break;
//    case 14:
//     mode = SkBlendMode::kScreen;
//     break;
//    case 15:
//     mode = SkBlendMode::kOverlay;
//     break;
//    case 16:
//     mode = SkBlendMode::kDarken;
//     break;
//    case 17:
//     mode = SkBlendMode::kLighten;
//     break;
//    case 18:
//     mode = SkBlendMode::kColorDodge;
//     break;
//    case 19:
//     mode = SkBlendMode::kColorBurn;
//     break;
//    case 20:
//     mode = SkBlendMode::kHardLight;
//     break;
//    case 21:
//     mode = SkBlendMode::kSoftLight;
//     break;
//    case 22:
//     mode = SkBlendMode::kDifference;
//     break;
//    case 23: 
//     mode = SkBlendMode::kExclusion;
//     break;
//    case 24:
//     mode = SkBlendMode::kMultiply;
//     break;
//    case 25:
//     mode = SkBlendMode::kHue;
//     break;
//    case 26:
//     mode = SkBlendMode::kSaturation;
//     break;
//    case 27:
//     mode = SkBlendMode::kColor;
//     break;
//    case 28:
//     mode = SkBlendMode::kLuminosity;
//     break;
//    default:
//     mode = SkBlendMode::kSrcOver;
//  }
 reinterpret_cast<SkPaint *>(paint)->setBlendMode(static_cast<SkBlendMode>(blendmode));
}

int _PaintGetTextSize(PaintRef paint) {
  return reinterpret_cast<SkPaint *>(paint)->getTextSize();
}

void _PaintSetTextSize(PaintRef paint, int size) {
 reinterpret_cast<SkPaint *>(paint)->setTextSize(size);
}

ShaderRef _PaintGetShader(PaintRef paint) {
  // TODO: giving this is a reference to a existing-owned object, this is extremely inneficient
  // maybe if we try to cache it somehow so subsequent calls to the same object would
  // not mean a new heap allocation everytime
  SkShader* shader = reinterpret_cast<SkPaint *>(paint)->getShader();
  return new SkiaShader(shader);
}

void _PaintSetShader(PaintRef paint, ShaderRef shader) {
  reinterpret_cast<SkPaint *>(paint)->setShader(reinterpret_cast<SkiaShader *>(shader)->own());
}

DrawLooperRef _PaintGetDrawLooper(PaintRef paint) {
  // TODO: giving this is a reference to a existing-owned object, this is extremely inneficient
  // maybe if we try to cache it somehow so subsequent calls to the same object would
  // not mean a new heap allocation everytime
  //sk_sp<SkDrawLooper> drawlooper = reinterpret_cast<SkPaint *>(paint)->getLooper();
  return new SkiaDrawLooper(reinterpret_cast<SkPaint *>(paint)->getLooper());//std::move(drawlooper));
}

void _PaintSetDrawLooper(PaintRef paint, DrawLooperRef looper) {
  //auto* looper_handle = reinterpret_cast<SkiaDrawLooper *>(looper)->handle();
  reinterpret_cast<SkPaint *>(paint)->setLooper(reinterpret_cast<SkiaDrawLooper *>(looper)->own());
}

TypefaceRef _PaintGetTypeface(PaintRef paint) {
  // TODO: giving this is a reference to a existing-owned object, this is extremely inneficient
  // maybe if we try to cache it somehow so subsequent calls to the same object would
  // not mean a new heap allocation everytime
  SkTypeface* typeface = reinterpret_cast<SkPaint *>(paint)->getTypeface();
  return new SkiaTypeface(typeface);
}

void _PaintSetTypeface(PaintRef paint, TypefaceRef typeface) {
 // SkTypeface* skia_typeface = reinterpret_cast<SkiaTypeface *>(typeface)->handle();
  reinterpret_cast<SkPaint *>(paint)->setTypeface(reinterpret_cast<SkiaTypeface *>(typeface)->own());
}

int _PaintGetStrokeWidth(PaintRef paint) {
  return reinterpret_cast<SkPaint *>(paint)->getStrokeWidth();
}

void _PaintSetStrokeWidth(PaintRef paint, int width) {
  reinterpret_cast<SkPaint *>(paint)->setStrokeWidth(width);
}

int _PaintIsFakeBoldText(PaintRef paint) {
  return reinterpret_cast<SkPaint *>(paint)->isFakeBoldText() ? 1 : 0;
}

void _PaintSetIsFakeBoldText(PaintRef paint, int fake) {
  reinterpret_cast<SkPaint *>(paint)->setFakeBoldText(fake == 0 ? false : true);
}

uint32_t _PaintGetFilterQuality(PaintRef paint) {
  uint32_t out = 0;
  SkFilterQuality quality = reinterpret_cast<SkPaint *>(paint)->getFilterQuality();
  switch (quality) {
    case kNone_SkFilterQuality:
      out = 0;
      break;
    case kLow_SkFilterQuality:
      out = 1;
      break;
    case kMedium_SkFilterQuality:
      out = 2;
      break;
    case kHigh_SkFilterQuality:
      out = 3;
      break;  
    default:
      out = 0; 
  }
  return out;
}

void _PaintSetFilterQuality(PaintRef paint, uint32_t quality) {
  SkFilterQuality out = kNone_SkFilterQuality;
  switch (quality) {
    case 0:
      out = kNone_SkFilterQuality;
      break;
    case 1:
      out = kLow_SkFilterQuality;
      break;
    case 2:
      out = kMedium_SkFilterQuality;
      break;
    case 3:
      out = kHigh_SkFilterQuality;
      break;  
    default:
      out = kNone_SkFilterQuality;
  }
  reinterpret_cast<SkPaint *>(paint)->setFilterQuality(out);
}

int _PaintIsSubpixelText(PaintRef paint) {
  return reinterpret_cast<SkPaint *>(paint)->isSubpixelText() ? 1 : 0;
}

void _PaintSetIsSubpixelText(PaintRef paint, int subpixel) {
  reinterpret_cast<SkPaint *>(paint)->setSubpixelText(subpixel == 0 ? false : true);
}

int _PaintIsLCDRenderText(PaintRef paint) {
  return reinterpret_cast<SkPaint *>(paint)->isLCDRenderText() ? 1 : 0;
}

void _PaintSetIsLCDRenderText(PaintRef paint, int lcd) {
  reinterpret_cast<SkPaint *>(paint)->setLCDRenderText(lcd == 0 ? false : true);
}

uint32_t _PaintGetHinting(PaintRef paint) {
  return reinterpret_cast<SkPaint *>(paint)->getHinting();
}

void _PaintSetHinting(PaintRef paint, uint32_t hinting) {
  SkPaint::Hinting hintingMode;

  switch (hinting) {
    case 0:
       hintingMode = SkPaint::kNo_Hinting;
      break;
    case 1:
       hintingMode = SkPaint::kSlight_Hinting;
      break;
    case 2:
      hintingMode = SkPaint::kNormal_Hinting;
      break;
    case 3:
      hintingMode = SkPaint::kFull_Hinting;
      break;
    default:
      hintingMode = SkPaint::kNormal_Hinting;
  }

  reinterpret_cast<SkPaint *>(paint)->setHinting(hintingMode);
}

uint32_t _PaintGetTextEncoding(PaintRef paint) {
  return reinterpret_cast<SkPaint *>(paint)->getTextEncoding();
}

void _PaintSetTextEncoding(PaintRef paint, uint32_t encoding) {
  SkPaint::TextEncoding textEncoding;
  switch (encoding) {
    case 0:
      textEncoding = SkPaint::kUTF8_TextEncoding;
      break;
    case 1:
      textEncoding = SkPaint::kUTF16_TextEncoding;
      break;
    case 2:
      textEncoding = SkPaint::kUTF32_TextEncoding;
      break;
    case 3:
      textEncoding = SkPaint::kGlyphID_TextEncoding;
      break;
    default:
      textEncoding = SkPaint::SkPaint::kUTF8_TextEncoding;
  }

  reinterpret_cast<SkPaint *>(paint)->setTextEncoding(textEncoding);
}

int _PaintIsAutoHinted(PaintRef paint) {
  return reinterpret_cast<SkPaint *>(paint)->isAutohinted() ? 1 : 0;
}

void _PaintSetIsAutoHinted(PaintRef paint, int autohinted) {
  reinterpret_cast<SkPaint *>(paint)->setAutohinted(autohinted == 0 ? false : true);
}

MaskFilterRef _PaintGetMaskFilter(PaintRef paint) {
  SkMaskFilter* maskfilter = reinterpret_cast<SkPaint *>(paint)->getMaskFilter();
  // TODO: giving this is a reference to a existing-owned object, this is extremely inneficient
  // maybe if we try to cache it somehow so subsequent calls to the same object would
  // not mean a new heap allocation everytime
  return new SkiaMaskFilter(maskfilter);
}

void _PaintSetMaskFilter(PaintRef paint, MaskFilterRef filter) {
  reinterpret_cast<SkPaint *>(paint)->setMaskFilter(reinterpret_cast<SkiaMaskFilter *>(filter)->own());
}

ColorFilterRef _PaintGetColorFilter(PaintRef paint) {
  SkColorFilter* colorfilter = reinterpret_cast<SkPaint *>(paint)->getColorFilter();
  // TODO: giving this is a reference to a existing-owned object, this is extremely inneficient
  // maybe if we try to cache it somehow so subsequent calls to the same object would
  // not mean a new heap allocation everytime
  return new SkiaColorFilter(colorfilter);
}

void _PaintSetColorFilter(PaintRef paint, ColorFilterRef filter) {
  reinterpret_cast<SkPaint *>(paint)->setColorFilter(reinterpret_cast<SkiaColorFilter *>(filter)->own());
}

// Path

PathRef _PathCreate() {
	return new SkiaPath();
}

void _PathDestroy(PathRef path) {
  delete reinterpret_cast<SkiaPath *>(path);
}

void _PathSetFillType(PathRef path, int type) {
  SkPath::FillType fill;
  switch (type) {
      case 0:
        fill = SkPath::kWinding_FillType;
        break;
      case 1:
        fill = SkPath::kEvenOdd_FillType;
        break;
      case 2:
        fill = SkPath::kInverseWinding_FillType;
        break;
      case 3:
        fill = SkPath::kInverseEvenOdd_FillType;
        break;
      default:   
        fill = SkPath::kWinding_FillType;
  }   
  reinterpret_cast<SkiaPath *>(path)->handle()->setFillType(static_cast<SkPath::FillType>(fill));
}

int _PathGetFillType(PathRef path) {
  return reinterpret_cast<SkiaPath *>(path)->handle()->getFillType();
}

int _PathIsInverseFillType(PathRef path) {
  return reinterpret_cast<SkiaPath *>(path)->handle()->isInverseFillType();
}

int _PathIsEmpty(PathRef path) {
  return reinterpret_cast<SkiaPath *>(path)->handle()->isEmpty();
}

int _PathIsRect(PathRef path, float x, float y, float width, float height) {
  SkRect r = SkRect::MakeXYWH(x, y, width, height);
  return reinterpret_cast<SkiaPath *>(path)->handle()->isRect(&r);
}

int _PathIsOval(PathRef path, float x, float y, float width, float height) {
  SkRect r = SkRect::MakeXYWH(x, y, width, height);
  return reinterpret_cast<SkiaPath *>(path)->handle()->isOval(&r);
}

int _PathIsRRect(PathRef path, float x, float y, float width, float height) {
  SkRect r = SkRect::MakeXYWH(x, y, width, height);
  SkRRect rr;
  rr.setRect(r);
  return reinterpret_cast<SkiaPath *>(path)->handle()->isRRect(&rr);
}

void _PathMoveTo(PathRef path, float x, float y) {
  reinterpret_cast<SkiaPath *>(path)->handle()->moveTo(x, y);
}

void _PathLineTo(PathRef path, float x, float y) {
  reinterpret_cast<SkiaPath *>(path)->handle()->lineTo(x, y);
}

void _PathArcTo(PathRef path, float x, float y, float width, float height, double start_angle, double sweep_angle, int force_move_to) {
  SkRect r = SkRect::MakeXYWH(x, y, width, height);
  reinterpret_cast<SkiaPath *>(path)->handle()->arcTo(r, start_angle, sweep_angle, force_move_to);
}

void _PathAddRect(PathRef path, float x, float y, float width, float height, int direction) {
  SkPath::Direction dir = (direction == 0 ? SkPath::kCW_Direction : SkPath::kCCW_Direction); 
  SkRect r = SkRect::MakeXYWH(x, y, width, height);
  reinterpret_cast<SkiaPath *>(path)->handle()->addRect(r, dir);
}

void _PathAddRoundRect(PathRef path, float x, float y, float width, float height, float rx, float ry, int direction) {
  SkPath::Direction dir = (direction == 0 ? SkPath::kCW_Direction : SkPath::kCCW_Direction); 
  SkRect r = SkRect::MakeXYWH(x, y, width, height);
  reinterpret_cast<SkiaPath *>(path)->handle()->addRoundRect(r, rx, ry, dir);
}

void _PathAddOval(PathRef path, float x, float y, float width, float height) {
  SkRect r = SkRect::MakeXYWH(x, y, width, height);
  reinterpret_cast<SkiaPath *>(path)->handle()->addOval(r);
}

void _PathAddPath(PathRef path, PathRef other, float x, float y) {
  reinterpret_cast<SkiaPath *>(path)->handle()->addPath(reinterpret_cast<SkiaPath *>(other)->ref(), x, y);
}

void _PathClose(PathRef path) {
  reinterpret_cast<SkiaPath *>(path)->handle()->close();
}

void _PathReset(PathRef path) {
  reinterpret_cast<SkiaPath *>(path)->handle()->reset();
}

int _PathCountPoints(PathRef path) {
 return reinterpret_cast<SkiaPath *>(path)->handle()->countPoints();
}

int _PathGetPoint(PathRef path, int index, float* x, float*y) {
  SkPoint p = reinterpret_cast<SkiaPath *>(path)->handle()->getPoint(index);
  if (p.isZero()) {
   return 0;
  }
  *x = p.fX;
  *y = p.fY;
  return 1;
}

void _PathTransformMatrix44(PathRef path, Matrix44Ref mat, PathRef dest) {
  reinterpret_cast<SkiaPath *>(path)->handle()->transform(*reinterpret_cast<SkMatrix44 *>(mat), reinterpret_cast<SkiaPath *>(dest)->handle());
}

void _PathTransformMatrix(PathRef path, MatrixRef mat) {
  reinterpret_cast<SkiaPath *>(path)->handle()->transform(*reinterpret_cast<SkMatrix *>(mat));
}

PictureRef _PictureCreate() {
  LOG(ERROR) << "CALLING UNIMPLEMENTED _PictureCreate";
  return nullptr;
}

int _PictureSuitableForGpuRasterization(PictureRef picture, GrContextRef context) {
  LOG(ERROR) << "CALLING UNIMPLEMENTED _PictureSuitableForGpuRasterization";
  return 0;
}

int _PictureApproximateOpCount(PictureRef picture) {
  LOG(ERROR) << "CALLING UNIMPLEMENTED _PictureApproximateOpCount";
  return 0;
}

size_t _PictureApproximateBytesUsed(PictureRef picture) {
  LOG(ERROR) << "CALLING UNIMPLEMENTED _PictureApproximateBytesUsed";
  return 0;
}

void _PictureDestroy(PictureRef picture) {
  delete reinterpret_cast<SkiaPicture *>(picture);
}

int _PictureGetWidth(PictureRef picture) {
  SkRect rect = reinterpret_cast<SkiaPicture *>(picture)->handle()->cullRect();
  return rect.width();
}

int _PictureGetHeight(PictureRef picture) {
  SkRect rect = reinterpret_cast<SkiaPicture *>(picture)->handle()->cullRect();
  return rect.height();
}

void _PictureGetBounds(PictureRef picture, int* x, int* y, int* w, int* h) {
  SkRect rect = reinterpret_cast<SkiaPicture *>(picture)->handle()->cullRect();
  *x = rect.x();
  *y = rect.y();
  *w = rect.width();
  *h = rect.height();
}

void _PictureDraw(PictureRef picture, CanvasRef canvas) {
  sk_sp<SkPicture> pic = reinterpret_cast<SkiaPicture *>(picture)->handle(); 
  reinterpret_cast<SkiaCanvas *>(canvas)->handle()->drawPicture(pic);
}

PictureRecorderRef _PictureRecorderCreate() {
 return new SkiaPictureRecorder();
}

void _PictureRecorderDestroy(PictureRecorderRef recorder) {
 delete reinterpret_cast<SkiaPictureRecorder *>(recorder);
}

CanvasRef _PictureRecorderBeginRecording(PictureRecorderRef recorder, int x, int y, int width, int height) {
  SkRect r = SkRect::MakeXYWH(x, y, x + width, y + height);
  SkCanvas* canvas = reinterpret_cast<SkiaPictureRecorder *>(recorder)->handle()->beginRecording(r);
  if (!canvas)
    return nullptr;

  return new SkiaCanvas(canvas);
}

CanvasRef _PictureRecorderGetRecordingCanvas(PictureRecorderRef recorder) {
  SkCanvas* canvas = reinterpret_cast<SkiaPictureRecorder *>(recorder)->handle()->getRecordingCanvas();
  return new SkiaCanvas(canvas);
}

PictureRef _PictureRecorderFinishRecordingAsPicture(PictureRecorderRef recorder) {
  sk_sp<SkPicture> pic = reinterpret_cast<SkiaPictureRecorder *>(recorder)->handle()->finishRecordingAsPicture();
  return new SkiaPicture(std::move(pic));
}

ImageRef _ImageCreate(float width, float height) {
  if (width <= 0.0f && height <= 0.0f) {
    width = 1.0f;
    height = 1.0f;
  }
  //sk_sp<SkImage> image = skia::AdoptRef(handle);
  return new SkiaImage(width, height);//.Pass());
}

ImageRef _ImageCreateFrom1xPNGBytes(const unsigned char* input, size_t input_size) {
  return PNGCodec::DecodeAsImage(input, input_size);
}

ImageRef _ImageCreateFromBitmap(BitmapRef bitmap) {
  //sk_sp<SkImage> image = skia::AdoptRef(SkImage::NewFromBitmap(*reinterpret_cast<SkBitmap *>(bitmap)));
  return new SkiaImage(SkImage::MakeFromBitmap(*reinterpret_cast<SkBitmap *>(bitmap)));
}

ImageRef _ImageCreateFromBytes(const void* pixel_data,
  uint32_t width,
  uint32_t height,
  int is_image_bitmap_premultiplied,
  int is_image_bitmap_origin_clean,
  int color_type,
  uint8_t primaries,
  uint8_t transfer,
  uint8_t matrix,
  uint8_t range,
  int64_t icc_profile) {
  //DLOG(INFO) << "_ImageCreateFromBytes";
  gfx::ColorSpace color_space {
    static_cast<gfx::ColorSpace::PrimaryID>(primaries), 
    static_cast<gfx::ColorSpace::TransferID>(transfer), 
    static_cast<gfx::ColorSpace::MatrixID>(matrix), 
    static_cast<gfx::ColorSpace::RangeID>(range),
    icc_profile
  };
  SkImageInfo info =
      SkImageInfo::Make(width, height, static_cast<SkColorType>(color_type),
                        is_image_bitmap_premultiplied ? kPremul_SkAlphaType
                                                      : kUnpremul_SkAlphaType,
                        color_space.ToSkColorSpace());
  SkPixmap pixmap(info, pixel_data, info.bytesPerPixel() * width);
  sk_sp<SkImage> raster_copy = SkImage::MakeRasterCopy(pixmap);
  if (!raster_copy) {
    return nullptr;
  }
  return new SkiaImage(std::move(raster_copy));
}

void _ImageGetSize(ImageRef handle, float* width, float* height) {
 auto* image = reinterpret_cast<SkiaImage *>(handle)->handle();
 DCHECK(image);
 *width = image->width();
 *height = image->height();
}

int _ImageIsEmpty(ImageRef handle) {
 auto* image = reinterpret_cast<SkiaImage *>(handle)->handle();
 return image->width() == 0 && image->height() == 0;
}

BitmapRef _ImageGetBitmap(ImageRef handle) {
 SkBitmap* bitmap = new SkBitmap();
 reinterpret_cast<SkiaImage *>(handle)->handle()->asLegacyBitmap(bitmap, SkImage::kRO_LegacyBitmapMode);
 return bitmap;
}

void _ImageDestroy(ImageRef image) {
 delete reinterpret_cast<SkiaImage *>(image);
}

GrGLInterfaceRef _CreateCommandBufferSkiaGLBinding() {
//   GrGLInterface* interface = new GrGLInterface;
//   interface->fStandard = kGLES_GrGLStandard;
//   interface->fExtensions.init(kGLES_GrGLStandard,
//                             glGetString,
//                             nullptr,
//                             glGetIntegerv);

//   GrGLInterface::Functions* functions = &interface->fFunctions;
//   functions->fActiveTexture = glActiveTexture;
//   functions->fAttachShader = glAttachShader;
//   functions->fBindAttribLocation = glBindAttribLocation;
//   functions->fBindBuffer = glBindBuffer;
//   functions->fBindTexture = glBindTexture;
//   functions->fBindVertexArray = glBindVertexArrayOES;
//   functions->fBlendBarrier = glBlendBarrierKHR;
//   functions->fBlendColor = glBlendColor;
//   functions->fBlendEquation = glBlendEquation;
//   functions->fBlendFunc = glBlendFunc;
//   functions->fBufferData = glBufferData;
//   functions->fBufferSubData = glBufferSubData;
//   functions->fClear = glClear;
//   functions->fClearColor = glClearColor;
//   functions->fClearStencil = glClearStencil;
//   functions->fColorMask = glColorMask;
//   functions->fCompileShader = glCompileShader;
//   functions->fCompressedTexImage2D = glCompressedTexImage2D;
//   functions->fCopyTexSubImage2D = glCopyTexSubImage2D;
//   functions->fCreateProgram = glCreateProgram;
//   functions->fCreateShader = glCreateShader;
//   functions->fCullFace = glCullFace;
//   functions->fDeleteBuffers = glDeleteBuffers;
//   functions->fDeleteProgram = glDeleteProgram;
//   functions->fDeleteShader = glDeleteShader;
//   functions->fDeleteTextures = glDeleteTextures;
//   functions->fDeleteVertexArrays = glDeleteVertexArraysOES;
//   functions->fDepthMask = glDepthMask;
//   functions->fDisable = glDisable;
//   functions->fDisableVertexAttribArray = glDisableVertexAttribArray;
//   functions->fDiscardFramebuffer = glDiscardFramebufferEXT;
//   functions->fDrawArrays = glDrawArrays;
//   functions->fDrawElements = glDrawElements;
//   functions->fEnable = glEnable;
//   functions->fEnableVertexAttribArray = glEnableVertexAttribArray;
//   functions->fFinish = glFinish;
//   functions->fFlush = glFlush;
//   functions->fFrontFace = glFrontFace;
//   functions->fGenBuffers = glGenBuffers;
//   functions->fGenTextures = glGenTextures;
//   functions->fGenVertexArrays = glGenVertexArraysOES;
//   functions->fGetBufferParameteriv = glGetBufferParameteriv;
//   functions->fGetError = glGetError;
//   functions->fGetIntegerv = glGetIntegerv;
//   functions->fGetProgramInfoLog = glGetProgramInfoLog;
//   functions->fGetProgramiv = glGetProgramiv;
//   functions->fGetShaderInfoLog = glGetShaderInfoLog;
//   functions->fGetShaderiv = glGetShaderiv;
//   functions->fGetShaderPrecisionFormat = glGetShaderPrecisionFormat;
//   functions->fGetString = glGetString;
//   functions->fGetUniformLocation = glGetUniformLocation;
//   functions->fInsertEventMarker = glInsertEventMarkerEXT;
//   functions->fLineWidth = glLineWidth;
//   functions->fLinkProgram = glLinkProgram;
//   functions->fMapBufferSubData = glMapBufferSubDataCHROMIUM;
//   functions->fMapTexSubImage2D = glMapTexSubImage2DCHROMIUM;
//   functions->fPixelStorei = glPixelStorei;
//   functions->fPopGroupMarker = glPopGroupMarkerEXT;
//   functions->fPushGroupMarker = glPushGroupMarkerEXT;
//   functions->fReadPixels = glReadPixels;
//   functions->fScissor = glScissor;
//   functions->fShaderSource = glShaderSource;
//   functions->fStencilFunc = glStencilFunc;
//   functions->fStencilFuncSeparate = glStencilFuncSeparate;
//   functions->fStencilMask = glStencilMask;
//   functions->fStencilMaskSeparate = glStencilMaskSeparate;
//   functions->fStencilOp = glStencilOp;
//   functions->fStencilOpSeparate = glStencilOpSeparate;
//   functions->fTexImage2D = glTexImage2D;
//   functions->fTexParameteri = glTexParameteri;
//   functions->fTexParameteriv = glTexParameteriv;
//   functions->fTexStorage2D = glTexStorage2DEXT;
//   functions->fTexSubImage2D = glTexSubImage2D;
//   functions->fUniform1f = glUniform1f;
//   functions->fUniform1i = glUniform1i;
//   functions->fUniform1fv = glUniform1fv;
//   functions->fUniform1iv = glUniform1iv;
//   functions->fUniform2f = glUniform2f;
//   functions->fUniform2i = glUniform2i;
//   functions->fUniform2fv = glUniform2fv;
//   functions->fUniform2iv = glUniform2iv;
//   functions->fUniform3f = glUniform3f;
//   functions->fUniform3i = glUniform3i;
//   functions->fUniform3fv = glUniform3fv;
//   functions->fUniform3iv = glUniform3iv;
//   functions->fUniform4f = glUniform4f;
//   functions->fUniform4i = glUniform4i;
//   functions->fUniform4fv = glUniform4fv;
//   functions->fUniform4iv = glUniform4iv;
//   functions->fUniformMatrix2fv = glUniformMatrix2fv;
//   functions->fUniformMatrix3fv = glUniformMatrix3fv;
//   functions->fUniformMatrix4fv = glUniformMatrix4fv;
//   functions->fUnmapBufferSubData = glUnmapBufferSubDataCHROMIUM;
//   functions->fUnmapTexSubImage2D = glUnmapTexSubImage2DCHROMIUM;
//   functions->fUseProgram = glUseProgram;
//   functions->fVertexAttrib1f = glVertexAttrib1f;
//   functions->fVertexAttrib2fv = glVertexAttrib2fv;
//   functions->fVertexAttrib3fv = glVertexAttrib3fv;
//   functions->fVertexAttrib4fv = glVertexAttrib4fv;
//   functions->fVertexAttribPointer = glVertexAttribPointer;
//   functions->fViewport = glViewport;
//   functions->fBindFramebuffer = glBindFramebuffer;
//   functions->fBindRenderbuffer = glBindRenderbuffer;
//   functions->fCheckFramebufferStatus = glCheckFramebufferStatus;
//   functions->fDeleteFramebuffers = glDeleteFramebuffers;
//   functions->fDeleteRenderbuffers = glDeleteRenderbuffers;
//   functions->fFramebufferRenderbuffer = glFramebufferRenderbuffer;
//   functions->fFramebufferTexture2D = glFramebufferTexture2D;
//   functions->fFramebufferTexture2DMultisample =
//     glFramebufferTexture2DMultisampleEXT;
//   functions->fGenFramebuffers = glGenFramebuffers;
//   functions->fGenRenderbuffers = glGenRenderbuffers;
//   functions->fGetFramebufferAttachmentParameteriv =
//     glGetFramebufferAttachmentParameteriv;
//   functions->fGetRenderbufferParameteriv = glGetRenderbufferParameteriv;
//   functions->fRenderbufferStorage = glRenderbufferStorage;
//   functions->fRenderbufferStorageMultisample =
//     glRenderbufferStorageMultisampleCHROMIUM;
//   functions->fRenderbufferStorageMultisampleES2EXT =
//     glRenderbufferStorageMultisampleEXT;
//   functions->fBindUniformLocation = glBindUniformLocationCHROMIUM;
//   functions->fBlitFramebuffer = glBlitFramebufferCHROMIUM;
//   functions->fGenerateMipmap = glGenerateMipmap;
//   if (false) {
//     // These are disabled until the full extension is implemented.
//     // Otherwise the interface fails validation and the context can not
//     // be created.
//     functions->fMatrixLoadf = glMatrixLoadfCHROMIUM;
//     functions->fMatrixLoadIdentity = glMatrixLoadIdentityCHROMIUM;
//     functions->fPathCommands = glPathCommandsCHROMIUM;
//     functions->fPathParameteri = glPathParameteriCHROMIUM;
//     functions->fPathParameterf = glPathParameterfCHROMIUM;
//     functions->fGenPaths = glGenPathsCHROMIUM;
//     functions->fIsPath = glIsPathCHROMIUM;
//     functions->fDeletePaths = glDeletePathsCHROMIUM;
//     functions->fPathStencilFunc = glPathStencilFuncCHROMIUM;
//     functions->fStencilFillPath = glStencilFillPathCHROMIUM;
//     functions->fStencilStrokePath = glStencilStrokePathCHROMIUM;
//     functions->fCoverFillPath = glCoverFillPathCHROMIUM;
//     functions->fCoverStrokePath = glCoverStrokePathCHROMIUM;
//     functions->fStencilThenCoverFillPath = glStencilThenCoverFillPathCHROMIUM;
//     functions->fStencilThenCoverStrokePath =
//       glStencilThenCoverStrokePathCHROMIUM;
//     functions->fStencilFillPathInstanced = glStencilFillPathInstancedCHROMIUM;
//     functions->fStencilStrokePathInstanced =
//       glStencilStrokePathInstancedCHROMIUM;
//     functions->fCoverFillPathInstanced = glCoverFillPathInstancedCHROMIUM;
//     functions->fCoverStrokePathInstanced = glCoverStrokePathInstancedCHROMIUM;
//     functions->fStencilThenCoverFillPathInstanced =
//       glStencilThenCoverFillPathInstancedCHROMIUM;
//     functions->fStencilThenCoverStrokePathInstanced =
//       glStencilThenCoverStrokePathInstancedCHROMIUM;
//     functions->fProgramPathFragmentInputGen =
//       glProgramPathFragmentInputGenCHROMIUM;
//     functions->fBindFragmentInputLocation = glBindFragmentInputLocationCHROMIUM;
//   }

//  return interface;
  gl::ExtensionSet extensions = {"extensions"};
  gl::GLVersionInfo info("4.3 INTEL-11.6.33", nullptr, extensions);
  info.is_es = true;
  info.is_angle = false;
  info.is_d3d = false;
  info.is_mesa = false;
  info.is_swiftshader = false;
  info.major_version = 4;
  info.minor_version = 3;
  info.is_es2 = true;
  info.is_es3 = false;
  info.is_desktop_core_profile = true;
  info.is_es3_capable = true;

  sk_sp<const GrGLInterface> interface = gl::init::CreateGrGLInterface(info);
  return const_cast<GrGLInterface *>(interface.release());
}

// void _GrGLInterfaceSetCallback(GrGLInterfaceRef handle, GrGLInterfaceCallback callback, const void* callbackData) {
//   reinterpret_cast<GrGLInterface *>(handle)->fCallback = callback;
//   reinterpret_cast<GrGLInterface *>(handle)->fCallbackData = reinterpret_cast<intptr_t>(callbackData);
// }

// void* _GrGLInterfaceGetCallbackData(GrGLInterfaceRef handle) {
//   return reinterpret_cast<void *>(reinterpret_cast<GrGLInterface *>(handle)->fCallbackData);
// }

RegionRef _RegionCreate() {
  return new SkRegion();
}

void _RegionDestroy(RegionRef handle) {
  delete reinterpret_cast<SkRegion *>(handle);
}

RegionRef _RegionCreateWithRect(int x, int y, int width, int height) {
  SkIRect r = SkIRect::MakeXYWH(x, y, width, height);
  return new SkRegion(r);
}

void _RegionBounds(RegionRef handle, int* x, int* y, int* width, int* height) {
  SkIRect bounds = reinterpret_cast<SkRegion *>(handle)->getBounds();
  *x = bounds.x();
  *y = bounds.y();
  *width = bounds.width();
  *height = bounds.height();
}

int _RegionEmpty(RegionRef handle) {
  return reinterpret_cast<SkRegion *>(handle)->isEmpty() ? 1 : 0;
}

int _RegionContains(RegionRef handle, int x, int y) {
  return reinterpret_cast<SkRegion *>(handle)->contains(x, y) ? 1 : 0;
}

void _RegionSetRect(RegionRef handle, int x, int y, int width, int height) {
  SkIRect r = SkIRect::MakeXYWH(x, y, width, height);
  reinterpret_cast<SkRegion *>(handle)->setRect(r);
}

int _RegionSetPath(RegionRef handle, PathRef mask, RegionRef clip) {
  return reinterpret_cast<SkRegion *>(handle)->setPath(reinterpret_cast<SkiaPath *>(mask)->ref(), *reinterpret_cast<SkRegion *>(clip)) ? 1 : 0;
}

int _RegionUnionRect(RegionRef handle, int x, int y, int width, int height) {
  SkIRect r = SkIRect::MakeXYWH(x, y, width, height);
  return reinterpret_cast<SkRegion *>(handle)->op(r, SkRegion::kUnion_Op) ? 1 : 0;
}

int _RegionUnionRegion(RegionRef handle, RegionRef other) {
  return reinterpret_cast<SkRegion *>(handle)->op(*reinterpret_cast<SkRegion *>(other), SkRegion::kUnion_Op) ? 1 : 0;
}

void _RegionClear(RegionRef handle) {
  reinterpret_cast<SkRegion *>(handle)->setEmpty();
}

PathRef _RegionGetBoundaryPath(RegionRef handle) {
  SkiaPath* path = new SkiaPath();
  if (!reinterpret_cast<SkRegion *>(handle)->getBoundaryPath(path->handle())) {
    delete path;
    return nullptr;
  }
  return path;
}

RegionIteratorRef _RegionIteratorCreate(RegionRef region) {
  SkRegion::Iterator* it = new SkRegion::Iterator();
  it->reset(*reinterpret_cast<SkRegion *>(region));
  return it;
}

void _RegionIteratorDestroy(RegionIteratorRef handle) {
  delete reinterpret_cast<SkRegion::Iterator *>(handle);
}

int _RegionIteratorIsDone(RegionIteratorRef handle) {
  return reinterpret_cast<SkRegion::Iterator *>(handle)->done() ? 1 : 0;
}

int _RegionIteratorHasRect(RegionIteratorRef handle) {
  return reinterpret_cast<SkRegion::Iterator *>(handle)->done() ? 0 : 1;
}

void _RegionIteratorGetRect(RegionIteratorRef handle, int* x, int* y, int* width, int* height) {
  auto* it = reinterpret_cast<SkRegion::Iterator *>(handle);
  *x = it->rect().x();
  *y = it->rect().y();
  *width = it->rect().width();
  *height = it->rect().height();
}

void _RegionIteratorNext(RegionIteratorRef handle) {
  reinterpret_cast<SkRegion::Iterator *>(handle)->next();
}

MatrixRef _MatrixCreate() {
  return new SkMatrix();
}

void _MatrixDestroy(MatrixRef handle) {
  delete reinterpret_cast<SkMatrix *>(handle);
}

double _MatrixGet(MatrixRef handle, int index) {
  return reinterpret_cast<SkMatrix *>(handle)->get(index);
}

void _MatrixSet(MatrixRef handle, int index, double value) {
  reinterpret_cast<SkMatrix *>(handle)->set(index, value);
}

void _MatrixToIdentity(MatrixRef handle) {
  reinterpret_cast<SkMatrix *>(handle)->setIdentity();
}

void _MatrixPreTranslate(MatrixRef handle, double dx, double dy) {
  reinterpret_cast<SkMatrix *>(handle)->preTranslate(dx, dy);
}

void _MatrixPostTranslate(MatrixRef handle, double dx, double dy) {
  reinterpret_cast<SkMatrix *>(handle)->postTranslate(dx, dy);
}

void _MatrixScale(MatrixRef handle, double x, double y) {
  reinterpret_cast<SkMatrix *>(handle)->setScale(x, y);
}

void _MatrixTranslate(MatrixRef handle, double x, double y) {
 reinterpret_cast<SkMatrix *>(handle)->setTranslate(x, y); 
}

void _MatrixPreScale(MatrixRef handle, double sx, double sy) {
  reinterpret_cast<SkMatrix *>(handle)->preScale(sx, sy);
}

void _MatrixPostConcat(MatrixRef handle, MatrixRef matrix) {
  reinterpret_cast<SkMatrix *>(handle)->postConcat(*reinterpret_cast<SkMatrix *>(matrix));
}

void _MatrixPreConcat(MatrixRef handle, MatrixRef matrix) {
  reinterpret_cast<SkMatrix *>(handle)->preConcat(*reinterpret_cast<SkMatrix *>(matrix));
}

int _MatrixInvert(MatrixRef handle, MatrixRef matrix) {
  return reinterpret_cast<SkMatrix *>(handle)->invert(reinterpret_cast<SkMatrix *>(matrix)) ? 1 : 0;
}

int _MatrixEquals(MatrixRef left, MatrixRef right) {
  return (*reinterpret_cast<SkMatrix *>(left)) == (*reinterpret_cast<SkMatrix *>(right)) ? 1 : 0;
}

int _MatrixNotEquals(MatrixRef left, MatrixRef right) {
  return (*reinterpret_cast<SkMatrix *>(left)) != (*reinterpret_cast<SkMatrix *>(right)) ? 1 : 0;
}

 int _MatrixRectStaysRect(MatrixRef handle) {
   return reinterpret_cast<SkMatrix *>(handle)->rectStaysRect() ? 1 : 0;
 }

Matrix44Ref _Matrix44Create(int is_identity) {
  Matrix44Ref ref = nullptr;
  if (is_identity) {
    ref = new SkMatrix44(SkMatrix44::kIdentity_Constructor);
  } else {
    ref = new SkMatrix44(SkMatrix44::kUninitialized_Constructor);
  }
  return ref;
}

void _Matrix44Destroy(Matrix44Ref handle) {
  delete reinterpret_cast<SkMatrix44 *>(handle);
}

double _Matrix44Get(Matrix44Ref handle, int row, int col) {
  return reinterpret_cast<SkMatrix44 *>(handle)->get(row, col);
}

void _Matrix44Set(Matrix44Ref handle, int row, int col, double value) {
  reinterpret_cast<SkMatrix44 *>(handle)->set(row, col, value);
}

void _Matrix44SetRotateDegreesAbout(Matrix44Ref reference, double x, double y, double z, double degrees) {
  reinterpret_cast<SkMatrix44 *>(reference)->setRotateDegreesAbout(x, y, z, degrees);
}

double _Matrix44GetDeterminant(Matrix44Ref handle) {
  return reinterpret_cast<SkMatrix44 *>(handle)->determinant();
}

int _Matrix44IsIdentity(Matrix44Ref handle) {
  return reinterpret_cast<SkMatrix44 *>(handle)->isIdentity() ? 1 : 0;
}

int _Matrix44IsScaleTranslate(Matrix44Ref handle) {
  return reinterpret_cast<SkMatrix44 *>(handle)->isScaleTranslate() ? 1 : 0;
}

int _Matrix44IsTranslate(Matrix44Ref handle) {
  return reinterpret_cast<SkMatrix44 *>(handle)->isTranslate() ? 1 : 0;
}

void _Matrix44ToIdentity(Matrix44Ref handle) {
  reinterpret_cast<SkMatrix44 *>(handle)->setIdentity();
}

void _Matrix44PreTranslate(Matrix44Ref handle, double dx, double dy, double dz) {
  reinterpret_cast<SkMatrix44 *>(handle)->preTranslate(dx, dy, dz);
}

void _Matrix44Transpose(Matrix44Ref handle) {
  reinterpret_cast<SkMatrix44 *>(handle)->transpose();
}

void _Matrix44PreScale(Matrix44Ref handle, double sx, double sy, double sz) {
  reinterpret_cast<SkMatrix44 *>(handle)->preScale(sx, sy, sz);
}

void _Matrix44PostConcat(Matrix44Ref handle, Matrix44Ref matrix) {
  reinterpret_cast<SkMatrix44 *>(handle)->postConcat(*reinterpret_cast<SkMatrix44 *>(matrix));
}

void _Matrix44Set3x3(Matrix44Ref handle, 
  double m00, double m10, double m20, 
  double m01, double m11, double m21, 
  double m02, double m12, double m22) {
  reinterpret_cast<SkMatrix44 *>(handle)->set3x3(
    m00, m10, m20,
    m01, m11, m21,
    m02, m12, m22);
}

void _Matrix44Scale(Matrix44Ref handle, double x, double y, double z) {
  reinterpret_cast<SkMatrix44 *>(handle)->setScale(x, y, z);
}

void _Matrix44PreConcat(Matrix44Ref handle, Matrix44Ref matrix) {
  reinterpret_cast<SkMatrix44 *>(handle)->preConcat(*reinterpret_cast<SkMatrix44 *>(matrix));
}

int _Matrix44Invert(Matrix44Ref handle, Matrix44Ref matrix) {
  return reinterpret_cast<SkMatrix44 *>(handle)->invert(reinterpret_cast<SkMatrix44 *>(matrix)) ? 1 : 0;
}

void _Matrix44Translate(Matrix44Ref reference, double x, double y, double z) {
  reinterpret_cast<SkMatrix44 *>(reference)->setTranslate(x, y, z);
}

void _Matrix44MapRect(Matrix44Ref handle, int* x, int* y, int* width, int* height) {
  SkMatrix mat(*reinterpret_cast<SkMatrix44 *>(handle));
  SkRect r = SkRect::MakeXYWH(*x, *y, *width, *height);
  mat.mapRect(&r);
  *x = r.x();
  *y = r.y();
  *width = r. width();
  *height = r.height();
}

void _Matrix44MapRectf(Matrix44Ref handle, float* x, float* y, float* width, float* height) {
  SkMatrix mat(*reinterpret_cast<SkMatrix44 *>(handle));
  SkRect r = SkRect::MakeXYWH(*x, *y, *width, *height);
  mat.mapRect(&r);
  *x = r.x();
  *y = r.y();
  *width = r. width();
  *height = r.height();
}

void _Matrix44MapScalars(Matrix44Ref handle, double* x, double* y, double* z, double* w) {
  SkMScalar p[4] = {*x, *y, *z, *w};
  reinterpret_cast<SkMatrix44 *>(handle)->mapMScalars(p);
  *x = p[0];
  *y = p[1];
  *z = p[2];
  *w = p[3];
}

void _Matrix44MapScalars2(Matrix44Ref handle, 
  double x0, double y0, double z0, double w0, 
  double* x1, double* y1, double* z1, double* w1) {

  SkScalar input[4] = {x0, y0, z0, w0};
  SkScalar output[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  reinterpret_cast<SkMatrix44 *>(handle)->mapScalars(input, output);
  *x1 = output[0];
  *y1 = output[1];
  *z1 = output[2];
  *w1 = output[3];
}

Matrix44Ref _Matrix44Multiply(Matrix44Ref left, Matrix44Ref right) {
  SkMatrix44 result = (*reinterpret_cast<SkMatrix44 *>(left)) * (*reinterpret_cast<SkMatrix44 *>(right));
  return new SkMatrix44(result);
}

int _Matrix44Equals(Matrix44Ref left, Matrix44Ref right) {
  return (*reinterpret_cast<SkMatrix44 *>(left)) == (*reinterpret_cast<SkMatrix44 *>(right)) ? 1 : 0;
}

int _Matrix44NotEquals(Matrix44Ref left, Matrix44Ref right) {
  return (*reinterpret_cast<SkMatrix44 *>(left)) != (*reinterpret_cast<SkMatrix44 *>(right)) ? 1 : 0;
}

ShaderRef _ShaderCreateEmpty() {
 sk_sp<SkShader> shader = SkShader::MakeEmptyShader();
 return new SkiaShader(std::move(shader));
}


static SkShader::TileMode _ToShaderTileMode(int mode) {
  if (mode == 0){
    return SkShader::kClamp_TileMode;
  } else if (mode == 1) {
    return SkShader::kRepeat_TileMode;
  } else if (mode == 2) {
    return SkShader::kMirror_TileMode;
  }
  return SkShader::kClamp_TileMode;
}

ShaderRef _ShaderCreateBitmap(BitmapRef bitmap, int xmode, int ymode, MatrixRef localMatrix) {
 SkBitmap* bitmapPtr = reinterpret_cast<SkBitmap *>(bitmap);
 SkMatrix* mptr = localMatrix != nullptr ? reinterpret_cast<SkMatrix *>(localMatrix) : nullptr; 
 //DCHECK(bitmapPtr);
 sk_sp<SkShader> shader = SkShader::MakeBitmapShader(*bitmapPtr, _ToShaderTileMode(xmode), _ToShaderTileMode(ymode), mptr);
 return new SkiaShader(std::move(shader));
}

ShaderRef _ShaderCreateColor(uint8_t a, uint8_t r, uint8_t g, uint8_t b) {
 sk_sp<SkShader> shader = SkShader::MakeColorShader(SkColorSetARGB(a, r, g, b));
 return new SkiaShader(std::move(shader)); 
}

ShaderRef _ShaderCreatePicture(PictureRef picture) {
 sk_sp<SkShader> shader = SkShader::MakeEmptyShader();
 return new SkiaShader(std::move(shader)); //SkShader::CreatePictureShader(picture->handle);
}

ShaderRef _ShaderCreateLocalMatrix() {
 sk_sp<SkShader> shader = SkShader::MakeEmptyShader();
 return new SkiaShader(std::move(shader)); //SkShader::CreateLocalMatrixShader();
}

EXPORT ShaderRef _ShaderCreateGradient() {
 sk_sp<SkShader> shader = SkShader::MakeEmptyShader();
 return new SkiaShader(std::move(shader));//SkShader::CreateGradientLinearShader();
}

void _ShaderDestroy(ShaderRef handle) {
 delete reinterpret_cast<SkiaShader *>(handle);
}

TypefaceRef _TypefaceCreate(const char* name, int bold, int italic) {
  
  SkFontStyle skia_style;

  if (bold == 1) {
    skia_style = SkFontStyle::Bold();
  } else if (italic == 1) {
    skia_style = SkFontStyle::Italic();
  } else if (bold  == 1 && italic == 1) {
    skia_style = SkFontStyle::BoldItalic();
  } else {
    skia_style = SkFontStyle::Normal();
  }

  sk_sp<SkTypeface> typeface = SkTypeface::MakeFromName(name, skia_style);
  
  if (!typeface) {(
    typeface = SkTypeface::MakeFromName(kFallbackFontFamilyName, SkFontStyle::Normal()));
    
    CHECK(typeface) << "Could not find fonts: '" << name << "', fallback: '" << kFallbackFontFamilyName << "'";
 
    if (!typeface) { // pass null so the caller knows we failed to instantiate the typeface
      return nullptr;
    }
  }
  return new SkiaTypeface(std::move(typeface));
}

void _TypefaceDestroy(TypefaceRef handle) {
 delete reinterpret_cast<SkiaTypeface *>(handle);
}

int _TypefaceIsBold(TypefaceRef handle) {
 return reinterpret_cast<SkiaTypeface *>(handle)->handle()->isBold() ? 1 : 0;
}

int _TypefaceIsItalic(TypefaceRef handle) {
 return reinterpret_cast<SkiaTypeface *>(handle)->handle()->isItalic() ? 1 : 0;
}

DrawLooperRef _DrawLooperCreateBlur(uint8_t a, uint8_t r, uint8_t g, uint8_t b, double sigma, double dx, double dy) {
 sk_sp<SkDrawLooper> looper = SkBlurDrawLooper::Make(SkColorSetARGB(a, r, g, b), sigma, dx, dy);
 return new SkiaDrawLooper(std::move(looper));
}

DrawLooperRef _DrawLooperCreateLayer() {
 SkLayerDrawLooper::Builder builder;
 // TODO: fix for the real thing later
 builder.addLayer();
 sk_sp<SkDrawLooper> looper = builder.detach();
 return new SkiaDrawLooper(std::move(looper));
}

void _DrawLooperDestroy(DrawLooperRef handle) {
 delete reinterpret_cast<SkiaDrawLooper *>(handle);
}

DrawLooperBuilderRef _DrawLooperLayerBuilderCreate() {
 return new SkLayerDrawLooper::Builder();
}

void _DrawLooperLayerBuilderDestroy(DrawLooperBuilderRef handle) {
  delete reinterpret_cast<SkLayerDrawLooper::Builder *>(handle);
}

PaintRef _DrawLooperLayerBuilderAddLayer(DrawLooperBuilderRef handle, int flags, int colormode, int x, int y, int posttrans) {
  SkLayerDrawLooper::LayerInfo info;
  info.fPaintBits = flags;
  info.fColorMode = static_cast<SkBlendMode>(colormode);
  info.fOffset.set(x, y);
  info.fPostTranslate = posttrans == 0 ? false : true;
  return reinterpret_cast<SkLayerDrawLooper::Builder *>(handle)->addLayer(info);  
}

void _DrawLooperLayerBuilderAddLayerXY(DrawLooperBuilderRef handle, int x, int y) {
  reinterpret_cast<SkLayerDrawLooper::Builder *>(handle)->addLayer(x, y); 
}

PaintRef _DrawLooperLayerBuilderAddLayerOnTop(DrawLooperBuilderRef handle, int flags, int colormode, int x, int y, int posttrans) {
  SkLayerDrawLooper::LayerInfo info;
  info.fPaintBits = flags;
  info.fColorMode = static_cast<SkBlendMode>(colormode);
  info.fOffset.set(x, y);
  info.fPostTranslate = posttrans == 0 ? false : true;
  return reinterpret_cast<SkLayerDrawLooper::Builder *>(handle)->addLayerOnTop(info);
}

DrawLooperRef _DrawLooperLayerBuilderDetachLooper(DrawLooperBuilderRef handle) {
   sk_sp<SkDrawLooper> looper = reinterpret_cast<SkLayerDrawLooper::Builder *>(handle)->detach();
   return new SkiaDrawLooper(std::move(looper));
 }

BitmapRef _BitmapCreate(float width, float height) {
 SkBitmap* bitmap = new SkBitmap();
 if (width > 0.0f || height > 0.0f) {
   bitmap->allocN32Pixels(width, height);
 }
 return bitmap;
}

BitmapRef _BitmapCreateButtonBackground(uint8_t a, uint8_t r, uint8_t g, uint8_t b, BitmapRef image, BitmapRef mask) {
  SkColor color = SkColorSetARGB(a, r, g, b);
  SkBitmap on_stack = SkBitmapOperations::CreateButtonBackground(color, *reinterpret_cast<SkBitmap *>(image), *reinterpret_cast<SkBitmap *>(mask));
  return new SkBitmap(on_stack);
}

BitmapRef _BitmapCreateBlendedBitmap(BitmapRef first, BitmapRef second, double alpha) {
  SkBitmap on_stack = SkBitmapOperations::CreateBlendedBitmap(*reinterpret_cast<SkBitmap *>(first), *reinterpret_cast<SkBitmap *>(second), alpha);
  return new SkBitmap(on_stack);
}

void _BitmapDestroy(BitmapRef handle) {
  //DLOG(INFO) << "_BitmapDestroy: " << handle;
  delete reinterpret_cast<SkBitmap *>(handle);
}

//int _BitmapCopyTo(BitmapRef handle, BitmapRef dest) {
  //return reinterpret_cast<SkBitmap *>(handle)->copyTo(reinterpret_cast<SkBitmap *>(dest)) ? 1 : 0;
//}

float _BitmapGetWidth(BitmapRef handle) {
  return reinterpret_cast<SkBitmap *>(handle)->width();
}

float _BitmapGetHeight(BitmapRef handle) {
 return reinterpret_cast<SkBitmap *>(handle)->height();
}

void _BitmapGetSize(BitmapRef handle, float* width, float* height) {
  SkBitmap* bitmap = reinterpret_cast<SkBitmap *>(handle);
  *width = bitmap->width();
  *height = bitmap->height();
}

int _BitmapIsImmutable(BitmapRef handle) {
 return reinterpret_cast<SkBitmap *>(handle)->isImmutable();
}

int _BitmapIsEmpty(BitmapRef handle) {
 return reinterpret_cast<SkBitmap *>(handle)->empty();
}

int _BitmapIsDrawable(BitmapRef handle) {
 return !reinterpret_cast<SkBitmap *>(handle)->drawsNothing();
}

int _BitmapIsNull(BitmapRef handle) {
 return reinterpret_cast<SkBitmap *>(handle)->isNull(); 
}

void _BitmapSetImmutable(BitmapRef handle) {
 reinterpret_cast<SkBitmap *>(handle)->setImmutable();
}

// void _BitmapLockPixels(BitmapRef handle) {
//   reinterpret_cast<SkBitmap *>(handle)->lockPixels();
// }

// void _BitmapUnlockPixels(BitmapRef handle) {
//   reinterpret_cast<SkBitmap *>(handle)->unlockPixels(); 
// }

void _BitmapGetColorAtARGB(BitmapRef handle, float x, float y, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b) {
 SkBitmap* bitmap = reinterpret_cast<SkBitmap *>(handle);
 
 SkColor color = bitmap->getColor(x, y);

 *a = SkColorGetA(color);
 *r = SkColorGetR(color);
 *g = SkColorGetG(color);
 *b = SkColorGetB(color);
}

int _BitmapGetColorAt(BitmapRef handle, float x, float y) {
  SkBitmap* bitmap = reinterpret_cast<SkBitmap *>(handle);
  return bitmap->getColor(x, y);  
}

void* _BitmapGetBufferAt(BitmapRef handle, float x, float y, size_t* size) {
  SkBitmap* bitmap = reinterpret_cast<SkBitmap *>(handle);
  *size = bitmap->width() *  bitmap->height();   
  return reinterpret_cast<SkBitmap *>(handle)->getAddr32(x, y);
}

void _BitmapEraseARGB(BitmapRef handle, uint8_t a, uint8_t r, uint8_t g, uint8_t b) {
  SkBitmap* bitmap = reinterpret_cast<SkBitmap *>(handle);
  bitmap->eraseColor(SkColorSetARGB(a, r, g, b));
}

void _BitmapAllocatePixels(BitmapRef handle, float width, float height) {
  SkBitmap* bitmap = reinterpret_cast<SkBitmap *>(handle);
  bitmap->allocN32Pixels(width, height);
}

void _BitmapAllocatePixelsAlpha(BitmapRef handle, float width, float height, int alpha_type) {
  SkBitmap* bitmap = reinterpret_cast<SkBitmap *>(handle);
  SkImageInfo info = SkImageInfo::MakeN32(width, height, static_cast<SkAlphaType>(alpha_type));
  bitmap->allocPixels(info);
}

BitmapRef _BitmapExtractSubset(BitmapRef handle, float x, float y, float width, float height) {
 SkBitmap* bitmap = reinterpret_cast<SkBitmap *>(handle);
 SkIRect subset = SkIRect::MakeXYWH(x, y, width, height);
 // we have to allocate in heap so we can return back
 SkBitmap *dst = new SkBitmap();
 bool result = bitmap->extractSubset(dst, subset);
 DCHECK(result);
 return dst;
}

DrawableRef _DrawableCreate(void* peer, CDrawableCallbacks callbacks) {
  return new SkDrawableImpl(peer, callbacks);
}

void _DrawableDestroy(DrawableRef handle) {
  delete reinterpret_cast<SkDrawableImpl *>(handle);
}

uint32_t _DrawableGetGenerationID(DrawableRef handle) {
  return reinterpret_cast<SkDrawableImpl *>(handle)->getGenerationID();
}

void _DrawableGetBounds(DrawableRef handle, int* x, int* y, int* w, int* h) {
  SkRect rect = reinterpret_cast<SkDrawableImpl *>(handle)->getBounds();
  *x = rect.x();
  *y = rect.y();
  *w = rect.width();
  *h = rect.height();
}

void _DrawableDraw(DrawableRef handle, CanvasRef canvas) {
  auto* canvas_handle = reinterpret_cast<SkiaCanvas *>(canvas)->handle();
  reinterpret_cast<SkDrawableImpl *>(handle)->draw(canvas_handle);
}

void _DrawableDrawAt(DrawableRef handle, CanvasRef canvas, int x, int y) {
  auto* canvas_handle = reinterpret_cast<SkiaCanvas *>(canvas)->handle();
  reinterpret_cast<SkDrawableImpl *>(handle)->draw(canvas_handle, x, y);
}

PictureRef _DrawableNewPictureSnapshot(DrawableRef handle) {
  SkPicture* pic = reinterpret_cast<SkDrawableImpl *>(handle)->newPictureSnapshot();
  return new SkiaPicture(pic);
}

void _DrawableNotifyDrawingChanged(DrawableRef handle) {
  reinterpret_cast<SkDrawableImpl *>(handle)->notifyDrawingChanged();
}

MaskFilterRef _MaskFilterCreateBlur(double radius, int style, int flags) {
  SkBlurStyle blurstyle = kNormal_SkBlurStyle;
  switch (style) {
    case 0:
      blurstyle = kNormal_SkBlurStyle;  //!< fuzzy inside and outside
      break;
    case 1:
      blurstyle = kSolid_SkBlurStyle;   //!< solid inside, fuzzy outside
      break;
    case 2:
      blurstyle = kOuter_SkBlurStyle;   //!< nothing inside, fuzzy outside
      break;
    case 3:
      blurstyle = kInner_SkBlurStyle;   //!< fuzzy
      break;
  }
  sk_sp<SkMaskFilter> filter = SkMaskFilter::MakeBlur(blurstyle, radius);
  return new SkiaMaskFilter(std::move(filter));
}

// MaskFilterRef _MaskFilterCreateEmboss(double sigma, double x, double y, double z, double ambient, double specular) {
//  SkScalar points[3];
//  points[0] = x;
//  points[1] = y;
//  points[2] = z;
//  sk_sp<SkMaskFilter> filter = skia::AdoptRef(SkBlurMaskFilter::CreateEmboss(sigma, points, ambient, specular));
//  return new SkiaMaskFilter(filter.Pass());
// }

void _MaskFilterDestroy(MaskFilterRef filter) {
  delete reinterpret_cast<SkiaMaskFilter *>(filter);
}

PathEffectRef _PathEffectCreateDash(const float* intervals, int count, float phase) {
  return new SkiaPathEffect(SkDashPathEffect::Make(intervals, count, phase));
}

PathEffectRef _PathEffectCreateSum(PathEffectRef first, PathEffectRef second) {
  return new SkiaPathEffect(SkPathEffect::MakeSum(
    reinterpret_cast<SkiaPathEffect *>(first)->handle(), 
    reinterpret_cast<SkiaPathEffect *>(second)->handle())
  );
}

PathEffectRef _PathEffectCreateCompose(PathEffectRef outer, PathEffectRef inner) {
  return new SkiaPathEffect(SkPathEffect::MakeCompose(
    reinterpret_cast<SkiaPathEffect *>(outer)->handle(),
    reinterpret_cast<SkiaPathEffect *>(inner)->handle()));
}

void _PathEffectDestroy(PathEffectRef handle) {
  delete reinterpret_cast<SkiaPathEffect *>(handle);
}

// PNGCodec

unsigned char* _PNGCodecDecodeAsRawBytes(const unsigned char* input, int input_size, int format, int* size, int* width, int* height) {
  unsigned char* output = nullptr;
  if (!PNGCodec::Decode(
    input, 
    input_size,
    static_cast<PNGCodec::ColorFormat>(format), 
    &output,
    size,
    width, 
    height)) {
    return nullptr;
  }
  return output;
}

BitmapRef _PNGCodecDecodeAsBitmap(const unsigned char* input, int input_size) {
  SkBitmap* result = new SkBitmap();
  if (!PNGCodec::Decode(input, input_size, result)) {
    delete result;
    return nullptr;
  }
  return result;
}

ImageRef _PNGCodecDecodeAsImage(const unsigned char* input, int input_size) {
  return PNGCodec::DecodeAsImage(input, input_size);
}