// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "CompositorStructsPrivate.h"

#include "cc/paint/record_paint_canvas.h"

_DisplayItemList::_DisplayItemList(scoped_refptr<cc::DisplayItemList> handle, bool avoid_meta_ops): canvas_(nullptr), handle_(std::move(handle)), avoid_meta_ops_(avoid_meta_ops) {
  ptr_ = handle_.get();
}//, flags_was_set_(false) {}

_DisplayItemList::_DisplayItemList(cc::DisplayItemList* handle, bool avoid_meta_ops): canvas_(nullptr), ptr_(handle), avoid_meta_ops_(avoid_meta_ops) {
  
}

_DisplayItemList::_DisplayItemList(cc::PaintRecorder* paint_recorder, bool avoid_meta_ops): avoid_meta_ops_(avoid_meta_ops) {
  canvas_ = static_cast<cc::RecordPaintCanvas *>(paint_recorder->getRecordingCanvas());
  ptr_ = canvas_->list();
  DCHECK(ptr_);
}

_DisplayItemList::_DisplayItemList(cc::PaintCanvas* canvas, bool avoid_meta_ops): canvas_(static_cast<cc::RecordPaintCanvas *>(canvas)), avoid_meta_ops_(avoid_meta_ops) {
  ptr_ = canvas_->list(); 
  DCHECK(ptr_);
}

_DisplayItemList::_DisplayItemList(): canvas_(nullptr), ptr_(nullptr), avoid_meta_ops_(true) {
  
}

_DisplayItemList::~_DisplayItemList() {}

cc::DisplayItemList& _DisplayItemList::handle() {
  //base::AutoLock lock(display_item_lock_);
  return *ptr_; 
}

cc::RecordPaintCanvas& _DisplayItemList::canvas() {
  //base::AutoLock lock(canvas_lock_);
  DCHECK(canvas_);
  return *canvas_;
}

bool _DisplayItemList::has_canvas() {
  //base::AutoLock lock(canvas_lock_);
  return canvas_ != nullptr; 
}

int _DisplayItemList::TotalOpCount() {
  return handle().TotalOpCount();
}

void _DisplayItemList::StartPaint() {
  // //DLOG(INFO) << "DisplayItemList::StartPaint";
  if (!avoid_meta_ops_)
    handle().StartPaint();
}

void _DisplayItemList::EndPaintOfPairedBegin() {
  // //DLOG(INFO) << "DisplayItemList::EndPaintOfPairedBegin";
  if (!avoid_meta_ops_)
    handle().EndPaintOfPairedBegin();
}

void _DisplayItemList::EndPaintOfPairedBegin(gfx::Rect& rect) {
  // //DLOG(INFO) << "DisplayItemList::EndPaintOfPairedBegin(rect)";
  if (!avoid_meta_ops_)
    handle().EndPaintOfPairedBegin(rect);
}

void _DisplayItemList::EndPaintOfPairedEnd() {
  // //DLOG(INFO) << "DisplayItemList::EndPaintOfPairedEnd";
  if (!avoid_meta_ops_)
    handle().EndPaintOfPairedEnd();
}

void _DisplayItemList::EndPaintOfUnpaired(gfx::Rect& rect) {
  // //DLOG(INFO) << "DisplayItemList::EndPaintOfUnpaired";   
  if (!avoid_meta_ops_)
    handle().EndPaintOfUnpaired(rect);
}

void _DisplayItemList::Finalize() {
  // //DLOG(INFO) << "DisplayItemList::Finalize";
  if (!avoid_meta_ops_)
    handle().Finalize(); 
}

sk_sp<cc::PaintRecord> _DisplayItemList::ReleaseAsRecord() {
  // //DLOG(INFO) << "DisplayItemList::ReleaseAsRecord";
  if (!avoid_meta_ops_) {
    return handle().ReleaseAsRecord();
  } 
  // paint recorder has a way to this, but
  // we should not use this op when it is PaintRecorder
  // because higher renderers might be waiting for this
  // and by doing this on our code, we will invalidate
  // the code expecting for this
  // TODO: maybe have a hint for cases this is not the case
  DCHECK(false);
  //return canvas_->finishRecordingAsPicture();
  return nullptr;
}

void _DisplayItemList::ClipPath(const SkPath& path, SkClipOp op, bool antialias) {
  //if (has_canvas()) {
  //  canvas().clipPath(path, op, antialias);
  //} else {
    handle().push<cc::ClipPathOp>(path, op, antialias);
  //}
}

void _DisplayItemList::ClipRect(const SkRect& rect, SkClipOp op, bool antialias) {
  // //DLOG(INFO) << "DisplayItemList::ClipRect";
  //if (has_canvas()) {
  //  canvas().clipRect(rect, op, antialias);
  //} else {
    handle().push<cc::ClipRectOp>(
      rect,
      op,
      antialias);
  //}
}

void _DisplayItemList::ClipRRect(const SkRRect& rrect, SkClipOp op, bool antialias) {
  //if (has_canvas()) {
  //  canvas().clipRRect(rrect, op, antialias);
  //} else {
    handle().push<cc::ClipRRectOp>(
    rrect,
    op,
    antialias);
  //}
}

void _DisplayItemList::Concat(const SkMatrix& matrix) {
  //if (has_canvas()) {
  //  canvas().concat(matrix);
  //} else {
    handle().push<cc::ConcatOp>(matrix);
  //}
}

void _DisplayItemList::RecordCustomData(uint32_t id) {
  //if (has_canvas()) {
  //  canvas().recordCustomData(id);
  //} else {
    handle().push<cc::CustomDataOp>(id);
  //} 
}

void _DisplayItemList::DrawColor(SkColor color, SkBlendMode blend_mode) {
  //if (has_canvas()) {
  //  canvas().drawColor(color, blend_mode);
  //} else {
    handle().push<cc::DrawColorOp>(
    color,
    blend_mode);
  //}
}

void _DisplayItemList::DrawDRRect(const SkRRect& outer,
                const SkRRect& inner,
                const cc::PaintFlags& flags) {
  //if (has_canvas()) {
  //  canvas().drawDRRect(outer, inner, flags);
  //} else {
    handle().push<cc::DrawDRRectOp>(outer, inner, flags);
  //}
}   

void _DisplayItemList::DrawImage(const cc::PaintImage& image,
               SkScalar left,
               SkScalar top,
               const cc::PaintFlags* flags) {
  //if (has_canvas()) {
  //  canvas().drawImage(image, left, top, flags);
  //} else {
    handle().push<cc::DrawImageOp>(
      image,
      left,
      top,
      flags);
  //}
}

void _DisplayItemList::DrawImageRect(const cc::PaintImage& image,
                   const SkRect& src,
                   const SkRect& dst,
                   const cc::PaintFlags* flags,
                   cc::PaintCanvas::SrcRectConstraint constraint) {
  //if (has_canvas()) {
  //  canvas().drawImageRect(image, src, dst, flags, constraint);
  //} else {    
    handle().push<cc::DrawImageRectOp>(
      image,
      src,
      dst,
      flags,
      constraint);
  //}
}

void _DisplayItemList::DrawBitmap(const SkBitmap& bitmap,
                SkScalar left,
                SkScalar top,
                const cc::PaintFlags* flags) {
  DrawImage(cc::PaintImageBuilder::WithDefault()
              .set_id(cc::PaintImage::GetNextId())
              .set_image(SkImage::MakeFromBitmap(bitmap),
                         cc::PaintImage::GetNextContentId())
              .TakePaintImage(),
              left, top, flags);
}

void _DisplayItemList::DrawIRect(const SkIRect& rect, const cc::PaintFlags& flags) {
  //if (has_canvas()) {
  //  canvas().drawIRect(rect, flags);
  //} else {
    handle().push<cc::DrawIRectOp>(rect, flags);
  //}    
}

void _DisplayItemList::DrawLine(SkScalar x0,
              SkScalar y0,
              SkScalar x1,
              SkScalar y1,
              const cc::PaintFlags& flags) {
  //if (has_canvas()) {
  //  canvas().drawLine(x0, y0, x1, y1, flags);
  //} else {
    handle().push<cc::DrawLineOp>(x0, y0, x1, y1, flags);
  //}
}

void _DisplayItemList::DrawOval(const SkRect& oval, const cc::PaintFlags& flags) {
  //if (has_canvas()) {
  //  canvas().drawOval(oval, flags);
  //} else {
    handle().push<cc::DrawOvalOp>(oval, flags);
  //}
}

void _DisplayItemList::DrawPath(const SkPath& path, const cc::PaintFlags& flags) {
  //if (has_canvas()) {
  //  canvas().drawPath(path, flags);
  //} else {
    handle().push<cc::DrawPathOp>(path, flags);
  //}
}

void _DisplayItemList::DrawRecord(sk_sp<const cc::PaintRecord> record) {
  //if (has_canvas()) {
  //  canvas().drawPicture(record);
  //} else {
    handle().push<cc::DrawRecordOp>(record);
  //}
}

void _DisplayItemList::DrawRect(const SkRect& rect, const cc::PaintFlags& flags) {
  //if (has_canvas()) {
  //  canvas().drawRect(rect, flags);
  //} else {
    handle().push<cc::DrawRectOp>(rect, flags);
  //}
}

void _DisplayItemList::DrawRRect(const SkRRect& rrect, const cc::PaintFlags& flags) {
  //if (has_canvas()) {
  //  canvas().drawRRect(rrect, flags);
  //} else {
    handle().push<cc::DrawRRectOp>(rrect, flags);
  //}
}

void _DisplayItemList::DrawTextBlob(const scoped_refptr<cc::PaintTextBlob>& blob,
                  SkScalar x,
                  SkScalar y,
                  const cc::PaintFlags& flags) {
  //if (has_canvas()) {
  //  //DLOG(INFO) << "canvas->drawTextBlob";
  //  canvas().drawTextBlob(blob, x, y, flags);
  //  //DLOG(INFO) << "canvas->drawTextBlob end";
  //} else {
    //DLOG(INFO) << "displayItem.push<cc::DrawTextBlobOp>";
    handle().push<cc::DrawTextBlobOp>(
      blob,
      x,
      y,
      flags);
    //DLOG(INFO) << "displayItem.push<cc::DrawTextBlobOp>";
  //}
}

void _DisplayItemList::Noop() {
  //if (!canvas_) {
    handle().push<cc::NoopOp>();
  //}
}

void _DisplayItemList::Restore() {
  // //DLOG(INFO) << "DisplayItemList::Restore";
  //if (has_canvas()) {
  //  canvas().restore();
  //} else {
    handle().push<cc::RestoreOp>();
  //}
}

void _DisplayItemList::Rotate(SkScalar degrees) {
  //if (has_canvas()) {
  //  canvas().rotate(degrees);
  //} else {
    handle().push<cc::RotateOp>(degrees);
  //}
}

void _DisplayItemList::Save() {
  // //DLOG(INFO) << "DisplayItemList::Save";
  //if (has_canvas()) {
    // //DLOG(INFO) << "DisplayItemList::Save: calling canvas().save()";
  //  canvas().save();
  //} else {
    // //DLOG(INFO) << "DisplayItemList::Save: pushing save op to display list";
    handle().push<cc::SaveOp>();
  //}
}

void _DisplayItemList::SaveLayer(const SkRect* bounds, const cc::PaintFlags* flags) {
  //if (has_canvas()) {
  //  canvas().saveLayer(bounds, flags);
  //} else {
    handle().push<cc::SaveLayerOp>(bounds, flags);
  //}
}

void _DisplayItemList::SaveLayerAlpha(
  const SkRect* bounds,
  uint8_t alpha,
  bool preserve_lcd_text_requests) {
  //if (has_canvas()) {
  //  canvas().saveLayerAlpha(bounds, alpha, preserve_lcd_text_requests);
  //} else {
    handle().push<cc::SaveLayerAlphaOp>(bounds, alpha, preserve_lcd_text_requests);
  //}
}

void _DisplayItemList::Scale(SkScalar sx, SkScalar sy) {
  //if (has_canvas()) {
  //  canvas().scale(sx, sy);
  //} else {
    handle().push<cc::ScaleOp>(sx, sy);
  //}
}

void _DisplayItemList::SetMatrix(const SkMatrix& matrix) {
  //if (has_canvas()) {
  //  canvas().setMatrix(matrix);
  //} else {
    handle().push<cc::SetMatrixOp>(matrix);
  //}
}

void _DisplayItemList::Translate(SkScalar dx, SkScalar dy) {
  //if (has_canvas()) {
  //  canvas().translate(dx, dy);
  //} else {
    handle().push<cc::TranslateOp>(dx, dy);
  //}
}
