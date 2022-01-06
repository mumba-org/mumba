// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "PDFShims.h"

#include <cmath>

#include "base/logging.h"
//#include "base/memory/scoped_ptr.h"
#include "third_party/pdfium/public/fpdf_edit.h"
#include "third_party/pdfium/public/fpdf_doc.h"
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
#include "third_party/skia/include/core/SkDrawFilter.h"
#include "third_party/skia/include/core/SkColorFilter.h"
#include "third_party/skia/include/core/SkDrawLooper.h"
#include "third_party/skia/include/core/SkDrawable.h"
#include "third_party/skia/include/core/SkPathEffect.h"
#include "third_party/skia/include/core/SkRSXform.h"
#include "third_party/skia/include/core/SkPictureRecorder.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "third_party/skia/include/core/SkImageInfo.h"

SkColorType FromPDFColorFormatToSkia(int format) {
  switch (format) { 
    case FPDFBitmap_Gray:
      return kGray_8_SkColorType;
    case FPDFBitmap_BGR:
      return kBGRA_8888_SkColorType;
    case FPDFBitmap_BGRx:
      return kBGRA_8888_SkColorType;
    case FPDFBitmap_BGRA:
      return kBGRA_8888_SkColorType;
  }
  return kBGRA_8888_SkColorType;
}

// Runtime
void _PDFRuntimeInit() {
  FPDF_InitLibrary();
}

void _PDFRuntimeShutdown() {
  FPDF_DestroyLibrary();
}

// PDFDocument

PDFDocumentRef _PDFDocumentLoad(const char* path) {
  return FPDF_LoadDocument(path, nullptr);
}

PDFDocumentRef _PDFDocumentCreate() {
  return FPDF_CreateNewDocument();
}

PDFDocumentRef _PDFDocumentLoadFromBytes(const void* bytes, int len) {
  return FPDF_LoadMemDocument(bytes, len, nullptr);
}

void _PDFDocumentDestroy(PDFDocumentRef document) {
  FPDF_CloseDocument(document);
}

int _PDFDocumentGetVersion(PDFDocumentRef document) {
  int fileVersion = 0;
  FPDF_GetFileVersion(document, &fileVersion);
  return fileVersion;
}

int _PDFDocumentGetPageCount(PDFDocumentRef document) {
  return FPDF_GetPageCount(document);
}

PDFPageRef _PDFDocumentLoadPage(PDFDocumentRef document, int index) {
  return FPDF_LoadPage(document, index);
}

PDFPageRef _PDFDocumentInsertPage(PDFDocumentRef document, int index, int width, int height) {
  return FPDFPage_New(document, index, width, height);
}

void _PDFDocumentRemovePage(PDFDocumentRef document, int index) {
 FPDFPage_Delete(document, index);
}

PDFLinkRef _PDFDocumentGetLink(PDFDocumentRef document, int index, int x, int y) {
 FPDF_PAGE page = FPDF_LoadPage(document, index);
 FPDF_LINK link = FPDFLink_GetLinkAtPoint(page, static_cast<double>(x), static_cast<double>(y));
 FPDF_ClosePage(page);
 return link;
}

int _PDFDocumentGetPageSize(PDFDocumentRef document, int index, int* width, int* height) {
  double w, h;
  int ret = FPDF_GetPageSizeByIndex(document, index, &w, &h);
  
  *width = static_cast<int>(std::ceil(w));
  *height = static_cast<int>(std::ceil(h));

  return ret != 0;
}

void _PDFDocumentSelectAll(PDFDocumentRef document) {
  DCHECK(false);
}

// PDFPage
int _PDFPageGetRotation(PDFPageRef page) {
 return FPDFPage_GetRotation(page);
}

void _PDFPageSetRotation(PDFPageRef page, int rot) {
 FPDFPage_SetRotation(page, rot);
}

void _PDFPageGetSize(PDFPageRef page, int* width, int* height) {
  *width = static_cast<int>(std::ceil(FPDF_GetPageWidth(page)));
  *height = static_cast<int>(std::ceil(FPDF_GetPageHeight(page)));
}

void _PDFPageDestroy(PDFPageRef page) {
 FPDF_ClosePage(page);
}

PDFLinkRef _PDFPageGetLinkAt(PDFPageRef page, int x, int y) {
 FPDF_LINK link = FPDFLink_GetLinkAtPoint(page, static_cast<double>(x), static_cast<double>(y));
 return link;
}

PDFBitmapRef _PDFPageCopyToBitmap(PDFPageRef page) {
  int width = static_cast<int>(std::ceil(FPDF_GetPageWidth(page)));
  int height = static_cast<int>(std::ceil(FPDF_GetPageHeight(page)));
  
  FPDF_BITMAP bitmap = FPDFBitmap_Create(width, height, 0);
  FPDFBitmap_FillRect(bitmap, 0, 0, width, height, 0xFFFFFFFF);
  FPDF_RenderPageBitmap(bitmap,
                        page,
                        0,
                        0,
                        width,
                        height,
                        FPDFPage_GetRotation(page),
                        0);
 return bitmap;                                   
}

int _PDFPageCopyToTextUTF8(PDFPageRef page, const char** buffer) {
 DCHECK(false);
 return 0;
}

// Search

PDFSearchRef _PDFSearchStart(PDFPageRef page, const char* str) {
 DCHECK(false);
 return nullptr;
}

void _PDFSearchDestroy(PDFSearchRef search) {
 DCHECK(false);
}

void _PDFSearchStop(PDFSearchRef search) {
 DCHECK(false);
}

// PDFLink
void _PDFLinkDestroy(PDFLinkRef link) {
 DCHECK(false);
}

// PDFBookmark
void _PDFBookmarkDestroy(PDFBookmarkRef bookmark) {
 DCHECK(false);
}

// PDFBitmap

PDFBitmapRef _PDFBitmapCreate(int width, int height) {
 return FPDFBitmap_Create(width, height, 0); 
}

void _PDFBitmapDestroy(PDFBitmapRef bitmap) {
  FPDFBitmap_Destroy(bitmap);
}

int _PDFBitmapGetStride(PDFBitmapRef bitmap) {
  return FPDFBitmap_GetStride(bitmap);
}

int _PDFBitmapGetWidth(PDFBitmapRef bitmap) {
  return FPDFBitmap_GetWidth(bitmap);
}

int _PDFBitmapGetHeight(PDFBitmapRef bitmap) {
  return FPDFBitmap_GetHeight(bitmap);
}

void _PDFBitmapGetSize(PDFBitmapRef bitmap, int* width, int* height) {
 *width = FPDFBitmap_GetWidth(bitmap);
 *height = FPDFBitmap_GetHeight(bitmap);
}

BitmapRef _PDFBitmapCopy(PDFBitmapRef bitmap) {
 int format = FPDFBitmap_GetFormat(bitmap);
 SkColorType sk_format = FromPDFColorFormatToSkia(format);
 SkImageInfo info = SkImageInfo::Make(
        FPDFBitmap_GetWidth(bitmap), 
        FPDFBitmap_GetHeight(bitmap),
        sk_format, 
        kOpaque_SkAlphaType);
 SkPixmap src(info, 
              FPDFBitmap_GetBuffer(bitmap),
              FPDFBitmap_GetStride(bitmap));
 SkBitmap* bmp = new SkBitmap();
 bmp->installPixels(src);
 return bmp;
}

void* _PDFBitmapGetBuffer(PDFBitmapRef bitmap) {
  return FPDFBitmap_GetBuffer(bitmap);
}

const void* _PDFBitmapGetConstBuffer(PDFBitmapRef bitmap) {
  return static_cast<const void*>(FPDFBitmap_GetBuffer(bitmap));
}
