// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_PDF_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_PDF_SHIMS_H_

#include "Globals.h"

typedef void* PDFDocumentRef;
typedef void* PDFPageRef;
typedef void* PDFSearchRef;
typedef void* PDFBookmarkRef;
typedef void* PDFLinkRef;
typedef void* PDFBitmapRef;
typedef void* BitmapRef;

EXPORT void _PDFRuntimeInit();
EXPORT void _PDFRuntimeShutdown();

// PDFDocument
EXPORT PDFDocumentRef _PDFDocumentCreate();
EXPORT PDFDocumentRef _PDFDocumentLoad(const char* path);
EXPORT PDFDocumentRef _PDFDocumentLoadFromBytes(const void* bytes, int len);
EXPORT void _PDFDocumentDestroy(PDFDocumentRef document);
EXPORT int _PDFDocumentGetVersion(PDFDocumentRef document);
EXPORT int _PDFDocumentGetPageCount(PDFDocumentRef document);
EXPORT PDFPageRef _PDFDocumentLoadPage(PDFDocumentRef document, int index);
EXPORT PDFPageRef _PDFDocumentInsertPage(PDFDocumentRef document, int index, int width, int height);
EXPORT void _PDFDocumentRemovePage(PDFDocumentRef document, int index);
EXPORT PDFLinkRef _PDFDocumentGetLink(PDFDocumentRef document, int index, int x, int y);
EXPORT int _PDFDocumentGetPageSize(PDFDocumentRef document, int index, int* width, int* height);
EXPORT void _PDFDocumentSelectAll(PDFDocumentRef document);

// PDFPage
EXPORT int _PDFPageGetRotation(PDFPageRef page);
EXPORT void _PDFPageSetRotation(PDFPageRef page, int rot);
EXPORT void _PDFPageGetSize(PDFPageRef page, int* width, int* height);
EXPORT void _PDFPageDestroy(PDFPageRef page);
EXPORT PDFLinkRef _PDFPageGetLinkAt(PDFPageRef page, int x, int y);
EXPORT PDFBitmapRef _PDFPageCopyToBitmap(PDFPageRef page);
EXPORT int _PDFPageCopyToTextUTF8(PDFPageRef page, const char** buffer);

// Search
EXPORT PDFSearchRef _PDFSearchStart(PDFPageRef page, const char* str);
EXPORT void _PDFSearchDestroy(PDFSearchRef search);
EXPORT void _PDFSearchStop(PDFSearchRef search);

// PDFLink
EXPORT void _PDFLinkDestroy(PDFLinkRef link);

// PDFBookmark
EXPORT void _PDFBookmarkDestroy(PDFBookmarkRef bookmark);

// PDFBitmap
EXPORT PDFBitmapRef _PDFBitmapCreate(int width, int height);
EXPORT void _PDFBitmapDestroy(PDFBitmapRef handle);
EXPORT int _PDFBitmapGetWidth(PDFBitmapRef bitmap);
EXPORT int _PDFBitmapGetHeight(PDFBitmapRef bitmap);
EXPORT int _PDFBitmapGetStride(PDFBitmapRef bitmap);
EXPORT void _PDFBitmapGetSize(PDFBitmapRef bitmap, int* width, int* height);
EXPORT BitmapRef _PDFBitmapCopy(PDFBitmapRef bitmap);
EXPORT void* _PDFBitmapGetBuffer(PDFBitmapRef bitmap);
EXPORT const void* _PDFBitmapGetConstBuffer(PDFBitmapRef bitmap);

#endif