// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public typealias PDFSearchHandle = PDFSearchRef
public typealias PDFPageHandle = PDFPageRef
public typealias PDFDocumentHandle = PDFDocumentRef
public typealias PDFBitmapHandle = PDFBitmapRef
public typealias PDFLinkHandle = PDFLinkRef

@inlinable
public func pdfRuntimeInit() {
  _PDFRuntimeInit()
}

@inlinable
public func pdfRuntimeShutdown() {
  _PDFRuntimeShutdown()
}

@inlinable
public func pdfSearchDestroy(_ ref: PDFSearchHandle) {
  _PDFSearchDestroy(ref)
}

@inlinable
public func pdfSearchStart(_ ref: PDFSearchHandle, _ cstr: UnsafePointer<Int8>) -> PDFSearchHandle? {
  return _PDFSearchStart(ref, cstr)	
}

@inlinable
public func pdfSearchStop(_ ref: PDFSearchHandle) {
  _PDFSearchStop(ref)
}

@inlinable
public func pdfPageDestroy(_ ref: PDFPageHandle) {
  _PDFPageDestroy(ref)
}

@inlinable
public func pdfPageGetRotation(_ ref: PDFPageHandle) -> CInt {
  return _PDFPageGetRotation(ref)
}

@inlinable
public func pdfPageSetRotation(_ ref: PDFPageHandle, _ value: CInt) {
  _PDFPageSetRotation(ref, value)
} 

@inlinable
public func pdfPageGetSize(_ ref: PDFPageHandle, _ width: inout CInt, _ height: inout CInt) {
  _PDFPageGetSize(ref, &width, &height)
}

@inlinable
public func pdfPageGetLinkAt(_ ref: PDFPageHandle, _ x: CInt, _ y: CInt) -> PDFLinkHandle? {
  return _PDFPageGetLinkAt(ref, x, y)
}

@inlinable
public func pdfPageCopyToBitmap(_ ref: PDFPageHandle) -> PDFBitmapHandle? {
  return _PDFPageCopyToBitmap(ref)
}

@inlinable
public func pdfPageCopyToTextUTF8(_ ref: PDFPageHandle, _ buffer: inout UnsafePointer<Int8>?) -> CInt {
  return _PDFPageCopyToTextUTF8(ref, &buffer)
}

@inlinable
public func pdfDocumentInsertPage(_ ref: PDFDocumentHandle, _ index: CInt, _ width: CInt, _ height: CInt) -> PDFPageHandle? {
  return _PDFDocumentInsertPage(ref, index, width, height)
}