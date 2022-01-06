// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

// TODO: fill up with the functionalities that clients
// would like to be able to respond to on a particular document
public protocol PDFDocumentDelegate {
 // pages
 func onPageLoaded(index: Int, page: PDFPage)
 func onPageAdded(index: Int, page: PDFPage, size: IntSize)
 func onPageRemoved(index: Int)
}

public class PDFDocument {
	
	public var version: Int {
		return Int(_PDFDocumentGetVersion(reference))
	}

	public var pageCount: Int {
		return Int(_PDFDocumentGetPageCount(reference))
	}

	public var delegate: PDFDocumentDelegate

	// Create a new blank pdf document
	public static func new(delegate: PDFDocumentDelegate) -> PDFDocument {
		let reference = _PDFDocumentCreate()
		return PDFDocument(reference: reference!, delegate: delegate)
	}

  // Load from path
	public static func load(path: String, delegate: PDFDocumentDelegate) -> PDFDocument? {
		var reference: PDFDocumentRef? = nil
		
		path.withCString { cstr in 
			reference = _PDFDocumentLoad(cstr)
		}

		if reference == nil {
			return nil
		}

		return PDFDocument(reference: reference!, delegate: delegate)
	}
 
  /// Load from bytes
	public static func load(bytes: UnsafeRawPointer, lenght: Int, delegate: PDFDocumentDelegate) -> PDFDocument? {
		let reference = _PDFDocumentLoadFromBytes(bytes, Int32(lenght))
		if reference == nil {
			return nil
		}
		return PDFDocument(reference: reference!, delegate: delegate)
	}

	var reference: PDFDocumentRef

	init(reference: PDFDocumentRef, delegate: PDFDocumentDelegate) {
		self.reference = reference
		self.delegate = delegate
	}

	deinit {
		_PDFDocumentDestroy(reference)
	}

	public func loadPage(index: Int) -> PDFPage? {
		let pageref = _PDFDocumentLoadPage(reference, Int32(index))
		if pageref == nil {
			return nil
		}
		let page = PDFPage(reference: pageref!, document: self)
		delegate.onPageLoaded(index: index, page: page)
		return page 
	}

	public func addPage(index: Int, size: IntSize) -> PDFPage? {
		let pageref = _PDFDocumentInsertPage(reference, Int32(index), Int32(size.width), Int32(size.height))
		if pageref == nil {
			return nil
		}
		let page = PDFPage(reference: pageref!, document: self)
		delegate.onPageAdded(index: index, page: page, size: size)
		return page
	}

	public func removePage(index: Int) {
		_PDFDocumentRemovePage(reference, Int32(index))
		delegate.onPageRemoved(index: index)
	}

	public func getLink(index: Int, at: IntPoint) -> PDFLink? {
		let linkref = _PDFDocumentGetLink(reference, Int32(index), Int32(at.x), Int32(at.y))
		if linkref == nil {
			return nil
		}
		return PDFLink(reference: linkref!)
	}

	public func getPageSizeAt(index: Int) -> IntSize? {
		var w: Int32 = 0, h: Int32 = 0
		let ok = _PDFDocumentGetPageSize(reference, Int32(index), &w, &h) == 0 ? false : true 
		if !ok {
			return nil
		}
		return IntSize(width: Int(w), height: Int(h))
	}

	public func selectAll() {
		_PDFDocumentSelectAll(reference)
	}

}