// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import _C
import Graphics

public class PDFSearchContext {

	public var page: PDFPage {
		return _page!
	}

  var reference: _C.PDFSearchHandle
	weak var _page: PDFPage?

	init(page: PDFPage, reference: _C.PDFSearchHandle) {
		self.reference = reference
		_page = page
	}

	deinit {
		_C.pdfSearchDestroy(reference)
	}

	public func stop() {
		_C.pdfSearchStop(reference)
	}

}

public class PDFPage : PDFElement {

	public enum Rotation : Int {
		case Rot0   = 0
		case Rot90  = 1
		case Rot180 = 2
		case Rot270 = 3
	}

	public var rotation: Rotation {
		get {
			let rot = _C.pdfPageGetRotation(reference) 
			return Rotation(rawValue: Int(rot))!
		}
		set {
			_C.pdfPageSetRotation(reference, CInt(newValue.rawValue))
		}
	}

	public var size: IntSize {
		//get {
			var w: CInt = 0, h: CInt = 0
			_C.pdfPageGetSize(reference, &w, &h)
			return IntSize(width: Int(w), height: Int(h))
		//}
		//set (value) {
		//	_PDFPageSetSize(reference, Int32(value.width), Int32(value.height))
		//}
	}
	
	public weak var document: PDFDocument?

	var reference: _C.PDFPageHandle

	public init(document: PDFDocument,
		        	index: Int,
            	size: IntSize) {
		self.document = document
		reference = _C.pdfDocumentInsertPage(document.reference, CInt(index), CInt(size.width), CInt(size.height))!
		document.delegate.onPageAdded(index: index, page: self, size: size)
	}

	init(reference: _C.PDFPageHandle, document: PDFDocument) {
  	self.document = document
		self.reference = reference
 	}

 	deinit {
		// TODO: the reference on c++ part should be aware of ownership semantics
    	// so it wont delete a reference owned by some other object
    _C.pdfPageDestroy(reference)
 	}

	public func getLink(at: IntPoint) -> PDFLink? {
		if let linkref = _C.pdfPageGetLinkAt(reference, CInt(at.x), CInt(at.y)) {
      return PDFLink(reference: linkref)
    }
		return nil
	}

	public func copyToBitmap() -> PDFBitmap? {
		if let ref = _C.pdfPageCopyToBitmap(reference) {
		  return PDFBitmap(reference: ref)
    }
    return nil
	}

	public func copyToText() -> String? {
		var buffer: UnsafePointer<Int8>?
		let _ = _C.pdfPageCopyToTextUTF8(reference, &buffer)
		return String(describing: buffer)
	}

	public func search(text: String) -> PDFSearchContext {
		var ref: _C.PDFSearchHandle? = nil 
		text.withCString { cstr in
			ref = _C.pdfSearchStart(reference, cstr)
		}
		return PDFSearchContext(page: self, reference: ref!)
	}

}