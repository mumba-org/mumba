// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class PDFLink : PDFElement {
	
  var reference : PDFLinkRef

  init(reference: PDFLinkRef) {
    self.reference = reference
  }
  
  deinit {
    // TODO: the reference on c++ part should be aware of ownership semantics
    // so it wont delete a reference owned by some other object
    _PDFLinkDestroy(reference)
  }

}