// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class HtmlFrameElement : HtmlElement {
  
  public var hasFrameBorder: Bool {
    return _HTMLFrameElementGetHasFrameBorder(reference) != 0
  }

  public var noResize: Bool {
    return _HTMLFrameElementGetNoResize(reference) != 0
  }

  public init(document: WebDocument) {
    super.init(reference: _HTMLFrameElementCreate(document.reference))
  }

  required init(reference: WebNodeRef) {
    super.init(reference: reference)
  }
  
}

extension WebElement {

  public func asHtmlFrame() -> HtmlFrameElement? {
    return asHtmlElement(to: HtmlFrameElement.self)
  }

}