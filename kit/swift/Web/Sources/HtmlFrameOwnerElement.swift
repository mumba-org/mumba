// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class HtmlFrameOwnerElement : HtmlElement {

    public init(name: String, document: WebDocument) {
      var nameStr: UnsafePointer<Int8>?
      name.withCString {
        nameStr = $0
      }
      super.init(reference: _HTMLFrameOwnerElementCreate(nameStr, document.reference))
    }

    required init(reference: WebNodeRef) {
        super.init(reference: reference)
    }

}

extension WebElement {

  public func asHtmlFrameOwner() -> HtmlFrameOwnerElement? {
    return asHtmlElement(to: HtmlFrameOwnerElement.self)
  }

}