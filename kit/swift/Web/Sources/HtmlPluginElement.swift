// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class HtmlPluginElement : HtmlElement {

    public init(name: String, document: WebDocument) {
      var nameStr: UnsafePointer<Int8>?
      name.withCString {
        nameStr = $0
      }
      super.init(reference: _HTMLPluginElementCreate(nameStr, document.reference))
    }

    required init(reference: WebNodeRef) {
        super.init(reference: reference)
    }

}

extension WebElement {

  public func asHtmlPlugin() -> HtmlPluginElement? {
    return asHtmlElement(to: HtmlPluginElement.self)
  }

}