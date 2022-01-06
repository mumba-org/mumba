// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public class HtmlInputElement : HtmlElement {

    public var value: String {
      get {
        var len: CInt = 0
        guard let ref = _HTMLInputElementGetValue(reference, &len) else {
            return String()
        }
        return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
      }
      set {
        newValue.withCString {
          _HTMLInputElementSetValue(reference, $0)
        }
      }
    }

    public init(document: WebDocument) {
        super.init(reference: _HTMLInputElementCreate(document.reference))
    }

    required init(reference: WebNodeRef) {
        super.init(reference: reference)
    }

}

extension WebElement {

  public func asHtmlInput() -> HtmlInputElement? {
    return asHtmlElement(to: HtmlInputElement.self)
  }

}