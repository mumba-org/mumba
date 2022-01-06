// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class HtmlFormElement : HtmlElement {

  public init(document: WebDocument) {
    super.init(reference: _HTMLFormElementCreate(document.reference))
  }

  required init(reference: WebNodeRef) {
    super.init(reference: reference)
  }
}

extension WebElement {

  public func asHtmlForm() -> HtmlFormElement? {
    return asHtmlElement(to: HtmlFormElement.self)
  }

}