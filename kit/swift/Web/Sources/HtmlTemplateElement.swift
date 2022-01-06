// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class HtmlTemplateElement : HtmlElement {

  public var content: WebDocumentFragment {
    let ref = _HTMLTemplateElementGetContent(reference)
    return WebDocumentFragment(reference: ref!)
  }

}

extension WebElement {

  public func asHtmlTemplate() -> HtmlTemplateElement? {
    return asHtmlElement(to: HtmlTemplateElement.self)
  }

}