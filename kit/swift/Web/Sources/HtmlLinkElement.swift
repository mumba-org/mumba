// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class HtmlLinkElement : HtmlElement {

    public init(document: WebDocument) {
        super.init(reference: _HTMLLinkElementCreate(document.reference))
    }

    required init(reference: WebNodeRef) {
        super.init(reference: reference)
    }

}

extension WebElement {

  public func asHtmlLink() -> HtmlLinkElement? {
    return asHtmlElement(to: HtmlLinkElement.self)
  }

}