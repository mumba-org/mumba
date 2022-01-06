// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebDocumentFragment : WebContainerNode {
 
  public var isTemplateContent: Bool {
    return _WebDocumentFragmentIsTemplateContent(reference) != 0
  }

  public static func create(document: WebDocument) -> WebDocumentFragment {
    let ref = _WebDocumentFragmentCreate(document.reference)
    return WebDocumentFragment(reference: ref!)
  }

  public func ParseHTML(_ html: String, context: WebElement) {
    html.withCString {
      _WebDocumentFragmentParseHTML(reference, $0, context.reference)
    }
  }
  
  public func ParseXML(_ xml: String, context: WebElement) -> Bool {
    return xml.withCString {
      return _WebDocumentFragmentParseXML(reference, $0, context.reference) != 0
    }
  }

}