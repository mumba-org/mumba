// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum WebShadowRootType : Int {
  case V0 = 0
  case Open = 1 
  case Closed  = 2
  case UserAgent = 3
}

public class WebShadowRoot : WebContainerNode {

  public var innerHtml: String {
    get {
      let ref = _WebShadowRootGetInnerHtml(reference)
      return ref != nil ? String(cString: ref!) : String()
    }
    set {
      newValue.withCString {
        _WebShadowRootSetInnerHtml(reference, $0, CInt(newValue.count))
      }  
    }
  }

  public var styleSheets: CSSStyleSheetList {
    get {
      let ref = _WebShadowRootGetStyleSheetList(reference)
      return CSSStyleSheetList(reference: ref!)
    }
    set {
      _WebShadowRootSetStyleSheetList(reference, newValue.reference)
    }
  }

  override init(reference: WebNodeRef) {
    super.init(reference: reference)
  }

}