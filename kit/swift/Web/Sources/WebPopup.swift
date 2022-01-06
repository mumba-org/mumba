// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum WebPopupType : Int {
	case None = 0
    case Page
}

public class WebPagePopup {
  
  var reference: WebPagePopupRef

  init(reference: WebPagePopupRef) {
    self.reference = reference
  }

}

public struct WebPopupMenuInfo {
  public var itemHeight: Int = 0
  public var itemFontSize: Int = 0
  public var selectedIndex: Int = 0
  public var items: [WebMenuItemInfo] = []
  public var rightAligned: Bool = false
  public var allowMultipleSelection: Bool = false

  public init() {}
}

public class WebExternalPopupMenuClient {
  
  var reference: WebExternalPopupMenuClientRef

  init(reference: WebExternalPopupMenuClientRef) {
    self.reference = reference
  }

}

public class WebExternalPopupMenu {
  
  var reference: WebExternalPopupMenuRef

  init(reference: WebExternalPopupMenuRef) {
    self.reference = reference
  }

}