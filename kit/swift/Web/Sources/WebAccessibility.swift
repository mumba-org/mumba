// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebAXObject {
  
  var reference: WebAXObjectRef

  init(reference: WebAXObjectRef) {
    self.reference = reference
  }

  deinit {
    _WebAXObjectDestroy(reference)
  }

}

public enum WebAXEvent : Int {
	case ActiveDescendantChanged = 0
    case Alert
    case AriaAttributeChanged
    case AutocorrectionOccured
    case Blur
    case CheckedStateChanged
    case ChildrenChanged
    case DocumentSelectionChanged
    case Focus
    case Hide
    case Hover
    case InvalidStatusChanged
    case LayoutComplete
    case LiveRegionChanged
    case LoadComplete
    case LocationChanged
    case MenuListItemSelected
    case MenuListItemUnselected
    case MenuListValueChanged
    case RowCollapsed
    case RowCountChanged
    case RowExpanded
    case ScrollPositionChanged
    case ScrolledToAnchor
    case SelectedChildrenChanged
    case SelectedTextChanged
    case Show
    case TextChanged
    case TextInserted
    case TextRemoved
    case ValueChanged
}