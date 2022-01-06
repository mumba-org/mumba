// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public class WebDragData {

  var reference: WebDragDataRef

  init(reference: WebDragDataRef) {
    self.reference = reference
  }

  deinit {}
  
}

public struct WebDraggableRegion {
 	public var draggable: Bool
  	public var bounds: IntRect
}

public struct WebDragOperation : OptionSet {
  
  public let rawValue: Int

  public static let None = WebDragOperation(rawValue: 0)
  public static let Copy = WebDragOperation(rawValue: 1)
  public static let Link = WebDragOperation(rawValue: 2)
  public static let Generic = WebDragOperation(rawValue: 4)
  public static let Private = WebDragOperation(rawValue: 8)
  public static let Move = WebDragOperation(rawValue: 16)
  public static let Delete = WebDragOperation(rawValue: 32)
  
  public init(rawValue: Int) { 
    self.rawValue = rawValue 
  }
}

public typealias WebDragOperationsMask = WebDragOperation