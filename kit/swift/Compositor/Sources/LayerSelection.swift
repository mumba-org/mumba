// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public struct LayerSelectionBound {
  
  public enum SelectionBoundType : Int {
  	case Unknown = 0
    case Left
    case Right
    case Center
    case Empty
  }

  public var type: SelectionBoundType
  public var edgeTop: IntPoint
  public var edgeBottom: IntPoint
  public var layerId: Int
  public var hidden: Bool

  public init() {
  	type = .Unknown
  	edgeTop = IntPoint()
  	edgeBottom = IntPoint()
  	layerId = -1
    hidden = false
  }
}

public struct LayerSelection {
	
	public var start: LayerSelectionBound
	public var end: LayerSelectionBound

	public init() {
		start = LayerSelectionBound()
		end = LayerSelectionBound()
	}
	
}
