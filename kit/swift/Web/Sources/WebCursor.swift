// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public struct WebCursorInfo {
  
  public enum CursorType : Int {
    case Pointer = 0
    case Cross
    case Hand
    case IBeam
    case Wait
    case Help
    case EastResize
    case NorthResize
    case NorthEastResize
    case NorthWestResize
    case SouthResize
    case SouthEastResize
    case SouthWestResize
    case WestResize
    case NorthSouthResize
    case EastWestResize
    case NorthEastSouthWestResize
    case NorthWestSouthEastResize
    case ColumnResize
    case RowResize
    case MiddlePanning
    case EastPanning
    case NorthPanning
    case NorthEastPanning
    case NorthWestPanning
    case SouthPanning
    case SouthEastPanning
    case SouthWestPanning
    case WestPanning
    case Move
    case VerticalText
    case Cell
    case ContextMenu
    case Alias
    case Progress
    case NoDrop
    case Copy
    case None
    case NotAllowed
    case ZoomIn
    case ZoomOut
    case Grab
    case Grabbing
    case Custom
  }
  
  public var type: CursorType = CursorType.Pointer
  public var hotSpot: IntPoint = IntPoint()
  public var imageScaleFactor: Float = 1.0
  public var customImage: ImageSkia?

  public init() {}

  public init(type: CursorType,
              hotSpot: IntPoint,
              imageScaleFactor: Float,
              customImage: ImageSkia?) {
    self.type = type
    self.hotSpot = hotSpot
    self.imageScaleFactor = imageScaleFactor
    self.customImage = customImage
  }

}