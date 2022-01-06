// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
public typealias PlatformCursor = UInt
public let PlatformCursorNil: UInt = 0
#else
public typealias PlatformCursor = Int
#endif

public enum CursorType : Int {
  case CursorPointer = 1
  case CursorCross = 2
  case CursorHand = 3
  case CursorIBeam = 4
  case CursorWait = 5
  case CursorHelp = 6
  case CursorEastResize = 7
  case CursorNorthResize = 8
  case CursorNorthEastResize = 9
  case CursorNorthWestResize = 10
  case CursorSouthResize = 11
  case CursorSouthEastResize = 12
  case CursorSouthWestResize = 13
  case CursorWestResize = 14
  case CursorNorthSouthResize = 15
  case CursorEastWestResize = 16
  case CursorNorthEastSouthWestResize = 17
  case CursorNorthWestSouthEastResize = 18
  case CursorColumnResize = 19
  case CursorRowResize = 20
  case CursorMiddlePanning = 21
  case CursorEastPanning = 22
  case CursorNorthPanning = 23
  case CursorNorthEastPanning = 24
  case CursorNorthWestPanning = 25
  case CursorSouthPanning = 26
  case CursorSouthEastPanning = 27
  case CursorSouthWestPanning = 28
  case CursorWestPanning = 29
  case CursorMove = 30
  case CursorVerticalText = 31
  case CursorCell = 32
  case CursorContextMenu = 33
  case CursorAlias = 34
  case CursorProgress = 35
  case CursorNoDrop = 36
  case CursorCopy = 37
  case CursorNone = 38
  case CursorNotAllowed = 39
  case CursorZoomIn = 40
  case CursorZoomOut = 41
  case CursorGrab = 42
  case CursorGrabbing = 43
  case CursorCustom = 44
}

public class Cursor {
  
  public var type: CursorType
  public var platformCursor: PlatformCursor
  public var deviceScaleFactor: Float

  public init() {
    type = .CursorNone
    platformCursor = PlatformCursorNil
    deviceScaleFactor = 1.0
  }

  public init(type: CursorType) {
    self.type = type
    platformCursor = PlatformCursorNil
    deviceScaleFactor = 1.0
  }

}
extension Cursor : Equatable {
  
  public static func == (left:	Cursor,	right: Cursor) -> Bool {
    return (left.type == right.type) && 
    (left.platformCursor == right.platformCursor) && 
    (left.deviceScaleFactor == right.deviceScaleFactor)
  }

  public static func != (left: Cursor, right: Cursor) -> Bool {
    return !(left == right)
  }

}