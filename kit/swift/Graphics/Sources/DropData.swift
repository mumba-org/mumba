// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum DragOperation: Int {
    case DragNone = 0
    case DragMove = 1
    case DragCopy = 2
    case DragLink = 4
}

public enum DragEventSource : Int {
  case None = -1
  case Mouse = 0
  case Touch = 1
}

public struct DropData {
  public struct Metadata {}
  public var viewId: Int = 0
  public var url: String = String()
  public var urlTitle: String = String()
  public var downloadMetadata: String = String()

  public init() {}
}