// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
public typealias AcceleratedWidget = UInt
public let NullAcceleratedWidget: UInt = 0
#else
public typealias AcceleratedWidget = Int
#endif

public enum WindowMode : Int {
  case Undefined = 0
  case Tabbed = 1
  case Window = 2
}

public enum WindowOpenDisposition : Int {
  case Unknown
  case CurrentTab
  case SingletonTab
  case NewForegroundTab
  case NewBackgroundTab
  case NewPopup
  case NewWindow
  case SaveToDisk
  case OffTheRecord
  case IgnoreAction
  case SwitchToTab
}