// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum WindowContainerType : Int {
  case Normal = 0
  case Background
  case Persistent
}

public enum WindowOpenDisposition : Int {
  case Unknown = 0
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

public struct WindowFeatures {
  public var x: Float?
  public var y: Float?
  public var width: Float?
  public var height: Float?
}

public struct CreateNewWindowParams {
  public var userGesture: Bool = false
  public var windowContainerType: WindowContainerType = .Normal
  public var windowName: String 
  public var openerSuppressed: Bool = false
  public var windowDisposition: WindowOpenDisposition = .NewWindow
  public var targetUrl: String
  public var windowFeatures: WindowFeatures = WindowFeatures()
  public var windowId: Int
  public var swappedOut: Bool = false
  public var hidden: Bool = false
  public var neverVisible: Bool = false
  public var enableAutoResize: Bool = false
  public var size: IntSize = IntSize()//IntSize(width: 400, height: 200)
  public var zoomLevel: Float = 1.0
}
