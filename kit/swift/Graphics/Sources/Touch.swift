// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum TouchAction : Int {
  case None          = 0
  case PanLeft       = 1
  case PanRight      = 2
  case PanX          = 3
  case PanUp         = 4
  case PanDown       = 8
  case PanY          = 12
  case Pan           = 15
  case PinchZoom     = 16
  case Manipulation  = 31
  case DoubleTapZoom = 32
  case Auto          = 63
}

public protocol TouchFactory {
  static func instance() -> Self?
}
