// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct UIException {
  public let code: Int
  public let message: String

  public static let Ok                = UIException(code: 0, message: "UI: OK")
  public static let CreateLayerTree   = UIException(code: 100, message: "UI: error creating LayerTreeHost")
  public static let CreateLayer       = UIException(code: 101, message: "UI: error creating Layer")
  public static let AddChildWindow    = UIException(code: 102, message: "UI: error adding child window")

  public init(code: Int, message: String) {
    self.code = code
    self.message = message
  }
}

public enum UIError : Error {
  case OnInit(exception: UIException)
  case OnCompositorCreate(exception: UIException)
  case OnLayerCreate(exception: UIException)
  case OnAddChild(exception: UIException)
  case Unknown(exception: UIException)
}
