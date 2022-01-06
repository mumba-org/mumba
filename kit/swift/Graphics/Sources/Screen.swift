// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO: isso aqui deve ser um protocolo, e deve ser implementado
// por classes concretas na UI

public enum ScreenType {
  case Native
}

open class Screen {

  public var cursorScreenPoint: IntPoint { 
    //assert(false)
    ////print("warning: called not implemented Screen.cursorScreenPoint.. remember to implement")
    return IntPoint() 
  }

  public var primaryDisplay: Display { 
    //assert(false)
    ////print("warning: called not implemented Screen.primaryDisplay.. remember to implement")
    return Display() 
  }

  public static var instance: Screen {
      if _instance == nil {
        _instance = Screen()
      }

      return _instance!
  }

  public static var nativeScreen: Screen {
    return Screen.instance
  }

  public init() {}

  public class func getDisplayNearestWindow(windowId: Int) -> Display? {
    return Screen.instance._getDisplayNearestWindow(windowId: windowId)
  }

  public class func getDisplayNearestPoint(point: IntPoint) -> Display? {
    return Display()
  }

  public class func getScreenFor(windowId: Int) -> Screen {
    return Screen.instance
  }

  public class func getScreenByType(type: ScreenType) -> Screen {
    return Screen.instance
  }

  public func getDisplayMatching(bounds: IntRect) -> Display? {
    return Display()
  }

  public func _getDisplayNearestWindow(windowId: Int) -> Display? {
    //assert(false)
    ////print("warning: called not implemented Screen.getDisplayNearestWindow.. remember to implement")
    return Display()
  }

  public func getAllDisplays() -> [Display] {
    //assert(false)
    ////print("warning: called not implemented Screen.getAllDisplays.. remember to implement")
    return [Display]()
  }

  public func addObserver(_ observer: DisplayObserver) {}
  public func removeObserver(_ observer: DisplayObserver) {}

  public func DIPToScreenRectInWindow(window: Int,
                                      dipRect: IntRect) -> IntRect {
    let scale = Screen.getDisplayNearestWindow(windowId: window)!.deviceScaleFactor
    return scaleToEnclosingRect(rect: dipRect, xScale: scale, yScale: scale)
  }

  private static var _instance: Screen?

}
