import Base
import Graphics
import UI
import Web
import Javascript
import Platform
import Compositor
import Foundation
import ProtocolBuffers
import WorldApi
import Channel
import Net

public class WorldApp : UIApplicationDelegate,
                        UIWebWindowDelegate,
                        UIWebFrameObserver {

  public var app: UIApplication?
  public var window: UIWindow? {
    return webWindow
  }
  private var webWindow: UIWebWindow?
  
  public init() {
    app = UIApplication(delegate: self)
    try! TaskScheduler.createAndStartWithDefaultParams()
  }

  public func run() {
    app!.run()
  }

  public func createWindow(application: UIApplication, dispatcher: UIDispatcher) -> UIWindow {
    webWindow = UIWebWindow(application: application, dispatcher: dispatcher, delegate: self, headless: application.isHeadless)
    return webWindow!
  }
  
  public func initializeVisualProperties(params: VisualProperties) {
    webWindow!.initializeVisualProperties(params: params)
  }

  public func onExternalTextureLayerRequested() {}

  public func willHandleMouseEvent(event: WebMouseEvent) {}
  public func willHandleGestureEvent(event: WebGestureEvent) {}
  public func willHandleKeyEvent(event: WebKeyboardEvent) {}
  public func setActive(active: Bool) {}
  public func setBackgroundOpaque(opaque: Bool) {}
  public func didStartLoading() {}
  public func didStopLoading() {}
  public func onFrameAttached(_ frame: UIWebFrame) {
    frame.addObserver(self)
  }
  public func onPageWasShown(_ window: UIWindow) {
    //print("World.onPageWasShown")
    //mainView.isVisible = true
  }

  public func onPageWasHidden(_ window: UIWindow) {
    //mainView.isVisible = false
  }
}

let app = WorldApp()
app.run()
