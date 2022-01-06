// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Web

public protocol UIWebFrameProxyDelegate : class {
  //var window: UIWebWindow? { get }
  func onFrameDetach()
}

public class UIWebFrameProxy : WebRemoteFrameClient {
  
  //private weak var window: UIWebWindow?
  public var frame: WebRemoteFrame!
  public weak var window: UIWebWindow?
  public let routingId: Int

  internal static var frameProxyMap: [Int: UIWebFrameProxy] = [:]
  
  private weak var delegate: UIWebFrameProxyDelegate?
  
  public static func fromRoutingID(routingId: Int) -> UIWebFrameProxy? {
    if let proxy = UIWebFrameProxy.frameProxyMap[routingId] {
      return proxy
    }
    return nil
  }

  public static func createProxyToReplaceFrame(
    delegate: UIWebFrameProxyDelegate,
    frameToReplace: UIWebFrame,
    routingId: Int,
    scope: WebTreeScopeType) -> UIWebFrameProxy {

    let proxy = UIWebFrameProxy(delegate: delegate, routingId: routingId)
    //proxy.uniqueName = frameToReplace.uniqueName
    //proxy.devtoolsFrameToken = frameToReplace.devToolsFrameToken

    // When a RenderFrame is replaced by a RenderProxy, the WebRemoteFrame should
    // always come from WebRemoteFrame.create and a call to WebFrame.swap must
    // follow later.
    let frame: WebRemoteFrame = WebFrame.createRemote(scope: scope, client: proxy)

    // If frame_to_replace has a RenderFrameProxy parent, then its
    // RenderUIWindow will be destroyed along with it, so the new
    // RenderFrameProxy uses its parent's RenderUIWindow.
    //var window: UIWebWindow? 
    //if frameToReplace.webFrame!.parent == nil ||
    //   frameToReplace.webFrame!.parent!.isWebLocalFrame {
    //  window = frameToReplace.window!
    //}
    //else {
      // oops
    //  //print("OOPS. UIWebFrameProxy.fromWebFrame() which is not implemented.\n therefore this program will break")
    //  window = UIWebFrameProxy.fromWebFrame(
    //              frameToReplace.webFrame!.parent!.toWebRemoteFrame()).window!
    //}
    
    proxy.initialize(webFrame: frame, window: frameToReplace.window!)
    
    return proxy
  }

  public static func fromWebFrame(_ webFrame: WebRemoteFrame) -> UIWebFrameProxy? {
    //print("calling the not implemented static func UIWebFrameProxy.fromWebFrame.. dont rely on the result")
    return nil
  }

  public init(delegate: UIWebFrameProxyDelegate, routingId: Int) {//, frame: WebFrame) {
    self.routingId = routingId
    self.delegate = delegate

    UIWebFrameProxy.frameProxyMap[routingId] = self
  }

  public func initialize(webFrame: WebRemoteFrame, window: UIWebWindow) {
    self.frame = webFrame
    self.window = window
  }

  // WebRemoteFrameClient
  public func frameDetached(type: WebFrameDetachType) {
    if let d = delegate {
      d.onFrameDetach()
    }
    // TODO:
    //UIWebFrameProxy.frameProxyMap.remove(routingId)
  }
  
  public func didChangeOpener(opener: WebFrame?) {
    //print("UIWebFrameProxy.didChangeOpener: not implemented") 
  }
  
  public func frameFocused() {
    //print("UIWebFrameProxy.frameFocused: not implemented")
  }
  
  public func checkCompleted() {
    //print("UIWebFrameProxy.checkCompleted: not implemented")
  }
  
  public func forwardPostMessage(sourceFrame: WebLocalFrame?,
                          targetFrame: WebRemoteFrame?,
                          targetOrigin: WebSecurityOrigin,
                          event: WebDOMMessageEvent,
                          hasUserGesture: Bool) {
    //print("UIWebFrameProxy.forwardPostMessage: not implemented")
  }
  
  public func navigate(request: WebURLRequest, shouldReplaceCurrentEntry: Bool) {
    //print("UIWebFrameProxy.navigate: not implemented")
  }
  
  public func reload(loadType: WebFrameLoadType, redirect: ClientRedirectPolicy) {
    //print("UIWebFrameProxy.reload: not implemented")
  }
  
  public func frameRectsChanged(localFrame: IntRect, screenSpace: IntRect) {
    //print("UIWebFrameProxy.frameRectsChanged: not implemented")
  }
  
  public func updateRemoteViewportIntersection(viewportIntersection: IntRect) {
    //print("UIWebFrameProxy.updateRemoteViewportIntersection: not implemented")
  }
  
  public func visibilityChanged(visible: Bool) {
    //print("UIWebFrameProxy.visibilityChanged: not implemented")
  }
  
  public func setIsInert(_ inert: Bool) {
    //print("UIWebFrameProxy.setIsInert: not implemented")
  }
  
  public func updateRenderThrottlingStatus(isThrottled: Bool,
                                           subtreeThrottled: Bool) {
    //print("UIWebFrameProxy.updateRenderThrottlingStatus: not implemented")
  }
  
  public func advanceFocus(type: WebFocusType, source: WebLocalFrame) {
    //print("UIWebFrameProxy.advanceFocus: not implemented")
  }

  public func onScreenInfoChanged(screenInfo: ScreenInfo) {
    //print("UIWebFrameProxy.onScreenInfoChanged: not implemented")
  }

  public func updateCaptureSequenceNumber(captureSequenceNumber: UInt32) {
    //print("UIWebFrameProxy.updateCaptureSequenceNumber: not implemented")
  }

  public func onDidStartLoading() {
    if let remoteFrame = frame {
      remoteFrame.didStartLoading()
    }
  }

}
