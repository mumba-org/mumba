// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public class WebRemoteFrame : WebFrame {

  public weak var client: WebRemoteFrameClient?

  internal init(scope: WebTreeScopeType, client: WebRemoteFrameClient) {
    self.client = client

    var callbacks = WebFrameClientCbs()
    memset(&callbacks, 0, MemoryLayout<WebFrameClientCbs>.stride)

    callbacks.frameDetached = { 
      (handle: UnsafeMutableRawPointer?, type: WebDetachEnum) in 
            
      guard handle != nil else {
          return
      }

      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)

      if let client = frame.client {
          client.frameDetached(
            type: WebFrameDetachType(rawValue: Int(type.rawValue))!)
      }
    }

    callbacks.frameRectsChangedRemote = { 
      (handle: UnsafeMutableRawPointer?, 
       localFrameX: CInt, localFrameY: CInt, 
       localFrameW: CInt, localFrameH: CInt,
       screenSpaceX: CInt, screenSpaceY: CInt, 
       screenSpaceW: CInt, screenSpaceH: CInt) in 
            
      guard handle != nil else {
          return
      }
    
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
          client.frameRectsChanged(
            localFrame: IntRect(x: Int(localFrameX), y: Int(localFrameY), width: Int(localFrameW), height: Int(localFrameH)),
            screenSpace: IntRect(x: Int(screenSpaceX), y: Int(screenSpaceY), width: Int(screenSpaceW), height: Int(screenSpaceH))
          )
      }
    }

    callbacks.didChangeOpener = { (handle: UnsafeMutableRawPointer?, targetFrame: WebFrameRef?) in      
      guard handle != nil else {
          return
      }
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
        client.didChangeOpener(opener: WebFrame(reference: targetFrame!))
      }
    }

    callbacks.frameFocused = { (handle: UnsafeMutableRawPointer?) in         
      guard handle != nil else {
          return
      }
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
        client.frameFocused()
      }
    }

    callbacks.checkCompleted = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
        client.checkCompleted()
      }
    }
    
    callbacks.forwardPostMessage = { (
      handle: UnsafeMutableRawPointer?,
      sourceFrame: UnsafeMutableRawPointer?,
      targetFrame: UnsafeMutableRawPointer?,
      targetOrigin: UnsafeMutableRawPointer?,
      event: UnsafeMutableRawPointer?,
      hasUserGesture: CInt) in
   
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
   
      if let client = frame.client {
        client.forwardPostMessage(sourceFrame: WebLocalFrame(reference: sourceFrame!),
                                  targetFrame: WebRemoteFrame(reference: targetFrame!),
                                  targetOrigin: WebSecurityOrigin(reference: targetOrigin!),
                                  event: WebDOMMessageEvent(reference: event!),
                                  hasUserGesture: hasUserGesture != 0)
      }
    }

    callbacks.navigate = { (handle: UnsafeMutableRawPointer?, 
      req: UnsafeMutableRawPointer?, 
      shouldReplaceCurrentEntry: CInt) in
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
        client.navigate(
          request: WebURLRequest(reference: req!), 
          shouldReplaceCurrentEntry: shouldReplaceCurrentEntry != 0)
      }
    }

    callbacks.reload = { (handle: UnsafeMutableRawPointer?,
      type: WebFrameLoadTypeEnum,
      policy: WebClientRedirectPolicyEnum) in
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
        client.reload(
          loadType: WebFrameLoadType(rawValue: Int(type.rawValue))!, 
          redirect: ClientRedirectPolicy(rawValue: Int(policy.rawValue))!)
      }
    }

    callbacks.updateRemoteViewportIntersection = { (
      handle: UnsafeMutableRawPointer?,
      x: CInt, y: CInt, w: CInt, h: CInt) in
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
        client.updateRemoteViewportIntersection(
          viewportIntersection: 
          IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h)))
      }
    }

    callbacks.visibilityChanged = { (handle: UnsafeMutableRawPointer?, visible: CInt) in
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
        client.visibilityChanged(
          visible: visible != 0)
      }
    }

    callbacks.setIsInert = { (handle: UnsafeMutableRawPointer?, inert: CInt) in
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
        client.setIsInert(inert != 0) 
      }
    }
    
    callbacks.updateRenderThrottlingStatus = { (handle: UnsafeMutableRawPointer?, isThrottled: CInt, subtreeThrottled: CInt) in
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
        client.updateRenderThrottlingStatus(isThrottled: isThrottled != 0,
                                            subtreeThrottled: subtreeThrottled != 0)
      }
    }
    
    callbacks.advanceFocus = { (handle: UnsafeMutableRawPointer?, type: WebFocusTypeEnum, source: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebRemoteFrame.self)
      if let client = frame.client {
        client.advanceFocus(type: WebFocusType(rawValue: Int(type.rawValue))!, source: WebLocalFrame(reference: source!))
      }
    }
    
    super.init()

    let peer = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let handle = _WebRemoteFrameCreate(peer, callbacks, CInt(scope.rawValue))
    self.reference = handle!
  }

  internal override init(reference: WebFrameRef) {
    super.init(reference: reference)
  }

  deinit {
    _WebRemoteFrameDestroy(reference)
  }

  public func didStartLoading() {
    _WebRemoteFrameDidStartLoading(reference)
  }

}