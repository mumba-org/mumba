// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import MumbaShims

public struct VideoPlaybackQuality {
  public var creationTime: TimeDelta = TimeDelta()
  public var totalVideoFrames: Int = 0 
  public var droppedVideoFrames: Int = 0
  public var corruptedVideoFrames: Int = 0

  public init() {}
}

public class HtmlVideoElement : HtmlMediaElement {

    public init(document: WebDocument) {
      super.init(reference: _HTMLVideoElementCreate(document.reference))
    }

    required init(reference: WebNodeRef) {
      super.init(reference: reference)
    }

    public var videoWidth: Int {
      return Int(_HTMLVideoElementGetVideoWidth(reference))
    }
    
    public var videoHeight: Int {
      return Int(_HTMLVideoElementGetVideoHeight(reference))
    }

    public var width: Int {
      get {
        return getIntegralAttribute("width")
      }
      set {
        setUnsignedIntegralAttribute("width", value: UInt(newValue))
      }
    }

    public var height: Int {
      get {
        return getIntegralAttribute("height")
      }
      set {
        setUnsignedIntegralAttribute("height", value: UInt(newValue))
      }
    }

    public var visibleSize: IntSize {
      var w: CInt = 0
      var h: CInt = 0
      _HTMLVideoElementGetVisibleSize(reference, &w, &h)
      return IntSize(width: Int(w), height: Int(h))
    }

    public var poster: String {
      var len: CInt = 0
      guard let ref = _HTMLVideoElementGetPoster(reference, &len) else {
          return String()
      }
      return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public var playbackQuality: VideoPlaybackQuality {
      var creation: Double = 0
      var total: CInt = 0 
      var dropped: CInt = 0
      var corrupted: CInt = 0

      _HTMLVideoElementGetPlaybackQuality(reference, &creation, &total, &dropped, &corrupted)

      var quality = VideoPlaybackQuality()
      quality.creationTime = TimeDelta(microseconds: Int64(creation))
      quality.totalVideoFrames = Int(total)
      quality.droppedVideoFrames = Int(dropped)
      quality.corruptedVideoFrames = Int(corrupted)

      return quality
    }

    public var supportsFullscreen: Bool {
      return _HTMLVideoElementSupportsFullscreen(reference) != 0
    }

    public var displayingFullscreen: Bool {
      return _HTMLVideoElementDisplayingFullscreen(reference) != 0
    }

    public var decodedFrameCount: UInt64 {
      return _HTMLVideoElementGetDecodedFrameCount(reference)
    }
    
    public var droppedFrameCount: UInt64 {
      return _HTMLVideoElementGetDroppedFrameCount(reference)
    }
    
    public func enterFullscreen() {
      _HTMLVideoElementEnterFullscreen(reference)
    }

    public func exitFullscreen() {
      _HTMLVideoElementExitFullscreen(reference)
    }

    public func paintCurrentFrame(
      canvas: CanvasRenderingContext2d,
      rect: IntRect,
      flags: PaintFlags) {
      _HTMLVideoElementPaintCurrentFrame(
        reference, 
        canvas.reference, 
        CInt(rect.x),
        CInt(rect.y),
        CInt(rect.width),
        CInt(rect.height),
        flags.reference)
    }

}

extension WebElement {

  public func asHtmlVideo() -> HtmlVideoElement? {
    return asHtmlElement(to: HtmlVideoElement.self)
  }

}