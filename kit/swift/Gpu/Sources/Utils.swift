// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum ContextType : Int32 {
  case WEBGL1    = 0
  case WEBGL2    = 1
  case OPENGLES2 = 2
  case OPENGLES3 = 3
}

public struct ContextCreationAttribHelper {
  public var alphaSize: Int32
  public var blueSize: Int32
  public var greenSize: Int32
  public var redSize: Int32
  public var depthSize: Int32
  public var stencilSize: Int32
  public var samples: Int32
  public var sampleBuffers: Int32
  public var bufferPreserved: Bool
  public var bindGeneratesResource: Bool
  public var failIfMajorPerfCaveat: Bool
  public var loseContextWhenOutOfMemory: Bool
  public var contextType: ContextType

  public init() {
    alphaSize = 0
    blueSize = 0
    greenSize = 0
    redSize = 0
    depthSize = 0
    stencilSize = 0
    samples = 0
    sampleBuffers = 0
    bufferPreserved = false
    bindGeneratesResource = false
    failIfMajorPerfCaveat = false
    loseContextWhenOutOfMemory = false
    contextType = .OPENGLES2
  }
}
