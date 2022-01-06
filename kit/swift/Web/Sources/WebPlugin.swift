// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Compositor

public struct WebPluginParams {
  public var url: String
  public var mimeType: String
  public var attributeNames: [String]
  public var attributeValues: [String]
  public var loadManually: Bool

  public init(url: String,
              mimeType: String,
              loadManually: Bool) {
    self.url = url
    self.mimeType = mimeType
    self.loadManually = loadManually
    attributeNames = []
    attributeValues = []
  }

}

public class WebPluginContainer {
  
  var reference: WebPluginContainerRef

  init(reference: WebPluginContainerRef) {
    self.reference = reference
  }
  
  deinit {
    _WebPluginContainerDestroy(reference)
  }
}

public class NPObject {

  var reference: NPObjectRef
  
  init(reference: NPObjectRef) {
    self.reference = reference
  }

  deinit {

  }
  
}

public class WebPlugin {

  public var layer: Layer {
    let ref = _WebPluginGetLayer(reference)
    return Layer(reference: ref!)
  }

  var reference: WebPluginRef

  public init() {
    reference = _WebPluginCreate()
  }

  public init(layer: Compositor.Layer) {
    reference = _WebPluginCreateLayer(layer.reference)
  }

  init(reference: WebPluginRef) {
    self.reference = reference
  }

  deinit {
    _WebPluginDestroy(reference)
  }

}

public struct WebPluginAction {
    
    public enum ActionType : Int {
      case Unknown = 0
      case Rotate90Clockwise
      case Rotate90Counterclockwise
    }

    public var type: ActionType
    public var enable: Bool
}