// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Gpu
import Graphics
import Compositor
import MumbaShims

public final class InProcessContextProvider : ContextProvider {

  public class func create(attributes: ContextCreationAttribHelper,
                           widget: AcceleratedWidget,
                           name: String) -> InProcessContextProvider {
    return InProcessContextProvider(attributes: attributes,
                                    widget: widget,
                                    name: name,
                                    offscreen: false)
  }

  public class func createOffscreen() -> InProcessContextProvider {
    var attribs = ContextCreationAttribHelper()
    attribs.alphaSize = 8
    attribs.blueSize = 8
    attribs.greenSize = 8
    attribs.redSize = 8
    attribs.depthSize = 0
    attribs.stencilSize = 8
    attribs.samples = 0
    attribs.sampleBuffers = 0
    attribs.failIfMajorPerfCaveat = false
    attribs.bindGeneratesResource = false
    return InProcessContextProvider(attributes: attribs,
                                    widget: NullAcceleratedWidget,
                                    name: "Offscreen",
                                    offscreen: true)
  }

  override init(attributes: ContextCreationAttribHelper,
       widget: AcceleratedWidget,
       name: String,
       offscreen: Bool) {
    super.init(attributes: attributes, widget: widget, name: name, offscreen: offscreen)
  }

}
