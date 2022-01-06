// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import MumbaShims

public class WebWindow {

  public var navigator: WebNavigator {
    return WebNavigator(window: self, reference: WebLocalDomWindowGetNavigator(reference))
  }

  public var location: Location {
    let ref = WebLocalDomWindowGetLocation(reference)
    return Location(reference: ref!)
  }
  
  public var reference: WebLocalDomWindowRef

  init(reference: WebLocalDomWindowRef) {
    self.reference = reference
  }

}