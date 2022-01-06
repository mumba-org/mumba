// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class SelectorQuery {
 
  public var first: WebElement? {
    if let ref = _WebSelectorQueryFirst(reference, container.reference) {
      return WebElement(reference: ref)
    }
    return nil
  }

  let container: WebNode
  var reference: WebSelectorQueryRef

  init(container: WebNode, reference: WebSelectorQueryRef) {
    self.container = container
    self.reference = reference
  }

  deinit {
    _WebSelectorQueryDestroy(reference)
  }

}