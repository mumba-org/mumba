// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

// TODO: make it adhere to sequence
// and provide (or be) a iterator

public class HtmlCollection {
  
  public var count: Int {
    return Int(_HTMLCollectionLenght(reference))
  }

  public var isEmpty: Bool {
    return _HTMLCollectionIsEmpty(reference) == 1
  }

  var reference: HTMLCollectionRef

  init(reference: HTMLCollectionRef) {
    self.reference = reference
  }

  deinit {
    _HTMLCollectionDestroy(reference)
  }
  
  public func nextItem() -> WebElement? {
    let elementHandle = _HTMLCollectionGetNextItem(reference)
    return elementHandle == nil ? nil : WebElement(reference: elementHandle!)
  }

  public func firstItem() -> WebElement? {
    let elementHandle = _HTMLCollectionGetFirstItem(reference)
    return elementHandle == nil ? nil : WebElement(reference: elementHandle!)
  }

  public func lastItem() -> WebElement? {
    let elementHandle = _HTMLCollectionGetLastItem(reference)
    return elementHandle == nil ? nil : WebElement(reference: elementHandle!)
  }
  
}
