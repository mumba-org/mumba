// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum RegionOp : Int {
    case DifferenceOp  = 0//!< subtract the op region from the first region
    case IntersectOp   = 1//!< intersect the two regions
    case UnionOp       = 2//!< union (inclusive-or) the two regions
    case XOROp         = 3//!< exclusive-or the two regions
    case ReverseDifferenceOp = 4   /** subtract the first region from the op region */
    case ReplaceOp     = 5//!< replace the dst region with the op region
}

public class Region {

  public var isEmpty: Bool {
    return _RegionEmpty(reference) == 1 ? true : false
  }

  public var bounds: IntRect {
    var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
    _RegionBounds(reference, &x, &y, &w, &h)
    return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
  }

  var reference: RegionRef
  private var owned: Bool

  public init() {
    reference = _RegionCreate()
    owned = true
  }

  public init(rect: IntRect) {
    reference = _RegionCreateWithRect(Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height))
    owned = true
  }

  init(reference: RegionRef, owned: Bool = true) {
    self.reference = reference
    self.owned = owned
  }

  deinit {
    _RegionDestroy(reference)
  }

  public func contains(x: Int, y: Int) -> Bool {
    return _RegionContains(reference, Int32(x), Int32(y)) == 1 ? true : false
  }

  public func setRect(x: Int, y: Int, width: Int, height: Int) {
    _RegionSetRect(reference, Int32(x), Int32(y), Int32(width), Int32(height))
  }

  public func setPath(mask: Path, clip: Region) -> Bool {
    return _RegionSetPath(reference, mask.reference, clip.reference) == 1 ? true : false
  }

  public func union(region: Region) -> Bool {
    return _RegionUnionRegion(reference, region.reference) == 1 ? true : false
  }

  public func union(rect: IntRect) -> Bool {
    let x = CInt(rect.x)
    let y = CInt(rect.y)
    let w = CInt(rect.width)
    let h = CInt(rect.height)
    return _RegionUnionRect(reference,
      x, y, w, h) == 1 ? true : false
  }

  public func clear() {
    _RegionClear(reference)
  }

  public func getBoundaryPath(path: inout Path) -> Bool {
    let phandle = _RegionGetBoundaryPath(reference)
    if phandle != nil {
      path.reference = phandle!
      return true
    }
    return false
  }

}

public class RegionIterator {

  public var isDone: Bool {
    return _RegionIteratorIsDone(reference) == 1 ? true : false
  }

  public var hasRect: Bool {
    return _RegionIteratorHasRect(reference) == 1 ? true : false
  }

  public var rect: IntRect {
    var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
    _RegionIteratorGetRect(reference, &x, &y, &w, &h)
    return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
  }

  var reference: RegionIteratorRef

  public init(region: Region) {
    reference = _RegionIteratorCreate(region.reference)
  }

  deinit {
    _RegionIteratorDestroy(reference)
  }

  public func next() {
    _RegionIteratorNext(reference)
  }

}
