// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class DisplayItemList {

    public enum UsageHint : Int {
      case topLevelDisplayItemList = 0
      case toBeReleasedAsPaintOpBuffer = 1
    }

    public var totalOpCount: Int {
      return Int(_DisplayItemListTotalOpCount(reference))
    }

    public var reference: DisplayItemListRef
    private var managed: Bool

    public init(hint: UsageHint = .topLevelDisplayItemList) {
      self.reference = _DisplayItemListCreate(CInt(hint.rawValue))
      managed = true
    }

    public init(reference: DisplayItemListRef, owned: Bool = true) {
      self.reference = reference
      self.managed = owned
    }

    deinit {
      if managed {
        _DisplayItemListDestroy(reference)
      }
    }

    public func releaseUnsafeReference() -> DisplayItemListRef {
      managed = false
      return reference 
    }


    public func withUnsafeReference(_ cb: (_: DisplayItemListRef) -> Void) {
      cb(reference)
    }

    public func startPaint() {
      _DisplayItemListStartPaint(reference)
    }

    public func endPaintOfPairedBegin() {
      _DisplayItemListEndPaintOfPairedBegin(reference)
    }

    public func endPaintOfPairedBegin(rect: IntRect) {
      _DisplayItemListEndPaintOfPairedBeginWithRect(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height))
    }

    public func endPaintOfPairedEnd() {
      _DisplayItemListEndPaintOfPairedEnd(reference)
    }

    public func endPaintOfUnpaired(rect: IntRect) {
      _DisplayItemListEndPaintOfUnpaired(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height))
    }
    
    public func finalize() {
      _DisplayItemListFinalize(reference)
    }

    public func releaseAsRecord() -> PaintRecord {
      return PaintRecord(reference: _DisplayItemListReleaseAsRecord(reference))
    }

    public func push(_ item: DisplayItem) {
      switch item {
        case .clipPath(let path, let clip, let antialias):
          ////print("DisplayItem.push: .clipPath")
          _DisplayItemListPushClipPath(reference, path.reference, clip.rawValue, antialias.intValue)
        case .clipRect(let rect, let clip, let antialias):
          ////print("DisplayItem.push: .clipRect")
          _DisplayItemListPushClipRect(reference, rect.x, rect.y, rect.width, rect.height, clip.rawValue, antialias.intValue)
        case .clipRRect(let rect, let clip, let antialias):
          ////print("DisplayItem.push: .clipRRect")
          _DisplayItemListPushClipRRect(reference, rect.x, rect.y, rect.width, rect.height, clip.rawValue, antialias.intValue)
        case .concat(let matrix):
          ////print("DisplayItem.push: .concat")
          _DisplayItemListPushConcat(reference, 
              matrix[0],
              matrix[1],
              matrix[2],
              matrix[3],
              matrix[4],
              matrix[5],
              matrix[6],
              matrix[7],
              matrix[8])
        case .customData(let id):
          ////print("DisplayItem.push: .customData")
          _DisplayItemListPushCustomData(reference, id)
        case .drawColor(let color, let blend):
          ////print("DisplayItem.push: .drawColor")
          _DisplayItemListPushDrawColor(reference, Int32(color.r), Int32(color.g), Int32(color.b), Int32(color.a), Int32(blend.rawValue))
        case .drawDRRect(let outer, let inner, let flags):
          ////print("DisplayItem.push: .drawDRRect")
          _DisplayItemListPushDrawDRRect(reference, inner.x, inner.y, inner.width, inner.height, outer.x, outer.y, outer.width, outer.height, flags.reference)
        case .drawBitmap(let bitmap, let left, let top, .some(let flags)):
           ////print("DisplayItem.push: .drawBitmap")
          _DisplayItemListPushDrawBitmap(reference, bitmap.reference, left, top, flags.reference)
        case .drawBitmap(let bitmap, let left, let top, .none):
           ////print("DisplayItem.push: .drawBitmap")
          _DisplayItemListPushDrawBitmap(reference, bitmap.reference, left, top, nil)  
        case .drawImage(let image, let left, let top, .some(let flags)):
           ////print("DisplayItem.push: .drawImage")
          _DisplayItemListPushDrawImage(reference, image.reference, left, top, flags.reference)
        case .drawImage(let image, let left, let top, .none):
          ////print("DisplayItem.push: .drawImage")
          _DisplayItemListPushDrawImage(reference, image.reference, left, top, nil)
        case .drawImageRect(let image, let src, let dest, let srcRectConstraint, .some(let flags)):
          ////print("DisplayItem.push: .drawImageRect")
          _DisplayItemListPushDrawImageRect(reference, image.reference, src.x, src.y, src.width, src.height, dest.x, dest.y, dest.width, dest.height, srcRectConstraint.rawValue, flags.reference)
        case .drawImageRect(let image, let src, let dest, let srcRectConstraint, .none):
          ////print("DisplayItem.push: .drawImageRect")
          _DisplayItemListPushDrawImageRect(reference, image.reference, src.x, src.y, src.width, src.height, dest.x, dest.y, dest.width, dest.height, srcRectConstraint.rawValue, nil)
        case .drawIRect(let rect, let flags):
          ////print("DisplayItem.push: .drawIRect")
          _DisplayItemListPushDrawIRect(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height), flags.reference)
        case .drawLine(let start, let end, let flags):
          ////print("DisplayItem.push: .drawLine")
          _DisplayItemListPushDrawLine(reference, start.x, start.y, end.x, end.y, flags.reference)
        case .drawOval(let oval, let flags):
          ////print("DisplayItem.push: .drawOval")
          _DisplayItemListPushDrawOval(reference, oval.x, oval.y, oval.width, oval.height, flags.reference)
        case .drawPath(let path, let flags):
          ////print("DisplayItem.push: .drawPath")
          _DisplayItemListPushDrawPath(reference, path.reference, flags.reference) 
        case .drawRecord(let record):
          ////print("DisplayItem.push: .drawRecord")
          _DisplayItemListPushDrawRecord(reference, record.reference)
        case .drawRect(let rect, let flags):
          ////print("DisplayItem.push: .drawRect")
          _DisplayItemListPushDrawRect(reference, rect.x, rect.y, rect.width, rect.height, flags.reference)
        case .drawRRect(let rect, let flags):
          ////print("DisplayItem.push: .drawRRect")
          _DisplayItemListPushDrawRRect(reference, rect.x, rect.y, rect.width, rect.height, flags.reference)
        case .drawTextBlob(let text, let x, let y, let flags):
          _DisplayItemListPushDrawTextBlob(reference, text.reference, x, y, flags.reference)
        case .noop:
          ////print("DisplayItem.push: .noop")
          _DisplayItemListPushNoop(reference)
        case .restore:
          ////print("DisplayItem.push: .restore")
          _DisplayItemListPushRestore(reference)
        case .rotate(let degrees):
          ////print("DisplayItem.push: .rotate")
          _DisplayItemListPushRotate(reference, degrees)
        case .save:
          _DisplayItemListPushSave(reference)
        case .saveLayer(.some(let bounds), .some(let flags)):
          ////print("DisplayItem.push: .saveLayer")
          _DisplayItemListPushSaveLayerBounds(reference, bounds.x, bounds.y, bounds.width, bounds.height, flags.reference)
        case .saveLayer(.some(let bounds), .none):
          ////print("DisplayItem.push: .saveLayer")
          _DisplayItemListPushSaveLayerBounds(reference, bounds.x, bounds.y, bounds.width, bounds.height, nil)
        case .saveLayer(.none, .some(let flags)):
          ////print("DisplayItem.push: .saveLayer")
          _DisplayItemListPushSaveLayer(reference, flags.reference)
        case .saveLayer(.none, .none):
          ////print("DisplayItem.push: .saveLayer")
          _DisplayItemListPushSaveLayer(reference, nil)
        case .saveLayerAlpha(.some(let bounds), let alpha, let preserveLcdTextRequests):
          ////print("DisplayItem.push: .saveLayerAlpha")
          _DisplayItemListPushSaveLayerAlphaBounds(reference,
            bounds.x, bounds.y, bounds.width, bounds.height,
            alpha,
            preserveLcdTextRequests.intValue)
        case .saveLayerAlpha(.none, let alpha, let preserveLcdTextRequests):
          ////print("DisplayItem.push: .saveLayerAlpha")
          _DisplayItemListPushSaveLayerAlpha(reference, 
            alpha,
            preserveLcdTextRequests.intValue)
        case .scale(let x, let y):
          ////print("DisplayItem.push: .scale")
          _DisplayItemListPushScale(reference, x, y)
        case .setMatrix(let matrix):
          ////print("DisplayItem.push: .setMatrix")
          _DisplayItemListPushSetMatrix(reference,
                 matrix[0],
                 matrix[1],
                 matrix[2],
                 matrix[3],
                 matrix[4],
                 matrix[5],
                 matrix[6],
                 matrix[7],
                 matrix[8])
        case .translate(let x, let y):
          ////print("DisplayItem.push: .translate")
          _DisplayItemListPushTranslate(reference, x, y)
      }
    }

}