// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public enum FilterType : Int {
  case Grayscale = 0
  case Sepia = 1
  case Saturate = 2
  case HueRotate = 3
  case Invert = 4
  case Brightness = 5
  case Contrast = 6
  case Opacity = 7
  case Blur = 8
  case DropShadow = 9
  case ColorMatrix = 10
  case Zoom = 11
  case Reference = 12
  case SaturatingBrightness = 13
  case AlphaThreshold = 14
}

public class ColorMatrix {
  
  public var data: ContiguousArray<Int>

  public init() {
    data = ContiguousArray<Int>(repeating: 0, count: 20)
  }

  public init(withCArray input: ContiguousArray<CInt>) {
    data = ContiguousArray<Int>()
    input.forEach { data.append(Int($0)) }
  }

  public init(with input: ContiguousArray<Int>) {
    data = ContiguousArray<Int>()
    input.forEach { data.append($0) }
  }

  public init(_ m0: CInt, _ m1: CInt, _ m2: CInt, _ m3: CInt, 
              _ m4: CInt, _ m5: CInt, _ m6: CInt, _ m7: CInt,
              _ m8: CInt, _ m9: CInt, _ m10: CInt, _ m11: CInt,
              _ m12: CInt, _ m13: CInt, _ m14: CInt, _ m15: CInt,
              _ m16: CInt, _ m17: CInt, _ m18: CInt, _ m19: CInt) {
    data = ContiguousArray<Int>(repeating: 0, count: 20)
    data[0] = Int(m0)
    data[1] = Int(m1)
    data[2] = Int(m2)
    data[3] = Int(m3)
    data[4] = Int(m4)
    data[5] = Int(m5)
    data[6] = Int(m6)
    data[7] = Int(m7)
    data[8] = Int(m8)
    data[9] = Int(m9)
    data[10] = Int(m10)
    data[11] = Int(m11)
    data[12] = Int(m12)
    data[13] = Int(m13)
    data[14] = Int(m14)
    data[15] = Int(m15)
    data[16] = Int(m16)
    data[17] = Int(m17)
    data[18] = Int(m18)
    data[19] = Int(m19)
  }

  public subscript(index: Int) -> Int {
    return data[index]
  }

}

public class FilterOperation {

  public var type: FilterType {
    return FilterType(rawValue: Int(_FilterOperationGetType(reference)))!
  }

  public var amount: Float {
    get {
      return _FilterOperationGetAmount(reference)
    }
    set {
      _FilterOperationSetAmount(reference, newValue)
    }
  }

  public var outerThreshold: Float {
    get {
      return _FilterOperationGetOuterThreshold(reference)
    }
    set {
      _FilterOperationSetOuterThreshold(reference, newValue)
    }
  }

  public var dropShadowOffset: IntPoint {
    get {
      var x: CInt = 0
      var y: CInt = 0
      _FilterOperationGetDropShadowOffset(reference, &x, &y)
      return IntPoint(x: Int(x), y: Int(y))
    }

    set {
      _FilterOperationSetDropShadowOffset(reference, CInt(newValue.x), CInt(newValue.y))
    }
  }


  public var dropShadowColor: Color {
    get {
      var a: UInt8 = 0
      var r: UInt8 = 0
      var g: UInt8 = 0
      var b: UInt8 = 0
      _FilterOperationGetDropShadowColor(reference, &a, &r, &g, &b)
      return Color(a: a, r: r, g: g, b: b)
    }
    set (c) {
      _FilterOperationSetDropShadowColor(reference, c.a, c.r, c.g, c.b) 
    }
  }

  public var imageFilter: PaintFilter? {
    get {
      guard let filterRef = _FilterOperationGetImageFilter(reference) else {
        return nil
      }
      if _imageFilter == nil {
        _imageFilter = PaintFilter(reference: filterRef)
      }
      return _imageFilter!
    }
    set {
      if let filter = newValue {
        _imageFilter = newValue
        _FilterOperationSetImageFilter(reference, filter.reference)
      }
    }
  }

  public var matrix: ColorMatrix? {
    get {
      guard type == .ColorMatrix else {
        return nil
      }
      var m0: CInt = 0
      var m1: CInt = 0
      var m2: CInt = 0
      var m3: CInt = 0
      var m4: CInt = 0
      var m5: CInt = 0
      var m6: CInt = 0
      var m7: CInt = 0
      var m8: CInt = 0
      var m9: CInt = 0
      var m10: CInt = 0
      var m11: CInt = 0
      var m12: CInt = 0
      var m13: CInt = 0
      var m14: CInt = 0
      var m15: CInt = 0
      var m16: CInt = 0
      var m17: CInt = 0
      var m18: CInt = 0
      var m19: CInt = 0
      _FilterOperationGetColorMatrix(
        reference, 
        &m0, &m1, &m2, &m3,
        &m4, &m5, &m6, &m7,
        &m8, &m9, &m10, &m11,
        &m12, &m13, &m14, &m15,
        &m16, &m17, &m18, &m19)
      return ColorMatrix(
        m0, m1, m2, m3,
        m4, m5, m6, m7,
        m8, m9, m10, m11,
        m12, m13, m14, m15,
        m16, m17, m18, m19)
    }
    set {
      if let m = newValue {
        _FilterOperationSetColorMatrix(reference,
          CInt(m[0]), CInt(m[1]), CInt(m[2]), CInt(m[3]),
          CInt(m[4]), CInt(m[5]), CInt(m[6]), CInt(m[7]),
          CInt(m[8]), CInt(m[9]), CInt(m[10]), CInt(m[11]),
          CInt(m[12]), CInt(m[13]), CInt(m[14]), CInt(m[15]),
          CInt(m[16]), CInt(m[17]), CInt(m[18]), CInt(m[19]))
      }
    }
  }

  public var zoomInset: Int {
    get {
      return Int(_FilterOperationGetZoomInset(reference))
    }
    set {
      _FilterOperationSetZoomInset(reference, CInt(newValue))
    }
  }

  public var shape: ContiguousArray<IntRect> {
    get {
      if _shape == nil || shapeDirty {
        var count: CInt = 0
        _FilterOperationGetShapeCount(reference, &count)
        _shape = ContiguousArray<Rect>()
        if count > 0 {
          var x = ContiguousArray<CInt>(repeating: 0, count: Int(count))
          var y = ContiguousArray<CInt>(repeating: 0, count: Int(count))
          var w = ContiguousArray<CInt>(repeating: 0, count: Int(count))
          var h = ContiguousArray<CInt>(repeating: 0, count: Int(count))
          var xptr: UnsafeMutablePointer<CInt>?
          var yptr: UnsafeMutablePointer<CInt>?
          var wptr: UnsafeMutablePointer<CInt>?
          var hptr: UnsafeMutablePointer<CInt>?

          x.withUnsafeMutableBufferPointer { (xbuf: inout UnsafeMutableBufferPointer<CInt>) in
            xptr = xbuf.baseAddress
          }
          y.withUnsafeMutableBufferPointer { (ybuf: inout UnsafeMutableBufferPointer<CInt>) in
            yptr = ybuf.baseAddress
          }
          w.withUnsafeMutableBufferPointer { (wbuf: inout UnsafeMutableBufferPointer<CInt>) in
            wptr = wbuf.baseAddress
          }
          h.withUnsafeMutableBufferPointer { (hbuf: inout UnsafeMutableBufferPointer<CInt>) in
            hptr = hbuf.baseAddress
          }
          
          _FilterOperationGetShapeNoCount(reference, &xptr, &yptr, &wptr, &hptr)
          
           for i in 0..<Int(count) {
            _shape!.append(IntRect(x: Int(x[i]), y: Int(y[i]), width: Int(w[i]), height: Int(h[i])))
          }

        }
      }
      return _shape!
    }
    set (s) {
      var x = ContiguousArray<CInt>(repeating: 0, count: s.count)
      var y = ContiguousArray<CInt>(repeating: 0, count: s.count)
      var w = ContiguousArray<CInt>(repeating: 0, count: s.count)
      var h = ContiguousArray<CInt>(repeating: 0, count: s.count)
      for i in 0..<s.count {
        let rect = s[i]
        x[i] = CInt(rect.x)
        y[i] = CInt(rect.y)
        w[i] = CInt(rect.width)
        h[i] = CInt(rect.height)
      }
      x.withUnsafeMutableBufferPointer { xbuf in
        y.withUnsafeMutableBufferPointer { ybuf in
          w.withUnsafeMutableBufferPointer { wbuf in
            h.withUnsafeMutableBufferPointer { hbuf in
              _FilterOperationSetShape(reference, xbuf.baseAddress, ybuf.baseAddress, wbuf.baseAddress, hbuf.baseAddress, CInt(s.count))
            }
          }
        }
      }
      // TODO: maybe we should just reuse the array that is given to us?
      shapeDirty = true
    }
  }

  var reference: FilterOperationRef!
  private var _imageFilter: PaintFilter?
  private var _shape: ContiguousArray<IntRect>?
  private var shapeDirty: Bool = false

  public init(type: FilterType, amount: Float) {
    reference = _FilterOperationCreateWithAmount(CInt(type.rawValue), amount)
  }

  public init(type: FilterType, 
              shape inshape: ContiguousArray<IntRect>,
              innerThreshold: Float, 
              outerThreshold: Float) {
    
    //self.reference = FilterOperationRef(bitPattern: 0)

    var x = ContiguousArray<CInt>(repeating: 0, count: inshape.count)
    var y = ContiguousArray<CInt>(repeating: 0, count: inshape.count)
    var w = ContiguousArray<CInt>(repeating: 0, count: inshape.count)
    var h = ContiguousArray<CInt>(repeating: 0, count: inshape.count)
    for i in 0..<inshape.count {
      let rect = inshape[i]
      x[i] = CInt(rect.x)
      y[i] = CInt(rect.y)
      w[i] = CInt(rect.width)
      h[i] = CInt(rect.height)
    }
    x.withUnsafeMutableBufferPointer { (xbuf: inout UnsafeMutableBufferPointer<CInt>) in
      y.withUnsafeMutableBufferPointer { (ybuf: inout UnsafeMutableBufferPointer<CInt>) in
        w.withUnsafeMutableBufferPointer { (wbuf: inout UnsafeMutableBufferPointer<CInt>) in
          h.withUnsafeMutableBufferPointer { (hbuf: inout UnsafeMutableBufferPointer<CInt>) in
            self.reference = _FilterOperationCreateWithShape(CInt(type.rawValue), xbuf.baseAddress, ybuf.baseAddress, wbuf.baseAddress, hbuf.baseAddress, CInt(inshape.count), innerThreshold, outerThreshold)
          }
        }
      }
    }
  }

  public init(type: FilterType, offset: IntPoint, deviation: Float, color: Color) {
    reference = _FilterOperationCreateWithOffset(CInt(type.rawValue), 
      CInt(offset.x), CInt(offset.y), 
      deviation,
      color.a, color.r, color.g, color.b)
  }

  public init(type: FilterType, amount: Float, inset: Int) {
    reference = _FilterOperationCreateWithInset(CInt(type.rawValue), amount, CInt(inset))!
  }

  public init(type: FilterType, matrix m: ColorMatrix) {
    reference = _FilterOperationCreateWithMatrix(CInt(type.rawValue),
      CInt(m[0]), CInt(m[1]), CInt(m[2]), CInt(m[3]),
      CInt(m[4]), CInt(m[5]), CInt(m[6]), CInt(m[7]),
      CInt(m[8]), CInt(m[9]), CInt(m[10]), CInt(m[11]),
      CInt(m[12]), CInt(m[13]), CInt(m[14]), CInt(m[15]),
      CInt(m[16]), CInt(m[17]), CInt(m[18]), CInt(m[19]))
  }

  public init(type: FilterType, filter: PaintFilter) {
    reference = _FilterOperationCreateWithFilter(CInt(type.rawValue), filter.reference)
  }

  init(reference: FilterOperationRef) {
    self.reference = reference
  }

  public static func createGrayscaleFilter(amount: Float) -> FilterOperation {
    return FilterOperation(type: .Grayscale, amount: amount)
  }

  public static func createSepiaFilter(amount: Float) -> FilterOperation {
    return FilterOperation(type: .Sepia, amount: amount)
  }

  public static func createSaturateFilter(amount: Float) -> FilterOperation {
    return FilterOperation(type: .Saturate, amount: amount)
  }

  public static func createHueRotateFilter(amount: Float) -> FilterOperation {
    return FilterOperation(type: .HueRotate, amount: amount)
  }

  public static func createInvertFilter(amount: Float) -> FilterOperation {
    return FilterOperation(type: .Invert, amount: amount)
  }

  public static func createBrightnessFilter(amount: Float) -> FilterOperation {
    return FilterOperation(type: .Brightness, amount: amount)
  }

  public static func createContrastFilter(amount: Float) -> FilterOperation {
    return FilterOperation(type: .Contrast, amount: amount)
  }

  public static func createOpacityFilter(amount: Float) -> FilterOperation {
    return FilterOperation(type: .Opacity, amount: amount)
  }

  public static func createBlurFilter(amount: Float) -> FilterOperation {
    return FilterOperation(type: .Blur, amount: amount)
  }

  public static func createDropShadowFilter(offset: IntPoint,
                                            stdDeviation: Float,
                                            color: Color) -> FilterOperation {
    return FilterOperation(type: .DropShadow, offset: offset, deviation: stdDeviation, color: color)
  }

  public static func createColorMatrixFilter(matrix: ColorMatrix) -> FilterOperation {
    return FilterOperation(type: .ColorMatrix, matrix: matrix)
  }

  public static func createZoomFilter(amount: Float, inset: Int) -> FilterOperation {
    return FilterOperation(type: .Zoom, amount: amount, inset: inset)
  }

  public static func createReferenceFilter(imageFilter: PaintFilter) -> FilterOperation {
    return FilterOperation(type: .Reference, filter: imageFilter)
  }

  public static func createSaturatingBrightnessFilter(amount: Float) -> FilterOperation {
    return FilterOperation(type: .SaturatingBrightness, amount: amount);
  }

  public static func createAlphaThresholdFilter(shape: ContiguousArray<IntRect>,
                                                innerThreshold: Float,
                                                outerThreshold: Float) -> FilterOperation {
    return FilterOperation(type: .AlphaThreshold, shape: shape,
                           innerThreshold: innerThreshold, outerThreshold: outerThreshold)
  }

  public static func createEmptyFilter() -> FilterOperation {
    return FilterOperation(type: .Grayscale, amount: 0.0)
  }

  public static func blend(from: FilterOperation,
                           to: FilterOperation,
                           progress: Double) -> FilterOperation {
    return FilterOperation(type: .Grayscale, amount: 0.0)
  }

}

public class FilterOperations {

  public var count: Int {
    return Int(_FilterOperationsGetCount(reference))
  }

   public var isEmpty: Bool {
    return count == 0
  }

  public var hasFilterThatMovesPixels: Bool {
    return _FilterOperationsHasFilterThatMovesPixels(reference) == 0 ? false : true
  }

  public var hasFilterThatAffectsOpacity: Bool {
    return _FilterOperationsHasFilterThatAffectsOpacity(reference) == 0 ? false : true
  }

  public var hasReferenceFilter: Bool {
    return _FilterOperationsHasReferenceFilter(reference) == 0 ? false : true
  }

  public subscript(index: Int) -> FilterOperation {
    let ref = _FilterOperationsGet(reference, CInt(index))
    return FilterOperation(reference: ref!)
  }

  var reference: FilterOperationRef

  public init() {
    reference = _FilterOperationsCreate()
  }

  init(reference: FilterOperationRef) {
    self.reference = reference
  }

  deinit {
    _FilterOperationsDestroy(reference)
  }

  public func append(filter: FilterOperation) {
    _FilterOperationsAppend(reference, filter.reference)
  }

  public func clear() {
    _FilterOperationsClear(reference)
  }

  //public func getOutsets(top: inout Int, right: inout Int, bottom: inout Int, left: inout Int) {
  //  _FilterOperationsGetOutsets(reference, top, right, bottom, left)
  //}

  public func blend(from: FilterOperations, progress: Float) -> FilterOperations {
    let ref = _FilterOperationsBlend(reference, from.reference, progress)
    return FilterOperations(reference: ref!)
  }
}
