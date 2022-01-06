// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import Foundation

public class OffscreenCanvasRenderingContext2d : CanvasRenderingContext,
                                                 CanvasTextRenderer {

  public var lineWidth: Double {
    return OffscreenCanvasRenderingContext2dGetLineWidth(reference)
  }

  public var lineCap: CanvasLineCap {
    return CanvasLineCap(rawValue: Int(OffscreenCanvasRenderingContext2dGetLineCap(reference)))!
  }

  public var lineJoin: CanvasLineJoin {
    return CanvasLineJoin(rawValue: Int(OffscreenCanvasRenderingContext2dGetLineJoin(reference)))!
  }

  public var miterLimit: Double {
    return OffscreenCanvasRenderingContext2dGetMiterLimit(reference)
  }

  public var lineDash: [Double] {
    get {
      var ret: [Double] = []
      var count: CInt = 0
      var doubles: UnsafeMutablePointer<Double>?
      OffscreenCanvasRenderingContext2dGetLineDash(reference, &doubles, &count)
      for i in 0..<count {
        ret.append(doubles![Int(i)])
      }
      free(doubles)
      return ret
    }
    set {
      newValue.withUnsafeBufferPointer {
        OffscreenCanvasRenderingContext2dSetLineDash(reference, UnsafeMutableBufferPointer<Double>(mutating: $0).baseAddress, CInt(newValue.count))
      }
    }
  }

  public var lineDashOffset: Double {
    return OffscreenCanvasRenderingContext2dGetLineDashOffset(reference)
  }

  public var font: String {
    var len: CInt = 0
    let cstr = OffscreenCanvasRenderingContext2dGetFont(reference, &len)
    return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
  }

  public var textAlign: CanvasTextAlign {
    return CanvasTextAlign(rawValue: Int(OffscreenCanvasRenderingContext2dGetTextAlign(reference)))!
  }
  
  public var textBaseline: CanvasTextBaseline {
    return CanvasTextBaseline(rawValue: Int(OffscreenCanvasRenderingContext2dGetTextBaseline(reference)))!
  }

  public var direction: CanvasTextDirection {
    return CanvasTextDirection(rawValue: Int(OffscreenCanvasRenderingContext2dGetTextDirection(reference)))!
  }

  public var globalAlpha: Double {
    get {
      return OffscreenCanvasRenderingContext2dGetGlobalAlpha(reference)
    }
    set {
      OffscreenCanvasRenderingContext2dSetGlobalAlpha(reference, newValue)
    }
  }

  public var globalCompositeOperation: BlendMode {
    return BlendMode(rawValue: OffscreenCanvasRenderingContext2dGetGlobalCompositeOperation(reference))!
  }

  public var filter: String {
    var len: CInt = 0
    let cstr = OffscreenCanvasRenderingContext2dGetFilter(reference, &len)
    return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
  }

  // image smoothing
  public var imageSmoothingEnabled: Bool {
    get {
      return OffscreenCanvasRenderingContext2dImageSmoothingEnabled(reference) != 0
    }
    set {
      OffscreenCanvasRenderingContext2dSetImageSmoothingEnabled(reference, newValue ? 1 : 0)
    }
  }

  public var imageSmoothingQuality: ImageSmoothingQuality {
    get {
      return ImageSmoothingQuality(rawValue: Int(OffscreenCanvasRenderingContext2dGetImageSmoothingQuality(reference)))!
    }
    set {
      OffscreenCanvasRenderingContext2dSetImageSmoothingQuality(reference, CInt(newValue.rawValue))
    }
  }

  // FIXME: support Color + CanvasGradient + CanvasPattern
  public var fillStyle: String {
    get {
      var len: CInt = 0 
      let cstr = OffscreenCanvasRenderingContext2dGetFillStyle(reference, &len)
      return String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    set {
      newValue.withCString {
        OffscreenCanvasRenderingContext2dSetFillStyle(reference, $0)
      }
    }
  }

  // FIXME: support Color + CanvasGradient + CanvasPattern
  public var strokeStyle: String {
    get {
      var len: CInt = 0 
      let cstr = OffscreenCanvasRenderingContext2dGetStrokeStyle(reference, &len)
      return String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    set {
      newValue.withCString {
        OffscreenCanvasRenderingContext2dSetStrokeStyle(reference, $0)
      }
    }
  }

   // shadows
  public var shadowOffsetX: Double {
    get {
      return OffscreenCanvasRenderingContext2dGetShadowOffsetX(reference)
    }
    set {
      OffscreenCanvasRenderingContext2dSetShadowOffsetX(reference, newValue)
    }
  }

  public var shadowOffsetY: Double {
    get {
      return OffscreenCanvasRenderingContext2dGetShadowOffsetY(reference)
    }
    set {
      OffscreenCanvasRenderingContext2dSetShadowOffsetY(reference, newValue)
    }
  }

  public var shadowBlur: Double {
    get {
      return OffscreenCanvasRenderingContext2dGetShadowBlur(reference)
    }
    set {
      OffscreenCanvasRenderingContext2dSetShadowBlur(reference, newValue)
    }
  }

  public var shadowColor: String {
    get {
      var len: CInt = 0 
      let cstr = OffscreenCanvasRenderingContext2dGetShadowColor(reference, &len)
      return String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    set {
      newValue.withCString {
        OffscreenCanvasRenderingContext2dSetShadowColor(reference, $0)
      }
    }
  }
  
  public var imageProvider: ImageProvider?
  var _nativeCanvas: SkiaCanvas?
  var reference: OffscreenCanvasRenderingContext2dRef
  private weak var canvas: OffscreenCanvas?
  private var callbacks: [OffscreenCanvasCommitState] = []

  init(canvas: OffscreenCanvas, reference: OffscreenCanvasRenderingContext2dRef) {
    self.canvas = canvas
    self.reference = reference
  }

  public func commit(_ cb: @escaping () -> Void) {
    let state = OffscreenCanvasCommitState(self, cb)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    if let w = canvas?.window {
      OffscreenCanvasRenderingContext2dCommit(reference, w.reference, statePtr, { (cbState: UnsafeMutableRawPointer?, ignore: UnsafeMutableRawPointer?) in
        let cb = unsafeBitCast(cbState, to: OffscreenCanvasCommitState.self)
        cb.callback()
        cb.dispose()
      })
    }
    if let w = canvas?.worker {
      OffscreenCanvasRenderingContext2dCommitFromWorker(reference, w.reference, statePtr, { (cbState: UnsafeMutableRawPointer?, ignore: UnsafeMutableRawPointer?) in
        let cb = unsafeBitCast(cbState, to: OffscreenCanvasCommitState.self)
        cb.callback()
        cb.dispose()
      })
    }
    if let w = canvas?.scope {
      OffscreenCanvasRenderingContext2dCommitFromServiceWorker(reference, w.reference, statePtr, { (cbState: UnsafeMutableRawPointer?, ignore: UnsafeMutableRawPointer?) in
        let cb = unsafeBitCast(cbState, to: OffscreenCanvasCommitState.self)
        cb.callback()
        cb.dispose()
      })
    }
  }

  public func transform(_ a: Double, _ b: Double, _ c: Double, _ d: Double, _ e: Double, _ f: Double) {
    OffscreenCanvasRenderingContext2dTransform(reference, a, b, c, d, e, f)
  }

  public func setTransform(_ a: Double, _ b: Double, _ c: Double, _ d: Double, _ e: Double, _ f: Double) {
    OffscreenCanvasRenderingContext2dSetTransform(reference, a, b, c, d, e, f)
  }

  public func resetTransform() {
    OffscreenCanvasRenderingContext2dResetTransform(reference)
  }

  public func createLinearGradient(_ x0: Double, _ y0: Double, _ x1: Double, _ y1: Double) -> CanvasGradient {
    return CanvasGradient(reference: OffscreenCanvasRenderingContext2dCreateLinearGradient(reference, x0, y0, x1, y1))
  }

  public func createRadialGradient(_ x0: Double, _ y0: Double, _ r0: Double, _ x1: Double, _ y1: Double, _ r1: Double) -> CanvasGradient {
    return CanvasGradient(reference: OffscreenCanvasRenderingContext2dCreateRadialGradient(reference, x0, y0, r0, x1, y1, r1))
  }

  public func createPattern(_ image: ImageBitmap, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let window = canvas?.window {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternImageBitmap(reference, window.reference, image.reference, cstr)!)
      }
      if let worker = canvas?.worker {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternImageBitmapForWorker(reference, worker.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternImageBitmapForServiceWorker(reference, canvas!.scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: CSSImageValue, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let window = canvas?.window {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternCSSImageValue(reference, window.reference, image.reference, cstr)!)
      }
      if let worker = canvas?.worker {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternCSSImageValueForWorker(reference, worker.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternCSSImageValueForServiceWorker(reference, canvas!.scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: HtmlImageElement, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let window = canvas?.window {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternHtmlImageElement(reference, window.reference, image.reference, cstr)!)
      }
      if let worker = canvas?.worker {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternHtmlImageElementForWorker(reference, worker.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternHtmlImageElementForServiceWorker(reference, canvas!.scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: SvgImageElement, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let window = canvas?.window {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternSVGImageElement(reference, window.reference, image.reference, cstr)!)
      }
      if let worker = canvas?.worker {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternSVGImageElementForWorker(reference, worker.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternSVGImageElementForServiceWorker(reference, canvas!.scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: HtmlCanvasElement, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let window = canvas?.window {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternHtmlCanvasElement(reference, window.reference, image.reference, cstr)!)
      }
      if let worker = canvas?.worker {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternHtmlCanvasElementForWorker(reference, worker.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternHtmlCanvasElementForServiceWorker(reference, canvas!.scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: OffscreenCanvas, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let window = canvas?.window {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternOffscreenCanvas(reference, window.reference, image.reference, cstr)!)
      }
      if let worker = canvas?.worker {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternOffscreenCanvasForWorker(reference, worker.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternOffscreenCanvasForServiceWorker(reference, canvas!.scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: HtmlVideoElement, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let window = canvas?.window {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternHtmlVideoElement(reference, window.reference, image.reference, cstr)!)
      }
      if let worker = canvas?.worker {
        return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternHtmlVideoElementForWorker(reference, worker.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: OffscreenCanvasRenderingContext2dCreatePatternHtmlVideoElementForServiceWorker(reference, canvas!.scope!.reference, image.reference, cstr)!)
    }
  }

  public func strokeRect(_ rect: FloatRect) {
    strokeRect(Int(rect.x), Int(rect.y), Int(rect.width), Int(rect.height))
  }

  public func strokeRect(_ rect: IntRect) {
    strokeRect(rect.x, rect.y, rect.width, rect.height)
  }

  public func strokeRect(_ x: Int, _ y: Int, _ width: Int, _ height: Int) {
    OffscreenCanvasRenderingContext2dStrokeRect(reference, CInt(x), CInt(y), CInt(width), CInt(height))
  }

  public func clearRect(_ x: Int, _ y: Int, _ width: Int, _ height: Int) {
    OffscreenCanvasRenderingContext2dClearRect(reference, CInt(x), CInt(y), CInt(width), CInt(height))
  }

  public func fillRect(_ x: Int, _ y: Int, _ width: Int, _ height: Int) {
    OffscreenCanvasRenderingContext2dFillRect(reference, CInt(x), CInt(y), CInt(width), CInt(height))
  }

  public func beginPath() {
    OffscreenCanvasRenderingContext2dBeginPath(reference)
  }

  public func fill(winding: CanvasFillRule?) {
    if let w = winding {
      OffscreenCanvasRenderingContext2dFillWithWinding(reference, CInt(w.rawValue))
      return
    }
    OffscreenCanvasRenderingContext2dFill(reference)
  }

  public func fill(path: Path2d, winding: CanvasFillRule?) {
    if let w = winding {
      OffscreenCanvasRenderingContext2dFillWithPathAndWinding(reference, path.reference, CInt(w.rawValue))
      return
    }
    OffscreenCanvasRenderingContext2dFillWithPath(reference, path.reference)
  }

  public func stroke() {
    OffscreenCanvasRenderingContext2dStroke(reference)
  }

  public func stroke(path: Path2d) {
    OffscreenCanvasRenderingContext2dStrokeWithPath(reference, path.reference)
  }

  public func clip() {
    OffscreenCanvasRenderingContext2dClip(reference)
  }

  public func clip(path: Path2d) {
    OffscreenCanvasRenderingContext2dClipWithPath(reference, path.reference)
  }

  public func isPointInPath(x: Double, y: Double, winding: CanvasFillRule?) -> Bool {
    guard let w = winding else {
      return OffscreenCanvasRenderingContext2dIsPointInPath(reference, x, y) != 0
    }
    return OffscreenCanvasRenderingContext2dIsPointInPathWithWinding(reference, x, y, CInt(w.rawValue)) != 0  
  }

  public func isPointInPath(path: Path2d, x: Double, y: Double, winding: CanvasFillRule?) -> Bool {
    guard let w = winding else {
      return OffscreenCanvasRenderingContext2dIsPointInPathWithPath(reference, path.reference, x, y) != 0
    }
    return OffscreenCanvasRenderingContext2dIsPointInPathWithPathAndWinding(reference, path.reference, x, y, CInt(w.rawValue)) != 0
  }

  public func isPointInStroke(x: Double, y: Double) -> Bool {
    return OffscreenCanvasRenderingContext2dIsPointInStroke(reference, x, y) != 0
  }

  public func isPointInStroke(path: Path2d, x: Double, y: Double) -> Bool {
    return OffscreenCanvasRenderingContext2dIsPointInStroke(reference, x, y) != 0
  }

  public func fillText(_ text: String, x: Double, y: Double, maxWidth: Double?) {
    text.withCString { cstr in
      if let width = maxWidth {      
        OffscreenCanvasRenderingContext2dFillTextWithWidth(reference, cstr, x, y, width)
        return
      } 
      OffscreenCanvasRenderingContext2dFillText(reference, cstr, x, y)
    }
  }

  public func strokeText(_ text: String, x: Double, y: Double, maxWidth: Double?) {
    text.withCString { cstr in
      if let width = maxWidth {
        OffscreenCanvasRenderingContext2dStrokeTextWithWidth(reference, cstr, x, y, width)
        return
      }
      OffscreenCanvasRenderingContext2dStrokeText(reference, cstr, x, y)
    }
  }

  // public func measureText(_ text: String) -> TextMetrics {}

  public func drawImage(_ image: ImageBitmap, x: Double, y: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageBitmap(reference, window.reference, image.reference, x, y)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageBitmapForWorker(reference, worker.reference, image.reference, x, y)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageBitmapForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: ImageBitmap, x: Double, y: Double, width: Double, height: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageBitmapWH(reference, window.reference, image.reference, x, y, width, height)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageBitmapWHForWorker(reference, worker.reference, image.reference, x, y, width, height)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageBitmapWHForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: ImageBitmap, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageBitmapSrcDst(reference, window.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageBitmapSrcDstForWorker(reference, worker.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageBitmapSrcDstForServiceWorker(reference, canvas!.scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: CSSImageValue, x: Double, y: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageCSSImage(reference, window.reference, image.reference, x, y)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageCSSImageForWorker(reference, worker.reference, image.reference, x, y)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageCSSImageForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: CSSImageValue, x: Double, y: Double, width: Double, height: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageCSSImageWH(reference, window.reference, image.reference, x, y, width, height)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageCSSImageWHForWorker(reference, worker.reference, image.reference, x, y, width, height)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageCSSImageWHForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: CSSImageValue, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageCSSImageSrcDst(reference, window.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageCSSImageSrcDstForWorker(reference, worker.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageCSSImageSrcDstForServiceWorker(reference, canvas!.scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: HtmlImageElement, x: Double, y: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageHTMLImage(reference, window.reference, image.reference, x, y)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageHTMLImageForWorker(reference, worker.reference, image.reference, x, y)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageHTMLImageForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: HtmlImageElement, x: Double, y: Double, width: Double, height: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageHTMLImageWH(reference, window.reference, image.reference, x, y, width, height)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageHTMLImageWHForWorker(reference, worker.reference, image.reference, x, y, width, height)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageHTMLImageWHForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: HtmlImageElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageHTMLImageSrcDst(reference, window.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageHTMLImageSrcDstForWorker(reference, worker.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageHTMLImageSrcDstForServiceWorker(reference, canvas!.scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: SvgImageElement, x: Double, y: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageSVGImage(reference, window.reference, image.reference, x, y)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageSVGImageForWorker(reference, worker.reference, image.reference, x, y)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageSVGImageForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: SvgImageElement, x: Double, y: Double, width: Double, height: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageSVGImageWH(reference, window.reference, image.reference, x, y, width, height)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageSVGImageWHForWorker(reference, worker.reference, image.reference, x, y, width, height)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageSVGImageWHForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: SvgImageElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageSVGImageSrcDst(reference, window.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageSVGImageSrcDstForWorker(reference, worker.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageSVGImageSrcDstForServiceWorker(reference, canvas!.scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: HtmlCanvasElement, x: Double, y: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageHTMLCanvas(reference, window.reference, image.reference, x, y)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasForWorker(reference, worker.reference, image.reference, x, y)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: HtmlCanvasElement, x: Double, y: Double, width: Double, height: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasWH(reference, window.reference, image.reference, x, y, width, height)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasWHForWorker(reference, worker.reference, image.reference, x, y, width, height)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasWHForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: HtmlCanvasElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasSrcDst(reference, window.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForWorker(reference, worker.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForServiceWorker(reference, canvas!.scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: OffscreenCanvas, x: Double, y: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvas(reference, window.reference, image.reference, x, y)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasForWorker(reference, worker.reference, image.reference, x, y)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: OffscreenCanvas, x: Double, y: Double, width: Double, height: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasWH(reference, window.reference, image.reference, x, y, width, height)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasWHForWorker(reference, worker.reference, image.reference, x, y, width, height)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasWHForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: OffscreenCanvas, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDst(reference, window.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForWorker(reference, worker.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForServiceWorker(reference, canvas!.scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: HtmlVideoElement, x: Double, y: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageHTMLVideo(reference, window.reference, image.reference, x, y)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageHTMLVideoForWorker(reference, worker.reference, image.reference, x, y)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageHTMLVideoForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: HtmlVideoElement, x: Double, y: Double, width: Double, height: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageHTMLVideoWH(reference, window.reference, image.reference, x, y, width, height)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageHTMLVideoWHForWorker(reference, worker.reference, image.reference, x, y, width, height)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageHTMLVideoWHForServiceWorker(reference, canvas!.scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: HtmlVideoElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let window = canvas?.window {
      OffscreenCanvasRenderingContext2dDrawImageHTMLVideoSrcDst(reference, window.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let worker = canvas?.worker {
      OffscreenCanvasRenderingContext2dDrawImageHTMLVideoSrcDstForWorker(reference, worker.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    OffscreenCanvasRenderingContext2dDrawImageHTMLVideoSrcDstForServiceWorker(reference, canvas!.scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func createImageData(data: ImageData) -> ImageData {
    return ImageData(reference: OffscreenCanvasRenderingContext2dCreateImageDataWithImageData(reference, data.reference)!)
  }
  
  public func createImageData(width: Int, height: Int) -> ImageData {
    let settings = ImageDataColorSettings()
    return ImageData(reference: OffscreenCanvasRenderingContext2dCreateImageData(reference, CInt(width), CInt(height), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
  }
  
  public func createImageData(width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData {
    return ImageData(reference: OffscreenCanvasRenderingContext2dCreateImageData(reference, CInt(width), CInt(height), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
  }
  
  public func createImageData(data: Data, width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData {
    return data.withUnsafeBytes {
      return ImageData(reference: OffscreenCanvasRenderingContext2dCreateImageDataWithBytes(reference, CInt(width), CInt(height), $0, CInt(data.count), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
    }
  }

  public func createImageData(data: Uint8ClampedArray, width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData {
    return ImageData(reference: OffscreenCanvasRenderingContext2dCreateImageDataWithUint8Array(reference, CInt(width), CInt(height), data.reference, CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
  }
  
  public func getImageData(x: Int, y: Int, width: Int, height: Int) -> ImageData {
    return ImageData(reference: OffscreenCanvasRenderingContext2dGetImageData(reference, CInt(x), CInt(y), CInt(width), CInt(height))!)
  }
  
  public func putImageData(_ data: ImageData, x: Int, y: Int) {
    OffscreenCanvasRenderingContext2dPutImageData(reference, data.reference, CInt(x), CInt(y))
  }

  public func putImageData(_ data: ImageData, x: Int, y: Int, dirtyX: Int, dirtyY: Int, dirtyWidth: Int, dirtyHeight: Int) {
    OffscreenCanvasRenderingContext2dPutImageDataWithDamage(reference, data.reference, CInt(x), CInt(y), CInt(dirtyX), CInt(dirtyY), CInt(dirtyWidth), CInt(dirtyHeight))
  }

  public func closePath() {
    OffscreenCanvasRenderingContext2dClosePath(reference)
  }

  public func moveTo(_ x: Float, _ y: Float) {
    OffscreenCanvasRenderingContext2dMoveTo(reference, x, y)
  }
  
  public func lineTo(_ x: Float, _ y: Float) {
    OffscreenCanvasRenderingContext2dLineTo(reference, x, y)
  }
  
  public func quadraticCurveTo(_ cpx: Float, _ cpy: Float, _ x: Float, _ y: Float) {
    OffscreenCanvasRenderingContext2dQuadraticCurveTo(reference, cpx, cpy, x, y)
  }
  
  public func bezierCurveTo(_ cp1x: Float, _ cp1y: Float, _ cp2x: Float, _ cp2y: Float, _ x: Float, _ y: Float) {
    OffscreenCanvasRenderingContext2dBezierCurveTo(reference, cp1x, cp1y, cp2x, cp2y, x, y)
  }
  
  public func arcTo(_ x1: Float, _ y1: Float, _ x2: Float, _ y2: Float, _ radius: Float) {
    OffscreenCanvasRenderingContext2dArcTo(reference, x1, y1, x2, y2, radius)
  }
  
  public func rect(_ x: Float, _ y: Float, _ width: Float, _ height: Float) {
    OffscreenCanvasRenderingContext2dRect(reference, x, y, width, height)
  }

  public func arc(_ x: Float, _ y: Float, _ radius: Float, _ startAngle: Float, _ endAngle: Float, anticlockwise: Bool = false) {
    OffscreenCanvasRenderingContext2dArc(reference, x, y, radius, startAngle, endAngle, anticlockwise ? 1 : 0)
  }
  
  public func ellipse(_ x: Float, _ y: Float, _ radiusX: Float, _ radiusY: Float, _ rotation: Float, _ startAngle: Float, _ endAngle: Float, anticlockwise: Bool = false) {
    OffscreenCanvasRenderingContext2dEllipse(reference, x, y, radiusX, radiusY, rotation, startAngle, endAngle, anticlockwise ? 1: 0)
  }

  internal func addCallback(_ cb: OffscreenCanvasCommitState) {
    callbacks.append(cb)
  }

  internal func removeCallback(_ state: OffscreenCanvasCommitState) {
    for (i, item) in callbacks.enumerated() {
      if item === state {
        callbacks.remove(at: i)
        return
      }
    }
  }
}

extension OffscreenCanvasRenderingContext2d : PaintCanvas {
  
  public var saveCount: Int {
    return Int(OffscreenCanvasRenderingContext2dGetSaveCount(reference))
  }

  public var displayItemList: DisplayItemList? {
    let ref = OffscreenCanvasRenderingContext2dGetDisplayItemList(reference)
    return ref != nil ? DisplayItemList(reference: ref!, owned: false) : nil
  }
  
  public var localClipBounds: FloatRect? {
    var x: Float = 0.0, y: Float = 0.0, width: Float = 0.0, height: Float = 0.0
    let result = OffscreenCanvasRenderingContext2dGetLocalClipBounds(reference, &x, &y, &width, &height)
    if result == 1 {
      return FloatRect(x: x, y: y, width: width, height: height)
    }
    return nil
  }

  public var deviceClipBounds: IntRect? {
    var x: Int32 = 0, y: Int32 = 0, width: Int32 = 0, height: Int32 = 0
    let result = OffscreenCanvasRenderingContext2dGetDeviceClipBounds(reference, &x, &y, &width, &height)
    if result == 1 {
      return IntRect(x: Int(x), y: Int(y), width: Int(width), height: Int(height))
    }
    return nil
  }

  public var isClipEmpty: Bool {
    return OffscreenCanvasRenderingContext2dIsClipEmpty(reference) == 0 ? false : true
  }

  public var isClipRect: Bool {
    return OffscreenCanvasRenderingContext2dIsClipRect(reference) == 0 ? false : true
  }

  public var totalMatrix: Mat {
    let ref = OffscreenCanvasRenderingContext2dTotalMatrix(reference)
    return Mat(reference: ref!, owned: false)
  }
  
  // todo: how to make this work?
  public var nativeCanvas: SkiaCanvas {
    assert(false)
    if let canvas = _nativeCanvas {
      return canvas
    }
    _nativeCanvas = SkiaCanvas()
    return _nativeCanvas!
  }

  public func flush() {
    OffscreenCanvasRenderingContext2dFlush(reference)
  }

  public func save() -> Int {
    return Int(OffscreenCanvasRenderingContext2dSave(reference))
  }

  public func saveLayer(bounds: FloatRect?, flags paintFlags: PaintFlags?) -> Int {
    if let rect = bounds {
      return Int(OffscreenCanvasRenderingContext2dSaveLayerRect(reference, rect.x, rect.y, rect.width, rect.height, paintFlags != nil ? paintFlags!.reference : nil))
    } else {
      return Int(OffscreenCanvasRenderingContext2dSaveLayer(reference, paintFlags != nil ? paintFlags!.reference : nil))
    }
  }

  public func saveLayerAlpha(alpha: UInt8) -> Int {
    return Int(OffscreenCanvasRenderingContext2dSaveLayerAlpha(reference, CInt(alpha)))
  }
  
  public func saveLayerAlpha(bounds: FloatRect?, alpha: UInt8, preserveLcdTextRequests: Bool) -> Int {
    if preserveLcdTextRequests {
      let paint = Paint()
      paint.alpha = alpha
      return saveLayerPreserveLCDTextRequests(paint: paint, bounds: bounds)
    }
    if let rect = bounds {
      return Int(OffscreenCanvasRenderingContext2dSaveLayerAlphaRect(reference, CInt(alpha), rect.x, rect.y, rect.width, rect.height))
    } else {
      return Int(OffscreenCanvasRenderingContext2dSaveLayerAlpha(reference, CInt(alpha)))
    }
  }

  public func saveLayerPreserveLCDTextRequests(paint: Paint, bounds: FloatRect?) -> Int {
    if let b = bounds {
      return Int(OffscreenCanvasRenderingContext2dSaveLayerPreserveLCDTextRequestsRect(reference, b.x, b.y, b.width, b.height, paint.reference))
    } else {
      return Int(OffscreenCanvasRenderingContext2dSaveLayerPreserveLCDTextRequests(reference, paint.reference))
    }
  }
  
  public func restore() {
    OffscreenCanvasRenderingContext2dRestore(reference)
  }
  
  public func restoreToCount(saveCount: Int) {
    OffscreenCanvasRenderingContext2dRestoreToCount(reference, Int32(saveCount))
  }

  public func translate(offset: IntVec2) {
    translate(x: Float(offset.x), y: Float(offset.y))
  }

  public func translate(offset: FloatVec2) {
    translate(x: offset.x, y: offset.y)
  }

  public func translate(x: Float, y: Float) {
    OffscreenCanvasRenderingContext2dTranslate(reference, x, y)
  }
  
  public func scale(x: Float, y: Float) {
    OffscreenCanvasRenderingContext2dScale(reference, x, y)
  }
  
  public func rotate(degrees: Float) {
    OffscreenCanvasRenderingContext2dRotate(reference, degrees)
  }
  
  public func concat(matrix: Mat) {
    OffscreenCanvasRenderingContext2dConcatHandle(reference, matrix.reference)
  }
  
  public func setMatrix(_ matrix: Mat) {
    OffscreenCanvasRenderingContext2dSetMatrixHandle(reference, matrix.reference)
  }
  
  public func clipRect(_ rect: FloatRect, clip: ClipOp, antiAlias: Bool) {
    OffscreenCanvasRenderingContext2dClipRect(reference, rect.x, rect.y, rect.width, rect.height, Int32(clip.rawValue), antiAlias.intValue)
  }
  
  public func clipRect(_ rect: FloatRect, clip: ClipOp) {
    clipRect(rect, clip: clip, antiAlias: true)
  }
 
  public func clipRRect(_ rrect: FloatRRect, clip: ClipOp, antiAlias: Bool) {
    OffscreenCanvasRenderingContext2dClipRRect(reference, rrect.x, rrect.y, rrect.width, rrect.height, Int32(clip.rawValue), antiAlias.intValue)
  }
  
  public func clipPath(_ path: Path, clip: ClipOp, antiAlias: Bool) {
    OffscreenCanvasRenderingContext2dClipPath(reference, path.reference, Int32(clip.rawValue), antiAlias.intValue)
  }
 
  public func clipPath(_ path: Path, clip: ClipOp) {
    clipPath(path, clip: clip, antiAlias: true)
  }

  public func drawColor(_ color: Color, mode: BlendMode) {
    OffscreenCanvasRenderingContext2dDrawColor(reference, CInt(color.a), CInt(color.r), CInt(color.g), CInt(color.b), CInt(mode.rawValue))
  }
 
  public func drawColor(_ color: Color) {
    drawColor(color, mode: .SrcOver)
  }

  public func clearRect(_ rect: IntRect) {
    OffscreenCanvasRenderingContext2dClearRect(reference, CInt(rect.x), CInt(rect.y), CInt(rect.width), CInt(rect.height));
  }

  public func clearRect(_ rect: FloatRect) {
    OffscreenCanvasRenderingContext2dClearRect(reference, CInt(rect.x), CInt(rect.y), CInt(rect.width), CInt(rect.height));
  }
 
  public func clear(color: Color) {
    OffscreenCanvasRenderingContext2dDrawColor(reference, CInt(color.a), CInt(color.r), CInt(color.g), CInt(color.b), CInt(BlendMode.Src.rawValue))
  }
 
  public func drawLine(x0: Float, y0: Float, x1: Float, y1: Float, flags: PaintFlags) {
    drawLine(start: FloatPoint(x: x0, y: y0), end: FloatPoint(x: x1, y: y1), flags: flags)
  }

  public func drawLine(start: FloatPoint, end: FloatPoint, flags: PaintFlags) {
    OffscreenCanvasRenderingContext2dDrawLine(reference, start.x, start.y, end.x, end.y, flags.reference)
  }
 
  public func drawRect(_ rect: FloatRect, flags: PaintFlags) {
    OffscreenCanvasRenderingContext2dDrawRect(reference, rect.x, rect.y, rect.width, rect.height, flags.reference)    
  }
 
  public func drawIRect(_ rect: IntRect, flags: PaintFlags) {
    OffscreenCanvasRenderingContext2dDrawIRect(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height), flags.reference)
  }
 
  public func drawOval(_ rect: FloatRect, flags: PaintFlags) {
    OffscreenCanvasRenderingContext2dDrawOval(reference, rect.x, rect.y, rect.width, rect.height, flags.reference)
  }
 
  public func drawRRect(_ rrect: FloatRRect, flags: PaintFlags) {
    OffscreenCanvasRenderingContext2dDrawRRect(reference, rrect.x, rrect.y, rrect.width, rrect.height, flags.reference)    
  }

  public func drawDRRect(outer: FloatRRect, inner: FloatRRect, flags: PaintFlags) {
    OffscreenCanvasRenderingContext2dDrawDRRect(reference, outer.x, outer.y, outer.width, outer.height, inner.x, inner.y, inner.width, inner.height, flags.reference)
  }
 
  public func drawRoundRect(_ rect: FloatRect, x: Float, y: Float, flags: PaintFlags) {
    OffscreenCanvasRenderingContext2dDrawRoundRect(reference, rect.x, rect.y, rect.width, rect.height, x, y, flags.reference)
  }
 
  public func drawPath(_ path: Path, flags: PaintFlags) {
    let paint = flags.toPaint()
    OffscreenCanvasRenderingContext2dDrawPath(reference, path.reference, paint.reference)
  }
 
  public func drawImage(_ image: ImageSkia, left: Float, top: Float, flags: PaintFlags?) {
    OffscreenCanvasRenderingContext2dDrawImage(reference, image.reference, left, top, flags != nil ? flags!.reference : nil)
  }
 
  public func drawImageRect(_ image: ImageSkia, src: FloatRect, dst: FloatRect, constraint: SrcRectConstraint, flags: PaintFlags?) { 
    OffscreenCanvasRenderingContext2dDrawImageRect(reference, 
      image.reference,
      src.x, src.y, src.width, src.height,
      dst.x, dst.y, dst.width, dst.height,
      constraint.rawValue, 
      flags != nil ? flags!.reference : nil)
  }
 
  public func drawBitmap(_ bitmap: Bitmap, left: Float, top: Float, flags: PaintFlags?) {
    OffscreenCanvasRenderingContext2dDrawBitmap(reference, bitmap.reference, left, top, flags != nil ? flags!.reference : nil)
  }
  
  public func drawTextBlob(_ blob: PaintTextBlob, x: Float, y: Float, flags: PaintFlags) {
    OffscreenCanvasRenderingContext2dDrawTextBlob(reference, blob.reference, x, y, flags.reference) 
  }
 
  public func drawPicture(record: PaintRecord) {
    OffscreenCanvasRenderingContext2dDrawPicture(reference, record.reference)
  }

  public func fillRect(_ rect: IntRect) {
    OffscreenCanvasRenderingContext2dFillRect(reference, CInt(rect.x), CInt(rect.y), CInt(rect.width), CInt(rect.height))
  }
 
  public func recordCustomData(id: UInt32) {}
}

public class OffscreenCanvasCommitState {
  
  weak var context: OffscreenCanvasRenderingContext2d?
  let callback: () -> Void
  
  init(_ context: OffscreenCanvasRenderingContext2d, _ cb: @escaping () -> Void) {
    self.context = context
    self.callback = cb
    context.addCallback(self)
  }

  func dispose() {
    context!.removeCallback(self)
  }

}