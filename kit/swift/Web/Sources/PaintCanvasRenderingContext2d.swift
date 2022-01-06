// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import Foundation

public class PaintCanvasRenderingContext2d : CanvasRenderingContext {

  public var lineWidth: Double {
    return PaintCanvasRenderingContext2dGetLineWidth(reference)
  }

  public var lineCap: CanvasLineCap {
    return CanvasLineCap(rawValue: Int(PaintCanvasRenderingContext2dGetLineCap(reference)))!
  }

  public var lineJoin: CanvasLineJoin {
    return CanvasLineJoin(rawValue: Int(PaintCanvasRenderingContext2dGetLineJoin(reference)))!
  }

  public var miterLimit: Double {
    return PaintCanvasRenderingContext2dGetMiterLimit(reference)
  }

  public var lineDash: [Double] {
    get {
      var ret: [Double] = []
      var count: CInt = 0
      var doubles: UnsafeMutablePointer<Double>?
      PaintCanvasRenderingContext2dGetLineDash(reference, &doubles, &count)
      for i in 0..<count {
        ret.append(doubles![Int(i)])
      }
      free(doubles)
      return ret
    }
    set {
      newValue.withUnsafeBufferPointer {
        PaintCanvasRenderingContext2dSetLineDash(reference, UnsafeMutableBufferPointer<Double>(mutating: $0).baseAddress, CInt(newValue.count))
      }
    }
  }

  public var lineDashOffset: Double {
    return PaintCanvasRenderingContext2dGetLineDashOffset(reference)
  }

  public var textAlign: CanvasTextAlign {
    return CanvasTextAlign(rawValue: Int(PaintCanvasRenderingContext2dGetTextAlign(reference)))!
  }
  
  public var textBaseline: CanvasTextBaseline {
    return CanvasTextBaseline(rawValue: Int(PaintCanvasRenderingContext2dGetTextBaseline(reference)))!
  }

  public var globalAlpha: Double {
    get {
      return PaintCanvasRenderingContext2dGetGlobalAlpha(reference)
    }
    set {
      PaintCanvasRenderingContext2dSetGlobalAlpha(reference, newValue)
    }
  }

  public var globalCompositeOperation: BlendMode {
    return BlendMode(rawValue: PaintCanvasRenderingContext2dGetGlobalCompositeOperation(reference))!
  }

  public var filter: String {
    var len: CInt = 0
    let cstr = PaintCanvasRenderingContext2dGetFilter(reference, &len)
    return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
  }

  // image smoothing
  public var imageSmoothingEnabled: Bool {
    get {
      return PaintCanvasRenderingContext2dImageSmoothingEnabled(reference) != 0
    }
    set {
      PaintCanvasRenderingContext2dSetImageSmoothingEnabled(reference, newValue ? 1 : 0)
    }
  }

  public var imageSmoothingQuality: ImageSmoothingQuality {
    get {
      return ImageSmoothingQuality(rawValue: Int(PaintCanvasRenderingContext2dGetImageSmoothingQuality(reference)))!
    }
    set {
      PaintCanvasRenderingContext2dSetImageSmoothingQuality(reference, CInt(newValue.rawValue))
    }
  }

  // FIXME: support Color + CanvasGradient + CanvasPattern
  public var fillStyle: String {
    get {
      var len: CInt = 0 
      let cstr = PaintCanvasRenderingContext2dGetFillStyle(reference, &len)
      return String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    set {
      newValue.withCString {
        PaintCanvasRenderingContext2dSetFillStyle(reference, $0)
      }
    }
  }

  // FIXME: support Color + CanvasGradient + CanvasPattern
  public var strokeStyle: String {
    get {
      var len: CInt = 0 
      let cstr = PaintCanvasRenderingContext2dGetStrokeStyle(reference, &len)
      return String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    set {
      newValue.withCString {
        PaintCanvasRenderingContext2dSetStrokeStyle(reference, $0)
      }
    }
  }

   // shadows
  public var shadowOffsetX: Double {
    get {
      return PaintCanvasRenderingContext2dGetShadowOffsetX(reference)
    }
    set {
      PaintCanvasRenderingContext2dSetShadowOffsetX(reference, newValue)
    }
  }

  public var shadowOffsetY: Double {
    get {
      return PaintCanvasRenderingContext2dGetShadowOffsetY(reference)
    }
    set {
      PaintCanvasRenderingContext2dSetShadowOffsetY(reference, newValue)
    }
  }

  public var shadowBlur: Double {
    get {
      return PaintCanvasRenderingContext2dGetShadowBlur(reference)
    }
    set {
      PaintCanvasRenderingContext2dSetShadowBlur(reference, newValue)
    }
  }

  public var shadowColor: String {
    get {
      var len: CInt = 0 
      let cstr = PaintCanvasRenderingContext2dGetShadowColor(reference, &len)
      return String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    set {
      newValue.withCString {
        PaintCanvasRenderingContext2dSetShadowColor(reference, $0)
      }
    }
  }

  public var imageProvider: ImageProvider?
  var _nativeCanvas: SkiaCanvas?
  var reference: PaintCanvasRenderingContext2dRef
  internal var window: WebWindow?
  internal var worker: WebWorker?
  internal var scope: ServiceWorkerGlobalScope?

  init(reference: PaintCanvasRenderingContext2dRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  init(reference: PaintCanvasRenderingContext2dRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }

  init(reference: PaintCanvasRenderingContext2dRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

  deinit {
    PaintCanvasRenderingContext2dDestroy(reference)
  }
  
  public func transform(_ a: Double, _ b: Double, _ c: Double, _ d: Double, _ e: Double, _ f: Double) {
    PaintCanvasRenderingContext2dTransform(reference, a, b, c, d, e, f)
  }

  public func setTransform(_ a: Double, _ b: Double, _ c: Double, _ d: Double, _ e: Double, _ f: Double) {
    PaintCanvasRenderingContext2dSetTransform(reference, a, b, c, d, e, f)
  }

  public func resetTransform() {
    PaintCanvasRenderingContext2dResetTransform(reference)
  }

  public func createLinearGradient(_ x0: Double, _ y0: Double, _ x1: Double, _ y1: Double) -> CanvasGradient {
    return CanvasGradient(reference: PaintCanvasRenderingContext2dCreateLinearGradient(reference, x0, y0, x1, y1))
  }

  public func createRadialGradient(_ x0: Double, _ y0: Double, _ r0: Double, _ x1: Double, _ y1: Double, _ r1: Double) -> CanvasGradient {
    return CanvasGradient(reference: PaintCanvasRenderingContext2dCreateRadialGradient(reference, x0, y0, r0, x1, y1, r1))
  }

  public func createPattern(_ image: ImageBitmap, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let wnd = window {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternImageBitmap(reference, wnd.reference, image.reference, cstr)!)
      }
      if let wrk = worker {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternImageBitmapForWorker(reference, wrk.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternImageBitmapForServiceWorker(reference, scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: CSSImageValue, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let wnd = window {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternCSSImageValue(reference, wnd.reference, image.reference, cstr)!)
      }
      if let wrk = worker {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternCSSImageValueForWorker(reference, wrk.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternCSSImageValueForServiceWorker(reference, scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: HtmlImageElement, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let wnd = window {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternHtmlImageElement(reference, wnd.reference, image.reference, cstr)!)
      }
      if let wrk = worker {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternHtmlImageElementForWorker(reference, wrk.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternHtmlImageElementForServiceWorker(reference, scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: SvgImageElement, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let wnd = window {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternSVGImageElement(reference, wnd.reference, image.reference, cstr)!)
      }
      if let wrk = worker {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternSVGImageElementForWorker(reference, wrk.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternSVGImageElementForServiceWorker(reference, scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: HtmlCanvasElement, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let wnd = window {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternHtmlCanvasElement(reference, wnd.reference, image.reference, cstr)!)
      }
      if let wrk = worker {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternHtmlCanvasElementForWorker(reference, wrk.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternHtmlCanvasElementForServiceWorker(reference, scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: OffscreenCanvas, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let wnd = window {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternOffscreenCanvas(reference, wnd.reference, image.reference, cstr)!)
      }
      if let wrk = worker {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternOffscreenCanvasForWorker(reference, wrk.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternOffscreenCanvasForServiceWorker(reference, scope!.reference, image.reference, cstr)!)
    }
  }

  public func createPattern(_ image: HtmlVideoElement, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let wnd = window {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternHtmlVideoElement(reference, wnd.reference, image.reference, cstr)!)
      }
      if let wrk = worker {
        return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternHtmlVideoElementForWorker(reference, wrk.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: PaintCanvasRenderingContext2dCreatePatternHtmlVideoElementForServiceWorker(reference, scope!.reference, image.reference, cstr)!)
    }
  }

  public func strokeRect(_ rect: FloatRect) {
    strokeRect(Int(rect.x), Int(rect.y), Int(rect.width), Int(rect.height))
  }

  public func strokeRect(_ rect: IntRect) {
    strokeRect(rect.x, rect.y, rect.width, rect.height)
  }

  public func strokeRect(_ x: Int, _ y: Int, _ width: Int, _ height: Int) {
    PaintCanvasRenderingContext2dStrokeRect(reference, CInt(x), CInt(y), CInt(width), CInt(height))
  }

  public func clearRect(_ x: Int, _ y: Int, _ width: Int, _ height: Int) {
    PaintCanvasRenderingContext2dClearRect(reference, CInt(x), CInt(y), CInt(width), CInt(height))
  }

  public func fillRect(_ x: Int, _ y: Int, _ width: Int, _ height: Int) {
    PaintCanvasRenderingContext2dFillRect(reference, CInt(x), CInt(y), CInt(width), CInt(height))
  }

  public func beginPath() {
    PaintCanvasRenderingContext2dBeginPath(reference)
  }

  public func fill(winding: CanvasFillRule?) {
    if let w = winding {
      PaintCanvasRenderingContext2dFillWithWinding(reference, CInt(w.rawValue))
      return
    }
    PaintCanvasRenderingContext2dFill(reference)
  }

  public func fill(path: Path2d, winding: CanvasFillRule?) {
    if let w = winding {
      PaintCanvasRenderingContext2dFillWithPathAndWinding(reference, path.reference, CInt(w.rawValue))
      return
    }
    PaintCanvasRenderingContext2dFillWithPath(reference, path.reference)
  }

  public func stroke() {
    PaintCanvasRenderingContext2dStroke(reference)
  }

  public func stroke(path: Path2d) {
    PaintCanvasRenderingContext2dStrokeWithPath(reference, path.reference)
  }

  public func clip() {
    PaintCanvasRenderingContext2dClip(reference)
  }

  public func clip(path: Path2d) {
    PaintCanvasRenderingContext2dClipWithPath(reference, path.reference)
  }

  public func isPointInPath(x: Double, y: Double, winding: CanvasFillRule?) -> Bool {
    guard let w = winding else {
      return PaintCanvasRenderingContext2dIsPointInPath(reference, x, y) != 0
    }
    return PaintCanvasRenderingContext2dIsPointInPathWithWinding(reference, x, y, CInt(w.rawValue)) != 0  
  }

  public func isPointInPath(path: Path2d, x: Double, y: Double, winding: CanvasFillRule?) -> Bool {
    guard let w = winding else {
      return PaintCanvasRenderingContext2dIsPointInPathWithPath(reference, path.reference, x, y) != 0
    }
    return PaintCanvasRenderingContext2dIsPointInPathWithPathAndWinding(reference, path.reference, x, y, CInt(w.rawValue)) != 0
  }

  public func isPointInStroke(x: Double, y: Double) -> Bool {
    return PaintCanvasRenderingContext2dIsPointInStroke(reference, x, y) != 0
  }

  public func isPointInStroke(path: Path2d, x: Double, y: Double) -> Bool {
    return PaintCanvasRenderingContext2dIsPointInStroke(reference, x, y) != 0
  }

  // public func measureText(_ text: String) -> TextMetrics {}

  public func drawImage(_ image: ImageBitmap, x: Double, y: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageBitmap(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageBitmapForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    PaintCanvasRenderingContext2dDrawImageBitmapForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: ImageBitmap, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageBitmapWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageBitmapWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    PaintCanvasRenderingContext2dDrawImageBitmapWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: ImageBitmap, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageBitmapSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageBitmapSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    PaintCanvasRenderingContext2dDrawImageBitmapSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: CSSImageValue, x: Double, y: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageCSSImage(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageCSSImageForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    PaintCanvasRenderingContext2dDrawImageCSSImageForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: CSSImageValue, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageCSSImageWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageCSSImageWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    PaintCanvasRenderingContext2dDrawImageCSSImageWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: CSSImageValue, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageCSSImageSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageCSSImageSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    PaintCanvasRenderingContext2dDrawImageCSSImageSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: HtmlImageElement, x: Double, y: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageHTMLImage(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageHTMLImageForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    PaintCanvasRenderingContext2dDrawImageHTMLImageForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: HtmlImageElement, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageHTMLImageWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageHTMLImageWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    PaintCanvasRenderingContext2dDrawImageHTMLImageWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: HtmlImageElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageHTMLImageSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageHTMLImageSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    PaintCanvasRenderingContext2dDrawImageHTMLImageSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: SvgImageElement, x: Double, y: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageSVGImage(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageSVGImageForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    PaintCanvasRenderingContext2dDrawImageSVGImageForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: SvgImageElement, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageSVGImageWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageSVGImageWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    PaintCanvasRenderingContext2dDrawImageSVGImageWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: SvgImageElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageSVGImageSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageSVGImageSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    PaintCanvasRenderingContext2dDrawImageSVGImageSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: HtmlCanvasElement, x: Double, y: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageHTMLCanvas(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageHTMLCanvasForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    PaintCanvasRenderingContext2dDrawImageHTMLCanvasForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: HtmlCanvasElement, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageHTMLCanvasWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageHTMLCanvasWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    PaintCanvasRenderingContext2dDrawImageHTMLCanvasWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: HtmlCanvasElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageHTMLCanvasSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    PaintCanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: OffscreenCanvas, x: Double, y: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageOffscreenCanvas(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageOffscreenCanvasForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    PaintCanvasRenderingContext2dDrawImageOffscreenCanvasForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: OffscreenCanvas, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageOffscreenCanvasWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageOffscreenCanvasWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    PaintCanvasRenderingContext2dDrawImageOffscreenCanvasWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: OffscreenCanvas, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    PaintCanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: HtmlVideoElement, x: Double, y: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageHTMLVideo(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageHTMLVideoForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    PaintCanvasRenderingContext2dDrawImageHTMLVideoForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: HtmlVideoElement, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageHTMLVideoWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageHTMLVideoWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    PaintCanvasRenderingContext2dDrawImageHTMLVideoWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: HtmlVideoElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      PaintCanvasRenderingContext2dDrawImageHTMLVideoSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      PaintCanvasRenderingContext2dDrawImageHTMLVideoSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    PaintCanvasRenderingContext2dDrawImageHTMLVideoSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func createImageData(data: ImageData) -> ImageData {
    return ImageData(reference: PaintCanvasRenderingContext2dCreateImageDataWithImageData(reference, data.reference)!)
  }
  
  public func createImageData(width: Int, height: Int) -> ImageData {
    let settings = ImageDataColorSettings()
    return ImageData(reference: PaintCanvasRenderingContext2dCreateImageData(reference, CInt(width), CInt(height), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
  }
  
  public func createImageData(width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData {
    return ImageData(reference: PaintCanvasRenderingContext2dCreateImageData(reference, CInt(width), CInt(height), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
  }
  
  public func createImageData(data: Data, width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData {
    return data.withUnsafeBytes {
      return ImageData(reference: PaintCanvasRenderingContext2dCreateImageDataWithBytes(reference, CInt(width), CInt(height), $0, CInt(data.count), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
    }
  }

  public func createImageData(data: Uint8ClampedArray, width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData {
    return ImageData(reference: PaintCanvasRenderingContext2dCreateImageDataWithUint8Array(reference, CInt(width), CInt(height), data.reference, CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
  }
  
  public func getImageData(x: Int, y: Int, width: Int, height: Int) -> ImageData {
    return ImageData(reference: PaintCanvasRenderingContext2dGetImageData(reference, CInt(x), CInt(y), CInt(width), CInt(height))!)
  }
  
  public func putImageData(_ data: ImageData, x: Int, y: Int) {
    PaintCanvasRenderingContext2dPutImageData(reference, data.reference, CInt(x), CInt(y))
  }

  public func putImageData(_ data: ImageData, x: Int, y: Int, dirtyX: Int, dirtyY: Int, dirtyWidth: Int, dirtyHeight: Int) {
    PaintCanvasRenderingContext2dPutImageDataWithDamage(reference, data.reference, CInt(x), CInt(y), CInt(dirtyX), CInt(dirtyY), CInt(dirtyWidth), CInt(dirtyHeight))
  }

  public func closePath() {
    PaintCanvasRenderingContext2dClosePath(reference)
  }

  public func moveTo(_ x: Float, _ y: Float) {
    PaintCanvasRenderingContext2dMoveTo(reference, x, y)
  }
  
  public func lineTo(_ x: Float, _ y: Float) {
    PaintCanvasRenderingContext2dLineTo(reference, x, y)
  }
  
  public func quadraticCurveTo(_ cpx: Float, _ cpy: Float, _ x: Float, _ y: Float) {
    PaintCanvasRenderingContext2dQuadraticCurveTo(reference, cpx, cpy, x, y)
  }
  
  public func bezierCurveTo(_ cp1x: Float, _ cp1y: Float, _ cp2x: Float, _ cp2y: Float, _ x: Float, _ y: Float) {
    PaintCanvasRenderingContext2dBezierCurveTo(reference, cp1x, cp1y, cp2x, cp2y, x, y)
  }
  
  public func arcTo(_ x1: Float, _ y1: Float, _ x2: Float, _ y2: Float, _ radius: Float) {
    PaintCanvasRenderingContext2dArcTo(reference, x1, y1, x2, y2, radius)
  }
  
  public func rect(_ x: Float, _ y: Float, _ width: Float, _ height: Float) {
    PaintCanvasRenderingContext2dRect(reference, x, y, width, height)
  }

  public func arc(_ x: Float, _ y: Float, _ radius: Float, _ startAngle: Float, _ endAngle: Float, anticlockwise: Bool = false) {
    PaintCanvasRenderingContext2dArc(reference, x, y, radius, startAngle, endAngle, anticlockwise ? 1 : 0)
  }
  
  public func ellipse(_ x: Float, _ y: Float, _ radiusX: Float, _ radiusY: Float, _ rotation: Float, _ startAngle: Float, _ endAngle: Float, anticlockwise: Bool = false) {
    PaintCanvasRenderingContext2dEllipse(reference, x, y, radiusX, radiusY, rotation, startAngle, endAngle, anticlockwise ? 1: 0)
  }

}

extension PaintCanvasRenderingContext2d : PaintCanvas {
  
  public var saveCount: Int {
    return Int(PaintCanvasRenderingContext2dGetSaveCount(reference))
  }

  public var displayItemList: DisplayItemList? {
    let ref = PaintCanvasRenderingContext2dGetDisplayItemList(reference)
    return ref != nil ? DisplayItemList(reference: ref!, owned: false) : nil
  }
  
  public var localClipBounds: FloatRect? {
    var x: Float = 0.0, y: Float = 0.0, width: Float = 0.0, height: Float = 0.0
    let result = PaintCanvasRenderingContext2dGetLocalClipBounds(reference, &x, &y, &width, &height)
    if result == 1 {
      return FloatRect(x: x, y: y, width: width, height: height)
    }
    return nil
  }

  public var deviceClipBounds: IntRect? {
    var x: Int32 = 0, y: Int32 = 0, width: Int32 = 0, height: Int32 = 0
    let result = PaintCanvasRenderingContext2dGetDeviceClipBounds(reference, &x, &y, &width, &height)
    if result == 1 {
      return IntRect(x: Int(x), y: Int(y), width: Int(width), height: Int(height))
    }
    return nil
  }

  public var isClipEmpty: Bool {
    return PaintCanvasRenderingContext2dIsClipEmpty(reference) == 0 ? false : true
  }

  public var isClipRect: Bool {
    return PaintCanvasRenderingContext2dIsClipRect(reference) == 0 ? false : true
  }

  public var totalMatrix: Mat {
    let ref = PaintCanvasRenderingContext2dTotalMatrix(reference)
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
    PaintCanvasRenderingContext2dFlush(reference)
  }

  public func save() -> Int {
    return Int(PaintCanvasRenderingContext2dSave(reference))
  }

  public func saveLayer(bounds: FloatRect?, flags paintFlags: PaintFlags?) -> Int {
    if let rect = bounds {
      return Int(PaintCanvasRenderingContext2dSaveLayerRect(reference, rect.x, rect.y, rect.width, rect.height, paintFlags != nil ? paintFlags!.reference : nil))
    } else {
      return Int(PaintCanvasRenderingContext2dSaveLayer(reference, paintFlags != nil ? paintFlags!.reference : nil))
    }
  }

  public func saveLayerAlpha(alpha: UInt8) -> Int {
    return Int(PaintCanvasRenderingContext2dSaveLayerAlpha(reference, CInt(alpha)))
  }
  
  public func saveLayerAlpha(bounds: FloatRect?, alpha: UInt8, preserveLcdTextRequests: Bool) -> Int {
    if preserveLcdTextRequests {
      let paint = Paint()
      paint.alpha = alpha
      return saveLayerPreserveLCDTextRequests(paint: paint, bounds: bounds)
    }
    if let rect = bounds {
      return Int(PaintCanvasRenderingContext2dSaveLayerAlphaRect(reference, CInt(alpha), rect.x, rect.y, rect.width, rect.height))
    } else {
      return Int(PaintCanvasRenderingContext2dSaveLayerAlpha(reference, CInt(alpha)))
    }
  }

  public func saveLayerPreserveLCDTextRequests(paint: Paint, bounds: FloatRect?) -> Int {
    if let b = bounds {
      return Int(PaintCanvasRenderingContext2dSaveLayerPreserveLCDTextRequestsRect(reference, b.x, b.y, b.width, b.height, paint.reference))
    } else {
      return Int(PaintCanvasRenderingContext2dSaveLayerPreserveLCDTextRequests(reference, paint.reference))
    }
  }
  
  public func restore() {
    PaintCanvasRenderingContext2dRestore(reference)
  }
  
  public func restoreToCount(saveCount: Int) {
    PaintCanvasRenderingContext2dRestoreToCount(reference, Int32(saveCount))
  }

  public func translate(offset: IntVec2) {
    translate(x: Float(offset.x), y: Float(offset.y))
  }

  public func translate(offset: FloatVec2) {
    translate(x: offset.x, y: offset.y)
  }

  public func translate(x: Float, y: Float) {
    PaintCanvasRenderingContext2dTranslate(reference, x, y)
  }
  
  public func scale(x: Float, y: Float) {
    PaintCanvasRenderingContext2dScale(reference, x, y)
  }
  
  public func rotate(degrees: Float) {
    PaintCanvasRenderingContext2dRotate(reference, degrees)
  }
  
  public func concat(matrix: Mat) {
    PaintCanvasRenderingContext2dConcatHandle(reference, matrix.reference)
  }
  
  public func setMatrix(_ matrix: Mat) {
    PaintCanvasRenderingContext2dSetMatrixHandle(reference, matrix.reference)
  }
  
  public func clipRect(_ rect: FloatRect, clip: ClipOp, antiAlias: Bool) {
    PaintCanvasRenderingContext2dClipRect(reference, rect.x, rect.y, rect.width, rect.height, Int32(clip.rawValue), antiAlias.intValue)
  }
  
  public func clipRect(_ rect: FloatRect, clip: ClipOp) {
    clipRect(rect, clip: clip, antiAlias: true)
  }
 
  public func clipRRect(_ rrect: FloatRRect, clip: ClipOp, antiAlias: Bool) {
    PaintCanvasRenderingContext2dClipRRect(reference, rrect.x, rrect.y, rrect.width, rrect.height, Int32(clip.rawValue), antiAlias.intValue)
  }
  
  public func clipPath(_ path: Path, clip: ClipOp, antiAlias: Bool) {
    PaintCanvasRenderingContext2dClipPath(reference, path.reference, Int32(clip.rawValue), antiAlias.intValue)
  }
 
  public func clipPath(_ path: Path, clip: ClipOp) {
    clipPath(path, clip: clip, antiAlias: true)
  }

  public func drawColor(_ color: Color, mode: BlendMode) {
    PaintCanvasRenderingContext2dDrawColor(reference, CInt(color.a), CInt(color.r), CInt(color.g), CInt(color.b), CInt(mode.rawValue))
  }
 
  public func drawColor(_ color: Color) {
    drawColor(color, mode: .SrcOver)
  }
 
  public func clear(color: Color) {
    PaintCanvasRenderingContext2dDrawColor(reference, CInt(color.a), CInt(color.r), CInt(color.g), CInt(color.b), CInt(BlendMode.Src.rawValue))
  }

  public func clearRect(_ rect: IntRect) {
    PaintCanvasRenderingContext2dClearRect(reference, CInt(rect.x), CInt(rect.y), CInt(rect.width), CInt(rect.height))
  }

  public func clearRect(_ rect: FloatRect) {
    PaintCanvasRenderingContext2dClearRect(reference, CInt(rect.x), CInt(rect.y), CInt(rect.width), CInt(rect.height))
  }
 
  public func drawLine(x0: Float, y0: Float, x1: Float, y1: Float, flags: PaintFlags) {
    drawLine(start: FloatPoint(x: x0, y: y0), end: FloatPoint(x: x1, y: y1), flags: flags)
  }

  public func drawLine(start: FloatPoint, end: FloatPoint, flags: PaintFlags) {
    PaintCanvasRenderingContext2dDrawLine(reference, start.x, start.y, end.x, end.y, flags.reference)
  }
 
  public func drawRect(_ rect: FloatRect, flags: PaintFlags) {
    PaintCanvasRenderingContext2dDrawRect(reference, rect.x, rect.y, rect.width, rect.height, flags.reference)    
  }
 
  public func drawIRect(_ rect: IntRect, flags: PaintFlags) {
    PaintCanvasRenderingContext2dDrawIRect(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height), flags.reference)
  }
 
  public func drawOval(_ rect: FloatRect, flags: PaintFlags) {
    PaintCanvasRenderingContext2dDrawOval(reference, rect.x, rect.y, rect.width, rect.height, flags.reference)
  }
 
  public func drawRRect(_ rrect: FloatRRect, flags: PaintFlags) {
    PaintCanvasRenderingContext2dDrawRRect(reference, rrect.x, rrect.y, rrect.width, rrect.height, flags.reference)    
  }

  public func drawDRRect(outer: FloatRRect, inner: FloatRRect, flags: PaintFlags) {
    PaintCanvasRenderingContext2dDrawDRRect(reference, outer.x, outer.y, outer.width, outer.height, inner.x, inner.y, inner.width, inner.height, flags.reference)
  }
 
  public func drawRoundRect(_ rect: FloatRect, x: Float, y: Float, flags: PaintFlags) {
    PaintCanvasRenderingContext2dDrawRoundRect(reference, rect.x, rect.y, rect.width, rect.height, x, y, flags.reference)
  }
 
  public func drawPath(_ path: Path, flags: PaintFlags) {
    let paint = flags.toPaint()
    PaintCanvasRenderingContext2dDrawPath(reference, path.reference, paint.reference)
  }
 
  public func drawImage(_ image: ImageSkia, left: Float, top: Float, flags: PaintFlags?) {
    PaintCanvasRenderingContext2dDrawImage(reference, image.reference, left, top, flags != nil ? flags!.reference : nil)
  }
 
  public func drawImageRect(_ image: ImageSkia, src: FloatRect, dst: FloatRect, constraint: SrcRectConstraint, flags: PaintFlags?) { 
    PaintCanvasRenderingContext2dDrawImageRect(reference, 
      image.reference,
      src.x, src.y, src.width, src.height,
      dst.x, dst.y, dst.width, dst.height,
      constraint.rawValue, 
      flags != nil ? flags!.reference : nil)
  }
 
  public func drawBitmap(_ bitmap: Bitmap, left: Float, top: Float, flags: PaintFlags?) {
    PaintCanvasRenderingContext2dDrawBitmap(reference, bitmap.reference, left, top, flags != nil ? flags!.reference : nil)
  }
  
  public func drawTextBlob(_ blob: PaintTextBlob, x: Float, y: Float, flags: PaintFlags) {
    //print("WebPaintCanvas.drawTextBlob")
    PaintCanvasRenderingContext2dDrawTextBlob(reference, blob.reference, x, y, flags.reference) 
  }
 
  public func drawPicture(record: PaintRecord) {
    PaintCanvasRenderingContext2dDrawPicture(reference, record.reference)
  }
 
  public func recordCustomData(id: UInt32) {}
}