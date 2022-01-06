// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import Foundation

public class CanvasRenderingContext2d : CanvasRenderingContext,
                                        CanvasTextRenderer {

  public var lineWidth: Double {
    return CanvasRenderingContext2dGetLineWidth(reference)
  }

  public var lineCap: CanvasLineCap {
    return CanvasLineCap(rawValue: Int(CanvasRenderingContext2dGetLineCap(reference)))!
  }

  public var lineJoin: CanvasLineJoin {
    return CanvasLineJoin(rawValue: Int(CanvasRenderingContext2dGetLineJoin(reference)))!
  }

  public var miterLimit: Double {
    return CanvasRenderingContext2dGetMiterLimit(reference)
  }

  public var lineDash: [Double] {
    get {
      var ret: [Double] = []
      var count: CInt = 0
      var doubles: UnsafeMutablePointer<Double>?
      CanvasRenderingContext2dGetLineDash(reference, &doubles, &count)
      for i in 0..<count {
        ret.append(doubles![Int(i)])
      }
      free(doubles)
      return ret
    }
    set {
      newValue.withUnsafeBufferPointer {
        CanvasRenderingContext2dSetLineDash(reference, UnsafeMutableBufferPointer<Double>(mutating: $0).baseAddress, CInt(newValue.count))
      }
    }
  }

  public var lineDashOffset: Double {
    return CanvasRenderingContext2dGetLineDashOffset(reference)
  }

  public var font: String {
    var len: CInt = 0
    let cstr = CanvasRenderingContext2dGetFont(reference, &len)
    return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
  }

  public var textAlign: CanvasTextAlign {
    return CanvasTextAlign(rawValue: Int(CanvasRenderingContext2dGetTextAlign(reference)))!
  }
  
  public var textBaseline: CanvasTextBaseline {
    return CanvasTextBaseline(rawValue: Int(CanvasRenderingContext2dGetTextBaseline(reference)))!
  }

  public var direction: CanvasTextDirection {
    return CanvasTextDirection(rawValue: Int(CanvasRenderingContext2dGetTextDirection(reference)))!
  }

  public var globalAlpha: Double {
    get {
      return CanvasRenderingContext2dGetGlobalAlpha(reference)
    }
    set {
      CanvasRenderingContext2dSetGlobalAlpha(reference, newValue)
    }
  }

  public var globalCompositeOperation: BlendMode {
    return BlendMode(rawValue: CanvasRenderingContext2dGetGlobalCompositeOperation(reference))!
  }

  public var filter: String {
    var len: CInt = 0
    let cstr = CanvasRenderingContext2dGetFilter(reference, &len)
    return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
  }

  // image smoothing
  public var imageSmoothingEnabled: Bool {
    get {
      return CanvasRenderingContext2dImageSmoothingEnabled(reference) != 0
    }
    set {
      CanvasRenderingContext2dSetImageSmoothingEnabled(reference, newValue ? 1 : 0)
    }
  }

  public var imageSmoothingQuality: ImageSmoothingQuality {
    get {
      return ImageSmoothingQuality(rawValue: Int(CanvasRenderingContext2dGetImageSmoothingQuality(reference)))!
    }
    set {
      CanvasRenderingContext2dSetImageSmoothingQuality(reference, CInt(newValue.rawValue))
    }
  }

  // FIXME: support Color + CanvasGradient + CanvasPattern
  public var fillStyle: String {
    get {
      var len: CInt = 0 
      let cstr = CanvasRenderingContext2dGetFillStyle(reference, &len)
      return String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    set {
      newValue.withCString {
        CanvasRenderingContext2dSetFillStyle(reference, $0)
      }
    }
  }

  // FIXME: support Color + CanvasGradient + CanvasPattern
  public var strokeStyle: String {
    get {
      var len: CInt = 0 
      let cstr = CanvasRenderingContext2dGetStrokeStyle(reference, &len)
      return String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    set {
      newValue.withCString {
        CanvasRenderingContext2dSetStrokeStyle(reference, $0)
      }
    }
  }

   // shadows
  public var shadowOffsetX: Double {
    get {
      return CanvasRenderingContext2dGetShadowOffsetX(reference)
    }
    set {
      CanvasRenderingContext2dSetShadowOffsetX(reference, newValue)
    }
  }

  public var shadowOffsetY: Double {
    get {
      return CanvasRenderingContext2dGetShadowOffsetY(reference)
    }
    set {
      CanvasRenderingContext2dSetShadowOffsetY(reference, newValue)
    }
  }

  public var shadowBlur: Double {
    get {
      return CanvasRenderingContext2dGetShadowBlur(reference)
    }
    set {
      CanvasRenderingContext2dSetShadowBlur(reference, newValue)
    }
  }

  public var shadowColor: String {
    get {
      var len: CInt = 0 
      let cstr = CanvasRenderingContext2dGetShadowColor(reference, &len)
      return String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    set {
      newValue.withCString {
        CanvasRenderingContext2dSetShadowColor(reference, $0)
      }
    }
  }

  public var imageProvider: ImageProvider?
  var _nativeCanvas: SkiaCanvas?
  var reference: CanvasRenderingContext2dRef
  internal var window: WebWindow?
  internal var worker: WebWorker?
  internal var scope: ServiceWorkerGlobalScope?

  init(reference: CanvasRenderingContext2dRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  init(reference: CanvasRenderingContext2dRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }

  init(reference: CanvasRenderingContext2dRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

  deinit {
    CanvasRenderingContext2dDestroy(reference)
  }

   public func transform(_ a: Double, _ b: Double, _ c: Double, _ d: Double, _ e: Double, _ f: Double) {
    CanvasRenderingContext2dTransform(reference, a, b, c, d, e, f)
  }

  public func setTransform(_ a: Double, _ b: Double, _ c: Double, _ d: Double, _ e: Double, _ f: Double) {
    CanvasRenderingContext2dSetTransform(reference, a, b, c, d, e, f)
  }

  public func resetTransform() {
    CanvasRenderingContext2dResetTransform(reference)
  }

  public func createLinearGradient(_ x0: Double, _ y0: Double, _ x1: Double, _ y1: Double) -> CanvasGradient {
    return CanvasGradient(reference: CanvasRenderingContext2dCreateLinearGradient(reference, x0, y0, x1, y1))
  }

  public func createRadialGradient(_ x0: Double, _ y0: Double, _ r0: Double, _ x1: Double, _ y1: Double, _ r1: Double) -> CanvasGradient {
    return CanvasGradient(reference: CanvasRenderingContext2dCreateRadialGradient(reference, x0, y0, r0, x1, y1, r1))
  }

  public func createPattern(_ image: ImageBitmap, repetitionType: String) -> CanvasPattern {
    return repetitionType.withCString { (cstr: UnsafePointer<Int8>?) -> CanvasPattern in
      if let wnd = window {
        return CanvasPattern(reference: CanvasRenderingContext2dCreatePatternImageBitmap(reference, wnd.reference, image.reference, cstr)!)
      }
      if let wrk = worker {
        return CanvasPattern(reference: CanvasRenderingContext2dCreatePatternImageBitmapForWorker(reference, wrk.reference, image.reference, cstr)!)
      }
      return CanvasPattern(reference: CanvasRenderingContext2dCreatePatternImageBitmapForServiceWorker(reference, scope!.reference, image.reference, cstr)!)
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
    CanvasRenderingContext2dStrokeRect(reference, CInt(x), CInt(y), CInt(width), CInt(height))
  }

  public func clearRect(_ x: Int, _ y: Int, _ width: Int, _ height: Int) {
    CanvasRenderingContext2dClearRect(reference, CInt(x), CInt(y), CInt(width), CInt(height))
  }

  public func fillRect(_ x: Int, _ y: Int, _ width: Int, _ height: Int) {
    CanvasRenderingContext2dFillRect(reference, CInt(x), CInt(y), CInt(width), CInt(height))
  }

  public func beginPath() {
    CanvasRenderingContext2dBeginPath(reference)
  }

  public func fill(winding: CanvasFillRule?) {
    if let w = winding {
      CanvasRenderingContext2dFillWithWinding(reference, CInt(w.rawValue))
      return
    }
    CanvasRenderingContext2dFill(reference)
  }

  public func fill(path: Path2d, winding: CanvasFillRule?) {
    if let w = winding {
      CanvasRenderingContext2dFillWithPathAndWinding(reference, path.reference, CInt(w.rawValue))
      return
    }
    CanvasRenderingContext2dFillWithPath(reference, path.reference)
  }

  public func stroke() {
    CanvasRenderingContext2dStroke(reference)
  }

  public func stroke(path: Path2d) {
    CanvasRenderingContext2dStrokeWithPath(reference, path.reference)
  }

  public func clip() {
    CanvasRenderingContext2dClip(reference)
  }

  public func clip(path: Path2d) {
    CanvasRenderingContext2dClipWithPath(reference, path.reference)
  }

  public func isPointInPath(x: Double, y: Double, winding: CanvasFillRule?) -> Bool {
    guard let w = winding else {
      return CanvasRenderingContext2dIsPointInPath(reference, x, y) != 0
    }
    return CanvasRenderingContext2dIsPointInPathWithWinding(reference, x, y, CInt(w.rawValue)) != 0  
  }

  public func isPointInPath(path: Path2d, x: Double, y: Double, winding: CanvasFillRule?) -> Bool {
    guard let w = winding else {
      return CanvasRenderingContext2dIsPointInPathWithPath(reference, path.reference, x, y) != 0
    }
    return CanvasRenderingContext2dIsPointInPathWithPathAndWinding(reference, path.reference, x, y, CInt(w.rawValue)) != 0
  }

  public func isPointInStroke(x: Double, y: Double) -> Bool {
    return CanvasRenderingContext2dIsPointInStroke(reference, x, y) != 0
  }

  public func isPointInStroke(path: Path2d, x: Double, y: Double) -> Bool {
    return CanvasRenderingContext2dIsPointInStroke(reference, x, y) != 0
  }

  public func fillText(_ text: String, x: Double, y: Double, maxWidth: Double?) {
    text.withCString { cstr in
      if let width = maxWidth {      
        CanvasRenderingContext2dFillTextWithWidth(reference, cstr, x, y, width)
        return
      } 
      CanvasRenderingContext2dFillText(reference, cstr, x, y)
    }
  }

  public func strokeText(_ text: String, x: Double, y: Double) {
    strokeText(text, x: x, y: y, maxWidth: nil)
  }

  public func strokeText(_ text: String, x: Double, y: Double, maxWidth: Double?) {
    text.withCString { cstr in
      if let width = maxWidth {
        CanvasRenderingContext2dStrokeTextWithWidth(reference, cstr, x, y, width)
        return
      }
      CanvasRenderingContext2dStrokeText(reference, cstr, x, y)
    }
  }

  // public func measureText(_ text: String) -> TextMetrics {}

  public func drawImage(_ image: ImageBitmap, x: Double, y: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageBitmap(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageBitmapForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    CanvasRenderingContext2dDrawImageBitmapForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: ImageBitmap, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageBitmapWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageBitmapWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    CanvasRenderingContext2dDrawImageBitmapWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: ImageBitmap, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageBitmapSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageBitmapSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    CanvasRenderingContext2dDrawImageBitmapSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: CSSImageValue, x: Double, y: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageCSSImage(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageCSSImageForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    CanvasRenderingContext2dDrawImageCSSImageForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: CSSImageValue, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageCSSImageWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageCSSImageWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    CanvasRenderingContext2dDrawImageCSSImageWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: CSSImageValue, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageCSSImageSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageCSSImageSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    CanvasRenderingContext2dDrawImageCSSImageSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: HtmlImageElement, x: Double, y: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageHTMLImage(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageHTMLImageForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    CanvasRenderingContext2dDrawImageHTMLImageForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: HtmlImageElement, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageHTMLImageWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageHTMLImageWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    CanvasRenderingContext2dDrawImageHTMLImageWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: HtmlImageElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageHTMLImageSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageHTMLImageSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    CanvasRenderingContext2dDrawImageHTMLImageSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: SvgImageElement, x: Double, y: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageSVGImage(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageSVGImageForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    CanvasRenderingContext2dDrawImageSVGImageForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: SvgImageElement, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageSVGImageWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageSVGImageWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    CanvasRenderingContext2dDrawImageSVGImageWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: SvgImageElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageSVGImageSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageSVGImageSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    CanvasRenderingContext2dDrawImageSVGImageSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: HtmlCanvasElement, x: Double, y: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageHTMLCanvas(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageHTMLCanvasForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    CanvasRenderingContext2dDrawImageHTMLCanvasForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: HtmlCanvasElement, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageHTMLCanvasWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageHTMLCanvasWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    CanvasRenderingContext2dDrawImageHTMLCanvasWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: HtmlCanvasElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageHTMLCanvasSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    CanvasRenderingContext2dDrawImageHTMLCanvasSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: OffscreenCanvas, x: Double, y: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageOffscreenCanvas(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageOffscreenCanvasForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    CanvasRenderingContext2dDrawImageOffscreenCanvasForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: OffscreenCanvas, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageOffscreenCanvasWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageOffscreenCanvasWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    CanvasRenderingContext2dDrawImageOffscreenCanvasWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: OffscreenCanvas, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageOffscreenCanvasSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    CanvasRenderingContext2dDrawImageOffscreenCanvasSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func drawImage(_ image: HtmlVideoElement, x: Double, y: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageHTMLVideo(reference, wnd.reference, image.reference, x, y)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageHTMLVideoForWorker(reference, wrk.reference, image.reference, x, y)
      return
    }
    CanvasRenderingContext2dDrawImageHTMLVideoForServiceWorker(reference, scope!.reference, image.reference, x, y)
  }

  public func drawImage(_ image: HtmlVideoElement, x: Double, y: Double, width: Double, height: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageHTMLVideoWH(reference, wnd.reference, image.reference, x, y, width, height)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageHTMLVideoWHForWorker(reference, wrk.reference, image.reference, x, y, width, height)
      return
    }
    CanvasRenderingContext2dDrawImageHTMLVideoWHForServiceWorker(reference, scope!.reference, image.reference, x, y, width, height)
  }

  public func drawImage(_ image: HtmlVideoElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double) {
    if let wnd = window {
      CanvasRenderingContext2dDrawImageHTMLVideoSrcDst(reference, wnd.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    if let wrk = worker {
      CanvasRenderingContext2dDrawImageHTMLVideoSrcDstForWorker(reference, wrk.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
      return
    }
    CanvasRenderingContext2dDrawImageHTMLVideoSrcDstForServiceWorker(reference, scope!.reference, image.reference, sx, sy, sw, sh, dx, dy, dw, dh)
  }

  public func createImageData(data: ImageData) -> ImageData {
    return ImageData(reference: CanvasRenderingContext2dCreateImageDataWithImageData(reference, data.reference)!)
  }
  
  public func createImageData(width: Int, height: Int) -> ImageData {
    let settings = ImageDataColorSettings()
    return ImageData(reference: CanvasRenderingContext2dCreateImageData(reference, CInt(width), CInt(height), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
  }
  
  public func createImageData(width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData {
    return ImageData(reference: CanvasRenderingContext2dCreateImageData(reference, CInt(width), CInt(height), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
  }
  
  public func createImageData(data: Data, width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData {
    return data.withUnsafeBytes {
      return ImageData(reference: CanvasRenderingContext2dCreateImageDataWithBytes(reference, CInt(width), CInt(height), $0, CInt(data.count), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
    }
  }

  public func createImageData(data: Uint8ClampedArray, width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData {
    return ImageData(reference: CanvasRenderingContext2dCreateImageDataWithUint8Array(reference, CInt(width), CInt(height), data.reference, CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))!)
  }
  
  public func getImageData(x: Int, y: Int, width: Int, height: Int) -> ImageData {
    return ImageData(reference: CanvasRenderingContext2dGetImageData(reference, CInt(x), CInt(y), CInt(width), CInt(height))!)
  }
  
  public func putImageData(_ data: ImageData, x: Int, y: Int) {
    CanvasRenderingContext2dPutImageData(reference, data.reference, CInt(x), CInt(y))
  }

  public func putImageData(_ data: ImageData, x: Int, y: Int, dirtyX: Int, dirtyY: Int, dirtyWidth: Int, dirtyHeight: Int) {
    CanvasRenderingContext2dPutImageDataWithDamage(reference, data.reference, CInt(x), CInt(y), CInt(dirtyX), CInt(dirtyY), CInt(dirtyWidth), CInt(dirtyHeight))
  }

  public func closePath() {
    CanvasRenderingContext2dClosePath(reference)
  }

  public func moveTo(_ x: Float, _ y: Float) {
    CanvasRenderingContext2dMoveTo(reference, x, y)
  }
  
  public func lineTo(_ x: Float, _ y: Float) {
    CanvasRenderingContext2dLineTo(reference, x, y)
  }
  
  public func quadraticCurveTo(_ cpx: Float, _ cpy: Float, _ x: Float, _ y: Float) {
    CanvasRenderingContext2dQuadraticCurveTo(reference, cpx, cpy, x, y)
  }
  
  public func bezierCurveTo(_ cp1x: Float, _ cp1y: Float, _ cp2x: Float, _ cp2y: Float, _ x: Float, _ y: Float) {
    CanvasRenderingContext2dBezierCurveTo(reference, cp1x, cp1y, cp2x, cp2y, x, y)
  }
  
  public func arcTo(_ x1: Float, _ y1: Float, _ x2: Float, _ y2: Float, _ radius: Float) {
    CanvasRenderingContext2dArcTo(reference, x1, y1, x2, y2, radius)
  }
  
  public func rect(_ x: Float, _ y: Float, _ width: Float, _ height: Float) {
    CanvasRenderingContext2dRect(reference, x, y, width, height)
  }

  public func arc(_ x: Float, _ y: Float, _ radius: Float, _ startAngle: Float, _ endAngle: Float, anticlockwise: Bool = false) {
    CanvasRenderingContext2dArc(reference, x, y, radius, startAngle, endAngle, anticlockwise ? 1 : 0)
  }
  
  public func ellipse(_ x: Float, _ y: Float, _ radiusX: Float, _ radiusY: Float, _ rotation: Float, _ startAngle: Float, _ endAngle: Float, anticlockwise: Bool = false) {
    CanvasRenderingContext2dEllipse(reference, x, y, radiusX, radiusY, rotation, startAngle, endAngle, anticlockwise ? 1: 0)
  }

}

extension CanvasRenderingContext2d : PaintCanvas {
  
  public var saveCount: Int {
    return Int(CanvasRenderingContext2dGetSaveCount(reference))
  }

  public var displayItemList: DisplayItemList? {
    let ref = CanvasRenderingContext2dGetDisplayItemList(reference)
    return ref != nil ? DisplayItemList(reference: ref!, owned: false) : nil
  }
  
  public var localClipBounds: FloatRect? {
    var x: Float = 0.0, y: Float = 0.0, width: Float = 0.0, height: Float = 0.0
    let result = CanvasRenderingContext2dGetLocalClipBounds(reference, &x, &y, &width, &height)
    if result == 1 {
      return FloatRect(x: x, y: y, width: width, height: height)
    }
    return nil
  }

  public var deviceClipBounds: IntRect? {
    var x: Int32 = 0, y: Int32 = 0, width: Int32 = 0, height: Int32 = 0
    let result = CanvasRenderingContext2dGetDeviceClipBounds(reference, &x, &y, &width, &height)
    if result == 1 {
      return IntRect(x: Int(x), y: Int(y), width: Int(width), height: Int(height))
    }
    return nil
  }

  public var isClipEmpty: Bool {
    return CanvasRenderingContext2dIsClipEmpty(reference) == 0 ? false : true
  }

  public var isClipRect: Bool {
    return CanvasRenderingContext2dIsClipRect(reference) == 0 ? false : true
  }

  public var totalMatrix: Mat {
    let ref = CanvasRenderingContext2dTotalMatrix(reference)
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
    CanvasRenderingContext2dFlush(reference)
  }

  public func save() -> Int {
    print("CanvasRenderingContext2d.save()")
    return Int(CanvasRenderingContext2dSave(reference))
  }

  public func saveLayer(bounds: FloatRect?, flags paintFlags: PaintFlags?) -> Int {
    if let rect = bounds {
      return Int(CanvasRenderingContext2dSaveLayerRect(reference, rect.x, rect.y, rect.width, rect.height, paintFlags != nil ? paintFlags!.reference : nil))
    } else {
      return Int(CanvasRenderingContext2dSaveLayer(reference, paintFlags != nil ? paintFlags!.reference : nil))
    }
  }

  public func saveLayerAlpha(alpha: UInt8) -> Int {
    return Int(CanvasRenderingContext2dSaveLayerAlpha(reference, CInt(alpha)))
  }
  
  public func saveLayerAlpha(bounds: FloatRect?, alpha: UInt8, preserveLcdTextRequests: Bool) -> Int {
    if preserveLcdTextRequests {
      let paint = Paint()
      paint.alpha = alpha
      return saveLayerPreserveLCDTextRequests(paint: paint, bounds: bounds)
    }
    if let rect = bounds {
      return Int(CanvasRenderingContext2dSaveLayerAlphaRect(reference, CInt(alpha), rect.x, rect.y, rect.width, rect.height))
    } else {
      return Int(CanvasRenderingContext2dSaveLayerAlpha(reference, CInt(alpha)))
    }
  }

  public func saveLayerPreserveLCDTextRequests(paint: Paint, bounds: FloatRect?) -> Int {
    if let b = bounds {
      return Int(CanvasRenderingContext2dSaveLayerPreserveLCDTextRequestsRect(reference, b.x, b.y, b.width, b.height, paint.reference))
    } else {
      return Int(CanvasRenderingContext2dSaveLayerPreserveLCDTextRequests(reference, paint.reference))
    }
  }
  
  public func restore() {
    print("CanvasRenderingContext2d.restore()")
    CanvasRenderingContext2dRestore(reference)
  }
  
  public func restoreToCount(saveCount: Int) {
    CanvasRenderingContext2dRestoreToCount(reference, Int32(saveCount))
  }

  public func translate(offset: IntVec2) {
    translate(x: Float(offset.x), y: Float(offset.y))
  }

  public func translate(offset: FloatVec2) {
    translate(x: offset.x, y: offset.y)
  }

  public func translate(x: Float, y: Float) {
    CanvasRenderingContext2dTranslate(reference, x, y)
  }
  
  public func scale(x: Float, y: Float) {
    CanvasRenderingContext2dScale(reference, x, y)
  }
  
  public func rotate(degrees: Float) {
    CanvasRenderingContext2dRotate(reference, degrees)
  }
  
  public func concat(matrix: Mat) {
    CanvasRenderingContext2dConcatHandle(reference, matrix.reference)
  }
  
  public func setMatrix(_ matrix: Mat) {
    CanvasRenderingContext2dSetMatrixHandle(reference, matrix.reference)
  }
  
  public func clipRect(_ rect: FloatRect, clip: ClipOp, antiAlias: Bool) {
    CanvasRenderingContext2dClipRect(reference, rect.x, rect.y, rect.width, rect.height, Int32(clip.rawValue), antiAlias.intValue)
  }
  
  public func clipRect(_ rect: FloatRect, clip: ClipOp) {
    clipRect(rect, clip: clip, antiAlias: true)
  }
 
  public func clipRRect(_ rrect: FloatRRect, clip: ClipOp, antiAlias: Bool) {
    CanvasRenderingContext2dClipRRect(reference, rrect.x, rrect.y, rrect.width, rrect.height, Int32(clip.rawValue), antiAlias.intValue)
  }
  
  public func clipPath(_ path: Path, clip: ClipOp, antiAlias: Bool) {
    CanvasRenderingContext2dClipPath(reference, path.reference, Int32(clip.rawValue), antiAlias.intValue)
  }
 
  public func clipPath(_ path: Path, clip: ClipOp) {
    clipPath(path, clip: clip, antiAlias: true)
  }

  public func drawColor(_ color: Color, mode: BlendMode) {
    CanvasRenderingContext2dDrawColor(reference, CInt(color.a), CInt(color.r), CInt(color.g), CInt(color.b), CInt(mode.rawValue))
  }
 
  public func drawColor(_ color: Color) {
    drawColor(color, mode: .SrcOver)
  }
 
  public func clear(color: Color) {
    CanvasRenderingContext2dDrawColor(reference, CInt(color.a), CInt(color.r), CInt(color.g), CInt(color.b), CInt(BlendMode.Src.rawValue))
  }

  public func clearRect(_ rect: IntRect) {
    CanvasRenderingContext2dClearRect(reference, CInt(rect.x), CInt(rect.y), CInt(rect.width), CInt(rect.height))
  }

  public func clearRect(_ rect: FloatRect) {
    CanvasRenderingContext2dClearRect(reference, CInt(rect.x), CInt(rect.y), CInt(rect.width), CInt(rect.height))
  }
 
  public func drawLine(x0: Float, y0: Float, x1: Float, y1: Float, flags: PaintFlags) {
    drawLine(start: FloatPoint(x: x0, y: y0), end: FloatPoint(x: x1, y: y1), flags: flags)
  }

  public func drawLine(start: FloatPoint, end: FloatPoint, flags: PaintFlags) {
    CanvasRenderingContext2dDrawLine(reference, start.x, start.y, end.x, end.y, flags.reference)
  }
 
  public func drawRect(_ rect: FloatRect, flags: PaintFlags) {
    CanvasRenderingContext2dDrawRect(reference, rect.x, rect.y, rect.width, rect.height, flags.reference)    
  }
 
  public func drawIRect(_ rect: IntRect, flags: PaintFlags) {
    CanvasRenderingContext2dDrawIRect(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height), flags.reference)
  }
 
  public func drawOval(_ rect: FloatRect, flags: PaintFlags) {
    CanvasRenderingContext2dDrawOval(reference, rect.x, rect.y, rect.width, rect.height, flags.reference)
  }
 
  public func drawRRect(_ rrect: FloatRRect, flags: PaintFlags) {
    CanvasRenderingContext2dDrawRRect(reference, rrect.x, rrect.y, rrect.width, rrect.height, flags.reference)    
  }

  public func drawDRRect(outer: FloatRRect, inner: FloatRRect, flags: PaintFlags) {
    CanvasRenderingContext2dDrawDRRect(reference, outer.x, outer.y, outer.width, outer.height, inner.x, inner.y, inner.width, inner.height, flags.reference)
  }
 
  public func drawRoundRect(_ rect: FloatRect, x: Float, y: Float, flags: PaintFlags) {
    CanvasRenderingContext2dDrawRoundRect(reference, rect.x, rect.y, rect.width, rect.height, x, y, flags.reference)
  }
 
  public func drawPath(_ path: Path, flags: PaintFlags) {
    let paint = flags.toPaint()
    CanvasRenderingContext2dDrawPath(reference, path.reference, paint.reference)
  }
 
  public func drawImage(_ image: ImageSkia, left: Float, top: Float, flags: PaintFlags?) {
    CanvasRenderingContext2dDrawImage(reference, image.reference, left, top, flags != nil ? flags!.reference : nil)
  }
 
  public func drawImageRect(_ image: ImageSkia, src: FloatRect, dst: FloatRect, constraint: SrcRectConstraint, flags: PaintFlags?) { 
    CanvasRenderingContext2dDrawImageRect(reference, 
      image.reference,
      src.x, src.y, src.width, src.height,
      dst.x, dst.y, dst.width, dst.height,
      constraint.rawValue, 
      flags != nil ? flags!.reference : nil)
  }
 
  public func drawBitmap(_ bitmap: Bitmap, left: Float, top: Float, flags: PaintFlags?) {
    CanvasRenderingContext2dDrawBitmap(reference, bitmap.reference, left, top, flags != nil ? flags!.reference : nil)
  }
  
  public func drawTextBlob(_ blob: PaintTextBlob, x: Float, y: Float, flags: PaintFlags) {
    //print("WebPaintCanvas.drawTextBlob")
    CanvasRenderingContext2dDrawTextBlob(reference, blob.reference, x, y, flags.reference) 
  }
 
  public func drawPicture(record: PaintRecord) {
    CanvasRenderingContext2dDrawPicture(reference, record.reference)
  }
 
  public func recordCustomData(id: UInt32) {}
}