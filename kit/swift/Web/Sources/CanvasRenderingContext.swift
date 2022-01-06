// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Foundation

public enum CanvasLineCap : Int {
  case butt = 0
  case round = 1
  case square = 2
}

public enum CanvasLineJoin : Int {
  case round = 0
  case bevel = 1
  case miter = 2
}

public enum CanvasTextAlign : Int {
  case start = 0
  case end = 1
  case left = 2
  case right = 3
  case center = 4
}

public enum CanvasTextBaseline : Int {
  case top = 0
  case hanging = 1
  case middle = 2
  case alphabetic = 3
  case ideographic = 4
  case bottom = 5
}

public enum CanvasTextDirection : Int {
  case inherit = 0
  case rtl = 1
  case ltr = 2
}

public enum CanvasBlendMode : Int {
  case srcOver = 0
  case multiply = 1
  case screen = 2
  case overlay = 3
  case darken = 4
  case lighten = 5
  case colorDodge = 6
  case colorBurn = 7
  case hardLight = 8
  case softLight = 9
  case difference = 10
  case exclusion = 11
  case hue = 12
  case saturation = 13
  case color = 14
  case luminosity = 15
}

public enum CanvasFillRule : Int { 
  case nonzero = 0
  case evenodd = 1
}

public enum ImageSmoothingQuality : Int {
  case low = 0
  case medium = 1
  case high = 2
}

public enum AlphaDisposition : Int {
  case PremultiplyAlpha = 0
  case UnpremultiplyAlpha = 1
  case DontChangeAlpha = 2
}

public enum DataColorType : Int {
  case RGBAColorType = 0
  case N32ColorType = 1
}

public enum CanvasPixelFormat : Int {
  case rgba8 = 0
  case rgb10a2 = 1
  case rgba12 = 2
  case f16 = 3
};

public enum CanvasColorSpace : Int {
  case srgb = 0 
  case rec2020 = 1
  case p3 = 2
}

public enum ImageDataStorageFormat : Int {
  case uint8 = 0
  case uint16 = 1
  case float32 = 2
}

public struct ImageDataColorSettings {
  var colorSpace: CanvasColorSpace = CanvasColorSpace.srgb
  var storageFormat: ImageDataStorageFormat = ImageDataStorageFormat.uint8
}

public protocol CanvasRenderingContext : PaintCanvas {

  var lineWidth: Double { get }
  var lineCap: CanvasLineCap { get }
  var lineJoin: CanvasLineJoin { get }
  var miterLimit: Double { get }
  var lineDash: [Double] { get set }
  var lineDashOffset: Double { get }
  var textAlign: CanvasTextAlign { get }
  var textBaseline: CanvasTextBaseline { get }
  var globalAlpha: Double { get set }
  var globalCompositeOperation: BlendMode { get }
  var filter: String { get }
  var imageSmoothingEnabled: Bool { get set }
  var imageSmoothingQuality: ImageSmoothingQuality { get set }
  var fillStyle: String { get set }
  var strokeStyle: String { get set }
  var shadowOffsetX: Double { get set }
  var shadowOffsetY: Double { get set }
  var shadowBlur: Double { get set }
  var shadowColor: String { get set }
  
  func transform(_: Double, _: Double, _: Double, _: Double, _: Double, _: Double)
  func setTransform(_: Double, _: Double, _: Double, _: Double, _: Double, _: Double)
  func resetTransform()
  func createLinearGradient(_: Double, _: Double, _: Double, _: Double) -> CanvasGradient
  func createRadialGradient(_: Double, _: Double, _: Double, _: Double, _: Double, _: Double) -> CanvasGradient
  func createPattern(_: ImageBitmap, repetitionType: String) -> CanvasPattern
  func createPattern(_: CSSImageValue, repetitionType: String) -> CanvasPattern
  func createPattern(_: HtmlImageElement, repetitionType: String) -> CanvasPattern
  func createPattern(_: SvgImageElement, repetitionType: String) -> CanvasPattern
  func createPattern(_: HtmlCanvasElement, repetitionType: String) -> CanvasPattern
  func createPattern(_: OffscreenCanvas, repetitionType: String) -> CanvasPattern
  func createPattern(_: HtmlVideoElement, repetitionType: String) -> CanvasPattern
  func strokeRect(_: FloatRect)
  func strokeRect(_: IntRect)
  func strokeRect(_: Int, _: Int, _: Int, _: Int)
  func clearRect(_: Int, _: Int, _: Int, _: Int)
  func fillRect(_: Int, _: Int, _: Int, _: Int)
  func beginPath()
  func fill()
  func fill(path: Path2d)
  func fill(winding: CanvasFillRule?)
  func fill(path: Path2d, winding: CanvasFillRule?)
  func stroke()
  func stroke(path: Path2d)
  func clip()
  func clip(path: Path2d)
  func isPointInPath(x: Double, y: Double) -> Bool
  func isPointInPath(path: Path2d, x: Double, y: Double) -> Bool
  func isPointInPath(x: Double, y: Double, winding: CanvasFillRule?) -> Bool
  func isPointInPath(path: Path2d, x: Double, y: Double, winding: CanvasFillRule?) -> Bool
  func isPointInStroke(x: Double, y: Double) -> Bool
  func isPointInStroke(path: Path2d, x: Double, y: Double) -> Bool
  func drawImage(_: ImageBitmap, x: Double, y: Double)
  func drawImage(_: ImageBitmap, x: Double, y: Double, width: Double, height: Double)
  func drawImage(_: ImageBitmap, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double)
  func drawImage(_: CSSImageValue, x: Double, y: Double)
  func drawImage(_: CSSImageValue, x: Double, y: Double, width: Double, height: Double)
  func drawImage(_: CSSImageValue, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double)
  func drawImage(_: HtmlImageElement, x: Double, y: Double)
  func drawImage(_: HtmlImageElement, x: Double, y: Double, width: Double, height: Double)
  func drawImage(_: HtmlImageElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double)
  func drawImage(_: SvgImageElement, x: Double, y: Double)
  func drawImage(_: SvgImageElement, x: Double, y: Double, width: Double, height: Double)
  func drawImage(_: SvgImageElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double)
  func drawImage(_: HtmlCanvasElement, x: Double, y: Double)
  func drawImage(_: HtmlCanvasElement, x: Double, y: Double, width: Double, height: Double)
  func drawImage(_: HtmlCanvasElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double)
  func drawImage(_: OffscreenCanvas, x: Double, y: Double)
  func drawImage(_: OffscreenCanvas, x: Double, y: Double, width: Double, height: Double)
  func drawImage(_: OffscreenCanvas, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double)
  func drawImage(_: HtmlVideoElement, x: Double, y: Double)
  func drawImage(_: HtmlVideoElement, x: Double, y: Double, width: Double, height: Double)
  func drawImage(_: HtmlVideoElement, sx: Double, sy: Double, sw: Double, sh: Double, dx: Double, dy: Double, dw: Double, dh: Double)
  func createImageData(data: ImageData) -> ImageData
  func createImageData(width: Int, height: Int) -> ImageData
  func createImageData(width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData
  func createImageData(data: Data, width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData
  func createImageData(data: Uint8ClampedArray, width: Int, height: Int, settings: ImageDataColorSettings) -> ImageData
  func getImageData(x: Int, y: Int, width: Int, height: Int) -> ImageData
  func putImageData(_: ImageData, x: Int, y: Int)
  func putImageData(_: ImageData, x: Int, y: Int, dirtyX: Int, dirtyY: Int, dirtyWidth: Int, dirtyHeight: Int)
  func closePath()
  func moveTo(_: Float, _: Float)
  func lineTo(_: Float, _: Float)
  func quadraticCurveTo(_: Float, _: Float, _: Float, _: Float)
  func bezierCurveTo(_: Float, _: Float, _: Float, _: Float, _: Float, _: Float)
  func arcTo(_: Float, _: Float, _: Float, _: Float, _: Float)
  func rect(_: Float, _: Float, _: Float, _: Float)
  func arc(_: Float, _: Float, _: Float, _: Float, _: Float)
  func arc(_: Float, _: Float, _: Float, _: Float, _: Float, anticlockwise: Bool)
  func ellipse(_: Float, _: Float, _: Float, _: Float, _:  Float, _: Float, _: Float)
  func ellipse(_: Float, _: Float, _: Float, _: Float, _: Float, _: Float, _: Float, anticlockwise: Bool)
}

extension CanvasRenderingContext { 
  
  public func fill() {
    fill(winding: nil)
  }

  public func fill(path: Path2d) {
    fill(path: path, winding: nil)
  }

  public func isPointInPath(x: Double, y: Double) -> Bool {
    return isPointInPath(x: x, y: y, winding: nil)
  }

  public func isPointInPath(path: Path2d, x: Double, y: Double) -> Bool {
    return isPointInPath(path: path, x: x, y: y, winding: nil)
  }

  public func arc(_ x: Float, _ y: Float, _ radius: Float, _ startAngle: Float, _ endAngle: Float) {
    arc(x, y, radius, startAngle, endAngle)
  }

  public func ellipse(_ x: Float, _ y: Float, _ radiusX: Float, _ radiusY: Float, _ rotation: Float, _ startAngle: Float, _ endAngle: Float) {
    ellipse(x, y, radiusX, radiusY, rotation, startAngle, endAngle)
  }

}

public protocol CanvasTextRenderer {

  var font: String { get }
  var direction: CanvasTextDirection { get }

  func fillText(_: String, x: Double, y: Double)
  func fillText(_: String, x: Double, y: Double, maxWidth: Double?)
  func strokeText(_: String, x: Double, y: Double)
  func strokeText(_: String, x: Double, y: Double, maxWidth: Double?)
}

extension CanvasTextRenderer {

  public func fillText(_ text: String, x: Double, y: Double) {
    fillText(text, x: x, y: y, maxWidth: nil)
  }

  public func strokeText(_ text: String, x: Double, y: Double) {
    strokeText(text, x: x, y: y)
  }

}