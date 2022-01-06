// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

// non-skia cc::PaintShader

public class PaintShader : Shader {
  
  public var type: ShaderType { return ShaderType.paint }

  var reference: PaintShaderRef?

  internal init(reference: PaintShaderRef) {
    self.reference = reference
  }

  internal init(reference: PaintShaderRef?) {
    assert(false)
  }

  deinit {
    if let ref = reference {
      _PaintShaderDestroy(ref)
    }
  }
}

public class ImageShader : PaintShader {
  
  public init(image: ImageSkia, x: TileMode, y: TileMode, matrix: Mat) {
   
    let ptr = _PaintShaderCreateImage(
      image.reference, 
      Int32(x.rawValue), 
      Int32(x.rawValue), 
      matrix.scaleX,
      matrix.skewX,
      matrix.transX,
      matrix.skewY,
      matrix.scaleY,
      matrix.transY,
      matrix.persp0,
      matrix.persp1,
      matrix.persp2)
   
    super.init(reference: ptr!)
  }

  public init(bitmap: Bitmap, x: TileMode, y: TileMode, matrix: Mat) {
   
    let ptr = _PaintShaderCreateImageFromBitmap(
      bitmap.reference, 
      Int32(x.rawValue), 
      Int32(x.rawValue), 
      matrix.scaleX,
      matrix.skewX,
      matrix.transX,
      matrix.skewY,
      matrix.scaleY,
      matrix.transY,
      matrix.persp0,
      matrix.persp1,
      matrix.persp2)
   
    super.init(reference: ptr!)
  }

}

public class ColorShader : PaintShader {
  
  public private(set) var color: Color

  public init(color: Color) {
    self.color = color
    let ptr = _PaintShaderCreateColor(Int32(color.a), Int32(color.r), Int32(color.g), Int32(color.b))
    super.init(reference: ptr!)
  }

}


public class LinearGradientShader : PaintShader {
  
  public init(points: [FloatPoint],
              colors: [Color], 
              pos: [Float], 
              count: Int,
              mode: TileMode) {
    
    var ptr: PaintShaderRef?

    var rawColors = ContiguousArray<CInt>(repeating: 0, count: colors.count)
    for (i, color) in colors.enumerated() {
      rawColors[i] = CInt(color.value)
    }

    var x = ContiguousArray<Float>(repeating: 0.0, count: points.count)
    var y = ContiguousArray<Float>(repeating: 0.0, count: points.count)

    for (i, point) in points.enumerated() {
      x[i] = point.x
      y[i] = point.y
    }
    
    x.withUnsafeBufferPointer { xPointPtr in
      y.withUnsafeBufferPointer { yPointPtr in
        rawColors.withUnsafeBufferPointer { colorsPtr in
          pos.withUnsafeBufferPointer { posPtr in
            ptr = _PaintShaderCreateLinearGradient(xPointPtr.baseAddress, 
              yPointPtr.baseAddress, 
              colorsPtr.baseAddress, 
              posPtr.baseAddress, 
              CInt(count), 
              CInt(mode.rawValue))
          }
        }
      }
    }
    
    super.init(reference: ptr!)
  }

}

public class RadialGradientShader : PaintShader {
  public init(center: FloatPoint, radius: Float, colors: [Color], pos: [Float], count: Int, mode: TileMode) {
    //let ptr = _PaintShaderCreateRadialGradient()
    //super.init(reference: ptr!)
    super.init(reference: nil)
  }
}

public class TwoPointConicalGradientShader : PaintShader {
  public init(start: FloatPoint, startRadius: Float, end: FloatPoint, endRadius: Float, colors: [Color], pos: [Float], count: Int, mode: TileMode) {
    //let ptr = _PaintShaderCreateTwoPointConicalGradient()
    super.init(reference: nil)//ptr!)
  }
}


public class SweepGradientShader : PaintShader {
  public init(
    center: FloatPoint, 
    colors: [Color], 
    pos: [Float], 
    count: Int, 
    mode: TileMode,
    startDegrees: Float,
    endDegrees: Float) {
    //let ptr = _PaintShaderCreateSweepGradient()
    super.init(reference: nil)//ptr!)
  }
}

public class PaintRecordShader : PaintShader {
  public init(record: PaintRecord, tile: FloatRect, x: TileMode, y: TileMode, matrix: Mat) {
    //let ptr = _PaintShaderCreatePaintRecord()
    assert(false)
    super.init(reference: nil)//ptr!)
  }
}

public struct PaintShaderFactory {
  
  public static func makeImage(image: ImageSkia, tileMode: TileMode, matrix: Mat) -> ImageShader {
    return PaintShaderFactory.makeImageForScale(image: image, tileMode: tileMode, matrix: matrix, scale: image.scale)
  }

  public static func makeImageForScale(image: ImageSkia, tileMode: TileMode, matrix localMatrix: Mat, scale: Float) -> ImageShader {
    let shaderScale = localMatrix
    shaderScale.preScale(x: Double(scale), y: Double(scale))
    shaderScale.scaleX = localMatrix.scaleX / Double(scale)
    shaderScale.scaleY = localMatrix.scaleY / Double(scale)
    
    return ImageShader(image: image, x: tileMode, y: tileMode, matrix: shaderScale)
  }

  public static func makeImageForScale(bitmap: Bitmap, tileMode: TileMode, matrix localMatrix: Mat, scale: Float) -> ImageShader {
    let shaderScale = localMatrix
    shaderScale.preScale(x: Double(scale), y: Double(scale))
    shaderScale.scaleX = localMatrix.scaleX / Double(scale)
    shaderScale.scaleY = localMatrix.scaleY / Double(scale)
    
    return ImageShader(bitmap: bitmap, x: tileMode, y: tileMode, matrix: shaderScale)
  }

  public static func makeColor(color: Color) -> ColorShader {
    return ColorShader(color: color)
  }

  public static func makeLinearGradient(points: [FloatPoint],
                                 colors: [Color], 
                                 pos: [Float], 
                                 count: Int,
                                 mode: TileMode) -> LinearGradientShader {
    return LinearGradientShader(points: points, colors: colors, pos: pos, count: count, mode: mode)
  }
}