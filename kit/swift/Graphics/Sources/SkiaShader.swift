// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class SkiaShader : Shader {

  public var type: ShaderType { return ShaderType.skia }

  var reference: ShaderRef

  internal init(reference: ShaderRef) {
    self.reference = reference
  }

  deinit {
    _ShaderDestroy(reference)
  }

}

public class SkiaEmptyShader : SkiaShader {
  
  public init() {
    let ptr = _ShaderCreateEmpty()
    super.init(reference: ptr!)
  }

}

public class SkiaBitmapShader : SkiaShader {
  
  public var bitmap: Bitmap {
    return _bitmap
  }

  public var x: TileMode {
    return _x
  }

  public var y: TileMode {
    return _y
  }

  public var localMatrix: Mat? {
    return _matrix
  }

  var _bitmap: Bitmap
  var _x: TileMode
  var _y: TileMode
  var _matrix: Mat?

  public init(bitmap: Bitmap, x: TileMode, y: TileMode, matrix: Mat?) {
    var mptr: MatrixRef? = nil
    if let m = matrix {
      mptr = m.reference
    }
    let ptr = _ShaderCreateBitmap(bitmap.reference, Int32(x.rawValue), Int32(x.rawValue), mptr)
    _bitmap = bitmap
    _x = x
    _y = y
    _matrix = matrix
    super.init(reference: ptr!)
  }

}

public class SkiaColorShader : SkiaShader {
  
  public var color: Color {
    return _color
  }

  var _color: Color

  public init(color: Color) {
    _color = color
    let ptr = _ShaderCreateColor(color.a, color.r, color.g, color.b)
    super.init(reference: ptr!)
  }

}

public class SkiaPictureShader : SkiaShader {
  
  public var picture: Picture {
    return _picture
  }

  var _picture: Picture
 
  public init(picture: Picture) {
    _picture = picture
    let ptr = _ShaderCreatePicture(picture.reference)
    super.init(reference: ptr!)
  }

}

public class SkiaLocalMatrixShader : SkiaShader {
  
  public init() {
    let ptr = _ShaderCreateLocalMatrix()
    super.init(reference: ptr!)
  }

}

public class SkiaGradientShader : SkiaShader {
  
  public init(points: [FloatPoint],
              colors: [Color], 
              pos: [Float], 
              count: Int,
              mode: TileMode) {
    let ptr = _ShaderCreateGradient()
    super.init(reference: ptr!)
  }

}

public struct SkiaShaderFactory {

  public static func makeEmpty() -> SkiaEmptyShader {
    return SkiaEmptyShader()
  }

  public static func makeBitmap(bitmap: Bitmap, x: TileMode, y: TileMode, matrix: Mat?) -> SkiaBitmapShader {
    return SkiaBitmapShader(bitmap: bitmap, x: x, y: y, matrix: matrix)
  }

  public static func makeBitmapForScale(bitmap: Bitmap, tileMode: TileMode, matrix localMatrix: Mat, scale: Float) -> SkiaBitmapShader {
    let shaderScale = localMatrix
    shaderScale.preScale(x: Double(scale), y: Double(scale))
    shaderScale.scaleX = localMatrix.scaleX / Double(scale)
    shaderScale.scaleY = localMatrix.scaleY / Double(scale)
    
    return SkiaShaderFactory.makeBitmap(bitmap: bitmap, x: tileMode, y: tileMode, matrix: shaderScale)
  }

  public static func makeColor(color: Color) -> SkiaColorShader {
    return SkiaColorShader(color: color)
  }

  public static func makePicture(picture: Picture) -> SkiaPictureShader {
    return SkiaPictureShader(picture: picture)
  }

  public static func makeLocalMatrix() -> SkiaLocalMatrixShader {
    return SkiaLocalMatrixShader()
  }

  public static func makeLinearGradient(points: [FloatPoint],
                                 colors: [Color], 
                                 pos: [Float], 
                                 count: Int,
                                 mode: TileMode) -> SkiaGradientShader {
    return SkiaGradientShader(points: points, colors: colors, pos: pos, count: count, mode: mode)
  }

  public static func makeImage(image: Image,
                               mode: TileMode,
                               matrix: Mat,
                               scale: Float) -> SkiaBitmapShader {
    return SkiaShaderFactory.makeBitmapForScale(bitmap: image.bitmap, tileMode: mode, matrix: matrix, scale: scale)
  }
}
