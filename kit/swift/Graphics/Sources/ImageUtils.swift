// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class ButtonImageSource : ImageSource {

  private let color: Color
  private let image: ImageSkia
  private let mask: ImageSkia

  public init(color: Color, image: ImageSkia, mask: ImageSkia) {
    self.color = color
    self.image = image
    self.mask = mask
  }

  public func getBitmapFor(scale: Float) -> Bitmap {
    let imageBmp = image.getBitmapFor(scale: scale)
    let maskBmp = mask.getBitmapFor(scale: scale)
    
    //if imageBmp.scale != maskBmp.scale {
    //  imageBmp = image.getBitmapFor(scale: 1.0)
    //  maskBmp = mask.getBitmapFor(scale: 1.0)
   // }

    return Bitmap.createButtonBackground(
      color: color,
      image: imageBmp!, 
      mask: maskBmp!)      
  }

}

public class BlendingImageSource : ImageSource {
  
  let first: ImageSkia 
  let second: ImageSkia
  let alpha: Double
  
  public init(first: ImageSkia, second: ImageSkia, alpha: Double) {
    self.first = first
    self.second = second
    self.alpha = alpha
  }

  public func getBitmapFor(scale: Float) -> Bitmap {
    let firstBmp = first.getBitmapFor(scale: scale)
    let secondBmp = second.getBitmapFor(scale: scale)
    
    return Bitmap.createBlendedBitmap(
      first: firstBmp!,
      second: secondBmp!, 
      alpha: alpha)  
  }

}

class ExtractSubsetImageSource : ImageSource {

	var image: ImageSkia
  var subsetBounds: FloatRect

	init(image: ImageSkia, subset: FloatRect) {
		self.image = image
		self.subsetBounds = subset
	}
	
	func getBitmapFor(scale: Float) -> Bitmap {
      let bitmap = image.getBitmapFor(scale: scale)
    	let subsetBoundsInPixel = DIPToPixelBounds(dip: subsetBounds, scale: image.scale)
    	return bitmap!.extractSubset(subset: subsetBoundsInPixel)
	}

}

extension ImageSkia {
	
	public static func extractSubset(image: ImageSkia, subset: FloatRect) -> ImageSkia {

  		let clippedBounds = Rect<Float>.intersectRects(a: subset, b: FloatRect(size: image.size))
  		
  		if image.isNull || clippedBounds.isEmpty {
    		return ImageSkia()
  		}

  		return ImageSkia(source: ExtractSubsetImageSource(image: image, subset: clippedBounds), size: clippedBounds.size)
	}

  public static func createButtonBackground(color: Color, image: ImageSkia, mask: ImageSkia) -> ImageSkia {
    if image.isNull || mask.isNull {
      return ImageSkia()
    }
    return ImageSkia(source: ButtonImageSource(color: color, image: image, mask: mask), size: mask.size)
  }

  public static func createBlendedImage(first: ImageSkia, second: ImageSkia, alpha: Double) -> ImageSkia {
    if first.isNull || second.isNull {
      return ImageSkia()
    }
    return ImageSkia(source: BlendingImageSource(first: first, second: second, alpha: alpha), size: second.size)
  }

}

fileprivate func DIPToPixelBounds(dip: FloatRect, scale: Float) -> FloatRect {
  return FloatRect(origin: Point<Float>.toFloored(point: dip.origin, scale: scale), size: DIPToPixelSize(dip: dip.size, scale: scale))
}

fileprivate func DIPToPixelSize(dip: FloatSize, scale: Float) -> FloatSize {
  return FloatSize.toCeiled(size: dip, scale: scale)
}