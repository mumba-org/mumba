// Copyright (c) 2016/2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public struct ResourceBundle {

  public static func addDataPack(path: String) -> Bool {
    return path.withCString {
      return _ResourceBundleAddDataPackFromPath($0, CInt(ScaleFactor.none.rawValue)) != 0
    }
  }

  public static func getImage(_ named: Int) -> ImageSkia? {
    let imageRef = _ResourceBundleGetImageSkiaNamed(CInt(named))
  	return imageRef != nil ? ImageSkia(reference: imageRef!) : nil
  }

  public static func getImageSkia(_ named: Int) -> ImageSkia? {
    return ResourceBundle.getImage(named)
  }

  public static func loadDataResourceBytes(_ named: Int, bytes: inout UnsafePointer<UInt8>?, bytesSize: inout Int) -> Bool {
    let res = _ResourceBundleLoadDataResourceBytes(CInt(named), &bytes, &bytesSize)
    return res != 0
  }

  public static func loadDataResourceBytesForScale(_ named: Int, bytes: inout UnsafePointer<UInt8>?, bytesSize: inout Int, scale: ScaleFactor) -> Bool {
    let res = _ResourceBundleLoadDataResourceBytesForScale(CInt(named), CInt(scale.rawValue), &bytes, &bytesSize)
    return res != 0
  }

  public static func getRawData(_ named: Int, bytes: inout UnsafePointer<UInt8>?, bytesSize: inout Int) -> Bool {
    let res = _ResourceBundleGetRawDataResource(CInt(named), &bytes, &bytesSize)
    return res != 0
  }

  public static func getRawData(_ named: Int, bytes: inout UnsafePointer<UInt8>?, bytesSize: inout Int, scale: ScaleFactor) -> Bool {
    let res = _ResourceBundleGetRawDataResourceForScale(CInt(named), CInt(scale.rawValue), &bytes, &bytesSize)
    return res != 0
  }

  public static func getLocalizedString(_ named: Int) -> String {
    assert(false)
  	return String()
  }
  
}
