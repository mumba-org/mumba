// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct PixelFormatInfo {
    public var bytesPerPixel: Int
    public var bitsPerPixel: Int

    public init() {
     bytesPerPixel = 0
     bitsPerPixel = 0
    }
}

public enum PixelFormat {
    case Unknown
    case Translucent
    case Transparent
    case Opaque
    case RGBA_8888
    case RGBX_8888
    case RGB_888
    case RGB_565

    public static func getInfo(_ format: PixelFormat) -> PixelFormatInfo {
        var info = PixelFormatInfo()
        switch format {
            case .RGBA_8888, .RGBX_8888:
                info.bitsPerPixel = 32
                info.bytesPerPixel = 4
            case .RGB_888:
                info.bitsPerPixel = 24
                info.bytesPerPixel = 3
            case .RGB_565:
                info.bitsPerPixel = 16
                info.bytesPerPixel = 2
            default:
                break
        }
        return info
    }
}