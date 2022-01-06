// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum ColorAlpha : UInt8 {
  case opaque = 0xff
  case transparent = 0x00
}

public struct Color {

  public static let Transparent:  Color = Color(0x00000000)
  public static let Black:        Color = Color(0xff000000)
  public static let DarkGray:     Color = Color(0xff444444)
  public static let Gray:         Color = Color(0xff888888)
  public static let LightGray:    Color = Color(0xffcccccc)
  public static let White:        Color = Color(0xffffffff)

  public static let Red:          Color = Color(0xffff0000)
  public static let Green:        Color = Color(0xff00ff00)
  public static let Blue:         Color = Color(0xff0000ff)
  public static let Yellow:       Color = Color(0xffffff00)
  public static let Cyan:         Color = Color(0xff00ffff)
  public static let Magenta:      Color = Color(0xffff00ff)

   /// return the alpha channel of the given color
  public static func alpha(color: Color) -> UInt8 {
    return UInt8((color.value >> 24) & 0xff)
  }

  public static func red(color: Color) -> UInt8  {
    return UInt8((color.value >> 16) & 0xff)
  }

  public static func green(color: Color) -> UInt8  {
    return UInt8((color.value >> 8) & 0xff)
  }

  public static func blue(color: Color) -> UInt8  {
    return UInt8((color.value >> 0) & 0xff)
  }

  public static func fromRGB(_ r: UInt8, _ g: UInt8, _ b: UInt8) -> Color {
    return Color(r: r, g: g, b: b)
  }

  public static func fromARGB(_ a: UInt8, _ r: UInt8, _ g: UInt8, _ b: UInt8) -> Color {
    return Color(a: a, r: r, g: g, b: b)
  }

  public var a: UInt8 {
    get {
      return UInt8(Int((value >> 24)) & 0xff)
    }
    set {

    }
  }

  public var r: UInt8 {
    get {
      return UInt8(Int((value >> 16)) & 0xff)
    }
    set {
      
    }
  }

  public var g: UInt8 {
    get {
      return UInt8(Int((value >> 8)) & 0xff)
    }
    set {
      
    }
  }

  public var b: UInt8 {
    get {
      return UInt8(Int((value >> 0)) & 0xff)
    }
    set {
      
    }
  }

  public private(set) var value: Int

  public init(_ code: Int) {
    value = code
  }

  //public init(_ value: Int) {
  //  self.value = UInt32(value)
  //}

  public init() {
    //value = UInt32((0 << 24) | (0 << 16) | (0 << 8) | (0 << 0))
    self.init(a: 0, r: 0, g: 0, b: 0)
  }

  public init(a: UInt8, r: UInt8, g: UInt8, b: UInt8) {
    guard a <= 255 && r <= 255 && g <= 255 && b <= 255 else {
      value = 0x00000000
      return  
    }
    let tmpA: Int = Int(a) << 24
    let tmpR: Int = Int(r) << 16
    let tmpG: Int = Int(g) << 8
    let tmpB: Int = Int(b) << 0
    value = Int(tmpA | tmpR | tmpG | tmpB)
  }

  public init(r: UInt8, g: UInt8, b: UInt8) {
    self.init(a: 0xff, r: r, g: g, b: b)
  }
  
}

extension Color : Equatable {}

public func == (left: Color, right: Color) -> Bool {
  return left.value == right.value
}

public func != (left: Color, right: Color) -> Bool {
  return !(left == right)
}

extension ColorAlpha : Equatable {}

public func == (left: ColorAlpha, right: ColorAlpha) -> Bool {
  return left.rawValue == right.rawValue
}

public func != (left: ColorAlpha, right: ColorAlpha) -> Bool {
  return !(left == right)
}

public func == (left: ColorAlpha, right: UInt8) -> Bool {
  return left.rawValue == right
}

public func != (left: ColorAlpha, right: UInt8) -> Bool {
  return !(left == right)
}
