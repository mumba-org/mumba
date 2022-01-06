// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum RRectType : Int {
  case empty = 0
  case rect
  case oval
  case simple
  case ninePatch
  case complex
}

public protocol RRectProtocol {

  associatedtype Element: SignedNumeric, Comparable

  var type: RRectType {
    get
  }

  var width: Element {
    get
    set
  }

  var height: Element {
    get
    set
  }

  var x: Element {
    get
    set
  }

  var y: Element {
    get
    set
  }

  var right: Element { get }
  var bottom: Element { get }
  var origin: Point<Element> { get set }
  var size: Size<Element> { get set }
  var isEmpty: Bool { get }
  var isRect: Bool { get }
  var isOval: Bool { get }
  var isSimple: Bool { get }
  var isNinePatch: Bool { get }
  var isComplex: Bool { get }
}

public struct RRect<T: SignedNumeric> : RRectProtocol where T : Comparable {

  public typealias Element = T

  public internal(set) var type: RRectType

  public var width: T {
    get {
      return rect.width
    }
    set {
      rect.width = newValue
    }
  }

  public var height: T {
    get {
      return rect.height
    }
    set {
      rect.height = newValue
    }
  }

  public var x: T {
    get {
      return rect.x
    }
    set {
      rect.x = newValue
    }
  }

  public var y: T {
    get {
      return rect.y
    }
    set {
      rect.y = newValue
    }
  }

  public var right: T {
    return rect.width
  }

  public var bottom: T {
    return rect.bottom
  }

  public var origin: Point<Element> { 
    get {
      return rect.origin
    } 
    set {
      rect.origin = newValue
    } 
  }
  
  public var size: Size<Element> { 
    get {
      return rect.size
    }
    set {
      rect.size = newValue
    }
  }

  public var isEmpty: Bool { return type == RRectType.empty }
  public var isRect: Bool { return type == RRectType.rect }
  public var isOval: Bool { return type == RRectType.oval }
  public var isSimple: Bool { return type == RRectType.simple }
  public var isNinePatch: Bool { return type == RRectType.ninePatch }
  public var isComplex: Bool { return type == RRectType.complex }

  public var rect: Rect<T> {
    get {
      return _rect
    }
    set {
      let _rect = newValue.makeSorted()
      if _rect.isEmpty {
        type = RRectType.empty
        radii = Array(repeating: Vec2<T>(), count: 4)
      } else {
        type = RRectType.rect
      }
    }
  }

  public var bounds: Rect<T> {
   return _rect
  }

  public internal(set) var radii: Array<Vec2<T>>

  internal var _rect: Rect<T>

  public init() {
    _rect = Rect<T>()
    radii = Array(repeating: Vec2<T>(), count: 4)
    type = RRectType.empty
  }

  public init(rect: Rect<T>) {
    radii = Array(repeating: Vec2<T>(), count: 4)
    
    _rect = rect.makeSorted() 
    if _rect.isEmpty {
      type = RRectType.empty
      return
    }
    type = RRectType.rect
  }

}

extension RRect where T == Float {
  
  public init(oval: Rect<T>) {
    type = RRectType.empty
    radii = Array(repeating: Vec2<T>(), count: 4)
    _rect = oval.makeSorted()
    if _rect.isEmpty {
      return
    }

    let xrad = _rect.width * 0.5
    let yrad = _rect.height * 0.5

    for i in 0..<4 {
      radii[i].set(x: xrad, y: yrad)
    }
    
    type = RRectType.oval
  }

  public init(rect inRect: Rect<T>, x xrad: Float, y yrad: Float) {
    type = RRectType.empty
    radii = Array(repeating: Vec2<T>(), count: 4)
    _rect = inRect.makeSorted()
    
    if _rect.isEmpty {
      return
    }

    if xrad <= 0.0 || yrad <= 0.0 {
      type = RRectType.rect
      return
    }

    var mx = xrad
    var my = yrad

    if _rect.width < mx+mx || _rect.height < my+my {
      let scale = min(_rect.width / (mx + mx), _rect.height / (my + my))
      mx *= scale
      my *= scale
    }

    for i in 0..<4 {
      radii[i].set(x: mx, y: my)
    }

    type = RRectType.simple
    if mx >= (_rect.width * 0.5) && my >= (_rect.height * 0.5) {
      type = RRectType.oval
    }
  }

  public mutating func setOval(_ oval: FloatRect) {
    _rect = oval.makeSorted()
    
    if _rect.isEmpty {
      return
    }

    let xrad = _rect.width * 0.5
    let yrad = _rect.height * 0.5

    for i in 0..<4 {
      radii[i].set(x: xrad, y: yrad)
    }
    
    type = RRectType.oval
  }

}

//public typealias IntRRect = RRect<Int>
public typealias FloatRRect = RRect<Float>
