// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base

public enum HarfBuzzDirection : Int {
  case Invalid = 0
  case LTR = 4
  case RTL = 5
  case TTB = 6
  case BTT = 7
}

public struct HarfBuzzGlyphInfo {
  public var codepoint: UInt
  public var mask: UInt
  public var cluster: UInt
}

public struct HarfBuzzGlyphPosition {
  public var xAdvance: Int
  public var yAdvance: Int
  public var xOffset: Int
  public var yOffset: Int
}

public struct HarfBuzzScript {
  
  public static func fromString(_ string: String) -> HarfBuzzScript {
    
    let value = string.withCString { cstr -> HarfBuzzScriptEnum in
      return _HarfBuzzScriptCreateString(cstr, Int32(string.count))
    }

    return HarfBuzzScript(rawValue: value)
  }

  public static func fromICUScript(_ script: UScriptCode) -> HarfBuzzScript {
    let value = _HarfBuzzScriptCreateICU(Int32(script))
    return HarfBuzzScript(rawValue: value)
  }
  
  var rawValue: HarfBuzzScriptEnum

  public init(rawValue: HarfBuzzScriptEnum) {
    self.rawValue = rawValue  
  }

}

public class HarfBuzzFont {
  
  var reference: HarfBuzzFontRef

  init(typeface: Typeface,
       textSize: Int,
       params: FontRenderParams,
       subpixelRenderingSuppressed: Bool) {

    reference = _HarfBuzzFontCreate(
      typeface.reference, 
      Int32(textSize), 
      params.antialiasing ? 1 : 0,
      params.subpixelPositioning ? 1 : 0,
      params.autohinted ? 1 : 0,
      Int32(params.subpixelRendering.rawValue),
      subpixelRenderingSuppressed ? 1 : 0,
      Int32(params.hinting.rawValue))
  }

  deinit {
    _HarfBuzzFontDestroy(reference)
  }

  public func shape(buffer: HarfBuzzBuffer) {
    _HarfBuzzFontShape(reference, buffer.reference)
  }

}

public class HarfBuzzBuffer {
  
  // TODO: hardcoded limit.. if theres more glyphs than this it will not work properly
  let defaultAllocSize = 128

  public var glyphInfos: [HarfBuzzGlyphInfo] {
    // TODO: cache result
    var result: [HarfBuzzGlyphInfo] = []
    var len: UInt32 = 0
    let count = defaultAllocSize
    let allocSize = count * MemoryLayout<Int32>.stride
    let alignSize = MemoryLayout<UInt32>.alignment

    let codepointsRaw = UnsafeMutableRawPointer.allocate(byteCount: allocSize,  alignment: alignSize)
    let masksRaw = UnsafeMutableRawPointer.allocate(byteCount: allocSize,  alignment: alignSize)
    let clustersRaw = UnsafeMutableRawPointer.allocate(byteCount: allocSize,  alignment: alignSize)

    let codepointsPtr = codepointsRaw.bindMemory(to: UInt32.self, capacity: count)
    let masksPtr = masksRaw.bindMemory(to: UInt32.self, capacity: count)
    let clustersPtr = clustersRaw.bindMemory(to: UInt32.self, capacity: count)
            
    _HarfBuzzBufferGetGlyphInfos(reference, codepointsPtr, masksPtr, clustersPtr, &len)
          
    result.reserveCapacity(Int(len)) 
          
    for i in 0..<Int(len) {
      
      let info = HarfBuzzGlyphInfo(
        codepoint: UInt(codepointsPtr[i]),
        mask: UInt(masksPtr[i]),
        cluster: UInt(clustersPtr[i]))
      
      result.append(info)
    }

    codepointsRaw.deallocate()
    masksRaw.deallocate()
    clustersRaw.deallocate()

    return result
  }

  public var glyphPositions: [HarfBuzzGlyphPosition] {
    // TODO: cache result
    let count = defaultAllocSize
    let allocSize = count * MemoryLayout<Int32>.stride
    let alignSize = MemoryLayout<Int32>.alignment
    var result: [HarfBuzzGlyphPosition] = []
    var len: UInt32 = 0

    let xAdvancesRaw = UnsafeMutableRawPointer.allocate(byteCount: allocSize,  alignment: alignSize)
    let yAdvancesRaw = UnsafeMutableRawPointer.allocate(byteCount: allocSize,  alignment: alignSize)
    let xOffsetsRaw = UnsafeMutableRawPointer.allocate(byteCount: allocSize,  alignment: alignSize)
    let yOffsetsRaw = UnsafeMutableRawPointer.allocate(byteCount: allocSize,  alignment: alignSize)

    let xAdvancesPtr = xAdvancesRaw.bindMemory(to: Int32.self, capacity: count)
    let yAdvancesPtr = yAdvancesRaw.bindMemory(to: Int32.self, capacity: count)
    let xOffsetsPtr = xOffsetsRaw.bindMemory(to: Int32.self, capacity: count)
    let yOffsetsPtr = yOffsetsRaw.bindMemory(to: Int32.self, capacity: count)

    _HarfBuzzBufferGetGlyphPositions(reference, xAdvancesPtr, yAdvancesPtr, xOffsetsPtr, yOffsetsPtr, &len)    
            
    result.reserveCapacity(Int(len)) 

    for i in 0..<Int(len) {
      let pos = HarfBuzzGlyphPosition(
        xAdvance: Int(xAdvancesPtr[i]),
        yAdvance: Int(yAdvancesPtr[i]),
        xOffset: Int(xOffsetsPtr[i]),
        yOffset: Int(yOffsetsPtr[i]))
              
      result.append(pos)
    }

    xAdvancesRaw.deallocate()
    yAdvancesRaw.deallocate()
    xOffsetsRaw.deallocate()
    yOffsetsRaw.deallocate()

    return result
  }

  var reference: HarfBuzzBufferRef

  init() {
    reference = _HarfBuzzBufferCreate()
  }

  deinit {
    _HarfBuzzBufferDestroy(reference)
  }

  public func addUTF16(text: String, start: Int, length: Int) {
    // TODO: check if theres a less memory copy intensive  way of doing this
    // didnt found any way of doing this by using the inner string pointer directly
    var glyphs: [UInt16] = []
    for glyph in text.utf16 {
      glyphs.append(glyph)
    }
    glyphs.withUnsafeBufferPointer { glyphPtr in 
      _HarfBuzzBufferAddUTF16(reference, glyphPtr.baseAddress, Int32(text.utf16.count), UInt32(start), Int32(length))
    }
  }

  public func setScript(_ script: HarfBuzzScript) {
    _HarfBuzzBufferSetScript(reference, script.rawValue)
  }

  public func setDirection(_ direction: HarfBuzzDirection) {
    _HarfBuzzBufferSetDirection(reference, Int32(direction.rawValue))
  }

  public func setLanguage(_ language: String) {
    language.withCString { langbuf in
      _HarfBuzzBufferSetLanguage(reference, langbuf, Int32(language.count))
    }
  }

  public func setDefaultLanguage() {
    _HarfBuzzBufferSetDefaultLanguage(reference)
  }
  
}