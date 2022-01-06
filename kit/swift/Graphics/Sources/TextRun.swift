// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import MumbaShims

public class TextRun {

  // Returns whether the given shaped run contains any missing glyphs.
  //public var hasMissingGlyphs: Bool {
  //  return false
  //}

  // Returns the number of missing glyphs in the shaped text run.
  public var countMissingGlyphs: Int {
    let missingGlyphId: UInt16 = 0
    
    var missing = 0
    
    for i in 0..<glyphCount {
      missing += (glyphs[i] == missingGlyphId) ? 1 : 0
    }
  
    return missing
  }

  var width: Float
  var precedingRunWidths: Float
  var range: TextRange
  var isRtl: Bool
  //var level: UBiDiLevel
  //var script: UScriptCode

  var glyphs: ContiguousArray<UInt16>
  var positions: [FloatPoint]
  var glyphToChar: [UInt32] 
  var glyphCount: Int

  var fontFamily: String
  //skia::RefPtr<SkTypeface> skia_face;
  var typeface: Typeface
  var renderParams: FontRenderParams
  var fontSize: Int
  var baselineOffset: Int
  var baselineType: BaselineStyle
  var fontStyle: FontStyle
  var strike: Bool
  var diagonalStrike: Bool
  var underline: Bool
  var level: UBiDiLevel
  var script: UScriptCode

  public init() {
    width = 0
    precedingRunWidths = 0
    range = TextRange(start: 0, end: 0)
    isRtl = false
    // TODO: We should reuse only one typeface for each font
    typeface = Typeface(font: "sans", style: .Normal)

    glyphs = ContiguousArray<UInt16>()
    positions = []
    glyphToChar = [] 
    glyphCount = 0

    fontFamily = "sans"
    renderParams = FontRenderParams()
    fontSize = 12
    baselineOffset = 0
    baselineType = .NormalBaseline
    fontStyle = FontStyle.Normal
    strike = false
    diagonalStrike = false
    underline = false
    level = 0
    script = UScriptCommon
  }

  public func charRangeToGlyphRange(range charRange: TextRange) -> TextRange {
    
    guard range.contains(range: charRange) && !charRange.isReversed && !charRange.isEmpty else {
      // should be temporary.. find final solution to warn about this (or use exception)
      //print("TextRun.charRangeToGlyphRange: invalid range input given (start:\(charRange.start) end:\(charRange.end))")
      return TextRange()
    }
    
    var startGlyphs = TextRange()
    var endGlyphs = TextRange()
    var tempRange = TextRange()
    
    getClusterAt(pos: Int(charRange.start), chars: &tempRange, glyphs: &startGlyphs)
    getClusterAt(pos: Int(charRange.end), chars: &tempRange, glyphs: &endGlyphs)

    //print("TextRun.charRangeToGlyphRange: startGlyphs.start: \(startGlyphs.start) startGlyphs.end: \(startGlyphs.end) endGlyphs.start: \(endGlyphs.start) endGlyphs.end: \(endGlyphs.end). isRtl ? \(isRtl)\nreturning text range = (\(startGlyphs.start), \(endGlyphs.end))")

    return isRtl ? TextRange(start: endGlyphs.start, end: startGlyphs.end) : 
      TextRange(start: startGlyphs.start, end: endGlyphs.end)
  }

  public func getClusterAt(pos: Int, chars: inout TextRange, glyphs: inout TextRange) {
    
    if glyphCount == 0 {
      chars = range
      glyphs = TextRange()
      return
    }

    if isRtl {
      // TODO: see if theres a less expensive way to do it (using index, etc..)
      var reversedGlyphToChar = glyphToChar
      reversedGlyphToChar.reverse()

      _getClusterAt(
        pos: pos,
        range: range,
        array: reversedGlyphToChar,
        //begin: reversed.startIndex,
        //end: reversed.endIndex,
        reversed: true,
        chars: &chars,
        glyphs: &glyphs)

      return
    }

    _getClusterAt(
        pos: pos, 
        range: range, 
        array: glyphToChar,
        //begin: glyphToChar.startIndex,
        //end: glyphToChar.endIndex, 
        reversed: false, 
        chars: &chars, 
        glyphs: &glyphs)
  
  }

  public func getGraphemeBounds(iterator: BreakIterator?, index textIndex: Int) -> TextRangef {
    
    if glyphCount == 0 {
      return TextRangef(start: precedingRunWidths, end: precedingRunWidths + width)
    }

    var chars = TextRange()
    var glyphs = TextRange()
    
    getClusterAt(pos: textIndex, chars: &chars, glyphs: &glyphs)
  
    ////print("count: \(positions.count) start: \(glyphs.start) end: \(glyphs.end)")

    let clusterBeginX = positions[Int(glyphs.start)].x
    let clusterEndX = glyphs.end < glyphCount ? positions[glyphs.end].x : width

    // A cluster consists of a number of code points and corresponds to a number
    // of glyphs that should be drawn together. A cluster can contain multiple
    // graphemes. In order to place the cursor at a grapheme boundary inside the
    // cluster, we simply divide the cluster width by the number of graphemes.
    if let graphemeIterator = iterator, chars.length > 1 {
      var before = 0
      var total = 0
      for i in chars.start..<chars.end {
        if graphemeIterator.isGraphemeBoundary(pos: i) {
          if i < textIndex {
            before += 1
          }
          total += 1
        }
      }
      //assert(total > 0)
      
      if total > 1 {

        if isRtl {
          before = total - before - 1
        }
        
        //assert(before >=  0)
        //assert(before < total)
        let clusterWidth = clusterEndX - clusterBeginX
        let graphemeBeginX = clusterBeginX + 0.5 + clusterWidth * Float(before) / Float(total)
        let graphemeEndX = clusterBeginX + 0.5 + clusterWidth * (Float(before) + 1) / Float(total)
        
        return TextRangef(start: precedingRunWidths + graphemeBeginX, end: precedingRunWidths + graphemeEndX)
      }
    }

    return TextRangef(start: precedingRunWidths + clusterBeginX, end: precedingRunWidths + clusterEndX)
  }

  public func getGlyphWidthForCharRange(range charRange: TextRange) -> Float {
    
    if charRange.isEmpty {
      return 0
    }

    //assert(range.contains(charRange))
    let glyphRange = charRangeToGlyphRange(range: charRange)

    // The |glyph_range| might be empty or invalid on Windows if a multi-character
    // grapheme is divided into different runs (e.g., there are two font sizes or
    // colors for a single glyph). In this case it might cause the browser crash,
    // see crbug.com/526234.
    if glyphRange.start >= glyphRange.end {
      // TODO: we should use a exception here

      //NOTREACHED() << "The glyph range is empty or invalid! Its char range: ["
      //    << char_range.start() << ", " << char_range.end()
      //    << "], and its glyph range: [" << glyph_range.start() << ", "
      //    << glyph_range.end() << "].";
      return 0
    }

    return ((Int(glyphRange.end) == glyphCount) ? width : Float(positions[glyphRange.end].x)) 
      - Float(positions[glyphRange.start].x)
  }

  func _getClusterAt(pos: Int,//Array<UInt32>.Index,
                     range: TextRange,
                     array: Array<UInt32>,
                     //begin: Array<UInt32>.Index,
                     //end: Array<UInt32>.Index,
                     reversed: Bool,
                     chars: inout TextRange,
                     glyphs: inout TextRange) {
                     
    var ipos = array.index(array.startIndex, offsetBy: pos)
    let begin = array.startIndex
    let end = array.endIndex

    //Iterator element = std::upper_bound(elements_begin, elements_end, pos);
    
    // TODO: check if the math is sound here
    chars.end = (ipos == end) ? range.end : ipos
    glyphs.end = reversed ? end - ipos : ipos - begin

    ////print("glyphs.end: \(glyphs.end), pos: \(pos), ipos: \(ipos), begin: \(begin), end: \(end), array.count: \(array.count)")

    //DCHECK(element != elements_begin);
    while ((ipos - 1) != begin) && (ipos == (ipos - 1)) {
      chars.start = ipos
      ipos -= 1
    }
  
    glyphs.start = reversed ? end - ipos : ipos - begin

   // //print("glyphs.start: \(glyphs.start), pos: \(pos), ipos: \(ipos), begin: \(begin), end: \(end), array.count: \(array.count)")
  
    if reversed {
      glyphs = TextRange(start: glyphs.end, end: glyphs.start)
    }

    //assert(!chars.isReversed)
    //assert(!chars.isEmpty)
    //assert(!glyphs.isReversed)
    //assert(!glyphs.isEmpty)
  }

}


public struct TextRunList {

  static let allocMax = 512
  static let allocAlignment = 8
    // Text runs in logical order.
  public var runs: [TextRun]

  // Maps visual run indices to logical run indices and vice versa.
  public var visualToLogical: [Int]
  
  public var logicalToVisual: [Int]

  public var width: Float

  public init() {
    runs = []
    visualToLogical = []
    logicalToVisual = []
    width = 0
  }
  
  public mutating func initIndexMap() {
    // to think: maybe if runcount = 0 we should only alloc * 1 or nothing at all? 
  
    let itemCount = runs.count == 0 ? TextRunList.allocMax : runs.count
    let allocSize = itemCount * MemoryLayout<Int32>.stride
    let alignment = MemoryLayout<Int32>.alignment

    let visualsContainer = UnsafeMutableRawPointer.allocate(byteCount: allocSize,  alignment: alignment)
    let logicalsContainer = UnsafeMutableRawPointer.allocate(byteCount: allocSize,  alignment: alignment)

    if runs.count == 1 {
      visualToLogical = Array<Int>(repeating: 0, count: 1)
      logicalToVisual = Array<Int>(repeating: 0, count: 1)
      return
    }
    
    var levels: [UBiDiLevel] = []
    levels.reserveCapacity(runs.count == 0 ? 1 : runs.count)

    for run in runs {
      levels.append(run.level)
    }

    let visualsTypedView = visualsContainer.bindMemory(to: Int32.self, capacity: itemCount)
    let logicalsTypedView = logicalsContainer.bindMemory(to: Int32.self, capacity: itemCount)

    levels.withUnsafeMutableBufferPointer { levelbuf in
      _ICUBiDiReorderVisual(levelbuf.baseAddress, Int32(runs.count), visualsTypedView)
      _ICUBiDiReorderLogical(levelbuf.baseAddress, Int32(runs.count), logicalsTypedView)
    }
    
    for i in 0..<runs.count {
      visualToLogical.append(Int(visualsTypedView[i]))
      logicalToVisual.append(Int(visualsTypedView[i]))
    }

    visualsContainer.deallocate()
    logicalsContainer.deallocate()
  }

  public mutating func computePrecedingRunWidths() {
    width = 0
    for i in 0..<runs.count {
      ////print("i: \(i) visualToLogical[i]: \(visualToLogical[i])")
      ////print("runs[\(i)].width: \(runs[i].width)")
      let run = runs[visualToLogical[i]]
      run.precedingRunWidths = width
      width += run.width
    }
  }

  public func getRunIndexAt(pos: Int) -> Int {
    var index = 0
    for run in runs {
      if run.range.start <= pos && run.range.end > pos {
        return index
      }
      index += index
    }
    return runs.count
  }

  public mutating func reset() {
    runs.removeAll()
    width = 0
  }

}