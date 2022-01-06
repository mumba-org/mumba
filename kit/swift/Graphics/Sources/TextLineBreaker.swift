// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import Glibc
#endif

public class TextLineBreaker {

  typealias SegmentHandle = (Int, Int)

  var maxWidth: Float
  var minBaseline: Int
  var minHeight: Float
  var wordWrapBehavior: WordWrapBehavior
  var text: String
  var words: BreakList<Int>?
  var runList: TextRunList

  // Stores the resulting lines.
  var lines: [Line]

  var maxDescent: Float
  var maxAscent: Float

  // Text space x coordinates of the next segment to be added.
  var textX: Float
  // Stores available width in the current line.
  var availableWidth: Float

  // IntSize of the multiline text, not including the currently processed line.
  var totalSize: FloatSize

  // The current RTL run segments, to be applied by |UpdateRTLSegmentRanges()|.
  var rtlSegments: [SegmentHandle]
  
  public init(maxWidth: Float,
              minBaseline: Int,
              minHeight: Float,
              behavior: WordWrapBehavior,
              text: String,
              words: BreakList<Int>?,
              list: TextRunList) {
    
    self.maxWidth = (maxWidth == 0.0) ? .nan : maxWidth
    self.minBaseline = minBaseline
    self.minHeight = minHeight
    self.text = text
    self.words = words
    runList = list
    wordWrapBehavior = behavior
    maxDescent = 0
    maxAscent = 0
    textX = 0.0
    availableWidth = maxWidth
    totalSize = FloatSize()
    lines = []
    rtlSegments = []
    
    advanceLine()
  }

  public func constructSingleLine() {
    for (i, run) in runList.runs.enumerated() {
      var segment = LineSegment()
      segment.run = i
      segment.charRange = TextRange(start: run.range.start, end: run.range.end)
      segment.xRange = TextRangef(start: Float(textX),
                                  end: Float(textX) + run.width)
      addLineSegment(segment)
    }
  }

  // Constructs multiple lines for |text_| based on words iteration approach.
  public func constructMultiLines() {
    
    guard let wordList = words else {
      return
    }

    //for i in 0...wordList.breaks.count {
    for i in 0..<wordList.breaks.count {
      
      let wordRange = wordList.range(at: i)
      var wordSegments: [LineSegment] = [] 

      var wordWidth = getWordWidth(range: wordRange, segments: &wordSegments)

      // If the last word is '\n', we should advance a new line after adding
      // the word to the current line.
      var newLine = false
      let textIndex = text.index(text.startIndex, offsetBy: Int(wordSegments.last!.charRange.start))
      if !wordSegments.isEmpty && text[textIndex] == "\n" {
        newLine = true
        wordWidth -= wordSegments.last!.width
        wordSegments.removeLast()
      }

      // If the word is not the first word in the line and it can't fit into
      // the current line, advance a new line.
      if wordWidth > availableWidth && availableWidth != maxWidth {
        advanceLine()
      }
      if !wordSegments.isEmpty {
        addWordToLine(wordSegments)
      }
      if newLine {
        advanceLine()
      }
    }

  }

  // Finishes line breaking and outputs the results. Can be called at most once.
  public func finalizeLines(_ outLines: inout [Line], size: inout FloatSize) {
    guard !lines.isEmpty else {
      return
    }

    // Add an empty line to finish the line size calculation and remove it.
    advanceLine()
    lines.removeLast()
    size = totalSize
    outLines.insert(contentsOf: lines, at: outLines.startIndex)
  }

  func segmentFromHandle(_ reference: SegmentHandle) -> LineSegment {
    return lines[reference.0].segments[reference.1]
  }

  func advanceLine() {

    if !lines.isEmpty {
      let lineOffset = lines.count - 1
      //sort(line->segments.begin(), line->segments.end(),
      //          [this](const internal::LineSegment& s1,
      //                 const internal::LineSegment& s2) -> bool {
      //            return run_list_.logical_to_visual(s1.run) <
      //                   run_list_.logical_to_visual(s2.run)
      //})

      lines[lineOffset].segments.sort {
        return runList.logicalToVisual[$0.run] < runList.logicalToVisual[$1.run]
      }

      lines[lineOffset].size.height = max(minHeight, maxDescent + maxAscent)
      lines[lineOffset].baseline = max(minBaseline, Int(maxAscent))
      lines[lineOffset].precedingHeights = ceilf(totalSize.height)
      totalSize.height = totalSize.height + lines[lineOffset].size.height
      totalSize.width = max(totalSize.width, lines[lineOffset].size.width)
    }

    maxDescent = 0
    maxAscent = 0
    availableWidth = maxWidth
    lines.append(Line())
  }

  func addWordToLine(_ wordSegments: [LineSegment]) {

    guard !lines.isEmpty || !wordSegments.isEmpty else {
      return
    }

    var hasTruncated = false
    for segment in wordSegments {
      if hasTruncated {
        break
      }
      if segment.width <= availableWidth || wordWrapBehavior == .IgnoreLongWords {
        addLineSegment(segment)
      } else {
        assert(wordWrapBehavior == .TruncateLongWords ||
               wordWrapBehavior == .WrapLongWords)
        hasTruncated = (wordWrapBehavior == .TruncateLongWords)

        let run = runList.runs[segment.run]
        var remainingSegment = segment
        while !remainingSegment.charRange.isEmpty {
          let cutoffPos = getCutoffPos(segment: remainingSegment)
          let width = run.getGlyphWidthForCharRange(range: TextRange(start: remainingSegment.charRange.start, end: cutoffPos))
          if width > 0 {
            var cutSegment = LineSegment()
            cutSegment.run = remainingSegment.run
            cutSegment.charRange = TextRange(start: remainingSegment.charRange.start, end: cutoffPos)
            cutSegment.xRange = TextRangef(start: Float(textX), end: Float(textX + width))
            addLineSegment(cutSegment)
            // Updates old segment range.
            remainingSegment.charRange.start = cutoffPos
            remainingSegment.xRange.start = Float(textX)
          }
          if hasTruncated {
            break
          }
          if !remainingSegment.charRange.isEmpty {
            advanceLine()
          }
        }
      }
    }
  }

  // Add a line segment to the current line. Note that, in order to keep the
  // visual order correct for ltr and rtl language, we need to merge segments
  // that belong to the same run.
  func addLineSegment(_ segment: LineSegment) {
    
    guard !lines.isEmpty else {
      return
    }

    let run = runList.runs[segment.run]
    let lineOffset = lines.count - 1
    
    if !lines[lineOffset].segments.isEmpty {
      var lastSegment = lines[lineOffset].segments.last!
      // Merge segments that belong to the same run.
      if lastSegment.run == segment.run {
        assert(lastSegment.charRange.end == segment.charRange.start)
        //assert(abs(lastSegment.xRange.end - segment.xRange.start) <= Float.epsilon)
        lastSegment.charRange.end = segment.charRange.end
        lastSegment.xRange.end = Float(textX + segment.width)
        
        if run.isRtl && lastSegment.charRange.end == run.range.end {
          updateRTLSegmentRanges()
        }

        lines[lineOffset].size.width = lines[lineOffset].size.width + segment.width
        textX += segment.width
        availableWidth -= segment.width
        
        let segmentOffset = lines[lineOffset].segments.count - 1
        lines[lineOffset].segments[segmentOffset] = lastSegment

        return
      }
    }

    lines[lineOffset].segments.append(segment)
 
    let paint = Paint()
    paint.typeface = run.typeface
    paint.textSize = run.fontSize
    paint.antiAlias = run.renderParams.antialiasing
    var metrics = Paint.FontMetrics()
    paint.getFontMetrics(metrics: &metrics)

    lines[lineOffset].size.width = lines[lineOffset].size.width + segment.width
    // TODO(dschuyler): Account for stylized baselines in string sizing.
    maxDescent = max(maxDescent, metrics.descent)
    // fAscent is always negative.
    maxAscent = max(maxAscent, -metrics.ascent)

    if run.isRtl {
      let segmentOffset = lines[lineOffset].segments.count - 1
      rtlSegments.append(SegmentHandle(lineOffset, segmentOffset))
      // If this is the last segment of an RTL run, reprocess the text-space x
      // ranges of all segments from the run.
      if segment.charRange.end == run.range.end {
        updateRTLSegmentRanges()
      }
    }
    textX += segment.width
    availableWidth -= segment.width
  }

  // Finds the end position |end_pos| in |segment| where the preceding width is
  // no larger than |available_width_|.
  func getCutoffPos(segment: LineSegment) -> Int {
    
    guard !segment.charRange.isEmpty else {
      return 0
    }
    
    let run = runList.runs[segment.run]
    var endPos = segment.charRange.start
    var width: Float = 0.0
    
    while endPos < segment.charRange.end {
      let charWidth = run.getGlyphWidthForCharRange(range: TextRange(start: endPos, end: endPos + 1))
      
      if width + charWidth > availableWidth {
        break
      }

      width += charWidth
      endPos += 1
    }

    let validEndPos = max(segment.charRange.start, findValidBoundaryBefore(text: text, index: Int(endPos)))
    
    if endPos != validEndPos {
      endPos = validEndPos
      width = run.getGlyphWidthForCharRange(range: 
          TextRange(start: segment.charRange.start, end: endPos))
    }

    // |max_width_| might be smaller than a single character. In this case we
    // need to put at least one character in the line. Note that, we should
    // not separate surrogate pair or combining characters.
    // See RenderTextTest.Multiline_MinWidth for an example.
    if width == 0 && availableWidth == maxWidth {
      endPos = min(segment.charRange.end, findValidBoundaryAfter(text: text, index: Int(endPos + 1)))
    }

    return endPos
  }

  // Gets the glyph width for |word_range|, and splits the |word| into different
  // segments based on its runs.
  func getWordWidth(range wordRange: TextRange,
                    segments: inout [LineSegment]) -> Float {

    guard !wordRange.isEmpty else {
      return 0.0
    }

    let runStartIndex = runList.getRunIndexAt(pos: wordRange.start)
    let runEndIndex = runList.getRunIndexAt(pos: wordRange.end - 1)
    var width: Float = 0.0

    for i in runStartIndex..<runEndIndex {
      let run = runList.runs[i]
      let charRange = run.range.intersect(range: wordRange)
      //assert(!charRange.isEmpty)
      let charWidth = run.getGlyphWidthForCharRange(range: charRange)
      width += charWidth

      var segment = LineSegment()
      segment.run = i
      segment.charRange = charRange
      segment.xRange = TextRangef(start: textX + width - charWidth,
                                  end: textX + width)
      segments.append(segment)
    }

    return width
  }

  // RTL runs are broken in logical order but displayed in visual order. To find
  // the text-space coordinate (where it would fall in a single-line text)
  // |x_range| of RTL segments, segment widths are applied in reverse order.
  // e.g. {[5, 10], [10, 40]} will become {[35, 40], [5, 35]}.
  func updateRTLSegmentRanges() {
    
    guard !rtlSegments.isEmpty else {
      return
    }

    var x = segmentFromHandle(rtlSegments[0]).xRange.start

    for i in stride(from: 0, to: rtlSegments.count, by: -1) {
      var segment = segmentFromHandle(rtlSegments[i - 1])
      segment.xRange = TextRangef(start: x, end: x + segment.width)
      x += segment.width
    }
    
    rtlSegments.removeAll()
  }

}