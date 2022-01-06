// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct BreakList<E>: Sequence where E : Equatable {
  
  public typealias Break = (index: Int, value: E)
  public typealias Iterator = IndexingIterator<Array<Break>>

  public var max: Int {
    get {
      return _max
    }
    set {
      let slice = self[newValue]
      if slice.count > 0 {
        var i = slice.startIndex
        i += (i == breaks.startIndex || slice[i].index < newValue) ? 1 : 0
        breaks.removeSubrange(i...breaks.endIndex)
      }

      _max = newValue
    }
  }

  public var breaks: [Break]

  var _max: Int

  public init() {
    breaks = [Break]()
    
    //breaks.insert((index: 0, value: false), at: FontStyle.Normal.rawValue)
    //breaks.insert((index: 1, value: false), at: FontStyle.Bold.rawValue)
    //breaks.insert((index: 2, value: false), at: FontStyle.Italic.rawValue)
    //breaks.insert((index: 3, value: false), at: FontStyle.Strike.rawValue)
    //breaks.insert((index: 4, value: false), at: FontStyle.DiagonalStrike.rawValue)
    //breaks.insert((index: 5, value: false), at: FontStyle.Underline.rawValue)
    _max = 0
  }

  public func makeIterator() -> BreakList.Iterator {
    return breaks.makeIterator()
  }

  public func range(at index: Int) -> TextRange {
    let next = index + 1
    return TextRange(start: breaks[index].index, end: next == breaks.endIndex ? _max : breaks[next].index)
  }

  public func range(from: Array<Break>) -> TextRange {
    let start = from.startIndex
    return TextRange(start: from[start].index, end: from[start + 1].index)
  }

  mutating func set(value: E) {
    breaks.removeAll()
    breaks.append(Break(index: 0, value: value)) 
  }

  // Adjust the breaks to apply |value| over the supplied |range|.
  mutating func apply(value: E, range: TextRange) {
    
    guard range.isValid && !range.isEmpty else {
      return
    }

    assert(!breaks.isEmpty)
    assert(!range.isReversed)
    assert(TextRange(start: 0, end: _max).contains(range: range))

   for i in range.start..<range.end {
     breaks.insert(Break(index: i, value: value), at: i)
   }

  }


  // equivalent to the c++ GetBreak()
  public subscript(_ index: Int) -> [Break] {
    let offset = getMaxOffset(index)
    //let subsequence = Array<Break>(breaks.suffix(offset))
    //return subsequence.makeIterator()
    return Array<Break>(breaks.suffix(offset))
  }

  func getMaxOffset(_ at: Int) -> Int {
    var offset = breaks.count

    for (i, _) in breaks.reversed() {
      if at == i {
        break
      }
      offset -= 1
    }
    return offset
  }

}