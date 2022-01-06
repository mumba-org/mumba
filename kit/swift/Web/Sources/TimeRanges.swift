// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct TimeRange {

    public var start: Double = 0.0
    public var end: Double = 0.0
    
    public init() {}
    
    public init(start: Double, end: Double) {
        self.start = start
        self.end = end
    }

    public func isPointInRange(point: Double) -> Bool {
      return start <= point && point < end
    }

    public func isOverlappingRange(range: TimeRange) -> Bool {
      return isPointInRange(point: range.start) || 
             isPointInRange(point: range.end) || 
             range.isPointInRange(point: start)
    }

    public func isContiguousWithRange(range: TimeRange) -> Bool {
      return range.start == end || range.end == start
    }

    public func unionWithOverlappingOrContiguousRange(range: TimeRange) -> TimeRange {
      var ret = TimeRange()

      ret.start = min(start, range.start)
      ret.end = max(end, range.end)

      return ret
    }

    public func isBeforeRange(range: TimeRange) -> Bool {
      return range.start >= end
    }
}

public typealias TimeRanges = [TimeRange]

extension TimeRanges {

  public init(start: Double, end: Double) {
      self.init()
      self.add(start, end)
  }

  public var length: Int { return self.count }
   
  public func copy() -> TimeRanges {
      var result = TimeRanges()
      for item in self {
          result.append(item)
      }
      return result
  }
  
  public func intersectWith(_ other: TimeRanges) {
      assert(false)
  }

  public func unionWith(_ ranges: TimeRanges) {
      assert(false)
  }

  public func start(_ index: Int) -> Double {
      guard index < count else {
          return 0
      }
      return self[index].start
  }

  public func end(_ index: Int) -> Double {
      guard index < count else {
          return 0
      }
      return self[index].end
  }

  public mutating func add(_ start: Double, _ end: Double) {
    var overlappingArcIndex: Int = 0
    var addedRange = TimeRange(start: start, end: end)

    for var i in 0 ..< self.count {
        if addedRange.isOverlappingRange(range: self[i]) ||
            addedRange.isContiguousWithRange(range: self[i]) {
            addedRange = addedRange.unionWithOverlappingOrContiguousRange(
                range: self[i])
            self.remove(at: i)
            i -= 1
        } else {
            if i == 0 {
                if addedRange.isBeforeRange(range: self[0]) {
                    break
                }
            } else {
                if self[i - 1].isBeforeRange(range: addedRange) &&
                    addedRange.isBeforeRange(range: self[i]) {
                    break
                }
            }
        }
        overlappingArcIndex = i
    }
      
    self.insert(addedRange, at: overlappingArcIndex)
  }

  public func contain(_ time: Double) -> Bool {
    for i in 0..<self.count {
        if time >= start(i) && time <= end(i) {
            return true
        }
    }
    return false
  }

  public func nearest(_ newPlaybackPosition: Double,
                      _ currentPlaybackPosition: Double) -> Double {
    assert(false)     
    return 0.0                 
  }
}