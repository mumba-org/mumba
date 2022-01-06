// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO: implement
public struct Time {
  public static let HoursPerDay: Int64 = 24
  public static let MillisecondsPerSecond: Int64 = 1000
  public static let MillisecondsPerDay: Int64 = MillisecondsPerSecond * 60 * 60 * HoursPerDay
  public static let MicrosecondsPerMillisecond: Int64 = 1000
  public static let MicrosecondsPerSecond: Int64 = MicrosecondsPerMillisecond * MillisecondsPerSecond
  public static let NanosecondsPerMicrosecond: Int64 = 1000
  public static let NanosecondsPerSecond: Int64 = NanosecondsPerMicrosecond * MicrosecondsPerSecond
  public static let TimeTToMicrosecondsOffset: Int64 = 11644473600000000

  public static var now: Time {
#if os(Linux) || os(macOS)
  var tv = timeval()
  var tz = timezone()
  tz.tz_minuteswest = 0
  tz.tz_dsttime = 0
  //struct timezone tz = {0, 0}  // UTC
  let rc = gettimeofday(&tv, &tz)
  assert(rc == 0)
  /// Combine seconds and microseconds in a 64-bit field containing microseconds
  /// since the epoch.  That's enough for nearly 600 centuries.  Adjust from
  /// Unix (1970) to Windows (1601) epoch.
  return Time() + TimeDelta.from(
    microseconds: (Int64(tv.tv_sec) * Time.MicrosecondsPerSecond + Int64(tv.tv_usec)) + Time.TimeTToMicrosecondsOffset)
#endif
  }

  public var microseconds: Int64 = 0

  public init() {}
  public init(microseconds: Int64) {
    self.microseconds = microseconds
  }

  public static func + (left: Time, right: TimeDelta) -> Time {
    return Time(microseconds: right.delta + left.microseconds)
  }

  public static func - (left: Time, right: Time) -> TimeDelta {
    return TimeDelta.from(microseconds: right.microseconds - left.microseconds)
  }
}

public protocol TickClock { 
  var nowTicks: TimeTicks { get }
}

public struct TimeTicks {

  public static var max: TimeTicks {
    return TimeTicks(microseconds: Int64.max)
  }

  public var microseconds: Int64

  public static var now: TimeTicks {
  #if os(Linux) || os(macOS)  
    return TimeTicks() + TimeDelta.from(microseconds: clockNow(CLOCK_MONOTONIC))
  #endif
  }

  public var isNull: Bool {
    return microseconds == 0
  }

  public var isMax: Bool {
    return self == TimeTicks.max
  }
  
  public init() {
    microseconds = 0
  }

  public init(microseconds: Int64) {
    self.microseconds = microseconds
  }

}

extension TimeTicks: Comparable {

  public static func < (lhs: TimeTicks, rhs: TimeTicks) -> Bool {
    return lhs.microseconds < rhs.microseconds
  }

  public static func == (lhs: TimeTicks, rhs: TimeTicks) -> Bool {
    return lhs.microseconds == rhs.microseconds
  }

}

extension TimeTicks {

  public static func + (left: TimeTicks, right: Int64) -> TimeTicks {
    return TimeTicks(microseconds: left.microseconds + right)
  }

  public static func - (left: TimeTicks, right: Int64) -> TimeTicks {
    return TimeTicks(microseconds: left.microseconds - right)
  }

  public static func * (left: TimeTicks, right: Int64) -> TimeTicks {
    return TimeTicks(microseconds: left.microseconds * right)
  }

  public static func / (left: TimeTicks, right: Int64) -> TimeTicks {
    return TimeTicks(microseconds: left.microseconds / right)
  }

  public static func + (left: TimeTicks, right: TimeTicks) -> TimeTicks {
    return TimeTicks(microseconds: left.microseconds + right.microseconds)
  }

  public static func - (left: TimeTicks, right: TimeTicks) -> TimeTicks {
    return TimeTicks(microseconds: left.microseconds - right.microseconds)
  }

  public static func * (left: TimeTicks, right: TimeTicks) -> TimeTicks {
    return TimeTicks(microseconds: left.microseconds * right.microseconds)
  }

  public static func / (left: TimeTicks, right: TimeTicks) -> TimeTicks {
    return TimeTicks(microseconds: left.microseconds / right.microseconds)
  }

  public static func - (left: TimeTicks, right: TimeTicks) -> TimeDelta {
    return TimeDelta(microseconds: left.microseconds - right.microseconds)
  }

  public static func + (left: TimeTicks, right: TimeDelta) -> TimeTicks {
    return TimeTicks(microseconds: left.microseconds + right.microseconds)
  }

  public static func - (left: TimeTicks, right: TimeDelta) -> TimeTicks {
    return TimeTicks(microseconds: left.microseconds - right.microseconds)
  }

}

public struct TimeDelta {

  public static func from(microseconds: Int64) -> TimeDelta {
    return TimeDelta(microseconds: microseconds)
  }

  public static func from(milliseconds: Int64) -> TimeDelta {
    return TimeDelta(milliseconds: milliseconds) 
  }

  public static func from(seconds: Int64) -> TimeDelta {
    return TimeDelta(seconds: seconds) 
  }

  public static func from(nanoseconds: Int64) -> TimeDelta {
    return TimeDelta(nanoseconds: nanoseconds) 
  }

  public static var now: TimeDelta {
#if os(Linux) || os(macOS)
  var tv = timeval()
  var tz = timezone()
  tz.tz_minuteswest = 0
  tz.tz_dsttime = 0
  //struct timezone tz = {0, 0}  // UTC
  let rc = gettimeofday(&tv, &tz)
  assert(rc == 0)
  /// Combine seconds and microseconds in a 64-bit field containing microseconds
  /// since the epoch.  That's enough for nearly 600 centuries.  Adjust from
  /// Unix (1970) to Windows (1601) epoch.
  return TimeDelta.from(
    microseconds: (Int64(tv.tv_sec) * Time.MicrosecondsPerSecond + Int64(tv.tv_usec)) + Time.TimeTToMicrosecondsOffset)
#endif
  }

  public static var max: TimeDelta {
    return TimeDelta(delta: Int64.max)
  }

  public var seconds: Int64 {
    return delta / Time.MicrosecondsPerSecond
  }

  public var milliseconds: Int64 {
    return delta / Time.MicrosecondsPerMillisecond
  }

  public var microseconds: Int64 {
    return delta
  }

  public var nanoseconds: Int64 {
    return delta * Time.NanosecondsPerMicrosecond
  }

  public var isZero: Bool {
    return delta == 0
  }

  public var isMax: Bool {
    return self == TimeDelta.max
  }

  var delta: Int64

  public init(delta: Int64) {
    self.delta = delta
  }

  public init(microseconds: Int64) {
    self.delta = microseconds
  }

  public init(milliseconds: Int64) {
    self.delta = milliseconds * Time.MicrosecondsPerMillisecond
  }

  public init(seconds: Int64) {
    self.delta = seconds * Time.MicrosecondsPerSecond
  }

  public init(ticks: TimeTicks) {
    self.init(microseconds: ticks.microseconds)
  }

  public init(nanoseconds: Int64) {
    self.delta = nanoseconds / Time.NanosecondsPerMicrosecond
  }

  public init() {
    delta = 0
  }

}

extension TimeDelta: Comparable {

  public static func < (lhs: TimeDelta, rhs: TimeDelta) -> Bool {
    return lhs.delta < rhs.delta
  }

  public static func == (lhs: TimeDelta, rhs: TimeDelta) -> Bool {
    return lhs.delta == rhs.delta
  }

}

extension TimeDelta {

  public static func * (left: TimeDelta, right: Int64) -> TimeDelta {
    return TimeDelta(delta: left.delta * right)
  }

  public static func + (left: TimeDelta, right: Int64) -> TimeDelta {
    return TimeDelta(delta: left.delta + right)
  }

  public static func - (left: TimeDelta, right: Int64) -> TimeDelta {
    return TimeDelta(delta: left.delta - right)
  }

  public static func / (left: TimeDelta, right: Int64) -> TimeDelta {
    return TimeDelta(delta: left.delta / right)
  }

  public static func * (left: TimeDelta, right: Int) -> TimeDelta {
    return TimeDelta(delta: left.delta * Int64(right))
  }

  public static func + (left: TimeDelta, right: Int) -> TimeDelta {
    return TimeDelta(delta: left.delta + Int64(right))
  }

  public static func - (left: TimeDelta, right: Int) -> TimeDelta {
    return TimeDelta(delta: left.delta - Int64(right))
  }

  public static func / (left: TimeDelta, right: Int) -> TimeDelta {
    return TimeDelta(delta: left.delta / Int64(right))
  }

  public static func * (left: TimeDelta, right: TimeDelta) -> TimeDelta {
    return TimeDelta(delta: left.delta * right.delta)
  }

  public static func + (left: TimeDelta, right: TimeDelta) -> TimeDelta {
    return TimeDelta(delta: left.delta + right.delta)
  }

  public static func - (left: TimeDelta, right: TimeDelta) -> TimeDelta {
    return TimeDelta(delta: left.delta - right.delta)
  }

  public static func / (left: TimeDelta, right: TimeDelta) -> TimeDelta {
    return TimeDelta(delta: left.delta / right.delta)
  }

}

// TimeTicks and TimeDelta

//public func + (left: TimeTicks, right: TimeDelta) -> TimeTicks {
//  return TimeTicks(microseconds: left.microseconds + right.microseconds)
//}

//public func - (left: TimeTicks, right: TimeDelta) -> TimeTicks {
//  return TimeTicks(microseconds: left.microseconds - right.microseconds)
//}

public class DefaultTickClock : TickClock {
  
  public var nowTicks: TimeTicks { 
    return TimeTicks.now  
  }
  
  public init() {}
  
}

#if os(Linux) || os(macOS)
fileprivate func clockNow(_ clk_id: clockid_t) -> Int64 {
  var ts = timespec()
  assert(clock_gettime(clk_id, &ts) == 0)
  return Int64(convertTimespecToMicros(ts))
}

fileprivate func convertTimespecToMicros(_ ts: timespec) -> Int {
  // On 32-bit systems, the calculation cannot overflow int64_t.
  // 2**32 * 1000000 + 2**64 / 1000 < 2**63
  //if sizeof(ts.tv_sec) <= 4 && sizeof(ts.tv_nsec) <= 8 {
  var result = ts.tv_sec
  result *= __time_t(Time.MicrosecondsPerSecond)
  result += (ts.tv_nsec / __time_t(Time.NanosecondsPerMicrosecond))
  return result
  //} else {
  //  base::CheckedNumeric<int64_t> result(ts.tv_sec)
  //  result *= Time.MicrosecondsPerSecond
  // result += (ts.tv_nsec / Time.NanosecondsPerMicrosecond)
  //  return result.ValueOrDie()
  //}
}

#endif