
public final class SequenceLocalStorageMap {

  public typealias ValueDestructorPair = (UnsafeMutableRawPointer, (_: UnsafeMutableRawPointer) -> Void)

  // public static var onCurrentThread: SequenceLocalStorageMap? {
  //   return current.currentValue
  // }

  public static func getForCurrentThread() -> SequenceLocalStorageMap? {
    return SequenceLocalStorageMap.current.currentValue
  }

  public static func setForCurrentThread(_ map: SequenceLocalStorageMap?) {
    SequenceLocalStorageMap.current.currentValue = map
  }

  static let current: ThreadSpecificVariable<SequenceLocalStorageMap> = ThreadSpecificVariable<SequenceLocalStorageMap>()

  var map: [Int : ValueDestructorPair] = [:]

  public init () {}

  public func get(id: Int) -> UnsafeMutableRawPointer? {
    if let item = map[id] {
      return item.0
    }
    return nil
  }

  public func set(id: Int, pair valueDestructorPair: ValueDestructorPair) {
    map[id] = valueDestructorPair
  }
}

public final class ScopedSetSequenceLocalStorageMapForCurrentThread {

  public init(_ sequenceLocalStorage: SequenceLocalStorageMap) {
    SequenceLocalStorageMap.current.currentValue = sequenceLocalStorage
  }

  deinit {
    SequenceLocalStorageMap.current.currentValue = nil
  }

}