// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct TaskSequenceSortKey {
  public var priority: TaskPriority
  public var nextTaskSequencedTime: TimeTicks

  public init(priority: TaskPriority,
              nextTaskSequencedTime: TimeTicks) {
    self.priority = priority
    self.nextTaskSequencedTime = nextTaskSequencedTime
  }
}

extension TaskSequenceSortKey : Comparable {

  public static func == (lhs: TaskSequenceSortKey, rhs: TaskSequenceSortKey) -> Bool {
    return lhs.priority == rhs.priority && lhs.nextTaskSequencedTime == rhs.nextTaskSequencedTime
  }

  public static func < (lhs: TaskSequenceSortKey, rhs: TaskSequenceSortKey) -> Bool {
    let priorityDiff = lhs.priority.rawValue - rhs.priority.rawValue
    if priorityDiff < 0 {
      return true
    }
    if priorityDiff > 0 {
      return false
    }
    return lhs.nextTaskSequencedTime > rhs.nextTaskSequencedTime
  }

}

public class TaskSequence {
  
  public var sortKey: TaskSequenceSortKey {
     let (nextTaskSequencedTime, priority) = lock.withLock { () -> (TimeTicks, TaskPriority) in
      var lastPriority = TaskPriority.lowest
      let highestPriorityIndex = TaskPriority.highest.rawValue
      let lowestPriorityIndex = TaskPriority.lowest.rawValue
      for i in (lowestPriorityIndex..<highestPriorityIndex).reversed() {
        if numTasksPerPriority[i] > 0 {
          lastPriority = TaskPriority(rawValue: i)!
          break
        }
      }
      guard let task = queue.peek() else {
        //print("warning - TaskSequence.sortKey: Queue<Task>.peek() == nil")
        return (TimeTicks(), lastPriority)
      }
      return (task.sequencedTime, lastPriority)
    }
    return TaskSequenceSortKey(priority: priority, nextTaskSequencedTime: nextTaskSequencedTime)
  }

  public let token: TaskSequenceToken
  public let sequenceLocalStorage: SequenceLocalStorageMap = SequenceLocalStorageMap()
  let lock: Lock = Lock()
  var queue: Queue<Task> = Queue<Task>() 
  var numTasksPerPriority: Array<Int>
  
  public init() {
    token = TaskSequenceToken.create()
    numTasksPerPriority = Array<Int>(repeating: 0, count: TaskPriority.highest.rawValue + 1)
  }

  public func pushTask(_ task: Task) -> Bool {
    task.sequencedTime = TimeTicks.now
    return lock.withLock {
      numTasksPerPriority[task.traits.priority.rawValue] += 1
      queue.push(task)
      return queue.count == 1
    }
  }

  public func takeTask() -> Task? {
    return lock.withLock {
      guard let task = queue.peek() else {
        return nil
      }
      let priorityIndex = task.traits.priority.rawValue
      numTasksPerPriority[priorityIndex] -= 1
      return task
    }
  }

  public func peekTaskTraits() -> TaskTraits? {
    return lock.withLock {
      return queue.peek()?.traits
    }
  }

  public func pop() -> Bool {
    return lock.withLock {
      let _ = queue.pop()
      return queue.isEmpty
    }
  }

}

// need to be a class for TLS
public class TaskSequenceToken {
  
  public static func create() -> TaskSequenceToken {
    return TaskSequenceToken(gSequenceTokenGenerator.next)
  }

  public static func getForCurrentThread() -> TaskSequenceToken? {
    return sequenceTokenTLS.currentValue
  }

  public static func setForCurrentThread(_ token: TaskSequenceToken?) {
    sequenceTokenTLS.currentValue = token
  }

  static let Invalid: Int = -1

  public var isValid: Bool {
    return token != TaskSequenceToken.Invalid
  }

  public var toInternalValue: Int {
    return token
  }
 
  var token: Int = TaskSequenceToken.Invalid

  public init(_ token: Int) {
    self.token = token
  }

}

extension TaskSequenceToken : Comparable {
 
  public static func == (lhs: TaskSequenceToken, rhs: TaskSequenceToken) -> Bool {
    return lhs.token == rhs.token && lhs.isValid
  }

  public static func < (lhs: TaskSequenceToken, rhs: TaskSequenceToken) -> Bool {
    return lhs.token < rhs.token
  }

}

fileprivate var gSequenceTokenGenerator: AtomicSequence = AtomicSequence()
fileprivate let sequenceTokenTLS: ThreadSpecificVariable<TaskSequenceToken> = ThreadSpecificVariable<TaskSequenceToken>()