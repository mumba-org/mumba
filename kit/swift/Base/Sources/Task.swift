// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class Callback1R<R> {
  public typealias Signature = () throws -> R

  public var isCancelled: Bool = false
  public var function: Signature

  public init(_ fn: @escaping Signature) {
    self.function = fn
  }

  public func call() throws -> R {
    return try function()
  }
}

public class Callback1R1P<R, P0> {
  public typealias Signature = (_: P0) throws -> R

  public var isCancelled: Bool = false
  public var function: Signature

  public init(_ fn: @escaping Signature) {
    self.function = fn
  }

  public func call(_ p0: P0) throws -> R {
    return try function(p0)
  }
}

extension Callback1R : Equatable {
  
  public static func == (lhs: Callback1R<R>, rhs: Callback1R<R>) -> Bool {
    print("warning: using a comparison that doesnt really work")
    return true//lhs.isCancelled == rhs.isCancelled
  }

}

extension Callback1R1P : Equatable {
  public static func == (lhs: Callback1R1P<R, P0>, rhs: Callback1R1P<R, P0>) -> Bool {
    print("warning: using a comparison that doesnt really work")
    return true
    //return lhs.isCancelled == rhs.isCancelled
  }
}

public typealias Closure = Callback1R<Void>

public protocol TaskTrait {}

public enum TaskPriority : Int, TaskTrait {
  case background = 0
  case userVisible = 1
  case userBlocking = 2
  
  public static let lowest: TaskPriority = TaskPriority.background
  public static let highest: TaskPriority = TaskPriority.userBlocking
  
  public static var count: Int {
    return TaskPriority.userBlocking.rawValue + 1
  }

  public static func getForCurrentThread() -> TaskPriority? {
    return taskPriorityTLS.currentValue?.priority
  }

  public static func setForCurrentThread(_ priority: TaskPriority?) {
    taskPriorityTLS.currentValue = priority == nil ? nil : TaskPriorityState(priority!)
  }

}

internal class TaskPriorityState {
  internal let priority: TaskPriority
  internal init(_ priority: TaskPriority) {
    self.priority = priority
  }
}

internal let taskPriorityTLS: ThreadSpecificVariable<TaskPriorityState> = ThreadSpecificVariable<TaskPriorityState>()

public enum TaskShutdownBehavior : TaskTrait {
  case continueOnShutdown
  case skipOnShutdown
  case blockShutdown
}

public struct MayBlock : TaskTrait {
  public init() {}
}

public struct WithSyncPrimitives : TaskTrait {}

public class TaskTraits {
  //case none
  //case mayBlock
  public private(set) var priority: TaskPriority
  public private(set) var shutdownBehavior: TaskShutdownBehavior
  public private(set) var mayBlock: Bool
  public private(set) var withSyncPrimitives: Bool
  public private(set) var prioritySetExplicitly: Bool
  public private(set) var shutdownBehaviorSetExplicitly: Bool

  public init() {
    priority = TaskPriority.userVisible
    shutdownBehavior = TaskShutdownBehavior.skipOnShutdown
    mayBlock = false
    withSyncPrimitives = false
    prioritySetExplicitly = false
    shutdownBehaviorSetExplicitly = false
  }

  public init(_ shutdownBehavior: TaskShutdownBehavior) {
    priority = TaskPriority.userVisible
    self.shutdownBehavior = shutdownBehavior
    mayBlock = false
    withSyncPrimitives = false
    prioritySetExplicitly = false
    shutdownBehaviorSetExplicitly = false
  }

  public static func `override`(left: TaskTraits, right: TaskTraits) -> TaskTraits {
    return TaskTraits(left: left, right: right)
  }

  private init(left: TaskTraits, right: TaskTraits) {
    prioritySetExplicitly = left.prioritySetExplicitly || right.prioritySetExplicitly
    priority = right.prioritySetExplicitly ? right.priority : left.priority
    shutdownBehaviorSetExplicitly = 
          left.shutdownBehaviorSetExplicitly || right.shutdownBehaviorSetExplicitly
    shutdownBehavior = right.shutdownBehaviorSetExplicitly
                         ? right.shutdownBehavior
                         : left.shutdownBehavior
    mayBlock = left.mayBlock || right.mayBlock
    withSyncPrimitives = left.withSyncPrimitives || right.withSyncPrimitives
  }

}

public enum Nestable {
  case nonNestable
  case nestable
}

public class PendingTask {
  // The task to run.
  public var task: Closure?

  // The time when the task should be run.
  public var delayedRunTime: TimeTicks

  // Task backtrace. mutable so it can be set while annotating const PendingTask
  // objects from TaskAnnotator.didQueueTask().
  //public var taskBacktrace: Array<UnsafeRawPointer> = Array<UnsafeRawPointer>(repeating: nil, count: 4)

  // Secondary sort key for run time.
  public var sequenceNum: Int = 0

  // OK to dispatch from a nested loop.
  public var nestable: Nestable

  // Needs high resolution timers.
  public var isHighRes: Bool = false

  public init(task: Closure,
              delayedRunTime: TimeTicks,
              nestable: Nestable) {
    self.task = task
    self.delayedRunTime = delayedRunTime
    self.nestable = nestable
  }
}

// PendingTasks are sorted by their |delayedRunTime| property.
extension PendingTask : Comparable {
  
  public static func == (lhs: PendingTask, rhs: PendingTask) -> Bool {
    if lhs === rhs {
      return true
    }

    return lhs.task == rhs.task && 
      lhs.delayedRunTime == rhs.delayedRunTime &&
      lhs.sequenceNum == rhs.sequenceNum &&
      lhs.nestable == rhs.nestable &&
      lhs.isHighRes == rhs.isHighRes
  }

  public static func < (lhs: PendingTask, rhs: PendingTask) -> Bool {
    // the order is inverted here on purpose
    // the top of a priority queue being defined as the 'greatest' element
    // the smaller time should be at the top of the heap.

    // TODO: check how PriorityQueue handle this
    if lhs.delayedRunTime < rhs.delayedRunTime {
     return false
    }

    if lhs.delayedRunTime > rhs.delayedRunTime {
      return true
    }

    return (lhs.sequenceNum - rhs.sequenceNum) > 0
  }

}

fileprivate var gSequenceNumsForTracing: AtomicSequence = AtomicSequence()

public class Task : PendingTask {

  public var traits: TaskTraits = TaskTraits()

  public var delay: TimeDelta = TimeDelta()

  public var sequencedTime: TimeTicks = TimeTicks()

  public var sequencedTaskRunner: SequencedTaskRunner?
  
  public var singleThreadTaskRunner: SingleThreadTaskRunner?
  
  public init(task: Closure,
              traits: TaskTraits,
              delay: TimeDelta) {
       
       super.init(
         task: task,
          delayedRunTime: (delay.isZero ? TimeTicks() : TimeTicks.now + delay),
          nestable: Nestable.nonNestable)
      // Prevent a delayed blockShutdown task from blocking shutdown before it
      // starts running by changing its shutdown behavior to skipOnShutdown.
      self.traits = 
          (!delay.isZero &&
           traits.shutdownBehavior == .blockShutdown)
              ? TaskTraits.override(left: traits,  right: TaskTraits(TaskShutdownBehavior.skipOnShutdown))
              : traits

      self.delay = delay
      self.sequenceNum = gSequenceNumsForTracing.next
  }

}

public typealias TaskQueue = Queue<PendingTask>

public typealias DelayedTaskQueue = Queue<PendingTask>//PriorityQueue<PendingTask>
