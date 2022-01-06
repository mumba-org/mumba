// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol TaskRunner {

  var runTasksInCurrentSequence: Bool { get }

  @discardableResult
  func postTask(_ task: @escaping () -> Void) -> Bool
  @discardableResult
  func postDelayedTask(_ task: @escaping () -> Void, delay: TimeDelta) -> Bool
  @discardableResult
  func postTaskAndReply(_ task: @escaping () -> Void, _ reply: @escaping () -> Void) -> Bool
}

extension TaskRunner {

  public func postTask(_ task: @escaping () -> Void)  -> Bool {
    return postDelayedTask(task, delay: TimeDelta())
  }

  public func postTaskAndReply(
    _ task: @escaping () -> Void,
    _ reply: @escaping () -> Void)  -> Bool {
    PostTaskAndReplyTaskRunner(destination: self).postTaskAndReply(task, reply)
    return true
  }

}

public protocol SequencedTaskRunner : TaskRunner {
  @discardableResult
  func postNonNestableTask(_ task: @escaping () -> Void) -> Bool
  @discardableResult
  func postNonNestableDelayedTask(_ task: @escaping () -> Void,
                                         delay: TimeDelta) -> Bool
}

extension SequencedTaskRunner {
  public func postNonNestableTask(_ task: @escaping () -> Void) -> Bool {
    return postNonNestableDelayedTask(task, delay: TimeDelta())
  }
}

public enum SingleThreadTaskRunnerThreadMode {
  case shared
  case dedicated
}

public protocol SingleThreadTaskRunner : SequencedTaskRunner {
  var belongsToCurrentThread: Bool { get }
}

extension SingleThreadTaskRunner {
  
  public var belongsToCurrentThread: Bool {
    return runTasksInCurrentSequence
  }

}

public class ThreadTaskRunnerHandle {

  public static func get() -> SingleThreadTaskRunner? {
    guard let current = ThreadTaskRunnerHandle.instance.currentValue else {
      print("Error: This caller requires a single-threaded context "
            + "(i.e. the current task needs to run from a "
            + "SingleThreadTaskRunner).")
      return nil
    }
    return current.taskRunner
  }

  public static var isSet: Bool {
    return ThreadTaskRunnerHandle.instance.currentValue != nil
  }

  private static let instance: ThreadSpecificVariable<ThreadTaskRunnerHandle> = ThreadSpecificVariable<ThreadTaskRunnerHandle>()

  var taskRunner: SingleThreadTaskRunner?

  public init(taskRunner: SingleThreadTaskRunner?) {
    self.taskRunner = taskRunner
    ThreadTaskRunnerHandle.instance.currentValue = self
  }

  deinit {
    // TODO: if the TLS retain a ref-count on this object
    // this will never be called.. so see if this really works
    // as intended
    ThreadTaskRunnerHandle.instance.currentValue = nil
  }

}


public class SequencedTaskRunnerHandle {
  
  public static func get() -> SequencedTaskRunner? {

    if let handle = SequencedTaskRunnerHandle.instance.currentValue {
      return handle.taskRunner
    }

    // Note if you hit this: the problem is the lack of a sequenced context. The
    // ThreadTaskRunnerHandle is just the last attempt at finding such a context.
    precondition(ThreadTaskRunnerHandle.isSet,  
        "Error: This caller requires a sequenced context (i.e. the current task needs to run from a SequencedTaskRunner).")
    
    return ThreadTaskRunnerHandle.get()
  }

  public static var isSet: Bool {
    return SequencedTaskRunnerHandle.instance.currentValue != nil || ThreadTaskRunnerHandle.isSet
  }

  private static let instance: ThreadSpecificVariable<SequencedTaskRunnerHandle> = ThreadSpecificVariable<SequencedTaskRunnerHandle>()

  var taskRunner: SequencedTaskRunner?
  
  public init(taskRunner: SequencedTaskRunner) {
    self.taskRunner = taskRunner
    SequencedTaskRunnerHandle.instance.currentValue = self
  }
  
  deinit {
    SequencedTaskRunnerHandle.instance.currentValue = nil
  }

  /// deallocate a RawPointer previously allocated manually by allocate
  /// so it will not leak
  public func deleteSoon(_ object: UnsafeMutableRawPointer) -> Bool {
    return taskRunner!.postNonNestableTask {
      object.deallocate()
    }
  }

}
