// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol RunLoopNestingObserver : class {
  func onBeginNestedRunLoop()
  func onExitNestedRunLoop()
}

public protocol RunLoopDelegate : class {

  var activeRunLoops: Queue<RunLoop> { get set }
  var nestingObservers: [RunLoopNestingObserver] { get set }
  var shouldQuitWhenIdle: Bool { get }
  var bound: Bool { get set }

  func run(applicationTasksAllowed: Bool) throws
  func quit()
  func ensureWorkScheduled()
}

// a class to hold a instance of a RunLoopDelegate impl
// so we can keep the RunLoopDelegate on a TLS without
// needing it  to be a class => AnyObject
internal class RunLoopDelegateTLSState {
  fileprivate let delegate: RunLoopDelegate
  fileprivate init(_ delegate: RunLoopDelegate) {
    self.delegate = delegate
  }
}

public enum RunLoopType {
  case normal
  case nestableTasksAllowed
}

public typealias RunLoopQuit = () -> ()

public class RunLoop {

  public static var isRunningOnCurrentThread: Bool {
    guard let delegate = threadSpecificDelegate.currentValue?.delegate else {
      return false
    }
    return !delegate.activeRunLoops.isEmpty
  }

  public static var isNestedOnCurrentThread: Bool {
    guard let delegate = threadSpecificDelegate.currentValue?.delegate else {
      return false
    }
    return delegate.activeRunLoops.count > 1
  }

  internal static let threadSpecificDelegate = ThreadSpecificVariable<RunLoopDelegateTLSState>()

  public var exitClosure: RunLoopQuit {
    return self.quit
  }

  public private(set) var isRunning: Bool = false
  public private(set) var delegate: RunLoopDelegate?
  var quitCalled: Bool = false
  var quitWhenIdleReceived: Bool = false
  var originTaskRunner: SingleThreadTaskRunner?
  var type: RunLoopType

  public init(_ type: RunLoopType = RunLoopType.normal) {
    delegate = RunLoop.threadSpecificDelegate.currentValue?.delegate
    originTaskRunner = ThreadTaskRunnerHandle.get()
    self.type = type
  }

  public func run() throws {
    if !beforeRun() {
      return
    }

    let applicationTasksAllowed =
      delegate!.activeRunLoops.count == 1 || type == RunLoopType.nestableTasksAllowed
  
    try delegate!.run(applicationTasksAllowed: applicationTasksAllowed)

    afterRun()
  }

  public func runUntilIdle() throws {
    quitWhenIdleReceived = true
    try run()
  }

  public func quit() {
    if !originTaskRunner!.runTasksInCurrentSequence {
      originTaskRunner!.postTask{ self.quit() }
      return
    }

    quitCalled = true
    if isRunning && delegate!.activeRunLoops.peek() === self {
      delegate!.quit()
    }
  }

  public func quitWhenIdle() {
    if !originTaskRunner!.runTasksInCurrentSequence {
      originTaskRunner!.postTask{self.quitWhenIdle()}
      return
    }

    quitWhenIdleReceived = true
  }

  public static func registerDelegateForCurrentThread(delegate: RunLoopDelegate) {
     RunLoop.threadSpecificDelegate.currentValue = RunLoopDelegateTLSState(delegate)
     delegate.bound = true
  }

  public func addNestingObserverOnCurrentThread(observer: RunLoopNestingObserver) {
    guard let delegate = RunLoop.threadSpecificDelegate.currentValue?.delegate else {
      return
    }
    delegate.nestingObservers.append(observer)
  }

  // static
  public func removeNestingObserverOnCurrentThread(observer: RunLoopNestingObserver) {
    guard let delegate = RunLoop.threadSpecificDelegate.currentValue?.delegate else {
      return
    }
    if let index = delegate.nestingObservers.firstIndex(where: { $0 === observer }) {
      delegate.nestingObservers.remove(at: index)
    }
  }

  func beforeRun() -> Bool {
    if quitCalled {
      return false
    }

    delegate!.activeRunLoops.push(self)

    isRunning = true

    return true
  }

  func afterRun() {
    isRunning = false

    guard var activeRunLoops = delegate?.activeRunLoops else {
      return
    }

    //guard activeRunLoops.top === self else {
    guard activeRunLoops.peek() === self else {
      return
    }
   
    let _ = activeRunLoops.pop()

    let previousRunLoop: RunLoop? = activeRunLoops.isEmpty ? nil : activeRunLoops.peek()
    
    if let d = delegate {
      for observer in d.nestingObservers {
        observer.onExitNestedRunLoop()
      }
    }

    if previousRunLoop != nil && previousRunLoop!.quitCalled {
      if let d = delegate {
        d.quit()
      }
    }

  }

}

extension RunLoop: Equatable {
  public static func == (lhs: RunLoop, rhs: RunLoop) -> Bool {
    return lhs === rhs
  }
}