// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol MessageLoopCurrentDestructionObserver : class {
  func willDestroyCurrentMessageLoop()
}

internal class ScopedNestableTaskAllower {

  var loop: MessageLoop
  var oldState: Bool

  convenience init() {
    self.init(MessageLoopCurrent.instance as! MessageLoop)
  }

  init(_ loop: MessageLoop) {
    self.loop = loop
    self.oldState = self.loop.nestableTasksAllowed
    self.loop.nestableTasksAllowed = true
  }
  
  deinit {
    loop.nestableTasksAllowed = oldState
  }
}

public protocol TaskObserver : class {
  func willProcessTask(pendingTask: PendingTask)
  func didProcessTask(pendingTask: PendingTask)
}

public protocol DestructionObserver : class {
  func willDestroyCurrentMessageLoop()
}

public class MessageLoopCurrent {

  public static var instance: MessageLoopCurrent {
    // TODO: use a guard and throw if theres nothing there
    return MessageLoopCurrent(loop: threadSpecificMessageLoop.currentValue!)
  }

  public static var isSet: Bool {
    return threadSpecificMessageLoop.currentValue != nil
  }
  
  private static let threadSpecificMessageLoop = ThreadSpecificVariable<MessageLoop>()

  // public var taskRunner: SingleThreadTaskRunner? {
  //   get {
  //     return current.taskRunner
  //   }
  //   set {
  //     current.taskRunner = newValue
  //   }
  // }

  var nestableTasksAllowed: Bool {
    get {
      return current!.taskExecutionAllowed
    }
    set {
      if newValue {
        // Kick the native pump just in case we enter a OS-driven nested message
        // loop that does not go through RunLoop::Run().
        current!.pump.scheduleWork()
      }
      current!.taskExecutionAllowed = newValue
    }
  }

  weak var current: MessageLoop?

  init() throws {}

  init(loop: MessageLoop) {
    self.current = loop
  }

  static func bindToCurrentThreadInternal(current: MessageLoop) throws {
    guard threadSpecificMessageLoop.currentValue == nil else {
      throw RuntimeError.MessageLoopAlreadySet(code: 0, message:
        "can't register a second MessageLoop on the same thread")
    }
    threadSpecificMessageLoop.currentValue = current
  }

  // Unbinds |current| from the current thread. Must be invoked on the same
  // thread that invoked |BindToCurrentThreadInternal(current)|. This is only
  // meant to be invoked by the MessageLoop itself.
  static func unbindFromCurrentThreadInternal(current: MessageLoop) {
    threadSpecificMessageLoop.currentValue = nil
  }

  // Returns true if |message_loop| is bound to MessageLoopCurrent on the
  // current thread. This is only meant to be invoked by the MessageLoop itself.
  static func isBoundToCurrentThreadInternal(messageLoop: MessageLoop) -> Bool {
    guard let current = threadSpecificMessageLoop.currentValue else {
      return false
    }
    return current === messageLoop
  }

  public func addDestructionObserver(observer: DestructionObserver) {
    current!.destructionObservers.append(observer)
  }

  public func removeDestructionObserver(observer: DestructionObserver) {
    if let index = current!.destructionObservers.firstIndex(where: { $0 === observer }) {
      current!.destructionObservers.remove(at: index)
    }
  }

  public func watchFileDescriptor(fd: CInt,
                                  persistent: Bool,
                                  mode: Int,
                                  controller: FdWatchController,
                                  delegate: FdWatcher) -> Bool {
    
    #if os(Linux) || os(macOS)
    let libeventPump = current!.pump as! IOMessagePumpLibevent
    return libeventPump.watchFileDescriptor(
      fd: fd,
      persistent: persistent,
      mode: mode,
      controller: controller,
      delegate: delegate)
    #endif
  }

  func addTaskObserver(observer: TaskObserver) {
    current!.taskObservers.append(observer)
  }
  
  func removeTaskObserver(observer: TaskObserver) {
    if let index = current!.taskObservers.firstIndex(where: { $0 === observer }) {
      current!.taskObservers.remove(at: index)
    }
  }
 
}

// public class IOMessageLoopCurrent : MessageLoopCurrent {
//   public init() {}
// }

// public class UIMessageLoopCurrent : MessageLoopCurrent {
//   public init() {}
// }
