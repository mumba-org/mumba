//===----------------------------------------------------------------------===//
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux) || os(macOS)
import PosixShim
#endif

#if os(Linux) || os(FreeBSD) || os(Android)
@_exported import Glibc
#endif
/// Allows to "box" another value.
final class Box<T> {
    let value: T
    init(_ value: T) { self.value = value }
}

private typealias ThreadBoxValue = (body: (PlatformThread) -> Void, name: String?)
private typealias ThreadBox = Box<ThreadBoxValue>


#if os(Linux)
private let sys_pthread_getname_np = CNIOLinux_pthread_getname_np
private let sys_pthread_setname_np = CNIOLinux_pthread_setname_np
#else
private let sys_pthread_getname_np = pthread_getname_np
// Emulate the same method signature as pthread_setname_np on Linux.
private func sys_pthread_setname_np(_ p: pthread_t, _ pointer: UnsafePointer<Int8>) -> Int32 {
    assert(pthread_equal(pthread_self(), p) != 0)
    pthread_setname_np(pointer)
    // Will never fail on macOS so just return 0 which will be used on linux to signal it not failed.
    return 0
}
#endif

#if os(Linux) || os(macOS)
public typealias PlatformThreadId = pid_t
#endif

public enum ThreadPriority : Int {
  case background = 0
  case normal = 1
  case display = 2
  case realtimeAudio = 3
}

extension ThreadPriority : Comparable {

  public static func == (lhs: ThreadPriority, rhs: ThreadPriority) -> Bool {
    return lhs.rawValue == rhs.rawValue
  }

  public static func < (lhs: ThreadPriority, rhs: ThreadPriority)  -> Bool {
    return lhs.rawValue < rhs.rawValue
  }

}

/// A `ThreadSpecificVariable` is a variable that can be read and set like a normal variable except that it holds
/// different variables per thread.
///
/// `ThreadSpecificVariable` is thread-safe so it can be used with multiple threads at the same time but the value
/// returned by `currentValue` is defined per thread.
///
/// - note: `ThreadSpecificVariable` has reference semantics.
public struct ThreadSpecificVariable<T: AnyObject> {
    private let key: pthread_key_t

    /// Initialize a new `ThreadSpecificVariable` without a current value (`currentValue == nil`).
    public init() {
        var key = pthread_key_t()
        let pthreadErr = pthread_key_create(&key) { ptr in
            Unmanaged<AnyObject>.fromOpaque((ptr as UnsafeMutableRawPointer?)!).release()
        }
        precondition(pthreadErr == 0, "pthread_key_create failed, error \(pthreadErr)")
        self.key = key
    }

    /// Initialize a new `ThreadSpecificVariable` with `value` for the calling thread. After calling this, the calling
    /// thread will see `currentValue == value` but on all other threads `currentValue` will be `nil` until changed.
    ///
    /// - parameters:
    ///   - value: The value to set for the calling thread.
    public init(value: T) {
        self.init()
        self.currentValue = value
    }

    /// The value for the current thread.
    public var currentValue: T? {
        /// Get the current value for the calling thread.
        get {
            guard let raw = pthread_getspecific(self.key) else {
                return nil
            }
            return Unmanaged<T>.fromOpaque(raw).takeUnretainedValue()
        }

        /// Set the current value for the calling threads. The `currentValue` for all other threads remains unchanged.
        nonmutating set {
            if let raw = pthread_getspecific(self.key) {
                Unmanaged<T>.fromOpaque(raw).release()
            }
            let pthreadErr = pthread_setspecific(self.key, newValue.map { v -> UnsafeMutableRawPointer in
                Unmanaged.passRetained(v).toOpaque()
            })
            precondition(pthreadErr == 0, "pthread_setspecific failed, error \(pthreadErr)")
        }
    }
}

public protocol PlatformThreadDelegate {
  func threadMain()
}

#if os(Linux) || os(macOS)
public typealias PlatformThreadHandle = pthread_t
#endif

extension PlatformThreadHandle {
  
  public var isNull: Bool {
    return self == PlatformThreadHandle()
  }

}

/// A Thread that executes some runnable block.
///
/// All methods exposed are thread-safe.
final class PlatformThread {

    public static var currentId: PlatformThreadId {
      #if os(macOS)
        return pthread_mach_thread_np(pthread_self())
      #elseif os(Linux)
        return posix_get_thread_id()
      #elseif os(Android)
        return gettid()
      #elseif os(Windows)
        return GetCurrentThreadId()
      #else // posix
        return pthread_self()
      #endif
    }

    public static let invalidThreadId: PlatformThreadId = PlatformThreadId(0)

    public static var currentHandle: PlatformThreadHandle {
      #if os(Linux) || os(macOS)
        return pthread_self()
      #endif
    }

    public static var current: PlatformThread {
        return PlatformThread(handle: pthread_self())
    }

    public static var currentName: String {
      get {
        return ThreadIdNameManager.instance.getName(id: currentId)
      }
      set {
        ThreadIdNameManager.instance.setName(newValue)

        if PlatformThread.currentId == getpid() {
          return
        }

        newValue.withCString {
          do {
            let err = try Posix.prctl(flag: PrctlFlag.PR_SET_NAME, buf: $0)
            // We expect EPERM failures in sandboxed processes, just ignore those.
            if err < 0 && errno != EPERM {
              print("prctl(PR_SET_NAME)")
            }
          } catch SystemError.OSError(let err) {
            print(err.function)
          } catch  {
            print("unknown error")
          }
        }
      }
    }

    public static var canIncreaseCurrentThreadPriority: Bool {
    #if os(Linux)  
      return geteuid() == 0
    #endif  
    }

    public static func sleep(duration: TimeDelta) {
      #if os(Linux) || os(macOS)
        var dur = duration
        var sleepTime = timespec()
        var remaining = timespec()
        sleepTime.tv_sec = Int(dur.seconds)
        dur = dur - TimeDelta.from(seconds: Int64(sleepTime.tv_sec))
        // nanoseconds
        sleepTime.tv_nsec = Int(dur.microseconds * 1000)

        while nanosleep(&sleepTime, &remaining) == -1 && errno == EINTR {
          sleepTime = remaining
        }
      #endif
    }

    public static func create(stackSize: Int,
                              delegate: PlatformThreadDelegate) -> PlatformThreadHandle? {
      return createWithPriority(stackSize: stackSize, 
                                delegate: delegate,
                                priority: ThreadPriority.normal)
    }

    public static func createWithPriority(stackSize: Int,
                                          delegate: PlatformThreadDelegate,
                                          priority: ThreadPriority) -> PlatformThreadHandle? {
      return createThread(stackSize: stackSize, 
                          joinable: true,
                          delegate: delegate,
                          priority: priority)
    }

    public static func createNonJoinable(stackSize: Int,
                                         delegate: PlatformThreadDelegate) -> PlatformThreadHandle? {
      return createNonJoinableWithPriority(
          stackSize: stackSize, 
          delegate: delegate,
          priority: ThreadPriority.normal)
    }

    public static func createNonJoinableWithPriority(stackSize: Int,
                                                     delegate: PlatformThreadDelegate,
                                                     priority: ThreadPriority) -> PlatformThreadHandle? {
      return createThread(
              stackSize: stackSize, 
              joinable: false,
              delegate: delegate, 
              priority: priority)
    }

    public static func join(handle: PlatformThreadHandle) {
      #if os(Linux) || os(macOS)
      let pthreadErr = pthread_join(handle, nil)
      precondition(pthreadErr == 0, "pthread_join failed, error \(pthreadErr)")
      #endif
    }

    public static func detach(handle: PlatformThreadHandle) {
      #if os(Linux) || os(macOS)
      let pthreadErr = pthread_detach(handle)
      precondition(pthreadErr == 0, "pthread_detach failed, error \(pthreadErr)")
      #endif
    }

    public static var currentThreadPriority: ThreadPriority {
      get {
        #if os(Linux)
        
        // looks like a specialization for when the priority is for realtime
        // enable when we are dealing with audio

        //if let platformSpecificPriority = getCurrentThreadPriorityForPlatform() {
        //  return platformSpecificPriority
        //}

        // Need to clear errno before calling getpriority():
        // http://man7.org/linux/man-pages/man2/getpriority.2.html
        let niceValue = getpriority(__priority_which_t(PRIO_PROCESS.rawValue), 0)

        let err = errno
        if err != 0 {
          print("failed to get nice value of thread \(PlatformThread.currentId)")
          return ThreadPriority.normal
        }

        return niceValueToThreadPriority(niceValue: Int(niceValue))
        #endif
      }
      set {
        #if os(Linux)  
          //if setCurrentThreadPriorityForPlatform(newValue) {
          //  return
          //}

          let niceSetting = threadPriorityToNiceValue(priority: newValue)
          let priorityErr = setpriority(__priority_which_t(PRIO_PROCESS.rawValue), 0, CInt(niceSetting))
          //precondition(priorityErr == 0, "Failed to set nice value of thread \(PlatformThread.currentId) to \(niceSetting). errno = \(errno)")
          if priorityErr != 0 {
            print("Thread.currentThreadPriority: Failed to set nice value of thread \(PlatformThread.currentId) to \(niceSetting). errno = \(errno)")
          }
       #endif   
      }
    }

    #if os(Linux)
    public static func setThreadPriority(threadId: PlatformThreadId,
                                         priority: ThreadPriority) {
     // cannot set the main thread priority
     assert(threadId != getpid())

     setThreadCgroupsForThreadPriority(threadId: threadId, priority: priority)

     let niceSetting = threadPriorityToNiceValue(priority: priority)
     let priorityErr = setpriority(__priority_which_t(PRIO_PROCESS.rawValue), id_t(threadId), CInt(niceSetting))
     
     //precondition(priorityErr == 0, "Failed to set nice value of thread \(PlatformThread.currentId) to \(niceSetting)")
     if priorityErr != 0 {
       print("Thread.setThreadPriority: Failed to set nice value of thread \(PlatformThread.currentId) to \(niceSetting)")
     }
    }
    #endif

    public var isNull: Bool {
      // does it work?
      return self.handle == 0
    }

    var isCurrent: Bool {
      #if os(Linux) || os(macOS)
      return pthread_equal(handle, pthread_self()) != 0
      #endif
    }
    
    private let handle: PlatformThreadHandle

    private init(handle: PlatformThreadHandle) {
      self.handle = handle
    }

    /// Execute the given body with the `pthread_t` that is used by this `Thread` as argument.
    ///
    /// - warning: Do not escape `pthread_t` from the closure for later use.
    ///
    /// - parameters:
    ///     - body: The closure that will accept the `pthread_t`.
    /// - returns: The value returned by `fn`.
    func withUnsafeHandle<T>(_ body: (PlatformThreadHandle) throws -> T) rethrows -> T {
        return try body(self.handle)
    }

    /// Get current name of the `Thread` or `nil` if not set.
    var name: String? {
        get {
            // 64 bytes should be good enough as on Linux the limit is usually 16 and it's very unlikely a user will ever set something longer anyway.
            var chars: [CChar] = Array(repeating: 0, count: 64)
            guard sys_pthread_getname_np(handle, &chars, chars.count) == 0 else {
                return nil
            }
            return String(cString: chars)
        }
    }

    /// Spawns and runs some task in a `Thread`.
    ///
    /// - arguments:
    ///     - name: The name of the `Thread` or `nil` if no specific name should be set.
    ///     - body: The function to execute within the spawned `Thread`.
    static func spawnAndRun(name: String? = nil, body: @escaping (PlatformThread) -> Void) {
        // Unfortunately the pthread_create method take a different first argument depending on if it's on Linux or macOS, so ensure we use the correct one.
        #if os(Linux)
            var pt: pthread_t = pthread_t()
        #else
            var pt: pthread_t? = nil
        #endif

        // Store everything we want to pass into the c function in a Box so we can hand-over the reference.
        let tuple: ThreadBoxValue = (body: body, name: name)
        let box = ThreadBox(tuple)
        let res = pthread_create(&pt, nil, { p in
            // Cast to UnsafeMutableRawPointer? and force unwrap to make the same code work on macOS and Linux.
            let b = Unmanaged<ThreadBox>.fromOpaque((p as UnsafeMutableRawPointer?)!).takeRetainedValue()

            let body = b.value.body
            let name = b.value.name

            let pt = pthread_self()

            if let threadName = name {
                _ = sys_pthread_setname_np(pt, threadName)
                // this is non-critical so we ignore the result here, we've seen EPERM in containers.
            }

            body(PlatformThread(handle: pt))
            return nil
        }, Unmanaged.passRetained(box).toOpaque())

        precondition(res == 0, "Unable to create thread: \(res)")

        let detachError = pthread_detach((pt as pthread_t?)!)
        precondition(detachError == 0, "pthread_detach failed with error \(detachError)")
    }
}

extension PlatformThread: Equatable {

    public static func == (lhs: PlatformThread, rhs: PlatformThread) -> Bool {
        return pthread_equal(lhs.handle, rhs.handle) != 0
    }

}


public struct ThreadOptions {

    //public var messageLoopType: MessageLoopType = MessageLoopType.default
    public var messageLoopType: MessageLoopType = MessageLoopType.IO
    //public var timerSlack: TimerSlack = TimerSlack.none

    public var stackSize: Int = 0

    public var priority: ThreadPriority = ThreadPriority.normal

    public var joinable: Bool = true

}

// A more higher-level impl over PlatformThread
public class Thread : PlatformThreadDelegate {

  public var taskRunner: SingleThreadTaskRunner? {
    if let loop = _messageLoop {
      return loop.taskRunner
    }
    return nil
  }

  public var threadId: PlatformThreadId {
    //let allowWait = ThreadRestrictionsScopedAllowWait()
    idEvent.wait()
    return id
  }

  // TODO: make this withUnsafeThreadHandle {}
  public var threadHandle: PlatformThreadHandle {
    return threadLock.withLock {
      return thread
    }
  }

  public var isRunning: Bool {

    if _messageLoop != nil && !stopping {
      return true
    }
    
    return runningLock.withLock {
      return running
    }

  }

  public private(set) var running: Bool = false

  public static var threadWasQuitProperly: Bool {
    get {
      return threadWasQuitProperlyTLS.currentValue != nil
    }
    set {
      if newValue {
        threadWasQuitProperlyTLS.currentValue = NotNullGuard()
      } else {
        threadWasQuitProperlyTLS.currentValue = nil
      }
    }
  }

  public var messageLoop: MessageLoop? {
    get {
      return _messageLoop
    }
    set {
      if newValue != nil {
        usingExternalMessageLoop = true
      }
      _messageLoop = newValue
    }
  }

  private static let threadWasQuitProperlyTLS: ThreadSpecificVariable<NotNullGuard> = ThreadSpecificVariable<NotNullGuard>()

  public private(set) var name: String

  private var joinable: Bool = true

  private var stopping: Bool = false

  private let runningLock: Lock = Lock()

  private var thread: PlatformThreadHandle = PlatformThreadHandle()

  private let threadLock: Lock = Lock()

  private var id: PlatformThreadId = PlatformThread.invalidThreadId
 
  private var idEvent: WaitableEvent

  private var runloop: RunLoop?

  private var usingExternalMessageLoop: Bool = false

  private var messageLoopTimerSlack: TimerSlack = TimerSlack.none

  private var _messageLoop: MessageLoop?

  let startEvent: WaitableEvent

  public init(name: String) {
    startEvent = WaitableEvent(resetPolicy: .automatic, initialState: .notSignaled)
    idEvent = WaitableEvent(resetPolicy: .automatic, initialState: .notSignaled)
    self.name = name
  }

  deinit {
    stop()
  }

  public func start() -> Bool {
    var options = ThreadOptions()
    #if os(Windows)
    if comStatus == .STA {
      options.messageLoopType = MessageLoopType.UI
    }
    #endif
    return start(options: options)
  }

  public func start(options: ThreadOptions) -> Bool {
    idEvent.reset()
    id = PlatformThread.invalidThreadId

    Thread.threadWasQuitProperly = false

    let type = options.messageLoopType
    
    //messageLoopTimerSlack = options.timerSlack
    _messageLoop = try! MessageLoop(type: type, unbound: true)
    startEvent.reset()

    // Hold |thread_lock_| while starting the new thread to synchronize with
    // Stop() while it's not guaranteed to be sequenced (until crbug/629139 is
    // fixed).
    let threadHandle = threadLock.withLock { () -> PlatformThreadHandle? in
      let handle =
          options.joinable
              ? PlatformThread.createWithPriority(stackSize: options.stackSize, delegate: self, priority: options.priority)
              : PlatformThread.createNonJoinableWithPriority(stackSize: options.stackSize, delegate: self, priority: options.priority)
      if handle == nil {
        print("failed to create thread")
        _messageLoop = nil
        return nil
      }
      return handle
    }

    if threadHandle == nil {
      print("failed to create thread: threadHandle = nil")
      return false
    }

    thread = threadHandle!

    joinable = options.joinable

    return true
  }

  public func stop() {
    threadLock.withLockVoid {
      stopSoon()

      guard !thread.isNull else {
        return
      }

      PlatformThread.join(handle: thread)
      thread = PlatformThreadHandle()

      stopping = false
    }
  }

  public func stopSoon() {
    guard !stopping && _messageLoop != nil else {
      return
    }

    stopping = true

    if usingExternalMessageLoop {
      assert(!isRunning)
      _messageLoop = nil
      return
    }

    taskRunner!.postTask {
      self.threadQuitHelper()
    }
  }

  public func detachFromSequence() {
    print("detachFromSequence: not implemented")
  }

  internal func initialize() {}

  // Called to start the run loop
  internal func run(runloop: RunLoop) throws {
    try runloop.run()
  }

  internal func cleanUp() {}

  func threadQuitHelper() {
    runloop!.quitWhenIdle()
    Thread.threadWasQuitProperly = true
  }

  public func threadMain() {
    do {
      id = PlatformThread.currentId
      idEvent.signal()

      PlatformThread.currentName = name
    
      // TODO: check if throwing exception HERE wont get things nasty
      // this is the threadMain after all
      try! _messageLoop!.bindToCurrentThread()
      //_messageLoop!.timerSlack = messageLoopTimerSlack

    #if os(Linux) || os(macOS)
      // Allow threads running a MessageLoopForIO to use FileDescriptorWatcher API.
      var fileDescriptorWatcher: FileDescriptorWatcher?
      if MessageLoop.isCurrent {
        fileDescriptorWatcher = FileDescriptorWatcher(messageLoop: _messageLoop!)
      }
    #endif

    #if os(Windows)
      var comInitializer: ScopedCOMInitializer?
      if comStatus != .none {
        com_initializer = comStatus == .STA ?
            ScopedCOMInitializer() :
            ScopedCOMInitializer(ScopedCOMInitializer.MTA)
      }
    #endif

      // Let the thread do extra initialization.
      initialize()

      runningLock.withLockVoid {
        running = true
      }

      startEvent.signal()

      let runloop = RunLoop()
      self.runloop = runloop
      try run(runloop: runloop)

      runningLock.withLockVoid {
        running = false
      }

      cleanUp()

    #if os(Windows)
      comInitializer = nil
    #endif

      if _messageLoop!.type != MessageLoopType.custom {
        assert(Thread.threadWasQuitProperly)
      }

      _messageLoop = nil
      self.runloop = nil
    } catch {
      print("generic exception on runloop run()")
    }
  }

}

fileprivate class NotNullGuard {
  public init() {}
}

fileprivate let threadPriorityToNiceValueMap: [(ThreadPriority, Int)] = [
    (ThreadPriority.background, 10),
    (ThreadPriority.normal, 0),
    (ThreadPriority.display, -8),
    (ThreadPriority.realtimeAudio, -10)
]

fileprivate func threadPriorityToNiceValue(priority: ThreadPriority) -> Int {
  for  pair in threadPriorityToNiceValueMap {
    if pair.0 == priority {
      return pair.1
    }
  }
  assert(false)
  return 0
}

fileprivate func niceValueToThreadPriority(niceValue: Int) -> ThreadPriority {
  for pair in threadPriorityToNiceValueMap.reversed() {
    if pair.1 >= niceValue {
      return pair.0
    }
  }

  return ThreadPriority.background
}

class ThreadParams {
  var delegate: PlatformThreadDelegate?
  var joinable: Bool
  var priority: ThreadPriority

  init() {
    joinable = false
    priority = ThreadPriority.normal
  }
}

fileprivate func createThread(stackSize: Int,
                              joinable: Bool,
                              delegate: PlatformThreadDelegate,
                              priority: ThreadPriority) -> PlatformThreadHandle? {

  var attributes: UnsafeMutablePointer<pthread_attr_t> = UnsafeMutablePointer.allocate(capacity: 1)
  pthread_attr_init(attributes)

  // Pthreads are joinable by default, so only specify the detached
  // attribute if the thread should be non-joinable.
  if !joinable {
    pthread_attr_setdetachstate(attributes, CInt(PTHREAD_CREATE_DETACHED))
  }

  // Get a better default if available.
  var mutStackSize = stackSize
  //if stackSize == 0 {
  //  mutStackSize = getDefaultThreadStackSize(attributes)
  //}

  if mutStackSize > 0 {
    pthread_attr_setstacksize(attributes, mutStackSize)
  }

  var params = ThreadParams()
  params.delegate = delegate
  params.joinable = joinable
  params.priority = priority

  defer {
    pthread_attr_destroy(attributes)
    attributes.deallocate()
  }

  var pthreadHandle = pthread_t()
  let err = pthread_create(
    &pthreadHandle, 
    attributes, 
    { p in
      var delegate: PlatformThreadDelegate?
      do {
        let threadParams = Unmanaged<ThreadParams>.fromOpaque((p as UnsafeMutableRawPointer?)!).takeRetainedValue()
        delegate = threadParams.delegate
        //if !threadParams.joinable {
          //ThreadRestrictions.singletonAllowed = false
        //}
        PlatformThread.currentThreadPriority = threadParams.priority
      }

      ThreadIdNameManager.instance.registerThread(
          handle: PlatformThread.currentHandle,
          id: PlatformThread.currentId)

      delegate!.threadMain()

      ThreadIdNameManager.instance.removeName(
          handle: PlatformThread.currentHandle,
          id: PlatformThread.currentId)

      return nil
    },
    Unmanaged.passRetained(params).toOpaque())
  
  if err != 0 {
    print("pthread_create: error \(err)")
    return nil
  }

  return pthreadHandle
}

internal class ThreadNameState {
  var name: String
  init() {
    self.name = String()
  }
  init(_ name: String) {
    self.name = name
  }
}

internal class ThreadIdNameManager {

  typealias SetNameCallback = (_: String) -> Void
  typealias ThreadIdToHandleMap = [PlatformThreadId: PlatformThreadHandle]
  typealias ThreadHandleToInternedNameMap = [PlatformThreadHandle: String?]
  typealias NameToInternedNameMap = [String: String?]

  static let defaultName: String = ""
  static var gDefaultName: String? 
  static let instance: ThreadIdNameManager = ThreadIdNameManager()
  static var threadNameTLS:  ThreadSpecificVariable<ThreadNameState> = ThreadSpecificVariable<ThreadNameState>()

  var lock: Lock = Lock()
  var nameToInternedName: NameToInternedNameMap = NameToInternedNameMap()
  var threadIdToHandle: ThreadIdToHandleMap = ThreadIdToHandleMap()
  var threadHandleToInternedName: ThreadHandleToInternedNameMap = ThreadHandleToInternedNameMap()
  var mainProcessName: String?
  var mainProcessId: PlatformThreadId = PlatformThread.invalidThreadId
  var setNameCallback: SetNameCallback?

  //static const char* GetDefaultInternedString();

  init () {
    
  }

  public func registerThread(handle: PlatformThreadHandle, id: PlatformThreadId) {
    lock.withLockVoid {
      threadIdToHandle[id] = handle
      threadHandleToInternedName[handle] = nameToInternedName[ThreadIdNameManager.defaultName]
    }
  }

  public func installSetNameCallback(callback: @escaping SetNameCallback) {
    lock.withLockVoid {
      setNameCallback = callback
    }
  }

  // Set the name for the current thread.
  public func setName(_ name: String) {
    let id = PlatformThread.currentId
    var leakedStr: String?
    lock.withLockVoid {
      if let item = nameToInternedName[name] {
        leakedStr = item
      } else {
        leakedStr = name
        nameToInternedName[name] = leakedStr
      }

      ThreadIdNameManager.threadNameTLS.currentValue = ThreadNameState(leakedStr!)
      if let cb = setNameCallback {
        cb(leakedStr!)
      }

      if let item = threadIdToHandle[id] {
        threadHandleToInternedName[item] = leakedStr
      } else {
        mainProcessName = leakedStr
        mainProcessId = id
      }
    }
  }

  public func getName(id: PlatformThreadId) -> String {
    return lock.withLock {
      
      if id == mainProcessId {
        return mainProcessName!
      }

      guard let handle = threadIdToHandle[id] else {
        return nameToInternedName[ThreadIdNameManager.defaultName]!! 
      }

      return threadHandleToInternedName[handle]!!
    }
  }

  public func getNameForCurrentThread() -> String {
    if let name = ThreadIdNameManager.threadNameTLS.currentValue?.name {
      return name.isEmpty ? ThreadIdNameManager.defaultName : name
    }
    return ThreadIdNameManager.defaultName
  }

  public func removeName(handle: PlatformThreadHandle, id: PlatformThreadId) {
    lock.withLockVoid {
      
      if let index = threadHandleToInternedName.index(forKey: handle) {
        threadHandleToInternedName.remove(at: index)
      }

      if let hndl = threadIdToHandle[id] {
        if hndl != handle {
          return
        }
        threadIdToHandle.removeValue(forKey: id)
      } 
    }
  }

}