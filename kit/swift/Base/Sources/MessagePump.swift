// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Libevent
import PosixShim

internal enum IOEvent : Int32 {
  case TIMEOUT = 1
  case READ = 2
  case WRITE = 4
  case SIGNAL = 8
  case PERSIST = 16
}

internal struct WatchMode {
   static let watchRead = WatchMode(rawValue: 1 << 0)
   static let watchWrite = WatchMode(rawValue: 1 << 1)
   static let watchReadWrite = WatchMode(rawValue: watchRead.rawValue | watchWrite.rawValue)
   
   var rawValue: Int

   init(rawValue: Int) {
     self.rawValue = rawValue
   }
 }

public protocol MessagePumpDelegate {
  func doWork() throws -> Bool
  func doDelayedWork(nextDelayedWorkTime: inout TimeTicks) throws -> Bool
  func doIdleWork() throws -> Bool
}
public protocol MessagePump {
  func run(delegate: MessagePumpDelegate) throws
  func quit()
  func scheduleWork()
  func scheduleDelayedWork(delayedWorkTime: TimeTicks)
}

#if os(Linux) || os(macOS) || os(FreeBSD)

public protocol FdWatcher {
  func onFileCanReadWithoutBlocking(pipe: PlatformFile)
  func onFileCanWriteWithoutBlocking(pipe: PlatformFile)
}

public protocol FdWatchControllerInterface {
  func stopWatchingFileDescriptor() -> Bool
}

/// helper class to allow a by-value type be defined in one method
/// be modified on another

internal struct Retain<T> {

  var isNull: Bool {
    return _value == nil
  }

  var value: T {
    get {
      return _value!
    }
    set {
      _value = newValue
    }
  }

  var _value: T?

  init() {}

  init(_ value: inout T) {
    self._value = value
  }
}

public class FdWatchController : FdWatchControllerInterface {

  var wasDestroyed: Retain<Bool> = Retain<Bool>()
  var event: Event?
  var pump: IOMessagePumpLibevent?
  var watcher: FdWatcher?
  
  //   explicit FdWatchController(const Location& from_here);

  //   // Implicitly calls StopWatchingFileDescriptor.
  //   ~FdWatchController() override;

  //   // FdWatchControllerInterface:
  //   bool StopWatchingFileDescriptor() override;

  //  private:
   
  //   // Called by MessagePumpLibevent.
  //   void Init(std::unique_ptr<event> e);

  //   // Used by MessagePumpLibevent to take ownership of |event_|.
  //   std::unique_ptr<event> ReleaseEvent();

  //   void set_pump(MessagePumpLibevent* pump) { pump_ = pump; }
  //   MessagePumpLibevent* pump() const { return pump_; }

  //   void set_watcher(FdWatcher* watcher) { watcher_ = watcher; }

  //   void OnFileCanReadWithoutBlocking(int fd, MessagePumpLibevent* pump);
  //   void OnFileCanWriteWithoutBlocking(int fd, MessagePumpLibevent* pump);

  //   std::unique_ptr<event> event_;
  //   MessagePumpLibevent* pump_ = nullptr;
  //   FdWatcher* watcher_ = nullptr;
  //   // If this pointer is non-NULL, the pointee is set to true in the
  //   // destructor.
  //   bool* was_destroyed_ = nullptr;
  public init() {}

  public func initialize(event: Event) {
    self.event = event
  }

  deinit {
    if event != nil {
      let _ = stopWatchingFileDescriptor()
    }

    if !wasDestroyed.isNull {
      wasDestroyed.value = true
    }
  }

  public func releaseEvent() -> Event? {
    guard let ev = event else {
      return nil
    }
    event = nil
    return ev
  }

  public func stopWatchingFileDescriptor() -> Bool {

    guard let e = releaseEvent() else {
      return true
    }

    // event_del() is a no-op if the event isn't active.
    let rv = e.delete()
    pump = nil
    watcher = nil
    e.dispose()

    return rv == 0
  }

  public func onLibeventNotification(pipe: PlatformFile, flags: Int32) {
    pump!.processedIOEvents = true

    if (flags & (IOEvent.READ.rawValue | IOEvent.WRITE.rawValue)) == (IOEvent.READ.rawValue | IOEvent.WRITE.rawValue) {
      // Both callbacks will be called. It is necessary to check that |controller|
      // is not destroyed.
      var controllerWasDestroyed = false
      wasDestroyed = Retain<Bool>(&controllerWasDestroyed)
      onFileCanWriteWithoutBlocking(pipe: pipe, pump: pump!)
      if !controllerWasDestroyed {
        onFileCanReadWithoutBlocking(pipe: pipe, pump: pump!)
      }
      if !controllerWasDestroyed {
        wasDestroyed = Retain<Bool>()
      }
    } else if (flags & IOEvent.WRITE.rawValue) > 0 {
      onFileCanWriteWithoutBlocking(pipe: pipe, pump: pump!)
    } else if (flags & IOEvent.READ.rawValue) > 0 {
      onFileCanReadWithoutBlocking(pipe: pipe, pump: pump!)
    }
  }

  func onFileCanReadWithoutBlocking(pipe: PlatformFile, pump: IOMessagePumpLibevent) {
    guard let w = watcher else {
      return
    }

    w.onFileCanReadWithoutBlocking(pipe: pipe)
  }
  
  func onFileCanWriteWithoutBlocking(pipe: PlatformFile, pump: IOMessagePumpLibevent) {
    guard let w = watcher else {
      return
    }
    w.onFileCanWriteWithoutBlocking(pipe: pipe)
  }

}

//
public class IOMessagePumpLibevent : MessagePump {
  
  internal var processedIOEvents: Bool {
    get {
      return processedIOEventsLock.withLock {
        return _processedIOEvents
      }
    }
    set {
      processedIOEventsLock.withLockVoid {
        _processedIOEvents = newValue
      }
    }
  }

  private var keepRunning: Bool {
    get {
      return keepRunningLock.withLock {
        return _keepRunning
      }
    }
    set {
      keepRunningLock.withLockVoid {
        _keepRunning = newValue
      }
    }
  }

  private var inRun: Bool {
    get {
      return inRunLock.withLock {
        return _inRun
      }
    }
    set {
      inRunLock.withLockVoid {
        _inRun = newValue
      }
    }
  }

  private var _keepRunning: Bool
  private var keepRunningLock: Lock = Lock()
  
  private var _inRun: Bool
  private var inRunLock: Lock = Lock()
  
  private var wakeupPipeIn: WakeupPipe
  private var wakeupPipeOut: WakeupPipe
  private var delayedWorkTime: TimeTicks

  // Libevent dispatcher.  Watches all sockets registered with it, and sends
  // readiness callbacks when a socket is ready for I/O.
  //var eventLoop: event_base
  private var eventLoop: EventLoop

  // ... libevent wrapper for read end
  private var wakeupEvent: Event

  private var processedIOEventsLock: Lock = Lock()
  private var _processedIOEvents: Bool
  

  public init() throws {
    let readEnd: CInt
    let writeEnd: CInt
    let errorCode: CInt

    _keepRunning = true
    _inRun = false
    _processedIOEvents = false
    eventLoop = EventLoop()
    delayedWorkTime = TimeTicks()
    //if !initialize() {
    //  throw RuntimeError.IOMessagePumpInitError(code: 0, message: "error initializing IOMessagePump")
    //}
    

    (readEnd: readEnd, writeEnd: writeEnd, error: errorCode) = createLocalNonBlockingPipe()
    
    if errorCode != 0 {
      throw RuntimeError.IOMessagePumpInitError(code: 0, message: "error initializing IOMessagePump: pipe creation failed")
    }

    wakeupPipeOut = WakeupPipe(descriptor: readEnd)
    wakeupPipeIn = WakeupPipe(descriptor: writeEnd)

    wakeupEvent  = Event()

    if !initializeEvents() {
      throw RuntimeError.IOMessagePumpInitError(code: 0, message: "error initializing IOMessagePump")
    }
  }

  deinit {
    wakeupEvent.dispose()
    try! wakeupPipeIn.close()
    try! wakeupPipeOut.close()
    eventLoop.dispose()
  }
  
  //@inline(never)
  public func run(delegate: MessagePumpDelegate) throws {
    
    //let autoResetKeepRunning = AutoReset<Bool>(value: &keepRunning, to: true)
    //let autoResetInRun = AutoReset<Bool>(value: &inRun, to: true)
    let lastKeepRunning = keepRunning
    let lastInRun = inRun

    keepRunning = true
    inRun = true

    defer {
      keepRunning = lastKeepRunning
      inRun = lastInRun
    }

    // event_base_loopexit() + EVLOOP_ONCE is leaky, see http://crbug.com/25641.
    // Instead, make our own timer and reuse it on each call to event_base_loop().
    let timerEvent = Event()//ScopedEvent.new()//Event()//ScopedEvent.new()
    
    repeat {
  /// TODO: NIO has an 'antidote' to this
  //#if os(macOS)
  //    let autoreleasePool = ScopedNSAutoreleasePool()
  //#endif

      var didWork = try delegate.doWork() ? 1 : 0
      
      if !keepRunning {
        break
      }
      
      eventLoop.loop(flags: EventLoopFlags.nonblock)
     
      didWork |= processedIOEvents ? 1 : 0
      
      processedIOEvents = false
      
      if !keepRunning {
        break
      }

      didWork |= try delegate.doDelayedWork(nextDelayedWorkTime: &delayedWorkTime) ? 1 : 0
     
      if !keepRunning {
        break
      }

      if didWork != 0 {
        continue
      }

      didWork = try delegate.doIdleWork() ? 1 : 0
      
      if !keepRunning {
        break
      }

      if didWork != 0 {
        continue
      }

      // EVLOOP_ONCE tells libevent to only block once,
      // but to service all pending events when it wakes up.
      if delayedWorkTime.isNull {
        eventLoop.loop(flags: EventLoopFlags.once)
      } else {
        let diff: TimeTicks = delayedWorkTime - TimeTicks.now
        let delay = TimeDelta(microseconds: diff.microseconds)
        
        if delay > TimeDelta() {
          let timeout = EventTimer(
            seconds: delay.seconds,
            microseconds: delay.microseconds % Time.MicrosecondsPerSecond)
          
          let eventLoopPtr = UnsafeMutableRawPointer(Unmanaged.passUnretained(eventLoop).toOpaque())

          timerEvent.set(
            pipe: nil, 
            flags: EventFlags.none, 
            callback: {
              (socket, flags, context) -> Void in
                if let eventLoopRef = context {
                let eventLoop = Unmanaged<EventLoop>.fromOpaque(eventLoopRef).takeUnretainedValue()
                eventLoop.loopbreak()
              }
            }, 
            context: eventLoopPtr)
          
          eventLoop.set(event: timerEvent)

          timerEvent.add(
            timeout: timeout)

          eventLoop.loop(flags: EventLoopFlags.once)
          
          timerEvent.delete()
        } else {
          // It looks like delayedWorkTime indicates a time in the past, so we
          // need to call doDelayedWork now.
          delayedWorkTime = TimeTicks()
        }
      }

      if !keepRunning {
        break
      }
    } while true

  }
  
  //@inline(never)
  public func quit() {
    guard inRun else {
      print("Quit was called outside of Run!")
      return
    }
    // Tell both libevent and Run that they should break out of their loops.
    keepRunning = false
    
    scheduleWork()
  }

  public func scheduleWork() {
    var chars = Array<Int8>(repeating: -1, count: 1)
    chars.withUnsafeMutableBufferPointer { buf in  
      // let nwrite = posix_write(wakeupPipeIn.descriptor, buf.baseAddress, 1)
      let nwrite = try! Posix.write(wakeupPipeIn.descriptor, buf.baseAddress, 1)
      assert(nwrite == 1)
    }
  }

  public func scheduleDelayedWork(delayedWorkTime: TimeTicks) {
    self.delayedWorkTime = delayedWorkTime
  }

  public func watchFileDescriptor(fd: CInt,
                                  persistent: Bool,
                                  mode: Int,
                                  controller: FdWatchController,
                                  delegate: FdWatcher) -> Bool {
    
    assert(fd >= 0)
    //assert(mode == WATCH_READ || mode == WATCH_WRITE || mode == WATCH_READ_WRITE)
    
    var eventMask: EventFlags = persistent ? EventFlags.persist : EventFlags.none
    if mode & WatchMode.watchRead.rawValue > 0 {
      eventMask.rawValue |= EventFlags.read.rawValue
    }

    if mode & WatchMode.watchWrite.rawValue > 0 {
      eventMask.rawValue |= EventFlags.write.rawValue
    }

    var ev = ScopedEvent()

    if let controllerEv = controller.releaseEvent() {
      ev.event = controllerEv
       // Make sure we don't pick up any funky internal libevent masks.
      let events = ev.events!
      let oldInterestMask = Int(events & (IOEvent.READ.rawValue | IOEvent.WRITE.rawValue | IOEvent.PERSIST.rawValue))

      // Combine old/new event masks.
      eventMask.rawValue |= oldInterestMask

      // Must disarm the event before we can reuse it.
      ev.delete()

      // It's illegal to use this function to listen on 2 separate fds with the
      // same |controller|.
      if let evfd = ev.fd, evfd != fd {
        print("FDs don't match \(evfd) != \(fd)")
        return false
      }
    } else {
      // Ownership is transferred to the controller.
      ev = ScopedEvent.new()
    }

    let controllerPtr = UnsafeMutableRawPointer(Unmanaged.passUnretained(controller).toOpaque())
    // Set current interest mask and message pump for this event.
    ev.set(
      fd: fd,
      flags: eventMask,
      callback: {
        (socket, flags, context) -> Void in
          if let controllerRef = context {
            let controller = Unmanaged<FdWatchController>.fromOpaque(controllerRef).takeUnretainedValue()
            controller.onLibeventNotification(pipe: PlatformFile(descriptor: socket), flags: Int32(flags))
          }
      },
      context: controllerPtr)

    // Tell libevent which message pump this socket will belong to when we add it.
    if eventLoop.set(event: ev.event!) != 0 {
      print("event_base_set(fd=\(ev.fd!))")
      return false
    }

    // Add this socket to the list of monitored sockets.
    if ev.add() != 0 {
      print("event_add failed(fd=\(ev.fd!))")
      return false
    }

    controller.initialize(event: ev.release())
    controller.watcher = delegate
    controller.pump = self
    return true
  }

  func initializeEvents() -> Bool {
    let selfptr = UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())

    wakeupEvent.set(
      pipe: wakeupPipeOut, 
      flags: EventFlags(rawValue: EventFlags.read.rawValue | EventFlags.persist.rawValue), 
      callback: {
        (socket, flags, context) -> Void in
          if let messagePumpRef = context {
            let messagePump = Unmanaged<IOMessagePumpLibevent>.fromOpaque(messagePumpRef).takeUnretainedValue()
            messagePump.onWakeup(pipe: WakeupPipe(descriptor: socket), flags: flags)
          }
      },
      context: selfptr)

    eventLoop.set(event: wakeupEvent)

    if wakeupEvent.add() != 0 {
      return false
    }
    
    return true
  }

  func onWakeup(pipe: WakeupPipe, flags: Int16) {
    assert(wakeupPipeOut.descriptor == pipe.descriptor)

    // Remove and discard the wakeup byte.
    var chars = Array<Int8>(repeating: -1, count: 1)
    chars.withUnsafeMutableBufferPointer { buf in  
      //let nread = posix_read(pipe.descriptor, buf.baseAddress, 1)
      let nread = try! Posix.read(pipe.descriptor, buf.baseAddress, 1)
      assert(nread == 1)
    }
    processedIOEvents = true
    // Tell libevent to break out of inner loop.
    eventLoop.loopbreak()
  }

}
#endif

#if os(Linux)
public typealias IOMessagePump = IOMessagePumpLibevent
public typealias UIMessagePump = IOMessagePumpLibevent
#endif