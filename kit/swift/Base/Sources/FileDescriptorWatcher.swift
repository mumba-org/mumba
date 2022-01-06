// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class FileDescriptorWatcherController {

    var callback: () -> ()

    var messageLoopForIOTaskRunner: SingleThreadTaskRunner

    var watcher: FileDescriptorWatcherControllerWatcher?

    init(mode: WatchMode, pipe: PlatformFile, callback: @escaping () -> ()) {
      self.callback = callback
      messageLoopForIOTaskRunner = tlsMessageLoopForIO.currentValue!.taskRunner!
      watcher = FileDescriptorWatcherControllerWatcher(controller: self, mode: mode, pipe: pipe)
      startWatching()
    }

    func startWatching() {
       messageLoopForIOTaskRunner.postTask {
         self.watcher!.startWatching()
       }
    }

    func runCallback() {
      callback()
      startWatching()
    }
}

public class FileDescriptorWatcher {

  public static func watchReadable(pipe: PlatformFile, callback: @escaping () -> ()) -> FileDescriptorWatcherController {
    return FileDescriptorWatcherController(mode: WatchMode.watchRead, pipe: pipe, callback: callback)
  }
  
  public static func watchWritable(pipe: PlatformFile, callback: @escaping () -> ()) -> FileDescriptorWatcherController {
    return FileDescriptorWatcherController(mode: WatchMode.watchWrite, pipe: pipe, callback: callback)
  }

  public init(messageLoop: MessageLoop) {
    tlsMessageLoopForIO.currentValue = messageLoop
  }

  deinit {
    tlsMessageLoopForIO.currentValue = nil
  }

}

fileprivate let tlsMessageLoopForIO: ThreadSpecificVariable<MessageLoop> = ThreadSpecificVariable<MessageLoop>()

internal class FileDescriptorWatcherControllerWatcher : FdWatcher,
                                                        DestructionObserver {

  var fileDescriptorWatcher: FdWatchController

  var callbackTaskRunner: SequencedTaskRunner

  weak var controller: FileDescriptorWatcherController?

  var mode: WatchMode

  var pipe: PlatformFile

  var registeredAsDestructionObserver: Bool = false
 
  init(controller: FileDescriptorWatcherController, mode: WatchMode, pipe: PlatformFile) {
    callbackTaskRunner = SequencedTaskRunnerHandle.get()!
    fileDescriptorWatcher = FdWatchController()
    self.controller = controller
    self.mode = mode
    self.pipe = pipe
  }

  deinit {
    MessageLoop.current.removeDestructionObserver(observer: self)
  }
  
  func startWatching() {
    if !MessageLoop.current.watchFileDescriptor(
          fd: pipe.descriptor, 
          persistent: false, 
          mode: mode.rawValue, 
          controller: fileDescriptorWatcher, 
          delegate: self) {
      // TODO: throw exception
      print("Failed to watch fd=\(pipe.descriptor)")
    }

    if !registeredAsDestructionObserver {
      MessageLoop.current.addDestructionObserver(observer: self)
      registeredAsDestructionObserver = true
    }
  }

  // FdWatcher
  func onFileCanReadWithoutBlocking(pipe: PlatformFile) {
    callbackTaskRunner.postTask {
      self.controller!.runCallback()
    }
  }

  func onFileCanWriteWithoutBlocking(pipe: PlatformFile) {
    callbackTaskRunner.postTask {
      self.controller!.runCallback()
    }
  }

  // MessageLoopDestructionObserver
  func willDestroyCurrentMessageLoop() {
    // A Watcher is owned by a Controller. When the Controller is deleted, it
    // transfers ownership of the Watcher to a delete task posted to the
    // MessageLoopForIO. If the MessageLoopForIO is deleted before the delete task
    // runs, the following line takes care of deleting the Watcher.
    
    // delete(self)
  }

}