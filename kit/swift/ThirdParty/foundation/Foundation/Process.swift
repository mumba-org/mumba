// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2016, 2018 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See http://swift.org/LICENSE.txt for license information
// See http://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//

#if !os(Android) // not available
import CoreFoundation

extension Process {
    public enum TerminationReason : Int {
        case exit
        case uncaughtSignal
    }
}

private func WIFEXITED(_ status: Int32) -> Bool {
    return _WSTATUS(status) == 0
}

private func _WSTATUS(_ status: Int32) -> Int32 {
    return status & 0x7f
}

private func WIFSIGNALED(_ status: Int32) -> Bool {
    return (_WSTATUS(status) != 0) && (_WSTATUS(status) != 0x7f)
}

private func WEXITSTATUS(_ status: Int32) -> Int32 {
    return (status >> 8) & 0xff
}

private func WTERMSIG(_ status: Int32) -> Int32 {
    return status & 0x7f
}

private var managerThreadRunLoop : RunLoop? = nil
private var managerThreadRunLoopIsRunning = false
private var managerThreadRunLoopIsRunningCondition = NSCondition()

#if os(macOS) || os(iOS)
internal let kCFSocketDataCallBack = CFSocketCallBackType.dataCallBack.rawValue
#endif

private func emptyRunLoopCallback(_ context : UnsafeMutableRawPointer?) -> Void {}


// Retain method for run loop source
private func runLoopSourceRetain(_ pointer : UnsafeRawPointer?) -> UnsafeRawPointer? {
    let ref = Unmanaged<AnyObject>.fromOpaque(pointer!).takeUnretainedValue()
    let retained = Unmanaged<AnyObject>.passRetained(ref)
    return unsafeBitCast(retained, to: UnsafeRawPointer.self)
}

// Release method for run loop source
private func runLoopSourceRelease(_ pointer : UnsafeRawPointer?) -> Void {
    Unmanaged<AnyObject>.fromOpaque(pointer!).release()
}

// Equal method for run loop source

private func runloopIsEqual(_ a : UnsafeRawPointer?, _ b : UnsafeRawPointer?) -> _DarwinCompatibleBoolean {
    
    let unmanagedrunLoopA = Unmanaged<AnyObject>.fromOpaque(a!)
    guard let runLoopA = unmanagedrunLoopA.takeUnretainedValue() as? RunLoop else {
        return false
    }
    
    let unmanagedRunLoopB = Unmanaged<AnyObject>.fromOpaque(a!)
    guard let runLoopB = unmanagedRunLoopB.takeUnretainedValue() as? RunLoop else {
        return false
    }
    
    guard runLoopA == runLoopB else {
        return false
    }
    
    return true
}


// Equal method for process in run loop source
private func processIsEqual(_ a : UnsafeRawPointer?, _ b : UnsafeRawPointer?) -> _DarwinCompatibleBoolean {
    
    let unmanagedProcessA = Unmanaged<AnyObject>.fromOpaque(a!)
    guard let processA = unmanagedProcessA.takeUnretainedValue() as? Process else {
        return false
    }
    
    let unmanagedProcessB = Unmanaged<AnyObject>.fromOpaque(a!)
    guard let processB = unmanagedProcessB.takeUnretainedValue() as? Process else {
        return false
    }
    
    guard processA == processB else {
        return false
    }
    
    return true
}

open class Process: NSObject {
    private static func setup() {
        struct Once {
            static var done = false
            static let lock = NSLock()
        }
        
        Once.lock.synchronized {
            if !Once.done {
                let thread = Thread {
                    managerThreadRunLoop = RunLoop.current
                    var emptySourceContext = CFRunLoopSourceContext()
                    emptySourceContext.version = 0
                    emptySourceContext.retain = runLoopSourceRetain
                    emptySourceContext.release = runLoopSourceRelease
                    emptySourceContext.equal = runloopIsEqual
                    emptySourceContext.perform = emptyRunLoopCallback
                    managerThreadRunLoop!.withUnretainedReference {
                        (refPtr: UnsafeMutablePointer<UInt8>) in
                        emptySourceContext.info = UnsafeMutableRawPointer(refPtr)
                    }
                    
                    CFRunLoopAddSource(managerThreadRunLoop?._cfRunLoop, CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &emptySourceContext), kCFRunLoopDefaultMode)
                    
                    managerThreadRunLoopIsRunningCondition.lock()
                    
                    CFRunLoopPerformBlock(managerThreadRunLoop?._cfRunLoop, kCFRunLoopDefaultMode) {
                        managerThreadRunLoopIsRunning = true
                        managerThreadRunLoopIsRunningCondition.broadcast()
                        managerThreadRunLoopIsRunningCondition.unlock()
                    }
                    
                    managerThreadRunLoop?.run()
                    fatalError("Process manager run loop exited unexpectedly; it should run forever once initialized")
                }
                thread.start()
                managerThreadRunLoopIsRunningCondition.lock()
                while managerThreadRunLoopIsRunning == false {
                    managerThreadRunLoopIsRunningCondition.wait()
                }
                managerThreadRunLoopIsRunningCondition.unlock()
                Once.done = true
            }
        }
    }

    // Create an Process which can be run at a later time
    // An Process can only be run once. Subsequent attempts to
    // run an Process will raise.
    // Upon process death a notification will be sent
    //   { Name = ProcessDidTerminateNotification; object = process; }
    //
    
    public override init() {

    }

    // These properties can only be set before a launch.
    open var executableURL: URL?
    open var currentDirectoryURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
    open var arguments: [String]?
    open var environment: [String : String]? // if not set, use current

    @available(*, deprecated, renamed: "executableURL")
    open var launchPath: String? {
        get { return executableURL?.path }
        set { executableURL = (newValue != nil) ? URL(fileURLWithPath: newValue!) : nil }
    }

    @available(*, deprecated, renamed: "currentDirectoryURL")
    open var currentDirectoryPath: String {
        get { return currentDirectoryURL.path }
        set { currentDirectoryURL = URL(fileURLWithPath: newValue) }
    }

    // Standard I/O channels; could be either a FileHandle or a Pipe

    open var standardInput: Any? {
        willSet {
            precondition(newValue is Pipe || newValue is FileHandle,
                         "standardInput must be either Pipe or FileHandle")
        }
    }

    open var standardOutput: Any? {
        willSet {
            precondition(newValue is Pipe || newValue is FileHandle,
                         "standardOutput must be either Pipe or FileHandle")
        }
    }
    
    open var standardError: Any? {
        willSet {
            precondition(newValue is Pipe || newValue is FileHandle,
                         "standardError must be either Pipe or FileHandle")
        }
    }
    
    private var runLoopSourceContext : CFRunLoopSourceContext?
    private var runLoopSource : CFRunLoopSource?
    
    fileprivate weak var runLoop : RunLoop? = nil
    
    private var processLaunchedCondition = NSCondition()
    
    // Actions
    
    @available(*, deprecated, renamed: "run")
    open func launch() {
        do {
            try run()
        } catch let nserror as NSError {
            if let path = nserror.userInfo[NSFilePathErrorKey] as? String, path == currentDirectoryPath {
                // Foundation throws an NSException when changing the working directory fails,
                // and unfortunately launch() is not marked `throws`, so we get away with a
                // fatalError.
                switch CocoaError.Code(rawValue: nserror.code) {
                case .fileReadNoSuchFile:
                    fatalError("Process: The specified working directory does not exist.")
                case .fileReadNoPermission:
                    fatalError("Process: The specified working directory cannot be accessed.")
                default:
                    fatalError("Process: The specified working directory cannot be set.")
                }
            }
        } catch {
            fatalError(String(describing: error))
        }
    }

    #if os(Windows)
    private func _socketpair() -> (first: SOCKET, second: SOCKET) {
      let listener: SOCKET = socket(AF_INET, SOCK_STREAM, 0)
      if listener == INVALID_SOCKET {
        return (first: INVALID_SOCKET, second: INVALID_SOCKET)
      }
      defer { closesocket(listener) }

      var result: Int32 = SOCKET_ERROR

      var address: sockaddr_in =
          sockaddr_in(sin_family: ADDRESS_FAMILY(AF_INET), sin_port: USHORT(0),
                      sin_addr: IN_ADDR(S_un: in_addr.__Unnamed_union_S_un(S_addr: ULONG("127.0.0.1")!)),
                      sin_zero: (CHAR(0), CHAR(0), CHAR(0), CHAR(0), CHAR(0), CHAR(0), CHAR(0), CHAR(0)))
      withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          result = bind(listener, $0, Int32(MemoryLayout<sockaddr_in>.size))
        }
      }

      if result == SOCKET_ERROR {
        return (first: INVALID_SOCKET, second: INVALID_SOCKET)
      }

      if listen(listener, 1) == SOCKET_ERROR {
        return (first: INVALID_SOCKET, second: INVALID_SOCKET)
      }

      withUnsafeMutablePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          var value: Int32 = Int32(MemoryLayout<sockaddr_in>.size)
          result = getsockname(listener, $0, &value)
        }
      }
      if result == SOCKET_ERROR {
        return (first: INVALID_SOCKET, second: INVALID_SOCKET)
      }

      let first: SOCKET = socket(AF_INET, SOCK_STREAM, 0)
      if first == INVALID_SOCKET {
        return (first: INVALID_SOCKET, second: INVALID_SOCKET)
      }

      var value: u_long = 1
      if ioctlsocket(first, FIONBIO, &value) == SOCKET_ERROR {
        closesocket(first)
        return (first: INVALID_SOCKET, second: INVALID_SOCKET)
      }

      withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          result = connect(first, $0, Int32(MemoryLayout<sockaddr_in>.size))
        }
      }

      if result == SOCKET_ERROR {
        closesocket(first)
        return (first: INVALID_SOCKET, second: INVALID_SOCKET)
      }

      let second: SOCKET = accept(listener, nil, nil)
      if second == INVALID_SOCKET {
        closesocket(first)
        return (first: INVALID_SOCKET, second: INVALID_SOCKET)
      }

      return (first: first, second: second)
    }
    #endif

    open func run() throws {
        self.processLaunchedCondition.lock()
        defer {
            self.processLaunchedCondition.broadcast()
            self.processLaunchedCondition.unlock()
        }

        // Dispatch the manager thread if it isn't already running
        Process.setup()

        // Ensure that the launch path is set
        guard let launchPath = self.executableURL?.path else {
            throw NSError(domain: NSCocoaErrorDomain, code: NSFileNoSuchFileError)
        }

#if os(Windows)
        // TODO(compnerd) quote the commandline correctly
        // https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/
        var command: [String] = [launchPath]
        if let arguments = self.arguments {
          command.append(contentsOf: arguments)
        }

        var siStartupInfo: STARTUPINFOW = STARTUPINFOW()
        siStartupInfo.cb = DWORD(MemoryLayout<STARTUPINFOW>.size)

        switch standardInput {
        case let pipe as Pipe:
          siStartupInfo.hStdInput = pipe.fileHandleForReading.handle
        case let handle as FileHandle:
          siStartupInfo.hStdInput = handle.handle
        default: break
        }

        switch standardOutput {
        case let pipe as Pipe:
          siStartupInfo.hStdOutput = pipe.fileHandleForWriting.handle
        case let handle as FileHandle:
          siStartupInfo.hStdOutput = handle.handle
        default: break
        }

        switch standardError {
        case let pipe as Pipe:
          siStartupInfo.hStdError = pipe.fileHandleForWriting.handle
        case let handle as FileHandle:
          siStartupInfo.hStdError = handle.handle
        default: break
        }

        var piProcessInfo: PROCESS_INFORMATION = PROCESS_INFORMATION()

        var environment: [String:String] = [:]
        if let env = self.environment {
          environment = env
        } else {
          environment = ProcessInfo.processInfo.environment
          environment["PWD"] = currentDirectoryURL.path
        }

        let szEnvironment: String = environment.map { $0.key + "=" + $0.value }.joined(separator: "\0")

        let sockets: (first: SOCKET, second: SOCKET) = _socketpair()

        var context: CFSocketContext = CFSocketContext()
        context.version = 0
        context.retain = runLoopSourceRetain
        context.release = runLoopSourceRelease
        context.info = Unmanaged.passUnretained(self).toOpaque()

        let socket: CFSocket =
            CFSocketCreateWithNative(nil, CFSocketNativeHandle(sockets.first), CFOptionFlags(kCFSocketDataCallBack), { (socket, type, address, data, info) in
          let process: Process = NSObject.unretainedReference(info!)
          process.processLaunchedCondition.lock()
          while process.isRunning == false {
            process.processLaunchedCondition.wait()
          }
          process.processLaunchedCondition.unlock()

          WaitForSingleObject(process.processHandle, WinSDK.INFINITE)

          var dwExitCode: DWORD = 0
          // FIXME(compnerd) how do we handle errors here?
          GetExitCodeProcess(process.processHandle, &dwExitCode)

          // TODO(compnerd) check if the process terminated abnormally
          process._terminationStatus = Int32(dwExitCode)
          process._terminationReason = .exit

          if let handler = process.terminationHandler {
            let thread: Thread = Thread { handler(process) }
            thread.start()
          }

          process.isRunning = false

          // Invalidate the source and wake up the run loop, if it is available
          CFRunLoopSourceInvalidate(process.runLoopSource)
          if let runloop = process.runLoop {
            CFRunLoopWakeUp(runloop._cfRunLoop)
          }

          CFSocketInvalidate(socket)
        }, &context)
        CFSocketSetSocketFlags(socket, CFOptionFlags(kCFSocketCloseOnInvalidate))

        let source: CFRunLoopSource =
            CFSocketCreateRunLoopSource(kCFAllocatorDefault, socket, 0)
        CFRunLoopAddSource(managerThreadRunLoop?._cfRunLoop, source, kCFRunLoopDefaultMode)

        try command.joined(separator: " ").withCString(encodedAs: UTF16.self) { wszCommandLine in
          try currentDirectoryURL.path.withCString(encodedAs: UTF16.self) { wszCurrentDirectory in
            try szEnvironment.withCString(encodedAs: UTF16.self) { wszEnvironment in
              if CreateProcessW(nil, UnsafeMutablePointer<WCHAR>(mutating: wszCommandLine),
                                nil, nil, TRUE,
                                DWORD(CREATE_UNICODE_ENVIRONMENT), UnsafeMutableRawPointer(mutating: wszEnvironment),
                                wszCurrentDirectory,
                                &siStartupInfo, &piProcessInfo) == FALSE {
                throw NSError(domain: _NSWindowsErrorDomain, code: Int(GetLastError()))
              }
            }
          }
        }

        self.processHandle = piProcessInfo.hProcess
        if CloseHandle(piProcessInfo.hThread) == FALSE {
          throw NSError(domain: _NSWindowsErrorDomain, code: Int(GetLastError()))
        }

        if let pipe = standardInput as? Pipe {
          pipe.fileHandleForReading.closeFile()
          pipe.fileHandleForWriting.closeFile()
        }
        if let pipe = standardOutput as? Pipe {
          pipe.fileHandleForReading.closeFile()
          pipe.fileHandleForWriting.closeFile()
        }
        if let pipe = standardError as? Pipe {
          pipe.fileHandleForWriting.closeFile()
          pipe.fileHandleForReading.closeFile()
        }

        self.runLoop = RunLoop.current
        self.runLoopSourceContext =
            CFRunLoopSourceContext(version: 0,
                                   info: Unmanaged.passUnretained(self).toOpaque(),
                                   retain: { runLoopSourceRetain($0) },
                                   release: { runLoopSourceRelease($0) },
                                   copyDescription: nil,
                                   equal: { processIsEqual($0, $1) },
                                   hash: nil,
                                   schedule: nil,
                                   cancel: nil,
                                   perform: { emptyRunLoopCallback($0) })
        self.runLoopSource = CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &self.runLoopSourceContext!)

        CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, kCFRunLoopDefaultMode)

        isRunning = true

        closesocket(sockets.second)
#else
        // Initial checks that the launchPath points to an executable file. posix_spawn()
        // can return success even if executing the program fails, eg fork() works but execve()
        // fails, so try and check as much as possible beforehand.
        try FileManager.default._fileSystemRepresentation(withPath: launchPath, { fsRep in
            var statInfo = stat()
            guard stat(fsRep, &statInfo) == 0 else {
                throw _NSErrorWithErrno(errno, reading: true, path: launchPath)
            }

            let isRegularFile: Bool = statInfo.st_mode & S_IFMT == S_IFREG
            guard isRegularFile == true else {
                throw NSError(domain: NSCocoaErrorDomain, code: NSFileNoSuchFileError)
            }

            guard access(fsRep, X_OK) == 0 else {
                throw _NSErrorWithErrno(errno, reading: true, path: launchPath)
            }
        })
        // Convert the arguments array into a posix_spawn-friendly format
        
        var args = [launchPath]
        if let arguments = self.arguments {
            args.append(contentsOf: arguments)
        }
        
        let argv : UnsafeMutablePointer<UnsafeMutablePointer<Int8>?> = args.withUnsafeBufferPointer {
            let array : UnsafeBufferPointer<String> = $0
            let buffer = UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>.allocate(capacity: array.count + 1)
            buffer.initialize(from: array.map { $0.withCString(strdup) }, count: array.count)
            buffer[array.count] = nil
            return buffer
        }
        
        defer {
            for arg in argv ..< argv + args.count {
                free(UnsafeMutableRawPointer(arg.pointee))
            }
            argv.deallocate()
        }

        var env: [String: String]
        if let e = environment {
            env = e
        } else {
            env = ProcessInfo.processInfo.environment
            env["PWD"] = currentDirectoryURL.path
        }

        let nenv = env.count
        let envp = UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>.allocate(capacity: 1 + nenv)
        envp.initialize(from: env.map { strdup("\($0)=\($1)") }, count: nenv)
        envp[env.count] = nil

        defer {
            for pair in envp ..< envp + env.count {
                free(UnsafeMutableRawPointer(pair.pointee))
            }
            envp.deallocate()
        }

        var taskSocketPair : [Int32] = [0, 0]
#if os(macOS) || os(iOS)
        socketpair(AF_UNIX, SOCK_STREAM, 0, &taskSocketPair)
#else
        socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &taskSocketPair)
#endif
        var context = CFSocketContext()
        context.version = 0
        context.retain = runLoopSourceRetain
        context.release = runLoopSourceRelease
        context.info = Unmanaged.passUnretained(self).toOpaque()
        
        let socket = CFSocketCreateWithNative( nil, taskSocketPair[0], CFOptionFlags(kCFSocketDataCallBack), {
            (socket, type, address, data, info )  in
            
            let process: Process = NSObject.unretainedReference(info!)
            
            process.processLaunchedCondition.lock()
            while process.isRunning == false {
                process.processLaunchedCondition.wait()
            }
            
            process.processLaunchedCondition.unlock()
            
            var exitCode : Int32 = 0
#if CYGWIN
            let exitCodePtrWrapper = withUnsafeMutablePointer(to: &exitCode) {
                exitCodePtr in
                __wait_status_ptr_t(__int_ptr: exitCodePtr)
            }
#endif
            var waitResult : Int32 = 0

            repeat {
#if CYGWIN
                waitResult = waitpid( process.processIdentifier, exitCodePtrWrapper, 0)
#else
                waitResult = waitpid( process.processIdentifier, &exitCode, 0)
#endif
            } while ( (waitResult == -1) && (errno == EINTR) )

            if WIFSIGNALED(exitCode) {
                process._terminationStatus = WTERMSIG(exitCode)
                process._terminationReason = .uncaughtSignal
            } else {
                assert(WIFEXITED(exitCode))
                process._terminationStatus = WEXITSTATUS(exitCode)
                process._terminationReason = .exit
            }
            
            // If a termination handler has been set, invoke it on a background thread
            
            if let terminationHandler = process.terminationHandler {
                let thread = Thread {
                    terminationHandler(process)
                }
                thread.start()
            }
            
            // Set the running flag to false
            process.isRunning = false

            // Invalidate the source and wake up the run loop, if it's available
            
            CFRunLoopSourceInvalidate(process.runLoopSource)
            if let runLoop = process.runLoop {
                CFRunLoopWakeUp(runLoop._cfRunLoop)
            }
            
            CFSocketInvalidate( socket )
            
            }, &context )
        
        CFSocketSetSocketFlags( socket, CFOptionFlags(kCFSocketCloseOnInvalidate))
        
        let source = CFSocketCreateRunLoopSource(kCFAllocatorDefault, socket, 0)
        CFRunLoopAddSource(managerThreadRunLoop?._cfRunLoop, source, kCFRunLoopDefaultMode)

        // file_actions
        #if os(macOS) || os(iOS) || CYGWIN
            var fileActions: posix_spawn_file_actions_t? = nil
        #else
            var fileActions: posix_spawn_file_actions_t = posix_spawn_file_actions_t()
        #endif
        posix(posix_spawn_file_actions_init(&fileActions))
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        // File descriptors to duplicate in the child process. This allows
        // output redirection to NSPipe or NSFileHandle.
        var adddup2 = [Int32: Int32]()

        // File descriptors to close in the child process. A set so that
        // shared pipes only get closed once. Would result in EBADF on OSX
        // otherwise.
        var addclose = Set<Int32>()

        switch standardInput {
        case let pipe as Pipe:
            adddup2[STDIN_FILENO] = pipe.fileHandleForReading.fileDescriptor
            addclose.insert(pipe.fileHandleForWriting.fileDescriptor)
        case let handle as FileHandle:
            adddup2[STDIN_FILENO] = handle.fileDescriptor
        default: break
        }

        switch standardOutput {
        case let pipe as Pipe:
            adddup2[STDOUT_FILENO] = pipe.fileHandleForWriting.fileDescriptor
            addclose.insert(pipe.fileHandleForReading.fileDescriptor)
        case let handle as FileHandle:
            adddup2[STDOUT_FILENO] = handle.fileDescriptor
        default: break
        }

        switch standardError {
        case let pipe as Pipe:
            adddup2[STDERR_FILENO] = pipe.fileHandleForWriting.fileDescriptor
            addclose.insert(pipe.fileHandleForReading.fileDescriptor)
        case let handle as FileHandle:
            adddup2[STDERR_FILENO] = handle.fileDescriptor
        default: break
        }

        for (new, old) in adddup2 {
            posix(posix_spawn_file_actions_adddup2(&fileActions, old, new))
        }
        for fd in addclose {
            posix(posix_spawn_file_actions_addclose(&fileActions, fd))
        }

        let fileManager = FileManager()
        let previousDirectoryPath = fileManager.currentDirectoryPath
        if !fileManager.changeCurrentDirectoryPath(currentDirectoryURL.path) {
            throw _NSErrorWithErrno(errno, reading: true, url: currentDirectoryURL)
        }

        defer {
            // Reset the previous working directory path.
            fileManager.changeCurrentDirectoryPath(previousDirectoryPath)
        }

        // Launch
        var pid = pid_t()
        guard posix_spawn(&pid, launchPath, &fileActions, nil, argv, envp) == 0 else {
            throw _NSErrorWithErrno(errno, reading: true, path: launchPath)
        }

        // Close the write end of the input and output pipes.
        if let pipe = standardInput as? Pipe {
            pipe.fileHandleForReading.closeFile()
        }
        if let pipe = standardOutput as? Pipe {
            pipe.fileHandleForWriting.closeFile()
        }
        if let pipe = standardError as? Pipe {
            pipe.fileHandleForWriting.closeFile()
        }

        close(taskSocketPair[1])

        self.runLoop = RunLoop.current
        self.runLoopSourceContext = CFRunLoopSourceContext(version: 0,
                                                           info: Unmanaged.passUnretained(self).toOpaque(),
                                                           retain: { return runLoopSourceRetain($0) },
                                                           release: { runLoopSourceRelease($0) },
                                                           copyDescription: nil,
                                                           equal: { return processIsEqual($0, $1) },
                                                           hash: nil,
                                                           schedule: nil,
                                                           cancel: nil,
                                                           perform: { emptyRunLoopCallback($0) })
        self.runLoopSource = CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &runLoopSourceContext!)
        CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, kCFRunLoopDefaultMode)
        
        isRunning = true
        
        self.processIdentifier = pid
#endif
    }
    
    open func interrupt() {
        precondition(hasStarted, "task not launched")
#if os(Windows)
        TerminateProcess(processHandle, UINT(SIGINT))
#else
        kill(processIdentifier, SIGINT)
#endif
    }

    open func terminate() {
        precondition(hasStarted, "task not launched")
#if os(Windows)
        TerminateProcess(processHandle, UINT(SIGTERM))
#else
        kill(processIdentifier, SIGTERM)
#endif
    }

    // Every suspend() has to be balanced with a resume() so keep a count of both.
    private var suspendCount = 0

    open func suspend() -> Bool {
#if os(Windows)
      let pNTSuspendProcess: Optional<(HANDLE) -> LONG> =
          unsafeBitCast(GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                       "NtSuspendProcess"),
                        to: Optional<(HANDLE) -> LONG>.self)
      if let pNTSuspendProcess = pNTSuspendProcess {
        if pNTSuspendProcess(processHandle) < 0 {
          return false
        }
        suspendCount += 1
        return true
      }
      return false
#else
        if kill(processIdentifier, SIGSTOP) == 0 {
            suspendCount += 1
            return true
        } else {
            return false
        }
#endif
    }

    open func resume() -> Bool {
        var success: Bool = true
#if os(Windows)
        if suspendCount == 1 {
          let pNTResumeProcess: Optional<(HANDLE) -> NTSTATUS> =
              unsafeBitCast(GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                           "NtResumeProcess"),
                            to: Optional<(HANDLE) -> NTSTATUS>.self)
          if let pNTResumeProcess = pNTResumeProcess {
            if pNTResumeProcess(processHandle) < 0 {
              success = false
            }
          }
        }
#else
        if suspendCount == 1 {
            success = kill(processIdentifier, SIGCONT) == 0
        }
#endif
        if success {
            suspendCount -= 1
        }
        return success
    }
    
    // status
#if os(Windows)
    open private(set) var processHandle: HANDLE = INVALID_HANDLE_VALUE
    open var processIdentifier: Int32 {
      return Int32(GetProcessId(processHandle))
    }
    open private(set) var isRunning: Bool = false

    private var hasStarted: Bool {
      return processHandle != INVALID_HANDLE_VALUE
    }
    private var hasFinished: Bool {
      return hasStarted && !isRunning
    }
#else
    open private(set) var processIdentifier: Int32 = 0
    open private(set) var isRunning: Bool = false
    private var hasStarted: Bool { return processIdentifier > 0 }
    private var hasFinished: Bool { return !isRunning && processIdentifier > 0 }
#endif

    private var _terminationStatus: Int32 = 0
    public var terminationStatus: Int32 {
        precondition(hasStarted, "task not launched")
        precondition(hasFinished, "task still running")
        return _terminationStatus
    }

    private var _terminationReason: TerminationReason = .exit
    public var terminationReason: TerminationReason {
        precondition(hasStarted, "task not launched")
        precondition(hasFinished, "task still running")
        return _terminationReason
    }

    /*
    A block to be invoked when the process underlying the Process terminates.  Setting the block to nil is valid, and stops the previous block from being invoked, as long as it hasn't started in any way.  The Process is passed as the argument to the block so the block does not have to capture, and thus retain, it.  The block is copied when set.  Only one termination handler block can be set at any time.  The execution context in which the block is invoked is undefined.  If the Process has already finished, the block is executed immediately/soon (not necessarily on the current thread).  If a terminationHandler is set on an Process, the ProcessDidTerminateNotification notification is not posted for that process.  Also note that -waitUntilExit won't wait until the terminationHandler has been fully executed.  You cannot use this property in a concrete subclass of Process which hasn't been updated to include an implementation of the storage and use of it.  
    */
    open var terminationHandler: ((Process) -> Void)?
    open var qualityOfService: QualityOfService = .default  // read-only after the process is launched


    open class func run(_ url: URL, arguments: [String], terminationHandler: ((Process) -> Void)? = nil) throws -> Process {
        let process = Process()
        process.executableURL = url
        process.arguments = arguments
        process.terminationHandler = terminationHandler
        try process.run()
        return process
    }

    @available(*, deprecated, renamed: "run(_:arguments:terminationHandler:)")
    // convenience; create and launch
    open class func launchedProcess(launchPath path: String, arguments: [String]) -> Process {
        let process = Process()
        process.launchPath = path
        process.arguments = arguments
        process.launch()
    
        return process
    }

    // poll the runLoop in defaultMode until process completes
    open func waitUntilExit() {
        
        repeat {
            
        } while( self.isRunning == true && RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.05)) )
        
        self.runLoop = nil
    }
}

extension Process {
    
    public static let didTerminateNotification = NSNotification.Name(rawValue: "NSTaskDidTerminateNotification")
}
    
private func posix(_ code: Int32) {
    switch code {
    case 0: return
    case EBADF: fatalError("POSIX command failed with error: \(code) -- EBADF")
    default: fatalError("POSIX command failed with error: \(code)")
    }
}
#endif
