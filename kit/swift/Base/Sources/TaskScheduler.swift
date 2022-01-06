// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct SchedulerWorkerPoolParams {
  public var maxThreads: Int = 0
  public var suggestedReclaimTime: TimeDelta = TimeDelta()

  public init(_ maxThreads: Int, _ suggestedReclaimTime: TimeDelta) {
    self.maxThreads = maxThreads
    self.suggestedReclaimTime = suggestedReclaimTime
  }
}

public class TaskScheduler {

  public struct InitParams {
    public var backgroundWorkerPool: SchedulerWorkerPoolParams
    public var backgroundBlockingWorkerPool: SchedulerWorkerPoolParams
    public var foregroundWorkerPool: SchedulerWorkerPoolParams
    public var foregroundBlockingWorkerPool: SchedulerWorkerPoolParams
  }

  public static func createAndStartWithDefaultParams() throws {
    TaskScheduler.create()
    try instance!.startWithDefaultParams()
  }

  public static func create() {
    TaskScheduler.instance = TaskScheduler(taskTracker: TaskTracker())
  }
  
  public static var instance: TaskScheduler?

  let serviceThread: Thread
  let taskTracker: TaskTracker
  let delayedTaskManager: DelayedTaskManager = DelayedTaskManager(tickClock: DefaultTickClock())
  let singleThreadTaskRunnerManager: SchedulerSingleThreadTaskRunnerManager

  // There are 4 SchedulerWorkerPool in this array to match the 4
  // SchedulerWorkerPoolParams in TaskScheduler.InitParams.
  var workerPools: Array<SchedulerWorkerPool> = Array<SchedulerWorkerPool>()

  public init(taskTracker: TaskTracker) {
    serviceThread = Thread(name: "TaskSchedulerServiceThread")
    self.taskTracker = taskTracker
    singleThreadTaskRunnerManager = 
      SchedulerSingleThreadTaskRunnerManager(
        taskTracker: taskTracker, 
        delayedTaskManager: delayedTaskManager)

    for environmentType in  0..<EnvironmentType.allCases.count {
      workerPools.insert( 
        SchedulerWorkerPool(
          poolLabel: String("TaskScheduler" + environmentParams[environmentType].nameSuffix),
          priorityHint: environmentParams[environmentType].priorityHint,
          taskTracker: taskTracker, 
          delayedTaskManager: delayedTaskManager),
        at: environmentType)
    }
  }

  public func start(params: InitParams) throws {
    // Start the service thread. On platforms that support it (POSIX except NaCL
    // SFI), the service thread runs a MessageLoopForIO which is used to support
    // FileDescriptorWatcher in the scope in which tasks run.
    var serviceThreadOptions = ThreadOptions()
    serviceThreadOptions.messageLoopType = MessageLoopType.IO
  //#if os(Linux) || os(macOS) // posix
  //      MessageLoopType.IO
  //#else
  //      MessageLoopType.default
  //#endif

    //serviceThreadOptions.timerSlack = TimerSlack.maximum
    //assert(serviceThread.startWithOptions(serviceThreadOptions))
    let _ = serviceThread.start(options: serviceThreadOptions)

  #if os(Linux) || os(macOS) // posix
    // Needs to happen after starting the service thread to get its
    // message_loop().
    //taskTracker.setWatchFileDescriptorMessageLoop(serviceThread.messageLoop as! IOMessageLoop)
    taskTracker.watchFileDescriptorMessageLoop = serviceThread.messageLoop
  #endif  // defined(OS_POSIX) && !defined(OS_NACL_SFI)

    // Needs to happen after starting the service thread to get its task_runner().
    guard let serviceThreadTaskRunner = serviceThread.taskRunner else {
      throw SystemError.IOError(code: 0, reason: "service thread task runners is not available")
    }
    
    delayedTaskManager.start(taskRunner: serviceThreadTaskRunner)

    singleThreadTaskRunnerManager.start()

    let workerEnvironment = WorkerEnvironment.none

    workerPools[EnvironmentType.background.rawValue].start(
      params: params.backgroundWorkerPool,
      serviceThreadTaskRunner: serviceThreadTaskRunner,
      workerEnvironment: workerEnvironment)

    workerPools[EnvironmentType.backgroundBlocking.rawValue].start(
        params: params.backgroundBlockingWorkerPool,
        serviceThreadTaskRunner: serviceThreadTaskRunner, 
        workerEnvironment: workerEnvironment)

    workerPools[EnvironmentType.foreground.rawValue].start(
        params: params.foregroundWorkerPool,
        serviceThreadTaskRunner: serviceThreadTaskRunner,
        workerEnvironment: workerEnvironment)

    workerPools[EnvironmentType.foregroundBlocking.rawValue].start(
        params: params.foregroundBlockingWorkerPool,
        serviceThreadTaskRunner: serviceThreadTaskRunner, 
        workerEnvironment: workerEnvironment)
  }

  public func startWithDefaultParams() throws {
    let numCores = SysInfo.numberOfCores
    let backgroundMaxThreads = 1
    let backgroundBlockingMaxThreads = 2
    let foregroundMaxThreads = max(1, numCores - 1)
    let foregroundBlockingMaxThreads = max(2, numCores - 1)

    let suggestedReclaimTime = TimeDelta.from(seconds: 30)

    try start(params: 
            InitParams(
              backgroundWorkerPool: SchedulerWorkerPoolParams(backgroundMaxThreads, suggestedReclaimTime),
              backgroundBlockingWorkerPool: SchedulerWorkerPoolParams(backgroundBlockingMaxThreads, suggestedReclaimTime),
              foregroundWorkerPool: SchedulerWorkerPoolParams(foregroundMaxThreads, suggestedReclaimTime),
              foregroundBlockingWorkerPool: SchedulerWorkerPoolParams(foregroundBlockingMaxThreads, suggestedReclaimTime)))
  }

  public func shutdown() {
    taskTracker.shutdown()
  }

  public func postDelayedTaskWithTraits(_ task: @escaping () -> Void,
                                        delay: TimeDelta,
                                        traits: TaskTraits) {
    // Post |task| as part of a one-off single-task TaskSequence.
    let newTraits = setUserBlockingPriorityIfNeeded(traits)
    let _ = getWorkerPoolForTraits(newTraits).postTaskWithSequence(task: Task(task: Closure(task), traits: newTraits, delay: delay), sequence: TaskSequence())
  }

  public func createTaskRunnerWithTraits(traits: TaskTraits) -> TaskRunner {
    let newTraits = setUserBlockingPriorityIfNeeded(traits)
    return getWorkerPoolForTraits(newTraits).createTaskRunnerWithTraits(traits: newTraits)
  }

  public func createSequencedTaskRunnerWithTraits(traits: TaskTraits) -> SequencedTaskRunner {
    let newTraits = setUserBlockingPriorityIfNeeded(traits)
    return getWorkerPoolForTraits(newTraits).createSequencedTaskRunnerWithTraits(traits: newTraits)
  }

  public func createSingleThreadTaskRunnerWithTraits(
      _ traits: TaskTraits,
      mode: SingleThreadTaskRunnerThreadMode) -> SingleThreadTaskRunner {
    return singleThreadTaskRunnerManager.createSingleThreadTaskRunnerWithTraits(
          traits: setUserBlockingPriorityIfNeeded(traits), threadMode: mode)
  }

  func getWorkerPoolForTraits(_ traits: TaskTraits) -> SchedulerWorkerPool {
    return workerPools[EnvironmentType.getEnvironmentIndexForTraits(traits)]
  }

  func setUserBlockingPriorityIfNeeded(_ traits: TaskTraits) -> TaskTraits {
    //return allTasksUserBlocking.isSet
    //         ? TaskTraits.override(traits, {TaskPriority.userBlocking})
    //         : traits
    return traits
  }


}