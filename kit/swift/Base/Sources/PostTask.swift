// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class PostTaskAndReplyRelay {

  let task: () -> Void
  let reply: () -> Void
  let replyTaskRunner: SequencedTaskRunner?

  public init(
    _ task: @escaping () -> Void,
    _ reply: @escaping () -> Void) {
      self.task = task
      self.reply = reply
      replyTaskRunner = SequencedTaskRunnerHandle.get()
  }

  public static func runTaskAndPostReply(_ relay: PostTaskAndReplyRelay) {
    relay.task()
    if let replyTaskRunner = relay.replyTaskRunner {
      replyTaskRunner.postTask {
        PostTaskAndReplyRelay.runReply(relay)
      }
    }
  }

  static func runReply(_ relay: PostTaskAndReplyRelay) {
    relay.reply()
  }

}

public class PostTaskAndReplyImpl {

  init() {}

  public func postTaskAndReply(
    _ task: @escaping () -> Void,
    _ reply: @escaping () -> Void) {
    
    postTask {
      PostTaskAndReplyRelay.runTaskAndPostReply(PostTaskAndReplyRelay(task, reply))
    }
  }
  
  public func postTask(_ task: @escaping () -> Void) {}

}

public class PostTaskAndReplyTaskRunner : PostTaskAndReplyImpl {
  
  let destination: TaskRunner

  public init(destination: TaskRunner) {
    self.destination = destination
  }

  public override func postTask(_ task: @escaping () -> Void) {
    destination.postTask(task)
  }

}

public func postTask(_ task: @escaping () -> Void) {
  postDelayedTask(task, delay: TimeDelta())
}

public func postDelayedTask(_ task: @escaping () -> Void, delay: TimeDelta) {
  postDelayedTaskWithTraits(task, delay: delay, traits: TaskTraits())
}

public func postTaskWithTraits(_ task: @escaping () -> Void, traits: TaskTraits) {
  postDelayedTaskWithTraits(task, delay: TimeDelta(), traits: traits)
}

public func postDelayedTaskWithTraits(_ task: @escaping () -> Void, delay: TimeDelta, traits: TaskTraits) {
  guard let scheduler = TaskScheduler.instance else {
    return
  }
  scheduler.postDelayedTaskWithTraits(task, delay: delay, traits: traits)
}

public func createTaskRunnerWithTraits(traits: TaskTraits) -> TaskRunner? {
  guard let scheduler = TaskScheduler.instance else {
    return nil
  }
  return scheduler.createTaskRunnerWithTraits(traits: traits)
}

public func createSequencedTaskRunnerWithTraits(traits: TaskTraits) -> SequencedTaskRunner? {
  guard let scheduler = TaskScheduler.instance else {
    return nil
  }
  return scheduler.createSequencedTaskRunnerWithTraits(traits: traits)
}

public func createSingleThreadTaskRunnerWithTraits(traits: TaskTraits, mode: SingleThreadTaskRunnerThreadMode) -> SingleThreadTaskRunner? {
  guard let scheduler = TaskScheduler.instance else {
    return nil
  }
  return scheduler.createSingleThreadTaskRunnerWithTraits(traits, mode: mode)
}
