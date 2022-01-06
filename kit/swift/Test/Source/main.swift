// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

let waitSecs: Int64 = 5

func doTask(name: StaticString, exit: RunLoopQuit, count: Int) {
  print("hello from task \(name)")
  if count == 2 {
   exit()
  }
}

func dedicatedTask(r: RunLoop) {
  print("sucessfully run dedicatedTask on a dedicated single thread")
  postDelayedTask({ doTask(name: "A", exit: r.exitClosure, count: 0) }, delay: TimeDelta.from(seconds: waitSecs))
  postDelayedTask({ doTask(name: "B", exit: r.exitClosure, count: 1) }, delay: TimeDelta.from(seconds: waitSecs * 2))
  postDelayedTask({ doTask(name: "C", exit: r.exitClosure, count: 2) }, delay: TimeDelta.from(seconds: waitSecs * 3))
}

do {
  
  try TaskScheduler.createAndStartWithDefaultParams()

  let dedicated: SingleThreadTaskRunner = TaskScheduler.instance!.createSingleThreadTaskRunnerWithTraits(TaskTraits(), mode: .dedicated)//.shared)
  //let dedicated: SequencedTaskRunner = TaskScheduler.instance!.createSequencedTaskRunnerWithTraits(traits: TaskTraits())

  let _ = try MessageLoop(type: .IO)
 
  let r = RunLoop()

  dedicated.postTask {
    dedicatedTask(r: r)
  }

  r.run()
} catch {
  print("error on TaskScheduler.createAndStartWithDefaultParams() or MessageLoop(type: .IO)") 
}