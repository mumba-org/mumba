// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct SchedulerWorkerStack {
  
  private var stack: ContiguousArray<SchedulerWorker>

  public var count: Int {
    return stack.count
  }

  public var isEmpty: Bool { 
    return stack.isEmpty
  }

  public init() {
    stack = ContiguousArray<SchedulerWorker>()
  }
   
  public mutating func push(_ worker: SchedulerWorker) {
    stack.append(worker)
  }

  public mutating func pop() -> SchedulerWorker? {
    guard !isEmpty else {
      return nil
    }
    let worker = stack.last
    stack.removeLast()
    return worker
  }

  public func peek() -> SchedulerWorker? {
    return stack.last
  }

  public func contains(_ worker: SchedulerWorker) -> Bool {
    if stack.firstIndex(of: worker) != nil {
      return true
    }
    return false
  }

  public mutating func remove(_ worker: SchedulerWorker) {
    if let index = stack.firstIndex(of: worker) {
      stack.remove(at: index)
    }
  }

}