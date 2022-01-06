// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

internal class SequenceAndSortKey {

  let sequence: TaskSequence
  let sortkey: TaskSequenceSortKey

  init(sequence: TaskSequence, sortkey: TaskSequenceSortKey) {
    self.sequence = sequence
    self.sortkey = sortkey
  }

}

extension SequenceAndSortKey : Comparable {

  public static func == (lhs: SequenceAndSortKey, rhs: SequenceAndSortKey) -> Bool {
    return lhs.sortkey == rhs.sortkey && lhs.sequence === rhs.sequence
  }

  public static func < (lhs: SequenceAndSortKey, rhs: SequenceAndSortKey) -> Bool {
    return lhs.sortkey < rhs.sortkey
  }

}

public final class SchedulerPriorityQueue {
  
  public class Transaction {
    
    public var count: Int {
      return queue.container.count
    }

    public var isEmpty: Bool {
      return queue.container.isEmpty
    }

    let lock: Lock
    let queue: SchedulerPriorityQueue

    var peekSortKey: TaskSequenceSortKey? {
      if let item = queue.container.peek() {
        return item.sortkey
      }
      return nil
    }

    internal init(queue: SchedulerPriorityQueue) {
      self.queue = queue
      lock = queue.containerLock
      lock.lock()
    }

    deinit {
      lock.unlock()
    }
    
    public func push(sequence: TaskSequence,
                     sortKey: TaskSequenceSortKey) {
      queue.container.push(SequenceAndSortKey(sequence: sequence, sortkey: sortKey))
    }

    public func popSequence() -> TaskSequence? {
      if let item = queue.container.peek() {
        queue.container.pop()
        return item.sequence
      }
      return nil
    }

  }

  var container: PriorityQueue<SequenceAndSortKey>
  let containerLock: Lock = Lock()

  public init() {
    container = PriorityQueue<SequenceAndSortKey>()
  }

  public func beginTransaction() -> Transaction {
    return Transaction(queue: self)
  }

}