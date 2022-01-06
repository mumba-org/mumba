// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

// Implemented by clients which take compositor lock. Used to notify the client
// when their lock times out.
public protocol UICompositorLockClient {
  // Called if the CompositorLock ends before being destroyed due to timeout.
  func compositorLockTimedOut()
}

// Implemented by clients which are locked by a compositor lock. Used by the
// CompositorLockManager to notify their parent that lock state has changed.
public protocol UICompositorLockManagerClient {
 func onCompositorLockStateChanged(locked: Bool)
}

// A helper class used to manage compositor locks. Should be created/used by
// classes which want to provide out compositor locking.
public class UICompositorLockManager {
  
  public var isLocked: Bool {
     return !activeLocks.isEmpty
  }

  public var allowLocksToExtendTimeout: Bool = false

  // The TaskRunner on which timeouts are run.
  private var taskRunner: SingleThreadTaskRunner?
  // A client which is notified about lock state changes.
  private var client: UICompositorLockManagerClient?
  // The estimated time that the locks will timeout.
  private var scheduledTimeout: TimeTicks = TimeTicks()
  // The set of locks that are held externally.
  private var activeLocks: [UICompositorLock] = []

  public init (taskRunner: SingleThreadTaskRunner?,
               client: UICompositorLockManagerClient) {
    self.taskRunner = taskRunner
    self.client = client
  }

  public func getCompositorLock(
      client: UICompositorLockClient,
      timeout: TimeDelta) -> UICompositorLock? {
    return nil
  }

  private func timeoutLocks() {

  }

  private func removeCompositorLock(lock: UICompositorLock) {

  }

}

public class UICompositorLock {
  let client: UICompositorLockClient?
  weak var manager: UICompositorLockManager?

  public init(client: UICompositorLockClient,
              manager: UICompositorLockManager) {
    self.client = client
    self.manager = manager
  }

  // Causes the CompositorLock to end due to a timeout.
  private func timeoutLock() {

  }
}
