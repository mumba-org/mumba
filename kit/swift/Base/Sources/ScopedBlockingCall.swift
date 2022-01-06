// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum BlockingType {
  // The call might block
  case mayBlock
  // The call will definitely block
  case willBlock
}

// because the implementors of this need to be in a TLS
// this cannot be a protocol
public protocol BlockingObserver : class {
  func blockingStarted(type: BlockingType)
  func blockingTypeUpgraded()
  func blockingEnded()
}

// a class to hold a instance of a BlockingObserver impl
// so we can keep the BlockingObserver on a TLS without
// needing it  to be a class => AnyObject
fileprivate class BlockingObserverTLSState {
  fileprivate let observer: BlockingObserver
  fileprivate init(_ observer: BlockingObserver) {
    self.observer = observer
  }
}

// Registers |blocking_observer| on the current thread. It is invalid to call
// this on a thread where there is an active ScopedBlockingCall.
public func setBlockingObserverForCurrentThread(observer: BlockingObserver) {
  tlsBlockingObserver.currentValue = BlockingObserverTLSState(observer)
}

class ScopedBlockingCall {
  
  var isWillBlock: Bool = false
  let blockingObserver: BlockingObserver?
  let previousScopedBlockingCall: ScopedBlockingCall?

  public init(type blockingType: BlockingType) {
    blockingObserver = tlsBlockingObserver.currentValue?.observer
    previousScopedBlockingCall = tlsLastScopedBlockingCall.currentValue
    isWillBlock = (blockingType == BlockingType.willBlock ||
                     (previousScopedBlockingCall != nil &&
                      previousScopedBlockingCall!.isWillBlock))
    tlsLastScopedBlockingCall.currentValue = self

    if let observer = blockingObserver {
      if previousScopedBlockingCall == nil {
        observer.blockingStarted(type: blockingType)
      } else if blockingType == BlockingType.willBlock && 
        !previousScopedBlockingCall!.isWillBlock {
        observer.blockingTypeUpgraded()
      }
    }
  }

  deinit {
    tlsLastScopedBlockingCall.currentValue = previousScopedBlockingCall
    if let observer = blockingObserver, previousScopedBlockingCall == nil {
      observer.blockingEnded()
    }
  }
  
}

fileprivate let tlsLastScopedBlockingCall: ThreadSpecificVariable<ScopedBlockingCall> = ThreadSpecificVariable<ScopedBlockingCall>()

fileprivate let tlsBlockingObserver: ThreadSpecificVariable<BlockingObserverTLSState> = ThreadSpecificVariable<BlockingObserverTLSState>()
