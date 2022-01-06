//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
import NIO
import Dispatch
import Foundation

class BlockingIOThreadPoolTest: XCTestCase {
    func testDoubleShutdownWorks() throws {
        let threadPool = BlockingIOThreadPool(numberOfThreads: 17)
        threadPool.start()
        try threadPool.syncShutdownGracefully()
        try threadPool.syncShutdownGracefully()
    }

    func testStateCancelled() throws {
        let threadPool = BlockingIOThreadPool(numberOfThreads: 17)
        let group = DispatchGroup()
        group.enter()
        threadPool.submit { state in
            XCTAssertEqual(BlockingIOThreadPool.WorkItemState.cancelled, state)
            group.leave()
        }
        group.wait()
        try threadPool.syncShutdownGracefully()
    }

    func testStateActive() throws {
        let threadPool = BlockingIOThreadPool(numberOfThreads: 17)
        threadPool.start()
        let group = DispatchGroup()
        group.enter()
        threadPool.submit { state in
            XCTAssertEqual(BlockingIOThreadPool.WorkItemState.active, state)
            group.leave()
        }
        group.wait()
        try threadPool.syncShutdownGracefully()
    }

    func testLoseLastReferenceAndShutdownWhileTaskStillRunning() throws {
        let blockThreadSem = DispatchSemaphore(value: 0)
        let allDoneSem = DispatchSemaphore(value: 0)

        ({
            let threadPool = BlockingIOThreadPool(numberOfThreads: 2)
            threadPool.start()
            threadPool.submit { _ in
                Foundation.Thread.sleep(forTimeInterval: 0.1)
            }
            threadPool.submit { _ in
                blockThreadSem.wait()
            }
            threadPool.shutdownGracefully { error in
                XCTAssertNil(error)
                allDoneSem.signal()
            }
        })()
        blockThreadSem.signal()
        allDoneSem.wait()
    }

    func testDeadLockIfCalledOutWithLockHeld() throws {
        let blockRunningSem = DispatchSemaphore(value: 0)
        let blockOneThreadSem = DispatchSemaphore(value: 0)
        let threadPool = BlockingIOThreadPool(numberOfThreads: 1)
        let allDone = DispatchSemaphore(value: 0)
        threadPool.start()
        // enqueue one that'll block the whole pool (1 thread only)
        threadPool.submit { state in
            XCTAssertEqual(state, .active)
            blockRunningSem.signal()
            blockOneThreadSem.wait()
        }
        blockRunningSem.wait()
        // enqueue one that will be cancelled and then calls shutdown again which needs the lock
        threadPool.submit { state in
            XCTAssertEqual(state, .cancelled)
            threadPool.shutdownGracefully { error in
                XCTAssertNil(error)
            }
        }
        threadPool.shutdownGracefully { error in
            XCTAssertNil(error)
            allDone.signal()
        }
        blockOneThreadSem.signal() // that'll unblock the thread in the pool
        allDone.wait()
    }

    func testPoolDoesGetReleasedWhenStoppedAndReferencedDropped() throws {
        let taskRunningSem = DispatchSemaphore(value: 0)
        let doneSem = DispatchSemaphore(value: 0)
        let shutdownDoneSem = DispatchSemaphore(value: 0)
        weak var weakThreadPool: BlockingIOThreadPool? = nil
        ({
            let threadPool = BlockingIOThreadPool(numberOfThreads: 1)
            weakThreadPool = threadPool
            threadPool.start()
            threadPool.submit { state in
                XCTAssertEqual(.active, state)
                taskRunningSem.signal()
                doneSem.wait()
            }
            taskRunningSem.wait()
            threadPool.shutdownGracefully { error in
                XCTAssertNil(error)
                shutdownDoneSem.signal()
            }
        })()
        XCTAssertNotNil(weakThreadPool)
        doneSem.signal()
        shutdownDoneSem.wait()
        assert(weakThreadPool == nil, within: .seconds(1))
    }
}
