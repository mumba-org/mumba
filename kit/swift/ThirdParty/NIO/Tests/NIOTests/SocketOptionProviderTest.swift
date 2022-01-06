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

import NIO
import XCTest

final class SocketOptionProviderTest: XCTestCase {
    var group: MultiThreadedEventLoopGroup!
    var serverChannel: Channel!
    var clientChannel: Channel!
    var ipv4DatagramChannel: Channel!
    var ipv6DatagramChannel: Channel?

    struct CastError: Error { }

    private func convertedChannel(file: StaticString = #file, line: UInt = #line) throws -> SocketOptionProvider {
        guard let provider = self.clientChannel as? SocketOptionProvider else {
            XCTFail("Unable to cast \(String(describing: self.clientChannel)) to SocketOptionProvider", file: file, line: line)
            throw CastError()
        }
        return provider
    }

    private func ipv4MulticastProvider(file: StaticString = #file, line: UInt = #line) throws -> SocketOptionProvider {
        guard let provider = self.ipv4DatagramChannel as? SocketOptionProvider else {
            XCTFail("Unable to cast \(String(describing: self.ipv4DatagramChannel)) to SocketOptionProvider", file: file, line: line)
            throw CastError()
        }
        return provider
    }

    private func ipv6MulticastProvider(file: StaticString = #file, line: UInt = #line) throws -> SocketOptionProvider? {
        guard let ipv6Channel = self.ipv6DatagramChannel else {
            return nil
        }

        guard let provider = ipv6Channel as? SocketOptionProvider else {
            XCTFail("Unable to cast \(ipv6Channel)) to SocketOptionChannel", file: file, line: line)
            throw CastError()
        }

        return provider
    }

    override func setUp() {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.serverChannel = try? assertNoThrowWithValue(ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).wait())
        self.clientChannel = try? assertNoThrowWithValue(ClientBootstrap(group: group).connect(to: serverChannel.localAddress!).wait())

        // We need to join these multicast groups on the loopback interface to work around issues with rapidly joining and leaving
        // many multicast groups. On some OSes, if we do that on a public interface, we can build up a kernel backlog of IGMP
        // joins/leaves that may eventually lead to an ENOMEM and a spurious test failure. As joining/leaving groups on loopback
        // interfaces does not require IGMP joins/leaves, forcing these joins onto the loopback interface saves us from this
        // risk.
        let v4LoopbackAddress = try! SocketAddress(ipAddress: "127.0.0.1", port: 0)
        let v6LoopbackAddress = try! SocketAddress(ipAddress: "::1", port: 0)
        let v4LoopbackInterface = try! System.enumerateInterfaces().filter { $0.address == v4LoopbackAddress }.first!

        self.ipv4DatagramChannel = try? assertNoThrowWithValue(
            DatagramBootstrap(group: group).bind(host: "127.0.0.1", port: 0).then { channel in
                return (channel as! MulticastChannel).joinGroup(try! SocketAddress(ipAddress: "224.0.2.66", port: 0), interface: v4LoopbackInterface).map { channel }
            }.wait()
        )

        // The IPv6 setup is allowed to fail, some hosts don't have IPv6.
       let v6LoopbackInterface = try! System.enumerateInterfaces().filter { $0.address == v6LoopbackAddress }.first
        self.ipv6DatagramChannel = try? DatagramBootstrap(group: group).bind(host: "::1", port: 0).then { channel in
            return (channel as! MulticastChannel).joinGroup(try! SocketAddress(ipAddress: "ff12::beeb", port: 0), interface: v6LoopbackInterface).map { channel }
        }.wait()
    }

    override func tearDown() {
        XCTAssertNoThrow(try ipv6DatagramChannel?.close().wait())
        XCTAssertNoThrow(try ipv4DatagramChannel.close().wait())
        XCTAssertNoThrow(try clientChannel.close().wait())
        XCTAssertNoThrow(try serverChannel.close().wait())
        XCTAssertNoThrow(try group.syncShutdownGracefully())
    }

    func testSettingAndGettingComplexSocketOption() throws {
        let provider = try assertNoThrowWithValue(self.convertedChannel())

        let newTimeout = timeval(tv_sec: 5, tv_usec: 0)
        let retrievedTimeout = try assertNoThrowWithValue(provider.unsafeSetSocketOption(level: SocketOptionLevel(SOL_SOCKET), name: SO_RCVTIMEO, value: newTimeout).then {
            provider.unsafeGetSocketOption(level: SocketOptionLevel(SOL_SOCKET), name: SO_RCVTIMEO) as EventLoopFuture<timeval>
        }.wait())

        XCTAssertEqual(retrievedTimeout.tv_sec, newTimeout.tv_sec)
        XCTAssertEqual(retrievedTimeout.tv_usec, newTimeout.tv_usec)
    }

    func testObtainingDefaultValueOfComplexSocketOption() throws {
        let provider = try assertNoThrowWithValue(self.convertedChannel())

        let retrievedTimeout: timeval = try assertNoThrowWithValue(provider.unsafeGetSocketOption(level: SocketOptionLevel(SOL_SOCKET), name: SO_RCVTIMEO).wait())
        XCTAssertEqual(retrievedTimeout.tv_sec, 0)
        XCTAssertEqual(retrievedTimeout.tv_usec, 0)
    }

    func testSettingAndGettingSimpleSocketOption() throws {
        let provider = try assertNoThrowWithValue(self.convertedChannel())

        let newReuseAddr = 1 as CInt
        let retrievedReuseAddr = try assertNoThrowWithValue(provider.unsafeSetSocketOption(level: SocketOptionLevel(SOL_SOCKET), name: SO_REUSEADDR, value: newReuseAddr).then {
            provider.unsafeGetSocketOption(level: SocketOptionLevel(SOL_SOCKET), name: SO_REUSEADDR) as EventLoopFuture<CInt>
        }.wait())

        XCTAssertNotEqual(retrievedReuseAddr, 0)
    }

    func testObtainingDefaultValueOfSimpleSocketOption() throws {
        let provider = try assertNoThrowWithValue(self.convertedChannel())

        let reuseAddr: CInt = try assertNoThrowWithValue(provider.unsafeGetSocketOption(level: SocketOptionLevel(SOL_SOCKET), name: SO_REUSEADDR).wait())
        XCTAssertEqual(reuseAddr, 0)
    }

    func testPassingInvalidSizeToSetComplexSocketOptionFails() throws {
        // You'll notice that there are no other size mismatch tests in this file. The reason for that is that
        // setsockopt is pretty dumb, and getsockopt is dumber. Specifically, setsockopt checks only that the length
        // of the option value is *at least as large* as the expected struct (which is why this test will actually
        // work), and getsockopt will happily return without error even in the buffer is too small. Either way,
        // we just abandon the other tests: this is sufficient to prove that the error path works.
        let provider = try assertNoThrowWithValue(self.convertedChannel())

        do {
            try provider.unsafeSetSocketOption(level: SocketOptionLevel(SOL_SOCKET), name: SO_RCVTIMEO, value: CInt(1)).wait()
            XCTFail("Did not throw")
        } catch let err as IOError where err.errnoCode == EINVAL {
            // Acceptable error
        } catch {
            XCTFail("Invalid error: \(error)")
        }
    }


    // MARK: Tests for the safe helper functions.
    func testLinger() throws {
        let newLingerValue = linger(l_onoff: 1, l_linger: 64)

        let provider = try self.convertedChannel()
        XCTAssertNoThrow(try provider.setSoLinger(newLingerValue).then {
            provider.getSoLinger()
        }.map {
            XCTAssertEqual($0.l_linger, newLingerValue.l_linger)
            XCTAssertEqual($0.l_onoff, newLingerValue.l_onoff)
        }.wait())
    }

    func testSoIpMulticastIf() throws {
        let channel = self.ipv4DatagramChannel!
        let provider = try assertNoThrowWithValue(self.ipv4MulticastProvider())

        let address: in_addr
        switch channel.localAddress! {
        case .v4(let addr):
            address = addr.address.sin_addr
        default:
            XCTFail("Local address must be IPv4!")
            return
        }

        XCTAssertNoThrow(try provider.setIPMulticastIF(address).then {
            provider.getIPMulticastIF()
        }.map {
            XCTAssertEqual($0.s_addr, address.s_addr)
        }.wait())
    }

    func testIpMulticastTtl() throws {
        let provider = try assertNoThrowWithValue(self.ipv4MulticastProvider())
        XCTAssertNoThrow(try provider.setIPMulticastTTL(6).then {
            provider.getIPMulticastTTL()
        }.map {
            XCTAssertEqual($0, 6)
        }.wait())
    }

    func testIpMulticastLoop() throws {
        let provider = try assertNoThrowWithValue(self.ipv4MulticastProvider())
        XCTAssertNoThrow(try provider.setIPMulticastLoop(1).then {
            provider.getIPMulticastLoop()
        }.map {
            XCTAssertNotEqual($0, 0)
        }.wait())
    }

    func testIpv6MulticastIf() throws {
        guard let provider = try assertNoThrowWithValue(self.ipv6MulticastProvider()) else {
            // Skip on systems without IPv6.
            return
        }

        // TODO: test this when we know what the interface indices are.
        let loopbackAddress = try assertNoThrowWithValue(SocketAddress(ipAddress: "::1", port: 0))
        guard let loopbackInterface = try assertNoThrowWithValue(System.enumerateInterfaces().filter({ $0.address == loopbackAddress }).first) else {
            XCTFail("Could not find index of loopback address")
            return
        }

        XCTAssertNoThrow(try provider.setIPv6MulticastIF(CUnsignedInt(loopbackInterface.interfaceIndex)).then {
            provider.getIPv6MulticastIF()
        }.map {
            XCTAssertEqual($0, CUnsignedInt(loopbackInterface.interfaceIndex))
        }.wait())
    }

    func testIPv6MulticastHops() throws {
        guard let provider = try assertNoThrowWithValue(self.ipv6MulticastProvider()) else {
            // Skip on systems without IPv6.
            return
        }

        XCTAssertNoThrow(try provider.setIPv6MulticastHops(6).then {
            provider.getIPv6MulticastHops()
        }.map {
            XCTAssertEqual($0, 6)
        }.wait())
    }

    func testIPv6MulticastLoop() throws {
        guard let provider = try assertNoThrowWithValue(self.ipv6MulticastProvider()) else {
            // Skip on systems without IPv6.
            return
        }

        XCTAssertNoThrow(try provider.setIPv6MulticastLoop(1).then {
            provider.getIPv6MulticastLoop()
        }.map {
            XCTAssertNotEqual($0, 0)
        }.wait())
    }
}
