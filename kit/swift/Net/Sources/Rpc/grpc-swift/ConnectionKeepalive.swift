/*
 * Copyright 2020, gRPC Authors All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//import NIO
import Base

/// Provides keepalive pings.
///
/// The defaults are determined by the gRPC keepalive
/// [documentation] (https://github.com/grpc/grpc/blob/master/doc/keepalive.md).
public struct ClientConnectionKeepalive {
  /// The amount of time to wait before sending a keepalive ping.
  public var interval: TimeDelta

  /// The amount of time to wait for an acknowledgment.
  /// If it does not receive an acknowledgment within this time, it will close the connection
  /// This value must be less than `interval`
  public var timeout: TimeDelta

  /// Send keepalive pings even if there are no calls in flight.
  public var permitWithoutCalls: Bool

  /// Maximum number of pings that can be sent when there is no data/header frame to be sent.
  public var maximumPingsWithoutData: UInt

  /// If there are no data/header frames being received:
  /// The minimum amount of time to wait between successive pings.
  public var minimumSentPingIntervalWithoutData: TimeDelta

  public init(
    interval: TimeDelta = TimeDelta(nanoseconds: Int64.max),
    timeout: TimeDelta = TimeDelta(seconds: 20),
    permitWithoutCalls: Bool = false,
    maximumPingsWithoutData: UInt = 2,
    minimumSentPingIntervalWithoutData: TimeDelta = TimeDelta(seconds: 5 * 60)
  ) {
    precondition(timeout < interval, "`timeout` must be less than `interval`")
    self.interval = interval
    self.timeout = timeout
    self.permitWithoutCalls = permitWithoutCalls
    self.maximumPingsWithoutData = maximumPingsWithoutData
    self.minimumSentPingIntervalWithoutData = minimumSentPingIntervalWithoutData
  }
}

public struct ServerConnectionKeepalive {
  /// The amount of time to wait before sending a keepalive ping.
  public var interval: TimeDelta

  /// The amount of time to wait for an acknowledgment.
  /// If it does not receive an acknowledgment within this time, it will close the connection
  /// This value must be less than `interval`
  public var timeout: TimeDelta

  /// Send keepalive pings even if there are no calls in flight.
  public var permitWithoutCalls: Bool

  /// Maximum number of pings that can be sent when there is no data/header frame to be sent.
  public var maximumPingsWithoutData: UInt

  /// If there are no data/header frames being received:
  /// The minimum amount of time to wait between successive pings.
  public var minimumSentPingIntervalWithoutData: TimeDelta

  /// If there are no data/header frames being sent:
  /// The minimum amount of time expected between receiving successive pings.
  /// If the time between successive pings is less than this value, then the ping will be considered a bad ping from the peer.
  /// Such a ping counts as a "ping strike".
  public var minimumReceivedPingIntervalWithoutData: TimeDelta

  /// Maximum number of bad pings that the server will tolerate before sending an HTTP2 GOAWAY frame and closing the connection.
  /// Setting it to `0` allows the server to accept any number of bad pings.
  public var maximumPingStrikes: UInt

  public init(
    interval: TimeDelta = TimeDelta(seconds: 7200),
    timeout: TimeDelta = TimeDelta(seconds: 20),
    permitWithoutCalls: Bool = false,
    maximumPingsWithoutData: UInt = 2,
    minimumSentPingIntervalWithoutData: TimeDelta = TimeDelta(seconds: 5 * 60),
    minimumReceivedPingIntervalWithoutData: TimeDelta = TimeDelta(seconds: 5 * 60),
    maximumPingStrikes: UInt = 2
  ) {
    precondition(timeout < interval, "`timeout` must be less than `interval`")
    self.interval = interval
    self.timeout = timeout
    self.permitWithoutCalls = permitWithoutCalls
    self.maximumPingsWithoutData = maximumPingsWithoutData
    self.minimumSentPingIntervalWithoutData = minimumSentPingIntervalWithoutData
    self.minimumReceivedPingIntervalWithoutData = minimumReceivedPingIntervalWithoutData
    self.maximumPingStrikes = maximumPingStrikes
  }
}
