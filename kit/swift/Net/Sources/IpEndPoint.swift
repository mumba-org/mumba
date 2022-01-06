// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class IpEndPoint {
  public var address: IpAddress = IpAddress()
  public var port: Int = 0
  public var addressFamily: AddressFamily = AddressFamily.unspecified

  public init() {
    address = IpAddress()
    port = 0
    addressFamily = AddressFamily.unspecified
  }

  public init(address: IpAddress, port: Int) {
    self.address = address
    self.port = port
  }

}

public class HostAndIpEndPoint {
  public var hostname: String
  public var ipAddress: IpEndPoint

  public init() {
    hostname = String()
    ipAddress = IpEndPoint()
  }

  public init(hostname: String, ipAddress: IpEndPoint) {
    self.hostname = hostname
    self.ipAddress = ipAddress
  }
}


extension IpEndPoint : Equatable {

  public static func == (rhs: IpEndPoint, lhs: IpEndPoint) -> Bool {
    return rhs.address == lhs.address && rhs.port == lhs.port && rhs.addressFamily == lhs.addressFamily
  }

}
