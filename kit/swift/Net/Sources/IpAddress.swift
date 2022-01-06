// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum AddressFamily : Int {
  case unspecified = 0
  case ipv4 = 1
  case ipv6 = 2
}

public class IpAddress {

  public static let Ipv4AddressSize: Int = 4 
  public static let Ipv6AddressSize: Int = 16

  public static var ipv4LocalHost: IpAddress {
    return IpAddress(bytes: [127, 0, 0, 1])
  }

  public static var ipv6LocalHost: IpAddress {
    return IpAddress(bytes: [0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 1])
  }

  public static var ipv4AllZeros: IpAddress {
    return IpAddress(bytes: [0, 0, 0, 0])
  }

  public static var ipv6AllZeros: IpAddress {
    return IpAddress(bytes: [0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0])
  }

  public var isIpv4: Bool {
    return bytes.count == IpAddress.Ipv4AddressSize
  }

  public var isIpv6: Bool {
    return bytes.count == IpAddress.Ipv6AddressSize
  }

  public var isValid: Bool {
    return isIpv4 || isIpv6
  }

  public var isZero: Bool {
    for x in bytes {
      if x != 0 {
        return false
      }
    }
    return !isEmpty
  }

  public var isEmpty: Bool {
    return bytes.isEmpty
  }
  
  public var bytes: [UInt8] = []
  
  public init() {
    bytes = []
  }

  public init(bytes: [UInt8]) {
    self.bytes = bytes
  }

  public init(_ b0: UInt8, _ b1: UInt8, _ b2: UInt8, _ b3: UInt8) {
    bytes.append(b0)
    bytes.append(b1)
    bytes.append(b2)
    bytes.append(b3)
  }

  public init(_ b0: UInt8, _ b1: UInt8, _ b2: UInt8, _ b3: UInt8,
              _ b4: UInt8, _ b5: UInt8, _ b6: UInt8, _ b7: UInt8,
              _ b8: UInt8, _ b9: UInt8, _ b10: UInt8, _ b11: UInt8,
              _ b12: UInt8, _ b13: UInt8, _ b14: UInt8, _ b15: UInt8) {
    bytes.append(b0)
    bytes.append(b1)
    bytes.append(b2)
    bytes.append(b3)
    bytes.append(b4)
    bytes.append(b5)
    bytes.append(b6)
    bytes.append(b7)
    bytes.append(b8)
    bytes.append(b9)
    bytes.append(b10)
    bytes.append(b11)
    bytes.append(b12)
    bytes.append(b13)
    bytes.append(b14)
    bytes.append(b15)
  }

  public func assignFromFromIpLiteral(ipLiteral: String) -> Bool {
     return parseIpLiteralToBytes(ipLiteral, &bytes)
  }
}

extension IpAddress : Equatable {

  public static func == (rhs: IpAddress, lhs: IpAddress) -> Bool {
    return rhs.bytes == lhs.bytes
  }

}

fileprivate func parseIpLiteralToBytes(_ literal: String, _ bytes: inout [UInt8]) -> Bool {
  return false
}