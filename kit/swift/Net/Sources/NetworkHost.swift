// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base

public enum NetworkConnectionType : Int {
   case unknown = 0  // a connection exists, but its type is unknown
   case ethernet = 1
   case wifi = 2
   case twoG = 3
   case threeG = 4
   case fourG = 5
   case none = 6     // no connection
   case bluetooth = 7
}

public enum NetworkConnectionSubtype : Int {
  case unknown = 0
  case none
  case other
  case gsm
  case iden
  case cdma
  case oneXRtt
  case gprs
  case edge
  case umts
  case evdoRev0
  case evdoRevA
  case hspa
  case evdoRevB
  case hsdpa
  case hsupa
  case ehrpd
  case hspap
  case lte
  case lteAdvanced
  case bluetooth1_2
  case bluetooth2_1
  case bluetooth3_0
  case bluetooth4_0
  case ethernet
  case fastEthernet
  case gigabitEthernet
  case tenGigabitEthernet
  case wifiB
  case wifiG
  case wifiN
  case wifiAc
  case wifiAd
}

public protocol NetworkObserver : class {
  func onStateChanged(state: NetworkConnectionType)
}


public class NetworkInterface {
  public var name: String = String()
  public var friendlyName: String = String()
  public var interfaceIndex: UInt32 = 0
  public var type: NetworkConnectionType = NetworkConnectionType.unknown
  public var address: IpAddress = IpAddress()
  public var prefixLength: UInt32 = 0
  public var ipAddressAttributes: Int = 0
}

public class NetworkHost {

  public static let instance: NetworkHost = NetworkHost()

  public static var isOffline: Bool {
    return true 
  }

  public private(set) var state: NetworkConnectionType = NetworkConnectionType.unknown

  public private(set) var observers: Array<NetworkObserver> = Array<NetworkObserver>()

  public private(set) var interfaces: Array<NetworkInterface> = Array<NetworkInterface>()

  public var containerContext: ShellContextRef?

  public static func initialize(context: ShellContextRef) {
     NetworkHost.instance.containerContext = context
  }

  public init() {}

  public func addObserver(_ observer: NetworkObserver) {
    observers.append(observer)
  }

  public func removeObserver(_ observer: NetworkObserver) {
    if let index = observers.firstIndex(where: { $0 === observer } ) {
      observers.remove(at: index)
    }
  }

}