import MumbaShims
import Base

public enum WebConnectionType : Int {
  case Cellular2G = 0
  case Cellular3G = 1
  case Cellular4G = 2
  case Bluetooth = 3
  case Ethernet = 4
  case Wifi = 5
  case Wimax = 6
  case Other = 7
  case None = 8
  case Unknown = 9
}

public enum WebEffectiveConnectionType : Int {
  case Unknown = 0
  case Offline = 1
  case Slow2G = 2
  case Cellular2G = 3
  case Cellular3G = 4
  case Cellular4G = 5
}

public struct WebNetworkStateNotifier {
  
  public static func setOnline(_ online: Bool) {
  	_WebNetworkStateNotifierSetOnline(online ? 1 : 0)
  }
  
  public static func setWebConnection(connectionType: WebConnectionType, maxBandwidthMbps: Double) {
  	_WebNetworkStateNotifierSetWebConnection(CInt(connectionType.rawValue), maxBandwidthMbps)
  }
  
  public static func setNetworkQuality(
      connectionType: WebEffectiveConnectionType,
      httpRtt: TimeDelta,
      transportRtt: TimeDelta,
      downlinkThroughputKbps: Int) {
    _WebNetworkStateNotifierSetNetworkQuality(CInt(connectionType.rawValue), httpRtt.microseconds, transportRtt.microseconds, CInt(downlinkThroughputKbps))
  }
  
  public static func setSaveDataEnabled(_ enabled: Bool) {
  	_WebNetworkStateNotifierSetSaveDataEnabled(enabled ? 1 : 0)
  }
}