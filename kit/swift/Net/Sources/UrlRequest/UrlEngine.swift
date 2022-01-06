// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims
#if os(macOS)
import Darwin
#elseif os(Linux)
import Glibc
#endif

public enum HttpCacheMode : Int {
  case Disabled = 0
  case InMemory = 1
  case DiskNoHttp = 2
  case Disk = 3
}

public struct PublicKeyPin {
  public var host: String = String()
  public var includeSubdomains: Bool = true
  public var expirationDate: Int64
  public var sha256: [String] = []
}

public struct UrlEngineParams {
  public var enableCheckResult: Bool = true
  public var userAgent: String = String()
  public var acceptLanguage: String = String()
  public var storagePath: String = String()
  public var enableQuic: Bool = true
  public var enableHttp2: Bool = true
  public var enableBrotli: Bool = true
  public var httpCacheMode: HttpCacheMode = HttpCacheMode.Disk
  public var httpCacheMaxSize: Int64 = 0
  public var enablePublicKeyPinningBypassForLocalTrustAnchors: Bool = true
  public var experimentalOptions: String = String()
  public var publicKeyPins: [PublicKeyPin] = []

  public init() {}
}

public class UrlEngine {

  public var versionString: String {
    return String(cString: Cronet_Engine_GetVersionString(reference)!)
  }

  public var defaultUserAgent: String {
    return String(cString: Cronet_Engine_GetDefaultUserAgent(reference)!)
  }

  public var enableCheckResult: Bool {
    get {
      return Cronet_EngineParams_enable_check_result_get(params) != 0
    }
    set {
      Cronet_EngineParams_enable_check_result_set(params, newValue ? 1 : 0)
    }
  }

  public var userAgent: String {
    get {
      return String(cString: Cronet_EngineParams_user_agent_get(params)!)
    }
    set {
      newValue.withCString {
        Cronet_EngineParams_user_agent_set(params, $0)
      }
    }
  }

  public var acceptLanguage: String {
    get {
      return String(cString: Cronet_EngineParams_accept_language_get(params)!)
    }
    set {
      newValue.withCString {
        Cronet_EngineParams_accept_language_set(params, $0)
      }
    }
  }

  public var storagePath: String {
    get {
      return String(cString: Cronet_EngineParams_storage_path_get(params)!)
    }
    set {
      newValue.withCString {
        Cronet_EngineParams_storage_path_set(params, $0)
      }
    }
  }

  public var enableQuic: Bool {
    get {
      return Cronet_EngineParams_enable_quic_get(params) != 0
    }
    set {
      Cronet_EngineParams_enable_quic_set(params, newValue ? 1 : 0)
    }
  }

  public var enableHttp2: Bool {
    get {
      return Cronet_EngineParams_enable_http2_get(params) != 0
    }
    set {
      Cronet_EngineParams_enable_http2_set(params, newValue ? 1 : 0)
    }
  }

  public var enableBrotli: Bool {
    get {
      return Cronet_EngineParams_enable_brotli_get(params) != 0
    }
    set {
      Cronet_EngineParams_enable_brotli_set(params, newValue ? 1 : 0)
    }
  }

  public var httpCacheMode: HttpCacheMode {
    get {
      return fromHttpCacheMode(Cronet_EngineParams_http_cache_mode_get(params))
    }
    set {
      Cronet_EngineParams_http_cache_mode_set(params, Cronet_EngineParams_HTTP_CACHE_MODE(UInt32(newValue.rawValue)))
    }
  }

  public var httpCacheMaxSize: Int64 {
    get {
      return Cronet_EngineParams_http_cache_max_size_get(params)
    }
    set {
      Cronet_EngineParams_http_cache_max_size_set(params, newValue)
    }
  }

  public var enablePublicKeyPinningBypassForLocalTrustAnchors: Bool {
    get {
      return Cronet_EngineParams_enable_public_key_pinning_bypass_for_local_trust_anchors_get(params) != 0
    }
    set {
      Cronet_EngineParams_enable_public_key_pinning_bypass_for_local_trust_anchors_set(params, newValue ? 1 : 0)
    }
  }

  public var experimentalOptions: String {
    get {
      return String(cString: Cronet_EngineParams_experimental_options_get(params)!)
    }
    set {
      newValue.withCString {
        Cronet_EngineParams_experimental_options_set(params, $0)
      }
    }
  }
  
  var reference: Cronet_EnginePtr
  var params: Cronet_EngineParamsPtr
  
  public init() {
    let defaultParams = UrlEngineParams()
    params = generateParams(defaultParams)
    reference = Cronet_Engine_Create()
    Cronet_Engine_StartWithParams(reference, params)
  }

  public init(_ p: UrlEngineParams) {
    params = generateParams(p)
    if !p.storagePath.isEmpty {
#if os(Linux)
      p.storagePath.withCString {
        mkdir($0, 0700)
      }
#endif
    }
    reference = Cronet_Engine_Create()
    Cronet_Engine_StartWithParams(reference, params)
  }

  deinit {
    Cronet_Engine_Destroy(reference)
    Cronet_EngineParams_Destroy(params);
  }

  public func shutdown() {
    Cronet_Engine_Shutdown(reference)
  }

}

private func generateParams(_ p: UrlEngineParams) -> Cronet_EngineParamsPtr {
  let params = Cronet_EngineParams_Create()
  if !p.userAgent.isEmpty {
    p.userAgent.withCString {
      Cronet_EngineParams_user_agent_set(params, $0)
    }
  }
  if !p.acceptLanguage.isEmpty {
    p.acceptLanguage.withCString {
      Cronet_EngineParams_accept_language_set(params, $0)
    }
  }
  if !p.storagePath.isEmpty {
    p.storagePath.withCString {
      Cronet_EngineParams_storage_path_set(params, $0)
    }
  }
  if !p.experimentalOptions.isEmpty {
    p.experimentalOptions.withCString {
      Cronet_EngineParams_experimental_options_set(params, $0)
    }
  }

  Cronet_EngineParams_enable_check_result_set(params, p.enableCheckResult ? 1 : 0)
  Cronet_EngineParams_enable_quic_set(params, p.enableQuic ? 1 : 0)
  Cronet_EngineParams_enable_http2_set(params, p.enableHttp2 ? 1 : 0)
  Cronet_EngineParams_enable_brotli_set(params, p.enableBrotli ? 1 : 0)
  Cronet_EngineParams_enable_public_key_pinning_bypass_for_local_trust_anchors_set(params, p.enablePublicKeyPinningBypassForLocalTrustAnchors ? 1 : 0)
  Cronet_EngineParams_http_cache_mode_set(params, Cronet_EngineParams_HTTP_CACHE_MODE(UInt32(p.httpCacheMode.rawValue)))
  Cronet_EngineParams_http_cache_max_size_set(params, p.httpCacheMaxSize)  

  return params!
}

private func fromHttpCacheMode(_ mode: Cronet_EngineParams_HTTP_CACHE_MODE) -> HttpCacheMode {
  switch mode {
    case Cronet_EngineParams_HTTP_CACHE_MODE_DISABLED:
      return HttpCacheMode.Disabled
    case Cronet_EngineParams_HTTP_CACHE_MODE_IN_MEMORY:
      return HttpCacheMode.InMemory    
    case Cronet_EngineParams_HTTP_CACHE_MODE_DISK_NO_HTTP:
      return HttpCacheMode.DiskNoHttp
    case Cronet_EngineParams_HTTP_CACHE_MODE_DISK:
      return HttpCacheMode.Disk
    default:
      return HttpCacheMode.Disabled    
  }
}