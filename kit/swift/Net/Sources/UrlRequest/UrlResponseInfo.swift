// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public struct UrlChain {

  public var count: Int {
    return Int(Cronet_UrlResponseInfo_url_chain_size(reference))
  }

  public subscript(index: Int) -> String? {
    guard index < count else {
      return nil
    }
    let str = Cronet_UrlResponseInfo_url_chain_at(reference, UInt32(index))
    return str != nil ? String(cString: str!) : String()
  }
  
  var reference: Cronet_UrlResponseInfoPtr
  
  init(reference: Cronet_UrlResponseInfoPtr) {
    self.reference = reference
  }

  public func add(_ s: String) {
    s.withCString {
      Cronet_UrlResponseInfo_url_chain_add(reference, $0)
    }
  }

  public func clear() {
    Cronet_UrlResponseInfo_url_chain_clear(reference)
  }

}

public class UrlResponseInfoHeaders {

  public var count: Int {
    return Int(Cronet_UrlResponseInfo_all_headers_list_size(reference))
  }
  
  public subscript(index: Int) -> (String, String) {
    get {
      guard let ptr = Cronet_UrlResponseInfo_all_headers_list_at(reference, UInt32(index)) else {
        return (String(), String())
      }
      guard let cname = Cronet_HttpHeader_name_get(ptr) else {
        return (String(), String())
      }
      guard let cvalue = Cronet_HttpHeader_value_get(ptr) else {
        return (String(cString: cname), String())
      }
      return (String(cString: cname), String(cString: cvalue))
    }
    set {
      if index < count {
        guard let ref = Cronet_UrlResponseInfo_all_headers_list_at(reference, UInt32(index)) else {
          return
        }
        newValue.1.withCString {
          Cronet_HttpHeader_value_set(ref, $0)
        }
      } else {
        let ref = Cronet_HttpHeader_Create()
        newValue.0.withCString {
          Cronet_HttpHeader_name_set(ref, $0)
        }
        newValue.1.withCString {
          Cronet_HttpHeader_value_set(ref, $0)
        }
        headers[newValue.0] = ref
      }
    }
  }

  public subscript(index: String) -> String? {
    let count = Cronet_UrlResponseInfo_all_headers_list_size(reference)
    for i in 0..<count {
      let ref = Cronet_UrlResponseInfo_all_headers_list_at(reference, UInt32(i))!
      let cname = Cronet_HttpHeader_name_get(ref)
      // can we compare both?
      if String(cString: cname!) == index {
        let cvalue = Cronet_HttpHeader_value_get(ref)
        return cvalue != nil ? String(cString: cvalue!) : String()
      }
    }
    return nil
  }
  
  var reference: Cronet_UrlResponseInfoPtr
  var headers: [String : Cronet_HttpHeaderPtr]

  init (reference: Cronet_UrlResponseInfoPtr) {
    self.reference = reference
    headers = [:]
  }

  deinit {
    for item in headers {
      Cronet_HttpHeader_Destroy(item.1)
    }
  }

  public func add(name: String, value: String) {
    let ptr = Cronet_HttpHeader_Create()
    name.withCString {
      Cronet_HttpHeader_name_set(ptr, $0)
    }
    value.withCString {
      Cronet_HttpHeader_value_set(ptr, $0)
    }
    Cronet_UrlResponseInfo_all_headers_list_add(reference, ptr)
    headers[name] = ptr
  }

  public func clear() {
    Cronet_UrlResponseInfo_all_headers_list_clear(reference)
  }

}

public class UrlResponseInfo {

  public var url: String {
    get {
      guard let ref = Cronet_UrlResponseInfo_url_get(reference) else {
        return String()
      }
      return String(cString: ref)
    }
    set {
      newValue.withCString {
        Cronet_UrlResponseInfo_url_set(reference, $0)
      }
    }
  }

  public private(set) var urlChain: UrlChain

  public var httpStatusCode: Int {
    get {
      return Int(Cronet_UrlResponseInfo_http_status_code_get(reference))
    }
    set {
      Cronet_UrlResponseInfo_http_status_code_set(reference, Int32(newValue))
    }
  }

  public var httpStatusText: String {
    get {
      guard let ref = Cronet_UrlResponseInfo_http_status_text_get(reference) else {
        return String()
      }
      return String(cString: ref)
    }
    set {
      newValue.withCString {
        Cronet_UrlResponseInfo_http_status_text_set(reference, $0)
      }
    }
  }

  public var wasCached: Bool {
    get {
      return Cronet_UrlResponseInfo_was_cached_get(reference) != 0
    }
    set {
      Cronet_UrlResponseInfo_was_cached_set(reference, newValue ? 1 : 0)  
    }
  }

  public private(set) var headers: UrlResponseInfoHeaders

  public var negotiatedProtocol: String {
    get {
      guard let ref = Cronet_UrlResponseInfo_negotiated_protocol_get(reference) else {
        return String()
      }
      return String(cString: ref)
    }
    set {
      newValue.withCString {
        Cronet_UrlResponseInfo_negotiated_protocol_set(reference, $0)
      }
    }
  }

  public var proxyServer: String {
    get {
      guard let ref = Cronet_UrlResponseInfo_proxy_server_get(reference) else {
        return String()
      }
      return String(cString: ref)
    }
    set {
      newValue.withCString {
        Cronet_UrlResponseInfo_proxy_server_set(reference, $0)
      }
    }
  }

  public var byteCount: Int64 {
    get {
      return Cronet_UrlResponseInfo_received_byte_count_get(reference)
    }
    set {
      Cronet_UrlResponseInfo_received_byte_count_set(reference, newValue)
    }
  }

  var reference: Cronet_UrlResponseInfoPtr
  var owned: Bool

  public init() {
    owned = true
    reference = Cronet_UrlResponseInfo_Create()
    urlChain = UrlChain(reference: reference)
    headers = UrlResponseInfoHeaders(reference: reference)
  }
  
  init(reference: Cronet_UrlResponseInfoPtr) {
    owned = false
    self.reference = reference
    urlChain = UrlChain(reference: reference)
    headers = UrlResponseInfoHeaders(reference: reference)
  }

  deinit {
    if owned {
      Cronet_UrlResponseInfo_Destroy(reference)
    }
  }
}