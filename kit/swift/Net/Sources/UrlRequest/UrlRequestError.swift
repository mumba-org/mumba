// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public enum UrlRequestErrorCode : Int {
  case ErrorCallback = 0
  case HostnameNotResolved = 1
  case InternetDisconnected = 2
  case NetworkChanged = 3
  case TimedOut = 4
  case ConnectionClosed = 5
  case ConnectionTimedOut = 6
  case ConnectionRefused = 7
  case ConnectionReset = 8
  case AddressUnreachable = 9
  case QuicProtocolFailed = 10
  case Other = 11
}

public class UrlRequestError {

  public var errorCode: UrlRequestErrorCode {
    get {
      let code = Cronet_Error_error_code_get(reference)
      return UrlRequestErrorCode(rawValue: Int(code.rawValue))!
    }
    set {
      Cronet_Error_error_code_set(reference, Cronet_Error_ERROR_CODE(UInt32(newValue.rawValue)))
    }
  }

  public var errorMessage: String {
    get {
      let ptr = Cronet_Error_message_get(reference)
      return ptr != nil ? String(cString: ptr!) : String()
    }
    set {
      newValue.withCString {
        Cronet_Error_message_set(reference, $0)
      }
    }
  }

  public var immediatelyRetryable: Bool {
    get {
      return Cronet_Error_immediately_retryable_get(reference) != 0
    }
    set {
      Cronet_Error_immediately_retryable_set(reference, newValue ? 1 : 0)
    }
  }

  public var quicDetailedErrorCode: Int {
    get {
      return Int(Cronet_Error_quic_detailed_error_code_get(reference))
    }
    set {
      Cronet_Error_quic_detailed_error_code_set(reference, Int32(newValue))
    }
  }

  public var internalErrorCode: Int {
    get {
      return Int(Cronet_Error_internal_error_code_get(reference))
    }
    set {
      Cronet_Error_internal_error_code_set(reference, Int32(newValue))
    }
  }

  var reference: Cronet_ErrorPtr

  internal init(reference: Cronet_ErrorPtr) {
    self.reference = reference
  }

  //deinit {
    //Cronet_Error_Destroy(reference)
  //}

}