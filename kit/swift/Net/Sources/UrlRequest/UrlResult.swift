// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum UrlResult : Int {
  case Success = 0
  case IllegalArgument = -100
  case IllegalArgumentStoragePathMustExist = -101
  case IllegalArgumentInvalidPin = -102
  case IllegalArgumentInvalidHostname = -103
  case IllegalArgumentInvalidHttpMethod = -104
  case IllegalArgumentInvalidHttpHeader = -105
  case IllegalState = -200
  case IllegalStateStoragePathInUse = -201
  case IllegalStateCannotShutdownEngineFromNetworkThread = -202
  case IllegalStateEngineAlreadyStarted = -203
  case IllegalStateRequestAlreadyStarted = -204
  case IllegalStateRequestNotInitialized = -205
  case IllegalStateRequestNotStarted = -206
  case IllegalStateUnexpectedRedirect = -207
  case IllegalStateUnexpectedRead = -208
  case IllegalStateReadFailed = -209
  case NullPointer = -300
  case NullPointerHostname = -301
  case NullPointerSha256Pins = -302
  case NullPointerExpirationDate = -303
  case NullPointerEngine = -304
  case NullPointerUrl = -305
  case NullPointerCallback = -306
  case NullPointerExecutor = -307
  case NullPointerMethod = -308
  case NullPointerHheaderName = -309
  case NullPointerHeaderValue = -310
  case NullPointerParams = -311
}

internal func fromResult(_ r: Cronet_RESULT) -> UrlResult {
  switch r {
    case Cronet_RESULT_SUCCESS:
      return UrlResult.Success
    case Cronet_RESULT_ILLEGAL_ARGUMENT:
      return UrlResult.IllegalArgument
    case Cronet_RESULT_ILLEGAL_ARGUMENT_STORAGE_PATH_MUST_EXIST:
      return UrlResult.IllegalArgumentStoragePathMustExist
    case Cronet_RESULT_ILLEGAL_ARGUMENT_INVALID_PIN:
      return UrlResult.IllegalArgumentInvalidPin
    case Cronet_RESULT_ILLEGAL_ARGUMENT_INVALID_HOSTNAME:
      return UrlResult.IllegalArgumentInvalidHostname
    case Cronet_RESULT_ILLEGAL_ARGUMENT_INVALID_HTTP_METHOD:
      return UrlResult.IllegalArgumentInvalidHttpMethod
    case Cronet_RESULT_ILLEGAL_ARGUMENT_INVALID_HTTP_HEADER:
      return UrlResult.IllegalArgumentInvalidHttpHeader
    case Cronet_RESULT_ILLEGAL_STATE:
      return UrlResult.IllegalState
    case Cronet_RESULT_ILLEGAL_STATE_STORAGE_PATH_IN_USE:
      return UrlResult.IllegalStateStoragePathInUse
    case Cronet_RESULT_ILLEGAL_STATE_CANNOT_SHUTDOWN_ENGINE_FROM_NETWORK_THREAD:
      return UrlResult.IllegalStateCannotShutdownEngineFromNetworkThread
    case Cronet_RESULT_ILLEGAL_STATE_ENGINE_ALREADY_STARTED:
      return UrlResult.IllegalStateEngineAlreadyStarted
    case Cronet_RESULT_ILLEGAL_STATE_REQUEST_ALREADY_STARTED:
      return UrlResult.IllegalStateRequestAlreadyStarted
    case Cronet_RESULT_ILLEGAL_STATE_REQUEST_NOT_INITIALIZED:
      return UrlResult.IllegalStateRequestNotInitialized
    case Cronet_RESULT_ILLEGAL_STATE_REQUEST_NOT_STARTED:
      return UrlResult.IllegalStateRequestNotStarted
    case Cronet_RESULT_ILLEGAL_STATE_UNEXPECTED_REDIRECT:
      return UrlResult.IllegalStateUnexpectedRedirect
    case Cronet_RESULT_ILLEGAL_STATE_UNEXPECTED_READ:
      return UrlResult.IllegalStateUnexpectedRead
    case Cronet_RESULT_ILLEGAL_STATE_READ_FAILED:
      return UrlResult.IllegalStateReadFailed 
    case Cronet_RESULT_NULL_POINTER:
      return UrlResult.NullPointer
    case Cronet_RESULT_NULL_POINTER_HOSTNAME:
      return UrlResult.NullPointerHostname
    case Cronet_RESULT_NULL_POINTER_SHA256_PINS:
      return UrlResult.NullPointerSha256Pins
    case Cronet_RESULT_NULL_POINTER_EXPIRATION_DATE:
      return UrlResult.NullPointerExpirationDate
    case Cronet_RESULT_NULL_POINTER_ENGINE:
      return UrlResult.NullPointerEngine
    case Cronet_RESULT_NULL_POINTER_URL:
      return UrlResult.NullPointerUrl
    case Cronet_RESULT_NULL_POINTER_CALLBACK:
      return UrlResult.NullPointerCallback
    case Cronet_RESULT_NULL_POINTER_EXECUTOR:
      return UrlResult.NullPointerExecutor
    case Cronet_RESULT_NULL_POINTER_METHOD:
      return UrlResult.NullPointerMethod
    case Cronet_RESULT_NULL_POINTER_HEADER_NAME:
      return UrlResult.NullPointerHheaderName
    case Cronet_RESULT_NULL_POINTER_HEADER_VALUE:
      return UrlResult.NullPointerHeaderValue
    case Cronet_RESULT_NULL_POINTER_PARAMS:
      return UrlResult.NullPointerParams
    default:
      return UrlResult.Success
  }
}