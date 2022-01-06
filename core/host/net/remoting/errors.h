// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_ERROR_H_
#define MUMBA_HOST_NET_ERROR_H_

#include <string>

namespace host {

// The UI implementations maintain corresponding definitions of this
// enumeration in webapp/base/js/error.js, webapp/base/js/chromoting_event.js,
// android/java/src/org/chromium/chromoting/jni/ConnectionListener.java and
// remoting/protocol/errors.cc.
// Be sure to update these locations if you make any changes to the ordering.
enum ErrorCode {
  OK = 0,
  PEER_IS_OFFLINE,
  SESSION_REJECTED,
  INCOMPATIBLE_PROTOCOL,
  AUTHENTICATION_FAILED,
  INVALID_ACCOUNT,
  CHANNEL_CONNECTION_ERROR,
  SIGNALING_ERROR,
  SIGNALING_TIMEOUT,
  HOST_OVERLOAD,
  MAX_SESSION_LENGTH,
  HOST_CONFIGURATION_ERROR,
  UNKNOWN_ERROR,
  ELEVATION_ERROR,
  HOST_CERTIFICATE_ERROR,
  HOST_REGISTRATION_ERROR,
  ERROR_CODE_MAX = UNKNOWN_ERROR,
};

bool ParseErrorCode(const std::string& name, ErrorCode* result);

// Returns the literal string of |error|.
const char* ErrorCodeToString(ErrorCode error);

}

#endif  // REMOTING_PROTOCOL_ERROR_H_
