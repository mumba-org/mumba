// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_ANDROID_GIN_JAVA_BRIDGE_ERRORS_H_
#define CONTENT_COMMON_ANDROID_GIN_JAVA_BRIDGE_ERRORS_H_

#include "core/shared/common/content_export.h"

namespace common {

enum GinJavaBridgeError {
  kGinJavaBridgeNoError = 0,
  kGinJavaBridgeUnknownObjectId,
  kGinJavaBridgeObjectIsGone,
  kGinJavaBridgeMethodNotFound,
  kGinJavaBridgeAccessToObjectGetClassIsBlocked,
  kGinJavaBridgeJavaExceptionRaised,
  kGinJavaBridgeNonAssignableTypes,
  kGinJavaBridgeRenderFrameDeleted,
  kGinJavaBridgeErrorLast = kGinJavaBridgeRenderFrameDeleted
};

CONTENT_EXPORT const char* GinJavaBridgeErrorToString(GinJavaBridgeError error);

}  // namespace common

#endif  // CONTENT_COMMON_ANDROID_GIN_JAVA_BRIDGE_ERRORS_H_
