// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_INPUT_ROUTER_CONFIG_HELPER_H_
#define MUMBA_HOST_APPLICATION_INPUT_INPUT_ROUTER_CONFIG_HELPER_H_

#include "core/host/application/input/input_router.h"

namespace host {

// Return an InputRouter configuration with parameters tailored to the current
// platform.
InputRouter::Config GetInputRouterConfigForPlatform();

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_INPUT_ROUTER_CONFIG_HELPER_H_
