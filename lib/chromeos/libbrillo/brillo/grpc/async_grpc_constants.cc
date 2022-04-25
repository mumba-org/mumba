// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/grpc/async_grpc_constants.h"

namespace brillo {

const int kMaxGrpcMessageSize = 4 * 1024 * 1024;

const base::TimeDelta kMinGrpcReconnectBackoffTime = base::TimeDelta::FromMilliseconds(100);
const base::TimeDelta kInitialGrpcReconnectBackoffTime =
    base::TimeDelta::FromMilliseconds(100);
const base::TimeDelta kMaxGrpcReconnectBackoffTime = base::TimeDelta::FromSeconds(5);

const base::TimeDelta kDefaultRpcDeadline = base::TimeDelta::FromMinutes(1);

}  // namespace brillo
