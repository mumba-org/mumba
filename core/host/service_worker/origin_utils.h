// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_HOST_SERVICE_WORKER_ORIGIN_UTILS_H_
#define CORE_HOST_SERVICE_WORKER_ORIGIN_UTILS_H_

#include <string>

#include "url/gurl.h"
#include "url/origin.h"

namespace host {

GURL GetOrigin(const GURL& url);
GURL CreateUrlOrigin(const GURL& url);
url::Origin CreateOrigin(const GURL& url);

}

#endif