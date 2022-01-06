// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_PARAMS_H_
#define MUMBA_HOST_APPLICATION_PARAMS_H_

#include <string>

#include "base/files/file_path.h"
#include "core/common/url.h"

namespace host {

struct DomainCreateParams {
  URL url;
  base::FilePath root_path;
  common::DomainManifest manifest;
};

}

#endif