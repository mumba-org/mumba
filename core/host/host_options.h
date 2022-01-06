// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_HOST_OPTIONS_H_
#define MUMBA_HOST_HOST_OPTIONS_H_

#include "core/shared/common/content_export.h"
#include "base/files/file_path.h"

namespace host {

struct CONTENT_EXPORT HostOptions {
  base::FilePath profile_path;
  std::string workspace_name;
  std::string admin_service_host = "127.0.0.1";
  int admin_service_port = 27761;
};

}

#endif