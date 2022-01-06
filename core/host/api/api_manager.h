// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_API_API_MANAGER_H_
#define MUMBA_HOST_API_API_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {
class Share;
class APIService;

class APIManager {
public:
  APIManager();
  ~APIManager();

  APIService* CreateAPIService(Share* share, const std::string& id);
  
private:

  std::vector<std::unique_ptr<APIService>> services_;

  DISALLOW_COPY_AND_ASSIGN(APIManager);
};

}

#endif