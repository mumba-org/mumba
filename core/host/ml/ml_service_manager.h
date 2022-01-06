// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_ML_SERVICE_MANAGER_H_
#define MUMBA_HOST_ML_ML_SERVICE_MANAGER_H_

#include <memory>
#include <string>
#include <unordered_map>

#include "base/macros.h"

namespace host {
class MLService;

class MLServiceManager {
public:
 MLServiceManager();
 ~MLServiceManager();

 MLService* GetService(const std::string& name);

private:

 std::unordered_map<std::string, std::unique_ptr<MLService>> services_;
 
 DISALLOW_COPY_AND_ASSIGN(MLServiceManager);
};

}

#endif
