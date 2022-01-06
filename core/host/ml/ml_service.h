// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_ML_SERVICE_H_
#define MUMBA_HOST_ML_ML_SERVICE_H_

#include <string>

#include "base/macros.h"

namespace host {
class MLModel;

class MLService {
public:
 virtual ~MLService() {}
 virtual const std::string& service_name() const = 0;
 virtual MLModel* model() const = 0;
};

}

#endif
