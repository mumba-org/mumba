// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_MODEL_SERVICE_H_
#define MUMBA_HOST_ML_MODEL_SERVICE_H_

#include "base/macros.h"
#include "core/host/ml/ml_service.h"

namespace host {
class MLModel;

class MLModelService : public MLService {
public:
 virtual ~MLModelService() override {}
 virtual MLModel* model() const = 0;
};

}

#endif