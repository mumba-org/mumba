// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_PREDICTOR_H_
#define MUMBA_HOST_ML_PREDICTOR_H_

#include <vector>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "core/host/ml/ml_service.h"

namespace mxnet {
namespace cpp {  
class NDArray;    
}
}

namespace host {
class MLModelManager;
  
class MLPredictor : public MLService {
public:
 virtual ~MLPredictor() override {}
 virtual void Init() = 0;
 virtual void LoadModel(MLModelManager* model_manager, const std::string& model_name, const std::vector<int>& bucket_keys) = 0;
 virtual void LoadParameters(const std::string& params_name) = 0;
 virtual void Inference(mxnet::cpp::NDArray* input, base::OnceCallback<void(mxnet::cpp::NDArray)> callback) = 0;
};

}

#endif
