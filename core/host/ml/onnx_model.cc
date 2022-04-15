// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ml/onnx_model.h"

namespace host {

ONNXModel::ONNXModel(const std::string& model_name): 
 uuid_(base::UUID::generate()), 
 model_name_(model_name),
 model_loaded_(false) {

}

ONNXModel::~ONNXModel() {

}

const std::string& ONNXModel::model_name() const {
  return model_name_;
}

void ONNXModel::Load(const std::vector<int>& bucket_keys) {
  model_loaded_ = true;
}

void ONNXModel::LoadParameters(const std::string& params_name) {
  
}

void ONNXModel::Compile() {
  
}

}