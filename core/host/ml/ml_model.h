// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_ML_MODEL_H_
#define MUMBA_HOST_ML_ML_MODEL_H_

#include <string>

#include "base/macros.h"

namespace host {

enum class MLModelType {
  kML_MODEL_ONNX = 0,
  kML_MODEL_MXNET = 1
};

class MLModel {
public:
 virtual ~MLModel() {}
 virtual const std::string& model_name() const = 0;
 virtual MLModelType type() const = 0;
 virtual bool is_loaded() const = 0;
 virtual void Load(const std::vector<int>& bucket_keys) = 0;
 virtual void LoadParameters(const std::string& params_name) = 0;
 virtual void Compile() = 0;
};

}

#endif
