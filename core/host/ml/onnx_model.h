// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_ONNX_MODEL_H_
#define MUMBA_HOST_ML_ONNX_MODEL_H_

#include "base/macros.h"

#include "core/host/ml/ml_model.h"
#include "third_party/onnx/onnx/onnx_ml.pb.h"

namespace host {

class ONNXModel : public MLModel {
public:
  static std::unique_ptr<ONNXModel> LoadFromProtobuf(const onnx::ModelProto& proto);

  ONNXModel(const std::string& model_name);
  ~ONNXModel() override;

  MLModelType type() const override {
    return MLModelType::kML_MODEL_ONNX;
  }

  const std::string& model_name() const override;

  bool is_loaded() const override {
    return model_loaded_;
  }
  void Load(const std::vector<int>& bucket_keys) override; 
  void LoadParameters(const std::string& params_name) override;
  void Compile() override;

private:

  std::string model_name_;  

  // int64_t ir_version_;

  // OperatorSetId opset_import_;

  // std::string producer_name_;

  // std::string producer_version_;

  // std::string domain_;

  // int64_t model_version_;

  // std::string doc_string_;

  // Graph graph_;

  // StringStringEntry metadata_props_;

  // TrainingInfo training_info_;

  // Function functions_;

  bool model_loaded_;

  DISALLOW_COPY_AND_ASSIGN(ONNXModel);
};

}

#endif
