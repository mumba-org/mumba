// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_MXNET_MODEL_H_
#define MUMBA_HOST_ML_MXNET_MODEL_H_

#include <string>
#include <unordered_map>
#include <map>

#include "base/macros.h"
#include "core/host/ml/ml_model.h"
// #include "mxnet/base.h"
// #include "mxnet/c_api.h"
// #include "mxnet/tuple.h"
// #include "mxnet-cpp/MxNetCpp.h"
// #include "mxnet-cpp/initializer.h"
// #undef LOG_INFO
// #undef LOG_WARNING
// #undef LOG_ERROR
// #undef LOG_FATAL
// #undef LOG_DFATAL
#include "base/files/file_path.h"

namespace mxnet {
class NDArray;    
}

namespace host {
class MXNetPredictor;

class MXNetModel : public MLModel {
public:
  MXNetModel(const std::string& model_name, const base::FilePath& model_path);
  ~MXNetModel() override;

  MLModelType type() const override {
    return MLModelType::kML_MODEL_MXNET;
  }

  const std::string& model_name() const override;

  void set_model_name(const std::string& model_name) {
    model_name_ = model_name;
  }

  const std::string& description() const { 
    return description_;
  }

  void set_description(const std::string& description) {
    description_ = description;
  }

  const std::string& model_version() const {
    return model_version_;
  }

  void set_model_version(const std::string& model_version) {
    model_version_ = model_version; 
  }
  
  const std::string& handler() const {
    return handler_;
  }

  void set_handler(const std::string& handler) {
    handler_ = handler;
  }

  void add_extension(const std::string& key, const std::string& value) {
    extensions_.emplace(std::make_pair(key, value));
  }
  
  bool is_loaded() const override {
    return model_loaded_;
  }
  
  void Load(const std::vector<int>& bucket_keys) override;
  void LoadParameters(const std::string& params_name) override;
  void Compile() override;

  void LoadDictionaryFile(const base::FilePath& input_dictionary);

private:
  
  friend class MXNetPredictor;

  std::string model_name_;
  base::FilePath model_path_;
  std::string description_;
  std::string model_version_;
  std::string handler_;
  std::unordered_map<std::string, std::string> extensions_;
  //std::map<std::string, mxnet::cpp::NDArray> args_map_;
  //std::map<std::string, mxnet::cpp::NDArray> aux_map_;
  //mxnet::cpp::Symbol net_;
  //mxnet::cpp::Context global_ctx_;
  //std::map<int, mxnet::cpp::Executor*> executor_buckets_;
  // FIXME
  std::map<std::string, int> word_to_index_;
  std::vector<int> bucket_keys_;
  int highest_bucket_key_;

  bool model_loaded_;
  bool params_loaded_;

  DISALLOW_COPY_AND_ASSIGN(MXNetModel);
};

}

#endif
