// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_MXNET_MODEL_MANIFEST_H_
#define MUMBA_HOST_ML_MXNET_MODEL_MANIFEST_H_

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/values.h"

namespace host {
class MXNetModel;

class MXNetModelManifest {
public:

  enum RuntimeType {
    kPYTHON = 0,
    kPYTHON2 = 1,
    kPYTHON3 = 2
  };

  struct Publisher {
    std::string author;
    std::string email;
  };

  struct Engine {
    std::string engine_name;
    std::string engine_version;
  };

  MXNetModelManifest();   
  ~MXNetModelManifest();

  bool is_valid() const {
    return is_valid_;
  }

  MXNetModel* model() const { 
    return model_.get();
  }

  const std::string& specification_version() const {
    return specification_version_;
  }

  void set_specification_version(const std::string& specification_version) {
    specification_version_ = specification_version;
  }

  const std::string& implementation_version() const {
    return implementation_version_;
  }

  void set_implementation_version(const std::string& implementation_version) {
    implementation_version_ = implementation_version;
  }

  const std::string& description() const {
    return description_;
  }

  void set_description(const std::string& description) {
    description_ = description;
  }
  
  const std::string& model_server_version() const {
    return model_server_version_;
  }

  void set_model_server_version(const std::string& model_server_version) {
    model_server_version_ = model_server_version;
  }

  const std::string& license() const {
    return license_;
  }

  void set_license(const std::string& license) {
    license_ = license;
  }

  RuntimeType runtime() const {
    return runtime_;
  }

  void set_runtime(RuntimeType runtime) {
    runtime_ = runtime;
  }

  const Engine& engine() const {
    return engine_;
  }
  
  const Publisher& publisher() const {
    return publisher_;
  }

  Engine& engine() {
    return engine_;
  }
  
  Publisher& publisher() {
    return publisher_;
  }

  std::unique_ptr<MXNetModel> OwnModel() {
    is_valid_ = false;
    return std::move(model_);
  }

  bool ParseFromFile(const base::FilePath& path);

private:

  bool ParseFromJson(base::Value* root);
  
  std::unique_ptr<MXNetModel> model_;
  std::string specification_version_;
  std::string implementation_version_;
  std::string description_;
  std::string model_server_version_;
  std::string license_;
  RuntimeType runtime_;
  Engine engine_;
  Publisher publisher_;
  base::FilePath path_;

  bool is_valid_;

  DISALLOW_COPY_AND_ASSIGN(MXNetModelManifest);
};

}

#endif
