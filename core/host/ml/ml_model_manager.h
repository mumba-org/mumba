// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_ML_MODEL_MANAGER_H_
#define MUMBA_HOST_ML_ML_MODEL_MANAGER_H_

#include <unordered_map>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/synchronization/lock.h"
#include "core/host/ml/ml_model.h"
#include "core/host/data/resource.h"

namespace host {

class MLModelManager : public ResourceManager {
public:
  MLModelManager(const base::FilePath& models_path);
  ~MLModelManager();

  const base::FilePath& models_path() const {
    return models_path_;
  }
  
  bool HaveModel(const std::string& model_name);
  bool HaveModel(const base::UUID& id);
  MLModel* GetModel(const std::string& model_name);
  MLModel* GetModel(const base::UUID& id);
  MLModel* LoadModel(MLModelType model_type, const std::string& model_name);
  void AddModel(std::unique_ptr<MLModel> model);
  // FIXME: this should be temporary
  void CopyModelFile(const base::FilePath& input_path);
  void CopyAndLoadModelFromFile(MLModelType model_type, const std::string& model_name, const base::FilePath& input_path);

  // ResourceManager 
  bool HaveResource(const base::UUID& id) override {
    return HaveModel(id);
  }

  bool HaveResource(const std::string& name) override {
    return HaveModel(name);
  }

  Resource* GetResource(const base::UUID& id) override {
    return GetModel(id);
  }

  Resource* GetResource(const std::string& name) override {
    return GetModel(name);
  }

  const google::protobuf::Descriptor* resource_descriptor() override;
  std::string resource_classname() const override;

private:

 void CopyAndLoadModelFromFileImpl(MLModelType model_type, const std::string& model_name, const base::FilePath& input_path);
 void CopyModelFileImpl(const base::FilePath& input_path);
 
 base::Lock model_lock_;

 base::FilePath models_path_;

 std::unordered_map<std::string, std::unique_ptr<MLModel>> models_; 

 DISALLOW_COPY_AND_ASSIGN(MLModelManager);
};

}

#endif