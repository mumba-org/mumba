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

namespace host {

class MLModelManager {
public:
 MLModelManager(const base::FilePath& models_path);
 ~MLModelManager();

 const base::FilePath& models_path() const {
   return models_path_;
 }
 
 bool HaveModel(const std::string& model_name);
 void AddModel(std::unique_ptr<MLModel> model);
 MLModel* GetModel(const std::string& model_name);
 MLModel* LoadModel(MLModelType model_type, const std::string& model_name);
 // FIXME: this should be temporary
 void CopyModelFile(const base::FilePath& input_path);
 void CopyAndLoadModelFromFile(MLModelType model_type, const std::string& model_name, const base::FilePath& input_path);

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