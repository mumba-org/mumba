// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MXNET_PREDICTION_SERVICE_H_
#define MUMBA_HOST_MXNET_PREDICTION_SERVICE_H_

#include "base/macros.h"
#include "core/host/ml/ml_predictor.h"
//#include "mxnet/c_api.h"
//#include "mxnet/tuple.h"
//#include "mxnet-cpp/MxNetCpp.h"
//#include "mxnet-cpp/initializer.h"

namespace host {
class MXNetModel;

/*
 * Those services are meant to be tied to a model on a 1x1 basis
 * the prediction service dispatcher is the one who is generic
 * and switch between these services according to their names
 */
class MXNetPredictor : public MLPredictor {
public:
 MXNetPredictor(const std::string& service_name);
 ~MXNetPredictor() override;

 const std::string& service_name() const override;
 MLModel* model() const override;
 
 void Init() override;
 void LoadModel(MLModelManager* model_manager, const std::string& model_name, const std::vector<int>& bucket_keys) override;
 void LoadParameters(const std::string& params_name) override;
 void LoadDictionaryFile(const base::FilePath& input_dictionary);
 void Inference(mxnet::cpp::NDArray* input, base::OnceCallback<void(mxnet::cpp::NDArray)> callback) override;

private:
 
  int ConvertToIndexVector(const std::string& input, std::vector<float> *input_vector);
  int GetIndexForOutputSymbolName(const std::string& output_symbol_name);
  float GetIndexForWord(const std::string& word);
  int GetClosestBucketKey(int num_words);
 
 MXNetModel* model_;
 std::string service_name_;
 
 //mxnet::cpp::Shape input_shape_;

 DISALLOW_COPY_AND_ASSIGN(MXNetPredictor);
};

}

#endif