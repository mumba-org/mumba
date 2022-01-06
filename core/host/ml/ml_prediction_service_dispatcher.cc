// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ml/ml_prediction_service_dispatcher.h"

namespace host {

MLPredictionServiceDispatcher::MLPredictionServiceDispatcher(MLModelManager* model_manager, MLServiceManager* service_manager):
 model_manager_(model_manager),
 service_manager_(service_manager) {

}

MLPredictionServiceDispatcher::~MLPredictionServiceDispatcher() {

}

void MLPredictionServiceDispatcher::Predict(
  const std::string& model_name, 
  const std::string& model_version, 
  ml::PredictRequestPtr request, 
  PredictCallback callback) {

}

}