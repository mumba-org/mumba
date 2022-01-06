// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ml/ml_model_service_dispatcher.h"

namespace host {

MLModelServiceDispatcher::MLModelServiceDispatcher(MLModelManager* model_manager):
 model_manager_(model_manager) {

}

MLModelServiceDispatcher::~MLModelServiceDispatcher() {

}

void MLModelServiceDispatcher::Compile(ml::ModelCompileRequestPtr request, CompileCallback callback) {
  
}

void MLModelServiceDispatcher::Load(ml::ModelLoadRequestPtr request, LoadCallback callback) {

}

void MLModelServiceDispatcher::Unload(ml::ModelUnloadRequestPtr request, UnloadCallback callback) {

}

}