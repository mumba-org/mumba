// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/index/index_controller.h"

namespace host {

IndexController::IndexController(IndexManager* manager): manager_(manager) {
  
}

IndexController::~IndexController() {
  
}

Index* IndexController::CreateIndex(const std::string& name, const IndexManager::CreateOptions& options) {
  
}

void IndexController::DestroyIndex(const std::string& name) {
  
}

void IndexController::DestroyIndex(const base::UUID& uuid) {
  
}

}