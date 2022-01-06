// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_MODULE_H_
#define MUMBA_DOMAIN_EXECUTION_MODULE_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/shared/domain/module/module_client.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/common/mojom/objects.mojom.h"
#include "core/domain/module/executable.h"

namespace domain {
class ModuleClient;

class Module : public ModuleState::Delegate {
public:
  virtual ~Module() {}
  virtual const base::UUID& id() const = 0;
  virtual const std::string& name() const = 0;
  virtual common::mojom::ModuleHandlePtr module_handle() const = 0;
  virtual ModuleClient* module_client() const = 0;
  virtual bool Load(Executable::InitParams executable_params) = 0;
  virtual void Unload() = 0;

};

}

#endif