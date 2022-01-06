// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_EXECUTION_DISPATCHER_H_
#define MUMBA_DOMAIN_EXECUTION_EXECUTION_DISPATCHER_H_

#include "base/macros.h"
#include "core/shared/common/mojom/execution.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class ExecutionDispatcher : public common::mojom::Execution {
public:
  ExecutionDispatcher();
  ~ExecutionDispatcher() override;

  void Bind(common::mojom::ExecutionAssociatedRequest request);

  void LoadModule(const std::string& name, const std::string& from_path, LoadModuleCallback callback) override;
  void UnloadModule(const std::string& name, UnloadModuleCallback callback) override;
  void GetModuleList(GetModuleListCallback callback) override;

private:
  class Handler;

  void ReplyLoadModule(LoadModuleCallback callback, bool result);
  void ReplyUnloadModule(UnloadModuleCallback callback, bool result);

  mojo::AssociatedBinding<common::mojom::Execution> binding_;

  scoped_refptr<Handler> handler_;

  base::WeakPtrFactory<ExecutionDispatcher> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ExecutionDispatcher);
};

}

#endif