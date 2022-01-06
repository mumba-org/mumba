// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MODULE_MODULE_DISPATCHER_H_
#define MUMBA_DOMAIN_MODULE_MODULE_DISPATCHER_H_

#include "base/macros.h"
#include "core/shared/common/mojom/module.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class ModuleDispatcher : public common::mojom::ModuleDispatcher {
public:
  ModuleDispatcher();
  ~ModuleDispatcher() override;

  void Bind(common::mojom::ModuleDispatcherAssociatedRequest request);

  void GetModuleList(GetModuleListCallback callback) override;
  void GetModuleHandle(const std::string& uuid, GetModuleHandleCallback callback) override;
  void Load(const std::string& uuid, LoadCallback callback) override;
  void Unload(const std::string& uuid, UnloadCallback callback) override;

private:
  class Handler;

  void ReplyGetModuleList(GetModuleListCallback callback, std::vector<common::mojom::ModuleHandlePtr> list);
  void ReplyGetModuleHandle(GetModuleHandleCallback callback, common::mojom::ModuleHandlePtr info);
  void ReplyLoad(LoadCallback callback, bool result);
  void ReplyUnload(UnloadCallback callback, bool result);
 
  mojo::AssociatedBinding<common::mojom::ModuleDispatcher> binding_;

  scoped_refptr<Handler> handler_;

  base::WeakPtrFactory<ModuleDispatcher> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ModuleDispatcher);
};

}

#endif