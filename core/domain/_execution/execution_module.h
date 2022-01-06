// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_EXECUTION_MODULE_H_
#define MUMBA_DOMAIN_EXECUTION_EXECUTION_MODULE_H_

#include <memory>

#include "base/macros.h"

#include "core/domain/execution/engine_client.h"
#include "core/domain/execution/engine_context.h"

namespace disk {
class Executable;
}

namespace domain {
class NativeLibrary;
class ExecutionContext;
class Namespace;

class ExecutionModule : public EngineContext::Delegate {
public:
  ExecutionModule(Namespace* ns, const std::string& name, disk::Executable* exe);//, NativeLibrary* library);
  ~ExecutionModule();

  const std::string& name() const;

  void Load();
  void Unload();

  //void SendEventForTest();

private:
  
  void OnBind(const std::string& concept_name, ConceptNode::Handler* handler) override;
  void OnStateChanged(ConceptNode* concept, ConceptState new_state) override;
  void OnSub(ConceptNode* concept, StreamSession* session) override;
  void OnUnsub(ConceptNode* concept, StreamSession* session) override;

  disk::Executable* executable_;

  std::string name_;

  EngineContext engine_context_;

  EngineClient* client_;

  base::Lock client_mutex_;

  //int event_count_;
  
  DISALLOW_COPY_AND_ASSIGN(ExecutionModule);
};

}

#endif