// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/execution_dispatcher.h"

#include "base/files/file_path.h"
#include "base/task_scheduler/post_task.h"
#include "core/domain/domain_process.h"
#include "core/domain/execution/execution_engine.h"
#include "core/domain/domain_main_thread.h"
#include "core/shared/domain/storage/storage_manager.h"

namespace domain {

class ExecutionDispatcher::Handler : public base::RefCountedThreadSafe<Handler> {
public:
  Handler() {}

  bool LoadModule(scoped_refptr<DomainContext> shell, const GURL& url) {
    
    if (!url.SchemeIs("code")) {
      //DLOG(INFO) << "bad url scheme. have '" << url.scheme() << "' expected 'code'";
      return false;
    }
    auto first_bar = url.path_piece().find_first_of('/');
    auto last_bar = url.path_piece().find_last_of('/');
    std::string mount_name = url.path_piece().substr(first_bar+2, last_bar-2).as_string();
    std::string mod_name = url.path_piece().substr(last_bar+1).as_string();
    //DLOG(INFO) << "Execution::LoadModule: loading '" << url.spec() << "'";

    auto* storage_manager = shell->storage_manager();
    auto* ns = storage_manager->GetNamespaceAtMount(mount_name);
    if (!ns) {
      //DLOG(ERROR) << "mount '" << mount_name << "' not found";
      return false;
    }
    // see if theres a concept, and the concept is a module
    ConceptNode* concept = ns->GetConcept(mod_name);
    if (!concept) {
      //DLOG(ERROR) << "concept '" << mod_name << "' not found";
      return false;
    }

    if (concept->type_name() != "module") {
      //DLOG(ERROR) << "concept '" << mod_name << "' not a module. type: '" << concept->type_name() << "'";
      return false;
    }

    // now load the module if its not already loaded
    auto* execution_engine = shell->execution_engine();
    execution_engine->LoadModule(ns, mod_name);
    return true;
  }

  bool UnloadModule(scoped_refptr<DomainContext> shell, const std::string& name) {
    auto* execution_engine = shell->execution_engine();
    execution_engine->UnloadModule(name);
    return true;
  }

private:
  friend class base::RefCountedThreadSafe<Handler>;

  ~Handler() {}
};

ExecutionDispatcher::ExecutionDispatcher(): 
  binding_(this),
  handler_(new Handler()),
  weak_factory_(this) {}

ExecutionDispatcher::~ExecutionDispatcher() {}

void ExecutionDispatcher::Bind(common::mojom::ExecutionAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void ExecutionDispatcher::LoadModule(const std::string& name, const std::string& from_path, LoadModuleCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  GURL url(name);
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::LoadModule,
       handler_,
       main_thread->domain_context(),
       url),
     base::Bind(&ExecutionDispatcher::ReplyLoadModule,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ExecutionDispatcher::UnloadModule(const std::string& name, UnloadModuleCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::UnloadModule,
       handler_,
       main_thread->domain_context(),
       name),
     base::Bind(&ExecutionDispatcher::ReplyUnloadModule,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ExecutionDispatcher::GetModuleList(GetModuleListCallback callback) {

}

void ExecutionDispatcher::ReplyLoadModule(LoadModuleCallback callback, bool result) {
  common::mojom::DomainStatus status = result ? common::mojom::DomainStatus::kOk : common::mojom::DomainStatus::kError;
  std::move(callback).Run(std::move(status)); 
}

void ExecutionDispatcher::ReplyUnloadModule(UnloadModuleCallback callback, bool result) {
  common::mojom::DomainStatus status = result ? common::mojom::DomainStatus::kOk : common::mojom::DomainStatus::kError;
  std::move(callback).Run(std::move(status)); 
}

}