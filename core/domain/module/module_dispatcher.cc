// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/module_dispatcher.h"

#include "base/files/file_path.h"
#include "base/task_scheduler/post_task.h"
#include "core/domain/domain_process.h"
#include "core/domain/module/module_loader.h"
#include "core/domain/domain_main_thread.h"
#include "core/shared/domain/storage/storage_manager.h"
#include "mojo/public/cpp/bindings/type_converter.h"

#if defined(OS_WIN)
#ifdef GetModuleHandle
#undef GetModuleHandle
#endif
#endif

namespace domain {

class ModuleDispatcher::Handler : public base::RefCountedThreadSafe<Handler> {
public:
  Handler() {}

private:
  friend class base::RefCountedThreadSafe<Handler>;

  ~Handler() {}
};

ModuleDispatcher::ModuleDispatcher(): 
  binding_(this),
  handler_(new Handler()),
  weak_factory_(this) {}

ModuleDispatcher::~ModuleDispatcher() {}

void ModuleDispatcher::Bind(common::mojom::ModuleDispatcherAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void ModuleDispatcher::GetModuleHandle(const std::string& uuid, GetModuleHandleCallback callback) {
  //DomainMainThread* main_thread = DomainMainThread::current();
  //base::PostTaskWithTraitsAndReplyWithResult(
  //  FROM_HERE,
  //  { base::MayBlock(),
  //    base::TaskPriority::USER_BLOCKING},
  //   base::Bind(
  //     &Handler::GetInfo,
  //     handler_,
  //     main_thread->domain_context()),
  //   base::Bind(&EngineDispatcher::ReplyGetInfo,
  //    weak_factory_.GetWeakPtr(),
  //    base::Passed(std::move(callback))));
}

void ModuleDispatcher::GetModuleList(GetModuleListCallback callback) {

}

void ModuleDispatcher::Load(const std::string& uuid, LoadCallback callback) {

}

void ModuleDispatcher::Unload(const std::string& uuid, UnloadCallback callback) {

}

void ModuleDispatcher::ReplyGetModuleList(GetModuleListCallback callback, std::vector<common::mojom::ModuleHandlePtr> list) {
  
}

void ModuleDispatcher::ReplyGetModuleHandle(GetModuleHandleCallback callback, common::mojom::ModuleHandlePtr info) {
  std::move(callback).Run(std::move(info)); 
}

void ModuleDispatcher::ReplyLoad(LoadCallback callback, bool result) {

}

void ModuleDispatcher::ReplyUnload(UnloadCallback callback, bool result) {

}


}