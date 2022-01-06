// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/namespace_dispatcher.h"

#include "base/files/file_path.h"
#include "base/task_scheduler/post_task.h"
#include "core/domain/domain_process.h"
#include "core/shared/domain/storage/namespace.h"
#include "core/shared/domain/storage/storage_manager.h"
#include "core/shared/domain/storage/namespace_builder.h"
#include "core/domain/module/engine_loader.h"
#include "core/domain/domain_main_thread.h"

namespace domain {

class NamespaceDispatcher::Handler : public base::RefCountedThreadSafe<Handler> {
public:
  Handler() {}

  bool CreateNamespace(scoped_refptr<DomainContext> shell, const std::string& namespace_name) {
    auto* storage = shell->storage_manager();
    Namespace* ds = storage->CreateNamespace(true);
    if (!ds) {
      return false;
    }
    return storage->Mount(namespace_name, ds->id());
  }

  std::unique_ptr<QueryReply> ExecuteQuery(scoped_refptr<DomainContext> shell, int32_t id, const std::string& address, const std::string& encoded_query) {
    std::string encoded_reply;
    auto* engine = shell->engine_loader();
    bool ok = engine->ExecuteQuery(id, address, encoded_query, &encoded_reply);
    return std::make_unique<QueryReply>(ok, id, std::move(encoded_reply));
  }

private:
  friend class base::RefCountedThreadSafe<Handler>;

  ~Handler() {}
};

NamespaceDispatcher::NamespaceDispatcher(): 
  binding_(this),
  handler_(new Handler()),
  weak_factory_(this) {
  
}

NamespaceDispatcher::~NamespaceDispatcher() {

}

void NamespaceDispatcher::Bind(common::mojom::NamespaceManagerAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void NamespaceDispatcher::CreateNamespace(const std::string& namespace_name, CreateNamespaceCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::CreateNamespace,
       handler_,
       main_thread->domain_context(),
       namespace_name),
     base::Bind(&NamespaceDispatcher::ReplyCreateNamespace,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void NamespaceDispatcher::DropNamespace(const std::string& namespace_name, DropNamespaceCallback callback) {

}

void NamespaceDispatcher::GetNamespaceList(GetNamespaceListCallback callback) {

}

void NamespaceDispatcher::ExecuteQuery(int32_t id, const std::string& address, const std::string& encoded_query, ExecuteQueryCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::ExecuteQuery,
       handler_,
       main_thread->domain_context(),
       id, 
       address,
       encoded_query),
     base::Bind(&NamespaceDispatcher::ReplyExecuteQuery,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback)))); 
}

void NamespaceDispatcher::ReplyCreateNamespace(CreateNamespaceCallback callback, bool result) {
  common::mojom::DomainStatus status = result ? common::mojom::DomainStatus::kOk : common::mojom::DomainStatus::kError;
  std::move(callback).Run(std::move(status)); 
}

void NamespaceDispatcher::ReplyExecuteQuery(ExecuteQueryCallback callback, std::unique_ptr<QueryReply> result) {
  DCHECK(result.get() != nullptr);
  common::mojom::DomainStatus status = result->result ? common::mojom::DomainStatus::kOk : common::mojom::DomainStatus::kError;
  std::move(callback).Run(std::move(status), result->mailbox, std::move(result->reply_data));
}

}