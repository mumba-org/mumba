// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_DISPATCHER_H_
#define MUMBA_DOMAIN_NAMESPACE_DISPATCHER_H_

#include "base/macros.h"
#include "core/shared/common/mojom/namespace.mojom.h"
#include "core/domain/domain_context.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class NamespaceDispatcher : public common::mojom::NamespaceManager {
public:
  NamespaceDispatcher();
  ~NamespaceDispatcher() override;

  void Bind(common::mojom::NamespaceManagerAssociatedRequest request);

  void CreateNamespace(const std::string& namespace_name, CreateNamespaceCallback callback) override;
  void DropNamespace(const std::string& namespace_name, DropNamespaceCallback callback) override;
  void GetNamespaceList(GetNamespaceListCallback callback) override;
  void ExecuteQuery(int32_t id, const std::string& address, const std::string& encoded_query, ExecuteQueryCallback callback) override;

private:
  class Handler;

  struct QueryReply {
    bool result;
    int mailbox;
    std::string reply_data;

    QueryReply(bool r, int m, std::string data): result(r), mailbox(m), reply_data(std::move(data)){}
  };

  void ReplyCreateNamespace(CreateNamespaceCallback callback, bool result);
  void ReplyExecuteQuery(ExecuteQueryCallback callback, std::unique_ptr<QueryReply> reply);

  mojo::AssociatedBinding<common::mojom::NamespaceManager> binding_;

  scoped_refptr<Handler> handler_;

  base::WeakPtrFactory<NamespaceDispatcher> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(NamespaceDispatcher);
};

}


#endif