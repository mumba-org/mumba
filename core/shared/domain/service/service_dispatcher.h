// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_SERVICE_DISPATCHER_H_
#define MUMBA_DOMAIN_SERVICE_DISPATCHER_H_

#include "base/macros.h"

#include "core/shared/common/mojom/objects.mojom.h"
#include "core/shared/common/mojom/service.mojom.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class CONTENT_EXPORT ServiceDispatcher : public common::mojom::ServiceDispatcher {
public:
  ServiceDispatcher();
  ~ServiceDispatcher() override;

  void Bind(common::mojom::ServiceDispatcherAssociatedRequest request);

  void LookupServiceByName(const std::string& name, LookupServiceByNameCallback cb);
  void LookupServiceByUUID(const std::string& uuid, LookupServiceByUUIDCallback cb);
  void HaveServiceByName(const std::string& name, HaveServiceByNameCallback cb);
  void HaveServiceByUUID(const std::string& uuid, HaveServiceByUUIDCallback cb);
  void ListServices(ListServicesCallback callback) override;
  void GetServiceCount(GetServiceCountCallback callback) override;
  void GetServiceHeader(const std::string& url, GetServiceHeaderCallback callback) override;
  void StartService(const std::string& uuid, StartServiceCallback callback) override;
  void StopService(const std::string& uuid, StopServiceCallback callback) override;
  void Subscribe(common::mojom::ServiceSubscriberPtr subscriber, SubscribeCallback callback) override;
  void Unsubscribe(int id) override;
  
private:
  class Handler;

  void ReplyLookupServiceByName(LookupServiceByNameCallback cb, common::mojom::ServiceEntryPtr info);
  void ReplyLookupServiceByUUID(LookupServiceByUUIDCallback cb, common::mojom::ServiceEntryPtr info);
  void ReplyHaveServiceByName(HaveServiceByNameCallback cb, bool have);
  void ReplyHaveServiceByUUID(HaveServiceByUUIDCallback cb, bool have);
  void ReplyGetServiceHeader(GetServiceHeaderCallback callback, const network::ResourceResponseHead& response);
  void ReplyListServices(ListServicesCallback callback, std::vector<common::mojom::ServiceEntryPtr> infos);
  void ReplyGetServiceCount(GetServiceCountCallback callback, uint32_t count);
  void ReplyStartService(StartServiceCallback callback, bool result);
  void ReplyStopService(StopServiceCallback callback, bool result);
  void ReplySubscribe(SubscribeCallback callback, int32_t id);
  
  mojo::AssociatedBinding<common::mojom::ServiceDispatcher> binding_;

  scoped_refptr<Handler> handler_;

  base::WeakPtrFactory<ServiceDispatcher> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ServiceDispatcher);
};

}

#endif