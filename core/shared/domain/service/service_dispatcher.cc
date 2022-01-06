// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/service/service_dispatcher.h"

#include "base/uuid.h"
#include "base/files/file_path.h"
#include "base/task_scheduler/post_task.h"

namespace domain {

class ServiceDispatcher::Handler : public base::RefCountedThreadSafe<Handler> {
public:
  Handler() {}

  std::vector<common::mojom::ServiceEntryPtr> ListServices() {
    return std::vector<common::mojom::ServiceEntryPtr>();
  }

  uint32_t GetServiceCount() {
    return 0;
  }

  bool StartService(const base::UUID& id) {
    return true;
  }

  bool StopService(const base::UUID& id) {
    return true;
  }

private:
  friend class base::RefCountedThreadSafe<Handler>;

  ~Handler() {}
};

ServiceDispatcher::ServiceDispatcher():
 binding_(this),
 handler_(new Handler()),
 weak_factory_(this) {}
 
ServiceDispatcher::~ServiceDispatcher() {

}

void ServiceDispatcher::Bind(common::mojom::ServiceDispatcherAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void ServiceDispatcher::LookupServiceByName(const std::string& name, LookupServiceByNameCallback cb) {

}

void ServiceDispatcher::LookupServiceByUUID(const std::string& uuid, LookupServiceByUUIDCallback cb) {

}

void ServiceDispatcher::HaveServiceByName(const std::string& name, HaveServiceByNameCallback cb) {

}

void ServiceDispatcher::HaveServiceByUUID(const std::string& uuid, HaveServiceByUUIDCallback cb) {

}

void ServiceDispatcher::ListServices(ListServicesCallback callback) {
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::ListServices,
       handler_),
     base::Bind(&ServiceDispatcher::ReplyListServices,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ServiceDispatcher::GetServiceHeader(const std::string& url, GetServiceHeaderCallback callback) {

}

void ServiceDispatcher::GetServiceCount(GetServiceCountCallback callback) {
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::GetServiceCount,
       handler_),
     base::Bind(&ServiceDispatcher::ReplyGetServiceCount,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ServiceDispatcher::StartService(const std::string& uuid, StartServiceCallback callback) {
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::StartService,
       handler_,
       base::UUID(reinterpret_cast<const uint8_t *>(uuid.data()))),
     base::Bind(&ServiceDispatcher::ReplyStartService,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ServiceDispatcher::StopService(const std::string& uuid, StopServiceCallback callback) {
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::StopService,
       handler_,
       base::UUID(reinterpret_cast<const uint8_t *>(uuid.data()))),
     base::Bind(&ServiceDispatcher::ReplyStopService,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void ServiceDispatcher::Subscribe(common::mojom::ServiceSubscriberPtr subscriber, SubscribeCallback callback) {

}

void ServiceDispatcher::Unsubscribe(int id) {

}

void ServiceDispatcher::ReplyLookupServiceByName(LookupServiceByNameCallback cb, common::mojom::ServiceEntryPtr info) {

}

void ServiceDispatcher::ReplyGetServiceHeader(GetServiceHeaderCallback callback, const network::ResourceResponseHead& response) {
  
}

void ServiceDispatcher::ReplyLookupServiceByUUID(LookupServiceByUUIDCallback cb, common::mojom::ServiceEntryPtr info) {

}

void ServiceDispatcher::ReplyHaveServiceByName(HaveServiceByNameCallback cb, bool have) {

}

void ServiceDispatcher::ReplyHaveServiceByUUID(HaveServiceByUUIDCallback cb, bool have) {

}

void ServiceDispatcher::ReplyListServices(ListServicesCallback callback, std::vector<common::mojom::ServiceEntryPtr> infos) {
  std::move(callback).Run(std::move(infos));
}

void ServiceDispatcher::ReplyGetServiceCount(GetServiceCountCallback callback, uint32_t count) {
  std::move(callback).Run(count);
}

void ServiceDispatcher::ReplyStartService(StartServiceCallback callback, bool result) {
  common::mojom::ServiceStatusCode status = result ? common::mojom::ServiceStatusCode::kSERVICE_STATUS_OK : common::mojom::ServiceStatusCode::kSERVICE_STATUS_ERR_FAILED;
  std::move(callback).Run(std::move(status));
}

void ServiceDispatcher::ReplyStopService(StopServiceCallback callback, bool result) {
  common::mojom::ServiceStatusCode status = result ? common::mojom::ServiceStatusCode::kSERVICE_STATUS_OK : common::mojom::ServiceStatusCode::kSERVICE_STATUS_ERR_FAILED;
  std::move(callback).Run(std::move(status));
}

void ServiceDispatcher::ReplySubscribe(SubscribeCallback callback, int32_t id) {

}

}