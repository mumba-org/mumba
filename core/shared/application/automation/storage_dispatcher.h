// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_STORAGE_DISPATCHER_H_
#define MUMBA_APPLICATION_STORAGE_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace blink {
class WebLocalFrame;
}

namespace service_manager {
class InterfaceProvider;
}

namespace IPC {
class SyncChannel;
}

namespace application {
class PageInstance;

class StorageDispatcher : public automation::Storage {
public:
  
  static void Create(automation::StorageRequest request, PageInstance* page_instance);

  StorageDispatcher(automation::StorageRequest request, PageInstance* page_instance);
  StorageDispatcher(PageInstance* page_instance);
  ~StorageDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::StorageAssociatedRequest request);

  void Register(int32_t application_id) override;
  void ClearDataForOrigin(const std::string& origin, const std::vector<automation::StorageType>& storage_types) override;
  void GetUsageAndQuota(const std::string& origin, int64_t usage, int64_t quota, std::vector<automation::UsageForTypePtr> usage_breakdown) override;
  void TrackCacheStorageForOrigin(const std::string& origin) override;
  void TrackIndexedDBForOrigin(const std::string& origin) override;
  void UntrackCacheStorageForOrigin(const std::string& origin) override;
  void UntrackIndexedDBForOrigin(const std::string& origin) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::Storage> binding_;
  automation::StorageClientAssociatedPtr storage_client_ptr_;

  DISALLOW_COPY_AND_ASSIGN(StorageDispatcher); 
};

}

#endif