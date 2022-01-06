// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_CACHE_STORAGE_DISPATCHER_H_
#define MUMBA_APPLICATION_CACHE_STORAGE_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/platform/heap/heap.h"
#include "third_party/blink/renderer/platform/heap/heap_traits.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_cache_storage.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom-blink.h"

namespace service_manager {
class InterfaceProvider;
}

namespace blink {
class WebLocalFrame;  
}

namespace IPC {
class SyncChannel;
}

namespace application {
class PageInstance;
class ApplicationWindowDispatcher;

class CacheStorageDispatcher : public automation::CacheStorage {
public:
  using CachesMap = HashMap<String, std::unique_ptr<blink::WebServiceWorkerCacheStorage>>;

  static void Create(automation::CacheStorageRequest request, PageInstance* page_instance);

  CacheStorageDispatcher(automation::CacheStorageRequest request, PageInstance* page_instance);
  CacheStorageDispatcher(PageInstance* page_instance);
  ~CacheStorageDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::CacheStorageAssociatedRequest request);

  void Register(int32_t application_id) override;
  void HasCache(const std::string& cache_id, HasCacheCallback callback) override;
  void OpenCache(const std::string& cache_id, OpenCacheCallback callback) override;
  void DeleteCache(const std::string& cache_id, DeleteCacheCallback callback) override;
  void DeleteEntry(const std::string& cache_id, const std::string& request, DeleteEntryCallback callback) override;
  void PutEntry(const std::string& cache_id, const std::string& request, blink::mojom::DataElementPtr data, PutEntryCallback callback) override;
  void PutEntryBlob(const std::string& cache_id, const std::string& request, blink::mojom::SerializedBlobPtr blob, automation::CacheStorage::PutEntryBlobCallback callback) override;
  void RequestCacheNames(const std::string& securityOrigin, RequestCacheNamesCallback callback) override;
  void RequestCachedResponse(const std::string& cache_id, const std::string& request_url, bool base64_encoded, RequestCachedResponseCallback callback) override;
  void RequestEntries(const std::string& cache_id, int32_t skipCount, int32_t pageSize, RequestEntriesCallback callback) override;

  bool enabled() const {
    return enabled_;
  }
  
  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:

  PageInstance* page_instance_;
  int32_t application_id_;
  mojo::AssociatedBinding<automation::CacheStorage> binding_;
  CachesMap caches_;
  bool enabled_;

  DISALLOW_COPY_AND_ASSIGN(CacheStorageDispatcher); 
};

}

#endif