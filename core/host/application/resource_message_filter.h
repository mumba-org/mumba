// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_LOADER_RESOURCE_MESSAGE_FILTER_H_
#define CONTENT_BROWSER_LOADER_RESOURCE_MESSAGE_FILTER_H_

#include <memory>

#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/sequenced_task_runner_helpers.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/common/content_export.h"
#include "core/host/host_associated_interface.h"
#include "core/host/host_message_filter.h"
#include "core/shared/common/resource_type.h"
#include "net/rpc/rpc_message_encoder.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"

namespace storage {
class FileSystemContext;
}  // namespace storage

namespace net {
class URLRequestContext;
}  // namespace net


namespace host {
class ChromeAppCacheService;
class ChromeBlobStorageContext;
class PrefetchURLLoaderService;
class ResourceContext;
class ResourceRequesterInfo;
class ServiceWorkerContextWrapper;
class RouteRegistry;
class HostNetworkContext;

// This class filters out incoming IPC messages for network requests and
// processes them on the IPC thread.  As a result, network requests are not
// delayed by costly UI processing that may be occuring on the main thread of
// the browser.  It also means that any hangs in starting a network request
// will not interfere with browser UI.
class CONTENT_EXPORT ResourceMessageFilter
    : public HostMessageFilter,
      public HostAssociatedInterface<network::mojom::URLLoaderFactory>,
      public network::mojom::URLLoaderFactory {
 public:
  typedef base::Callback<void(common::ResourceType resource_type,
                              ResourceContext**,
                              net::URLRequestContext**)> GetContextsCallback;

  // |appcache_service|, |blob_storage_context|, |file_system_context|,
  // |service_worker_context| may be nullptr in unittests.
  // InitializeForTest() needs to be manually called for unittests where
  // OnFilterAdded() would not otherwise be called.
  ResourceMessageFilter(
      int child_id,
      ChromeAppCacheService* appcache_service,
      ChromeBlobStorageContext* blob_storage_context,
      storage::FileSystemContext* file_system_context,
      ServiceWorkerContextWrapper* service_worker_context,
      PrefetchURLLoaderService* prefetch_url_loader_service,
      const GetContextsCallback& get_contexts_callback,
      const scoped_refptr<base::SingleThreadTaskRunner>& io_thread_runner);
  
  // meant for application process
  ResourceMessageFilter(
    ChromeAppCacheService* appcache_service,
    ChromeBlobStorageContext* blob_storage_context,
    storage::FileSystemContext* file_system_context,
    ServiceWorkerContextWrapper* service_worker_context,
    PrefetchURLLoaderService* prefetch_url_loader_service,
    const GetContextsCallback& get_contexts_callback,
    const scoped_refptr<base::SingleThreadTaskRunner>& io_thread_runner,
    RouteRegistry* registry,
    int process_id);

  // BrowserMessageFilter implementation.
  void OnFilterAdded(IPC::Channel* channel) override;
  void OnChannelClosing() override;
  bool OnMessageReceived(const IPC::Message& message) override;
  void OnDestruct() const override;

  base::WeakPtr<ResourceMessageFilter> GetWeakPtr();

  void CreateLoaderAndStart(network::mojom::URLLoaderRequest request,
                            int32_t routing_id,
                            int32_t request_id,
                            uint32_t options,
                            const network::ResourceRequest& url_request,
                            network::mojom::URLLoaderClientPtr client,
                            const net::MutableNetworkTrafficAnnotationTag&
                                traffic_annotation) override;
  void Clone(network::mojom::URLLoaderFactoryRequest request) override;

  int child_id() const;

  void set_routing_id(int routing_id) {
    routing_id_ = routing_id;
  }

  ResourceRequesterInfo* requester_info_for_test() {
    return requester_info_.get();
  }
  
  void InitializeForTest();

  // Overrides the network URLLoaderFactory for subsequent requests. Passing a
  // null pointer will restore the default behavior.
  // When the testing pointer's CreateLoaderAndStart() is being called,
  // |GetCurrentForTesting()| will return the filter that's calling the testing
  // pointer. Also, the testing pointer won't be used for nested
  // CreateLoaderAndStart's.
  // This method must be called either on the IO thread or before threads start.
  // This callback is run on the IO thread.
  static void SetNetworkFactoryForTesting(
      network::mojom::URLLoaderFactory* test_factory);
  static ResourceMessageFilter* GetCurrentForTesting();

 protected:
  // Protected destructor so that we can be overriden in tests.
  ~ResourceMessageFilter() override;

 private:
  friend class base::DeleteHelper<ResourceMessageFilter>;

  // Initializes the weak pointer of this filter in |requester_info_|.
  void InitializeOnIOThread();

  void GetEncoderAndCreateLoader(network::mojom::URLLoaderRequest request,
                                int32_t routing_id,
                                int32_t request_id,
                                uint32_t options,
                                const network::ResourceRequest& url_request,
                                network::mojom::URLLoaderClientPtr client,
                                const net::MutableNetworkTrafficAnnotationTag&
                                traffic_annotation);

  void CreateLoaderAndStartImpl(network::mojom::URLLoaderRequest request,
                                int32_t routing_id,
                                int32_t request_id,
                                uint32_t options,
                                const network::ResourceRequest& url_request,
                                network::mojom::URLLoaderClientPtr client,
                                const net::MutableNetworkTrafficAnnotationTag&
                                traffic_annotation,
                                HostNetworkContext* network_context,
                                std::unique_ptr<net::RpcMessageEncoder> encoder);

  bool is_channel_closed_;
  scoped_refptr<ResourceRequesterInfo> requester_info_;

  network::mojom::URLLoaderFactory* url_loader_factory_;
  std::unique_ptr<network::mojom::URLLoaderFactory> owned_url_loader_factory_;

  scoped_refptr<PrefetchURLLoaderService> prefetch_url_loader_service_;

  // Task runner for the IO thead.
  scoped_refptr<base::SingleThreadTaskRunner> io_thread_task_runner_;

  RouteRegistry* registry_;
  int routing_id_;
  int process_id_;

  // This must come last to make sure weak pointers are invalidated first.
  base::WeakPtrFactory<ResourceMessageFilter> weak_ptr_factory_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(ResourceMessageFilter);
};

}  // namespace host

#endif  // CONTENT_BROWSER_LOADER_RESOURCE_MESSAGE_FILTER_H_
