// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APP_URL_LOADER_FACTORY_H_
#define MUMBA_HOST_APPLICATION_APP_URL_LOADER_FACTORY_H_

#include <memory>
#include <map>

#include "base/macros.h"
#include "base/bind.h"
#include "base/debug/crash_logging.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/memory/ref_counted_memory.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_piece.h"
#include "base/task_scheduler/post_task.h"
#include "base/containers/flat_set.h"
#include "core/host/application/application_contents_observer.h"
#include "core/host/global_routing_id.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "services/network/public/mojom/network_service.mojom.h"
#include "third_party/zlib/google/compression_utils.h"
#include "ui/base/template_expressions.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"

namespace host {
class URLDataSource; 
class EntryContent;

class RpcURLLoaderFactory : public network::mojom::URLLoaderFactory,
                            public ApplicationContentsObserver {
 public:
  // |allowed_hosts| is an optional set of allowed host names. If empty then
  // all hosts are allowed.
  RpcURLLoaderFactory(ApplicationWindowHost* application_window_host,
                      const std::string& scheme,
                      base::flat_set<std::string> allowed_hosts);

  ~RpcURLLoaderFactory() override;

  network::mojom::URLLoaderFactoryPtr AddBinding();

  // network::mojom::URLLoaderFactory implementation:
  void CreateLoaderAndStart(network::mojom::URLLoaderRequest loader,
                            int32_t routing_id,
                            int32_t request_id,
                            uint32_t options,
                            const network::ResourceRequest& request,
                            network::mojom::URLLoaderClientPtr client,
                            const net::MutableNetworkTrafficAnnotationTag&
                                traffic_annotation) override;

  void Clone(network::mojom::URLLoaderFactoryRequest request) override;

  // ApplicationContentsObserver implementation:
  void ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) override;
  const std::string& scheme() const { return scheme_; }

  scoped_refptr<base::SingleThreadTaskRunner> impl_task_runner() const {
    return impl_task_runner_;
  }

 private:

  void StartURLLoader(const network::ResourceRequest& request,
                    int32_t process_id, 
                    int32_t routing_id,
                    network::mojom::URLLoaderClientPtrInfo client_info,
                    ApplicationContents* app_contents);
  
  void DataAvailable(network::mojom::URLLoaderClientPtrInfo client_info,
                     const GURL& url,                      
                     const std::string& path,
                     scoped_refptr<network::ResourceResponse> headers,
                     const ui::TemplateReplacements* replacements,
                     bool gzipped,
                     scoped_refptr<URLDataSource> source,
                     int call_id,
                     scoped_refptr<base::RefCountedMemory> contents,
                     bool should_complete);

  void ReadData(const GURL& url,
                const std::string& path,
                scoped_refptr<network::ResourceResponse> headers,
                const ui::TemplateReplacements* replacements,
                bool gzipped,
                scoped_refptr<URLDataSource> source,
                int call_id,
                scoped_refptr<base::RefCountedMemory> contents,
                bool should_complete);

  void ReadDataImpl(
                int call_id,
                const GURL& url,
                const std::string& path,
                scoped_refptr<network::ResourceResponse> headers,
                const ui::TemplateReplacements* replacements,
                bool gzipped,
                scoped_refptr<URLDataSource> source,
                scoped_refptr<base::RefCountedMemory> contents,
                bool should_complete);
 
  void CompleteRequest(int code, size_t data_length, size_t body_length);

  void CallOnError(int error_code);

  void ApplicationWindowDeletedOnIOThread(ApplicationWindowHost* application_window_host);

  MojoResult BeginWrite(void** data, uint32_t* available);
  
  ApplicationWindowHost* application_window_host_;
  std::string scheme_;
  const base::flat_set<std::string> allowed_hosts_;  // if empty all allowed.
  mojo::BindingSet<network::mojom::URLLoaderFactory> loader_factory_bindings_;
  network::mojom::URLLoaderClientPtr client_;
  bool headers_sent_;
  std::unique_ptr<mojo::DataPipe> data_pipe_;
  scoped_refptr<base::SingleThreadTaskRunner> impl_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(RpcURLLoaderFactory);
};

// Create a URLLoaderFactory for loading resources matching the specified
// |scheme| and also from a "pseudo host" matching one in |allowed_hosts|.
CONTENT_EXPORT std::unique_ptr<network::mojom::URLLoaderFactory>
CreateAppURLLoader(ApplicationWindowHost* application_window_host,
                   const std::string& scheme,
                   base::flat_set<std::string> allowed_hosts);

CONTENT_EXPORT network::mojom::URLLoaderFactoryPtr CreateAppURLLoaderBinding(
  ApplicationWindowHost* application_window_host,
  const std::string& scheme);

}

#endif