// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/blob_storage/blob_url_loader_factory.h"

#include <stddef.h>
#include <utility>
#include "base/bind.h"
#include "base/logging.h"
#include "base/macros.h"
#include "core/host/host_thread.h"
#include "storage/host/blob/blob_data_handle.h"
#include "storage/host/blob/blob_storage_context.h"
#include "storage/host/blob/blob_url_loader.h"

namespace host {

// static
scoped_refptr<BlobURLLoaderFactory> BlobURLLoaderFactory::Create(
    BlobContextGetter blob_storage_context_getter) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  auto factory = base::MakeRefCounted<BlobURLLoaderFactory>();
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&BlobURLLoaderFactory::InitializeOnIO, factory,
                     std::move(blob_storage_context_getter)));
  return factory;
}

void BlobURLLoaderFactory::HandleRequest(
    network::mojom::URLLoaderFactoryRequest request) {
  //DCHECK_CURRENTLY_ON(HostThread::UI);
  if (HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(HostThread::IO, FROM_HERE,
                         base::BindOnce(&BlobURLLoaderFactory::BindOnIO, this,
                                        std::move(request)));
  } else {
    BindOnIO(std::move(request));
  }
}

BlobURLLoaderFactory::BlobURLLoaderFactory() {}

BlobURLLoaderFactory::~BlobURLLoaderFactory() {}

void BlobURLLoaderFactory::InitializeOnIO(
    BlobContextGetter blob_storage_context_getter) {
  blob_storage_context_ = std::move(blob_storage_context_getter).Run();
}

void BlobURLLoaderFactory::BindOnIO(
    network::mojom::URLLoaderFactoryRequest request) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  loader_factory_bindings_.AddBinding(this, std::move(request));
}

// static
void BlobURLLoaderFactory::CreateLoaderAndStart(
    network::mojom::URLLoaderRequest loader,
    const network::ResourceRequest& request,
    network::mojom::URLLoaderClientPtr client,
    std::unique_ptr<storage::BlobDataHandle> blob_handle) {
  storage::BlobURLLoader::CreateAndStart(
      std::move(loader), request, std::move(client), std::move(blob_handle));
}

void BlobURLLoaderFactory::CreateLoaderAndStart(
    network::mojom::URLLoaderRequest loader,
    int32_t routing_id,
    int32_t request_id,
    uint32_t options,
    const network::ResourceRequest& request,
    network::mojom::URLLoaderClientPtr client,
    const net::MutableNetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(!request.download_to_file);
  DCHECK_CURRENTLY_ON(HostThread::IO);
  std::unique_ptr<storage::BlobDataHandle> blob_handle;
  if (blob_storage_context_) {
    blob_handle = blob_storage_context_->GetBlobDataFromPublicURL(request.url);
  }
  CreateLoaderAndStart(std::move(loader), request, std::move(client),
                       std::move(blob_handle));
}

void BlobURLLoaderFactory::Clone(
    network::mojom::URLLoaderFactoryRequest request) {
  loader_factory_bindings_.AddBinding(this, std::move(request));
}

}  // namespace host
