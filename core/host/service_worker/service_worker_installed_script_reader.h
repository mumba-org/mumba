// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_SERVICE_WORKER_SERVICE_WORKER_INSTALLED_SCRIPT_READER_H_
#define CONTENT_BROWSER_SERVICE_WORKER_SERVICE_WORKER_INSTALLED_SCRIPT_READER_H_

#include <memory>
#include <string>

#include "base/containers/flat_map.h"
#include "core/host/service_worker/service_worker_disk_cache.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "services/network/public/cpp/net_adapters.h"

namespace host {

// Reads a single service worker script from installed script storage. This is
// basically an adapter from ServiceWorkerResponseReader (AppCache/net style)
// to Mojo data pipe style.
class ServiceWorkerInstalledScriptReader {
 public:
  // Do not change the order. This is used for UMA.
  enum class FinishedReason {
    kNotFinished = 0,
    kSuccess = 1,
    kNoHttpInfoError = 2,
    kCreateDataPipeError = 3,
    kConnectionError = 4,
    kResponseReaderError = 5,
    kMetaDataSenderError = 6,
    // Add a new type here, then update kMaxValue and enums.xml.
    kMaxValue = kMetaDataSenderError,
  };

  // Receives the read data.
  class Client {
   public:
    virtual void OnStarted(std::string encoding,
                           base::flat_map<std::string, std::string> headers,
                           mojo::ScopedDataPipeConsumerHandle body_handle,
                           uint64_t body_size,
                           mojo::ScopedDataPipeConsumerHandle meta_data_handle,
                           uint64_t meta_data_size) = 0;
    virtual void OnHttpInfoRead(
        scoped_refptr<HttpResponseInfoIOBuffer> http_info) = 0;
    // Called after both body and metadata have finished being written to the
    // data pipes, or called immediately if an error occurred.
    virtual void OnFinished(FinishedReason reason) = 0;
  };

  // Uses |reader| to read an installed service worker script, and sends it to
  // |client|. |client| must outlive this.
  ServiceWorkerInstalledScriptReader(
      std::unique_ptr<ServiceWorkerResponseReader> reader,
      Client* client);
  ~ServiceWorkerInstalledScriptReader();

  // Starts reading the script.
  void Start();

 private:
  class MetaDataSender;
  void OnReadInfoComplete(scoped_refptr<HttpResponseInfoIOBuffer> http_info,
                          int result);
  void OnWritableBody(MojoResult);
  void OnResponseDataRead(int read_bytes);
  void OnMetaDataSent(bool success);
  void CompleteSendIfNeeded(FinishedReason reason);
  bool WasMetadataWritten() const { return !meta_data_sender_; }
  bool WasBodyWritten() const {
    return !body_handle_.is_valid() && !body_pending_write_;
  }

  base::WeakPtr<ServiceWorkerInstalledScriptReader> AsWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

  std::unique_ptr<ServiceWorkerResponseReader> reader_;
  // |client_| must outlive this.
  Client* client_;

  // For meta data.
  std::unique_ptr<MetaDataSender> meta_data_sender_;

  // For body.
  // Either |body_handle_| or |body_pending_write_| is valid during body is
  // streamed.
  mojo::ScopedDataPipeProducerHandle body_handle_;
  scoped_refptr<network::NetToMojoPendingBuffer> body_pending_write_;
  mojo::SimpleWatcher body_watcher_;

  base::WeakPtrFactory<ServiceWorkerInstalledScriptReader> weak_factory_;
};

}  // namespace host

#endif  // CONTENT_BROWSER_SERVICE_WORKER_SERVICE_WORKER_INSTALLED_SCRIPT_READER_H_
