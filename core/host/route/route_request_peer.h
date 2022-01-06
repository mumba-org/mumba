// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ROUTE_ROUTE_REQUEST_PEER_H_
#define MUMBA_HOST_ROUTE_ROUTE_REQUEST_PEER_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "base/task_scheduler/post_task.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/system/data_pipe.h"

namespace net {
struct RedirectInfo;
}

namespace network {
struct ResourceResponseInfo;
struct ResourceResponseHead;
struct URLLoaderCompletionStatus;
}

namespace host {

class CONTENT_EXPORT RouteRequestPeer {
 public:
  class CONTENT_EXPORT ReceivedData {
   public:
    virtual ~ReceivedData() {}
    virtual const char* payload() const = 0;
    virtual int length() const = 0;
  };
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnRequestStarted(int request_id) = 0;
    virtual void OnUploadProgress(int request, uint64_t position, uint64_t size) = 0;
    virtual bool OnReceivedRedirect(int request, const net::RedirectInfo& redirect_info, 
                          const network::ResourceResponseInfo& info,
                          scoped_refptr<base::SingleThreadTaskRunner> task_runner) = 0;
    virtual void OnReceivedResponse(int request, const network::ResourceResponseHead& response_head) = 0;
    virtual void OnStartLoadingResponseBody(int request, mojo::ScopedDataPipeConsumerHandle body) = 0;
    virtual void OnDownloadedData(int request, int len, int encoded_data_length) = 0;
    virtual void OnReceivedData(int request, std::unique_ptr<ReceivedData> data) = 0;
    virtual void OnTransferSizeUpdated(int request, int transfer_size_diff) = 0;
    virtual void OnReceivedCachedMetadata(int request, const std::vector<uint8_t>& data, int len) = 0;
    virtual void OnCompletedRequest(int request, const network::URLLoaderCompletionStatus& status) = 0;
  };  
  class CONTENT_EXPORT ThreadSafeReceivedData : public ReceivedData {};

  virtual void OnRequestStarted(int request_id) = 0;
  virtual void OnUploadProgress(int request, uint64_t position, uint64_t size) = 0;
  virtual bool OnReceivedRedirect(
      int request, 
      const net::RedirectInfo& redirect_info,
      const network::ResourceResponseInfo& info,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) = 0;
  virtual void OnReceivedResponse(
      int request, 
      const network::ResourceResponseHead& response_head) = 0;
  virtual void OnStartLoadingResponseBody(
      int request, 
      mojo::ScopedDataPipeConsumerHandle body) = 0;
  virtual void OnDownloadedData(int request, int len, int encoded_data_length) = 0;
  virtual void OnReceivedData(int request, std::unique_ptr<ReceivedData> data) = 0;
  virtual void OnTransferSizeUpdated(int request, int transfer_size_diff) = 0;
  virtual void OnReceivedCachedMetadata(int request, const std::vector<uint8_t>& data, int len) {}
  virtual void OnCompletedRequest(
      int request, 
      const network::URLLoaderCompletionStatus& status) = 0;

  virtual Delegate* GetDelegate() const = 0;

  virtual ~RouteRequestPeer() {}
};

}  // namespace host

#endif
