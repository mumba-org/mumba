// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_APPLICATION_URL_LOADER_H_
#define MUMBA_APPLICATION_APPLICATION_URL_LOADER_H_

#include "base/macros.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/single_thread_task_runner.h"
#include "base/cancelable_callback.h"
#include "base/observer_list.h"
#include "base/optional.h"
#include "base/strings/string16.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "build/build_config.h"
#include "core/shared/common/content_export.h"
#include "core/shared/application/request_peer.h"
#include "third_party/blink/public/platform/web_url_loader.h"
#include "third_party/blink/public/platform/web_url_loader_factory.h"
#include "third_party/blink/public/platform/web_data_consumer_handle.h"
#include "third_party/blink/public/platform/web_common.h"
#include "runtime/MumbaShims/ApplicationHandler.h"

namespace network {
class SharedURLLoaderFactory;
}

namespace application {
class ResourceDispatcher;
class ApplicationWindowDispatcher;

using Client = blink::WebDataConsumerHandle::Client;
using Reader = blink::WebDataConsumerHandle::Reader;

// A custom data stream handler to be implemented by clients
// This guy is mostly used when the resulting data handed over to
// the web renderer is different from the one received.

// this can be used to decode, decompress or simply mutate the result
// We use this mostly to delegate the decoding of Protobuf to the client
// application so it can process and return a valid web document

// But this also can be used for decompression like zip, or preprocessing
// eg. to replace symbols or turn one given UI IDL into HTML

// => ProtobufDecoder : ResponseHandler
// => JSXTransform: ResponseHandler

class ResponseHandler {
public:
  virtual ~ResponseHandler() {}
  virtual const std::string& name() const = 0;
  virtual bool WillHandleResponse(blink::WebURLResponse* response) = 0;
  // used for when streaming the output (partial input => partial output) is possible
  // when its not streamed, we just call GetResult() once after the OnDataAvailable()
  // return its final net::OK to us
  // when its a stream, we call GetResult() even when the result of DataAvailable
  // is a 'continuation' opcode
  virtual bool CanStreamOutput() const { 
    return false;
  }
  // int is net::ERR_CONTINUE, net::OK or error
  // once net::OK is returned GetResult will be called to get the resulting
  // buffer
  virtual int OnDataAvailable(const char* input, int input_len) = 0;
  virtual int OnFinishLoading(int error_code, int total_transfer_size) = 0;
  virtual std::unique_ptr<RequestPeer::ReceivedData> GetResult() = 0;
};

// used when it can process partial input (streaming)
// eg. a decompression or decoder that can process partial data
// => ZipDecompress : ResponseStreamHandler
// => MpegDecoder: ResponseStreamHandler
class ResponseStreamHandler : public ResponseHandler {
public:
  virtual ~ResponseStreamHandler() override {}
  virtual bool CanStreamOutput() const override { 
    return true;
  }
};

class CONTENT_EXPORT ApplicationURLLoader : public blink::WebURLLoader {
public:

  static void PopulateURLResponse(
    const blink::WebURL& url,
    const network::ResourceResponseInfo& info,
    blink::WebURLResponse* response,
    bool report_security_info);

  ApplicationURLLoader(
    ResourceDispatcher* resource_dispatcher,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory);  

  ApplicationURLLoader(
    ResourceDispatcher* resource_dispatcher,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
    CBlinkPlatformCallbacks callbacks,
    void* url_loader_state);

  ~ApplicationURLLoader() override;

  void LoadSynchronously(
      const blink::WebURLRequest&,
      blink::WebURLResponse&,
      base::Optional<blink::WebURLError>&,
      blink::WebData&,
      int64_t& encoded_data_length,
      int64_t& encoded_body_length,
      base::Optional<int64_t>& downloaded_file_length,
      blink::WebBlobInfo& downloaded_blob) override;

  void LoadAsynchronously(const blink::WebURLRequest&,
                          blink::WebURLLoaderClient*) override;

  void Cancel() override;

  // Suspends/resumes an asynchronous load.
  void SetDefersLoading(bool defers) override;

  void DidChangePriority(blink::WebURLRequest::Priority new_priority,
                         int intra_priority_value) override;

  void AddHandler(std::unique_ptr<ResponseHandler> handler);

private:
  class Context;
  class RequestPeerImpl;
  class SinkPeer;
 
  //const blink::WebURLRequest& request_;
  //scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  scoped_refptr<Context> context_;
  CBlinkPlatformCallbacks callbacks_;
  void* url_loader_state_;
  
  DISALLOW_COPY_AND_ASSIGN(ApplicationURLLoader);
};

// NOTE: about the callbacks reference. Its expected that the blink
// platform who owns the callbacks will outlive this object
class CONTENT_EXPORT ApplicationURLLoaderFactory : public blink::WebURLLoaderFactory {
public:
  // ApplicationURLLoaderFactory(
  //   base::WeakPtr<ResourceDispatcher> resource_dispatcher,
  //   scoped_refptr<network::SharedURLLoaderFactory> loader_factory,
  //   CBlinkPlatformCallbacks callbacks,
  //   void* url_loader_state);

  //  ApplicationURLLoaderFactory(
  //   base::WeakPtr<ResourceDispatcher> resource_dispatcher,
  //   scoped_refptr<network::SharedURLLoaderFactory> loader_factory);

   ApplicationURLLoaderFactory(
    base::WeakPtr<ResourceDispatcher> resource_dispatcher,
    scoped_refptr<network::SharedURLLoaderFactory> loader_factory,
    ApplicationWindowDispatcher* window_dispatcher);

  ApplicationURLLoaderFactory(
     base::WeakPtr<ResourceDispatcher> resource_dispatcher,
     scoped_refptr<network::SharedURLLoaderFactory> loader_factory,
     CBlinkPlatformCallbacks callbacks,
     ApplicationWindowDispatcher* window_dispatcher);
  
  ~ApplicationURLLoaderFactory() override;

  std::unique_ptr<blink::WebURLLoader> CreateURLLoader(
    const blink::WebURLRequest& request,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) override;

private:
  base::WeakPtr<ResourceDispatcher> resource_dispatcher_;
  scoped_refptr<network::SharedURLLoaderFactory> loader_factory_;
  CBlinkPlatformCallbacks callbacks_;
  void* url_loader_state_;
  ApplicationWindowDispatcher* window_dispatcher_;
  bool callbacks_set_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationURLLoaderFactory);
};

class WebDataConsumerHandleImpl final
    : public blink::WebDataConsumerHandle {
  typedef mojo::ScopedDataPipeConsumerHandle Handle;
  class Context;
 public:
  class CONTENT_EXPORT ReaderImpl final : public Reader {
   public:
    ReaderImpl(scoped_refptr<Context> context,
               Client* client,
               scoped_refptr<base::SingleThreadTaskRunner> task_runner);
    ~ReaderImpl() override;
    Result Read(void* data,
                size_t size,
                Flags flags,
                size_t* readSize) override;
    Result BeginRead(const void** buffer,
                     Flags flags,
                     size_t* available) override;
    Result EndRead(size_t readSize) override;

   private:
    Result HandleReadResult(MojoResult);
    void StartWatching();
    void OnHandleGotReadable(MojoResult);

    scoped_refptr<Context> context_;
    mojo::SimpleWatcher handle_watcher_;
    Client* client_;

    DISALLOW_COPY_AND_ASSIGN(ReaderImpl);
  };
  std::unique_ptr<Reader> ObtainReader(
      Client* client,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) override;

  explicit WebDataConsumerHandleImpl(Handle handle);
  ~WebDataConsumerHandleImpl() override;

 private:
  const char* DebugName() const override;
  
  scoped_refptr<Context> context_;

  DISALLOW_COPY_AND_ASSIGN(WebDataConsumerHandleImpl);
};


}

#endif