// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/cache_storage_dispatcher.h"

#define INSIDE_BLINK 1

#include "base/guid.h"
#include "core/shared/application/automation/page_instance.h"
#include "core/shared/application/application_window_dispatcher.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/public/platform/modules/cache_storage/cache_storage.mojom-blink.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_cache.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_cache_storage.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_request.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_response.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"
#include "third_party/blink/renderer/core/fetch/blob_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/global_fetch.h"
#include "third_party/blink/renderer/core/fetch/request.h"
#include "third_party/blink/renderer/core/fetch/response.h"
#include "third_party/blink/renderer/core/fetch/response_init.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader_client.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/network/http_header_map.h"
#include "third_party/blink/renderer/platform/shared_buffer.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/ref_counted.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/time.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/uuid.h"
#include "third_party/blink/renderer/bindings/core/v8/local_window_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/modules/cache_storage/cache.h"

#include "ipc/ipc_sync_channel.h"

using blink::HeapObjectHeader;
using blink::TraceDescriptor;
using blink::TraceWrapperDescriptor;
using blink::ThreadingTrait;
using blink::TraceEagerlyTrait;
using blink::ScriptWrappableVisitor;
using blink::kLargeObjectSizeThreshold;
using blink::IsEagerlyFinalizedType;
using blink::ThreadState;
using blink::ThreadStateFor;
using blink::GarbageCollectedMixinConstructorMarker;
using blink::TraceTrait;

namespace application {

namespace {

// CString CacheStorageErrorString(blink::mojom::CacheStorageError error) {
//   switch (error) {
//     case blink::mojom::CacheStorageError::kErrorNotImplemented:
//       return CString("not implemented.");
//     case blink::mojom::CacheStorageError::kErrorNotFound:
//       return CString("not found.");
//     case blink::mojom::CacheStorageError::kErrorExists:
//       return CString("cache already exists.");
//     case blink::mojom::CacheStorageError::kErrorQuotaExceeded:
//       return CString("quota exceeded.");
//     case blink::mojom::CacheStorageError::kErrorCacheNameNotFound:
//       return CString("cache not found.");
//     case blink::mojom::CacheStorageError::kErrorQueryTooLarge:
//       return CString("operation too large.");
//     case blink::mojom::CacheStorageError::kErrorStorage:
//       return CString("storage failure.");
//     case blink::mojom::CacheStorageError::kSuccess:
//       // This function should only be called upon error.
//       break;
//   }
//   NOTREACHED();
//   return "";
// }

std::string BuildCacheId(const String& security_origin, const String& cache_name) {
  String id(security_origin);
  id.append('|');
  id.append(cache_name);
  return std::string(id.Utf8().data(), id.Utf8().length());
}

bool ParseCacheId(const String& id,
                  String* security_origin,
                  String* cache_name) {
  size_t pipe = id.find('|');
  if (pipe == WTF::kNotFound) {
    //DLOG(ERROR) << "Invalid cache id.";
    return false;
  }
  *security_origin = id.Substring(0, pipe);
  *cache_name = id.Substring(pipe + 1);
  return true;
}

blink::LocalFrame* GetFrameWithOrigin(blink::InspectedFrames* frames, const String& security_origin) {
  for (blink::LocalFrame* frame : *frames) {
    //DLOG(INFO) << "comparing '" << frame->GetDocument()->Url().Protocol() << "' and '" << security_origin << "'";
    if (frame->GetDocument()->Url().Protocol() == security_origin) {
      return frame;
    }
  }
  return nullptr;
}

bool GetExecutionContext(blink::InspectedFrames* frames,
                         const String& security_origin,
                         blink::ExecutionContext** context) {
  //blink::LocalFrame* frame = frames->FrameWithSecurityOrigin(security_origin);
  blink::LocalFrame* frame = GetFrameWithOrigin(frames, security_origin);
  if (!frame) {
    //DLOG(ERROR) << "No frame with origin " << security_origin;
    return false;
  }

  blink::Document* document = frame->GetDocument();
  if (!document) {
    return false;
  }

  *context = document;

  return true;
}

bool AssertCacheStorage(
  const String& security_origin,
  blink::InspectedFrames* frames,
  CacheStorageDispatcher::CachesMap* caches,
  blink::WebServiceWorkerCacheStorage** result) {
  scoped_refptr<const blink::SecurityOrigin> sec_origin = blink::SecurityOrigin::CreateFromString(security_origin);

  // Cache Storage API is restricted to trustworthy origins.
  // if (!sec_origin->IsPotentiallyTrustworthy()) {
  //   //DLOG(ERROR) << "Origin " << security_origin << " is not considered potentially trustworthy";
  //   //return ProtocolResponse::Error(
  //   //    sec_origin->IsPotentiallyTrustworthyErrorMessage());
  //   return false;
  // }

  blink::ExecutionContext* context = nullptr;
  bool ok = GetExecutionContext(frames, security_origin, &context);
  if (!ok) {
    //DLOG(ERROR) << "Execution context not available";
    return false;
  }

  auto it = caches->find(security_origin);

  if (it == caches->end()) {
    std::unique_ptr<blink::WebServiceWorkerCacheStorage> cache_storage =
        blink::Platform::Current()->CreateCacheStorage(context->GetInterfaceProvider());
    if (!cache_storage) {
      //DLOG(ERROR) << "Could not find cache storage.";
      return false;//ProtocolResponse::Error("Could not find cache storage.");
    }
    *result = cache_storage.get();
    caches->Set(security_origin, std::move(cache_storage));
  } else {
    *result = it->value.get();
  }

  return true;
}

bool AssertCacheStorageAndNameForId(
  const String& cache_id,
  blink::InspectedFrames* frames,
  String* cache_name,
  CacheStorageDispatcher::CachesMap* caches,
  blink::WebServiceWorkerCacheStorage** result) {
  String security_origin;
  bool ok = ParseCacheId(cache_id, &security_origin, cache_name);
  if (!ok)
    return false;
  return AssertCacheStorage(security_origin, frames, caches, result);
}

class RequestCacheNamesImpl : public blink::WebServiceWorkerCacheStorage::CacheStorageKeysCallbacks {
 public:
  RequestCacheNamesImpl(const String& security_origin,
                    CacheStorageDispatcher::RequestCacheNamesCallback callback)
      : security_origin_(security_origin), 
        callback_(std::move(callback)) {}

  ~RequestCacheNamesImpl() override = default;

  void OnSuccess(const blink::WebVector<blink::WebString>& caches) override {
    std::vector<automation::CachePtr> array;
    for (size_t i = 0; i < caches.size(); i++) {
      std::string name(caches[i].Utf8(), caches[i].length());
      automation::CachePtr entry = automation::Cache::New();
      entry->security_origin = std::string(security_origin_.Utf8().data(), security_origin_.Utf8().length());
      entry->cache_name = name;
      entry->cache_id = BuildCacheId(security_origin_, String(caches[i]));
      array.push_back(std::move(entry));
    }
    std::move(callback_).Run(std::move(array));
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    // FIXME
    //DLOG(ERROR) << "Error requesting cache names: " << CacheStorageErrorString(error).data();
    std::move(callback_).Run(std::vector<automation::CachePtr>());
  }

 private:
  String security_origin_;
  CacheStorageDispatcher::RequestCacheNamesCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(RequestCacheNamesImpl);
};

struct DataRequestParams {
  String cache_name;
  int skip_count;
  int page_size;
};

struct RequestResponse {
  String request_url;
  String request_method;
  blink::HTTPHeaderMap request_headers;
  int response_status;
  String response_status_text;
  double response_time;
  blink::HTTPHeaderMap response_headers;
};

class ResponsesAccumulator : public RefCounted<ResponsesAccumulator> {
 public:
  ResponsesAccumulator(int num_responses,
                       const DataRequestParams& params,
                       CacheStorageDispatcher::RequestEntriesCallback callback)
      : params_(params),
        num_responses_left_(num_responses),
        responses_(static_cast<size_t>(num_responses)),
        callback_(std::move(callback)) {

  }

  void AddRequestResponsePair(const blink::WebServiceWorkerRequest& request,
                              const blink::WebServiceWorkerResponse& response) {
    DCHECK_GT(num_responses_left_, 0);
    RequestResponse& request_response =
        responses_.at(responses_.size() - num_responses_left_);

    request_response.request_url = request.Url().GetString();
    request_response.request_method = request.Method();
    request_response.request_headers = request.Headers();
    request_response.response_status = response.Status();
    request_response.response_status_text = response.StatusText();
    request_response.response_time = response.ResponseTime().ToDoubleT();
    request_response.response_headers = response.Headers();

    if (--num_responses_left_ != 0)
      return;

    std::sort(responses_.begin(), responses_.end(),
              [](const RequestResponse& a, const RequestResponse& b) {
                return WTF::CodePointCompareLessThan(a.request_url,
                                                     b.request_url);
              });
    if (params_.skip_count > 0)
      responses_.EraseAt(0, params_.skip_count);
    bool has_more = false;
    if (static_cast<size_t>(params_.page_size) < responses_.size()) {
      responses_.EraseAt(params_.page_size,
                         responses_.size() - params_.page_size);
      has_more = true;
    }
    std::vector<automation::DataEntryPtr> array;
    for (const auto& request_response : responses_) {
      automation::DataEntryPtr entry = automation::DataEntry::New();
      entry->request_url = std::string(request_response.request_url.Utf8().data(), request_response.request_url.Utf8().length());
      entry->request_method = std::string(request_response.request_method.Utf8().data(), request_response.request_method.Utf8().length());
      entry->request_headers = SerializeHeaders(request_response.request_headers);
      entry->response_status = request_response.response_status;
      entry->response_status_text = std::string(request_response.response_status_text.Utf8().data(), request_response.response_status_text.Utf8().length());
      entry->response_time = request_response.response_time;
      entry->response_headers = SerializeHeaders(request_response.response_headers);
      array.push_back(std::move(entry));
    }
    std::move(callback_).Run(std::move(array), has_more);
  }

  void SendFailure() {
    //callback_->sendFailure(error);
    std::move(callback_).Run(std::vector<automation::DataEntryPtr>(), false);
  }

  std::vector<automation::HeaderPtr> SerializeHeaders(
      const blink::HTTPHeaderMap& headers) {
    std::vector<automation::HeaderPtr> result;
    for (blink::HTTPHeaderMap::const_iterator it = headers.begin(),
                                              end = headers.end();
         it != end; ++it) {
      automation::HeaderPtr header = automation::Header::New();
      header->name = std::string(it->key.Utf8().data(), it->key.Utf8().length());
      header->value = std::string(it->value.Utf8().data(), it->value.Utf8().length());
      result.push_back(std::move(header));
    }
    return result;
  }

 private:
  DataRequestParams params_;
  int num_responses_left_;
  Vector<RequestResponse> responses_;
  CacheStorageDispatcher::RequestEntriesCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(ResponsesAccumulator);
};

class GetCacheResponsesForRequestData
    : public blink::WebServiceWorkerCache::CacheMatchCallbacks {
 public:
  GetCacheResponsesForRequestData(const DataRequestParams& params,
                                  const blink::WebServiceWorkerRequest& request,
                                  scoped_refptr<ResponsesAccumulator> accum)
      : params_(params), request_(request), accumulator_(std::move(accum)) {}
  ~GetCacheResponsesForRequestData() override = default;

  void OnSuccess(const blink::WebServiceWorkerResponse& response) override {
    accumulator_->AddRequestResponsePair(request_, response);
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    //DLOG(ERROR) << "Error requesting responses for cache " << 
    //  params_.cache_name.Utf8().data() << 
    // ": " << CacheStorageErrorString(error).data();
    accumulator_->SendFailure();
  }

 private:
  DataRequestParams params_;
  blink::WebServiceWorkerRequest request_;
  scoped_refptr<ResponsesAccumulator> accumulator_;

  DISALLOW_COPY_AND_ASSIGN(GetCacheResponsesForRequestData);
};

class GetCacheKeysForRequestData
    : public blink::WebServiceWorkerCache::CacheWithRequestsCallbacks {
 public:
  GetCacheKeysForRequestData(const DataRequestParams& params,
                             std::unique_ptr<blink::WebServiceWorkerCache> cache,
                             CacheStorageDispatcher::RequestEntriesCallback callback)
      : params_(params),
        cache_(std::move(cache)),
        callback_(std::move(callback)) {}
  ~GetCacheKeysForRequestData() override = default;

  blink::WebServiceWorkerCache* Cache() { return cache_.get(); }
  void OnSuccess(const blink::WebVector<blink::WebServiceWorkerRequest>& requests) override {
    if (requests.IsEmpty()) {
      std::move(callback_).Run(std::vector<automation::DataEntryPtr>(), false);
      return;
    }
    scoped_refptr<ResponsesAccumulator> accumulator =
        base::AdoptRef(new ResponsesAccumulator(requests.size(), 
                                                params_,
                                                std::move(callback_)));
    for (size_t i = 0; i < requests.size(); i++) {
      const auto& request = requests[i];
      auto cache_request = std::make_unique<GetCacheResponsesForRequestData>(
          params_, request, accumulator);
      cache_->DispatchMatch(std::move(cache_request), 
                            request,
                            blink::WebServiceWorkerCache::QueryParams());
    }
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    // callback_->sendFailure(ProtocolResponse::Error(
    //     String::Format("Error requesting requests for cache %s: %s",
    //                    params_.cache_name.Utf8().data(),
    //                    CacheStorageErrorString(error).data())));
    //DLOG(ERROR) << "Error requesting requests for cache " << params_.cache_name.Utf8().data() << 
    //                ": " << CacheStorageErrorString(error).data();
    std::move(callback_).Run(std::vector<automation::DataEntryPtr>(), false);                
  }

 private:
  DataRequestParams params_;
  std::unique_ptr<blink::WebServiceWorkerCache> cache_;
  CacheStorageDispatcher::RequestEntriesCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(GetCacheKeysForRequestData);
};

class GetCacheForRequestData
    : public blink::WebServiceWorkerCacheStorage::CacheStorageWithCacheCallbacks {
 public:
  GetCacheForRequestData(const DataRequestParams& params,
                         CacheStorageDispatcher::RequestEntriesCallback callback)
      : params_(params), 
        callback_(std::move(callback)) {}
  ~GetCacheForRequestData() override = default;

  void OnSuccess(std::unique_ptr<blink::WebServiceWorkerCache> cache) override {
    auto cache_request = std::make_unique<GetCacheKeysForRequestData>(
        params_, std::move(cache), std::move(callback_));
    cache_request->Cache()->DispatchKeys(std::move(cache_request),
                                         blink::WebServiceWorkerRequest(),
                                         blink::WebServiceWorkerCache::QueryParams());
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    // callback_->sendFailure(ProtocolResponse::Error(String::Format(
    //     "Error requesting cache %s: %s", params_.cache_name.Utf8().data(),
    //     CacheStorageErrorString(error).data())));
    //DLOG(ERROR) << "Error requesting cache " << params_.cache_name.Utf8().data() << " : " << CacheStorageErrorString(error).data();
    std::move(callback_).Run(std::vector<automation::DataEntryPtr>(), false);
  }

 private:
  DataRequestParams params_;
  CacheStorageDispatcher::RequestEntriesCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(GetCacheForRequestData);
};

class HasCacheImpl : public blink::WebServiceWorkerCacheStorage::CacheStorageCallbacks {
 public:
  explicit HasCacheImpl(CacheStorageDispatcher::HasCacheCallback callback)
      : callback_(std::move(callback)) {}
  ~HasCacheImpl() override = default;

  void OnSuccess() override { 
    std::move(callback_).Run(true);
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    //DLOG(ERROR) << "Error requesting cache names: " << CacheStorageErrorString(error).data();
    std::move(callback_).Run(false); 
  }

 private:
  CacheStorageDispatcher::HasCacheCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(HasCacheImpl);
};

class OpenCacheImpl : public blink::WebServiceWorkerCacheStorage::CacheStorageWithCacheCallbacks {
 public:
  explicit OpenCacheImpl(CacheStorageDispatcher::OpenCacheCallback callback)
      : callback_(std::move(callback)) {}
  ~OpenCacheImpl() override = default;

  void OnSuccess(std::unique_ptr<blink::WebServiceWorkerCache> cache) override { 
    // auto delete_request =
    //     std::make_unique<DeleteCacheEntry>(std::move(callback_));
    // blink::WebServiceWorkerCache::BatchOperation delete_operation;
    // delete_operation.operation_type =
    //     blink::WebServiceWorkerCache::kOperationTypeDelete;
    // delete_operation.request.SetURL(blink::KURL(request_spec_));
    // Vector<blink::WebServiceWorkerCache::BatchOperation> operations;
    // operations.push_back(delete_operation);
    // cache.release()->DispatchBatch(std::move(delete_request),
    //                                blink::WebVector<blink::WebServiceWorkerCache::BatchOperation>(operations));
    std::move(callback_).Run(static_cast<int>(cache ? blink::mojom::CacheStorageError::kSuccess : blink::mojom::CacheStorageError::kErrorStorage));
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    //DLOG(ERROR) << "Error requesting cache names: " << CacheStorageErrorString(error).data();
    std::move(callback_).Run(false); 
  }

 private:
  CacheStorageDispatcher::OpenCacheCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(OpenCacheImpl);
};

class DeleteCacheImpl : public blink::WebServiceWorkerCacheStorage::CacheStorageCallbacks {
 public:
  explicit DeleteCacheImpl(CacheStorageDispatcher::DeleteCacheCallback callback)
      : callback_(std::move(callback)) {}
  ~DeleteCacheImpl() override = default;

  void OnSuccess() override { 
    std::move(callback_).Run(true);
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    //DLOG(ERROR) << "Error requesting cache names: " << CacheStorageErrorString(error).data();
    std::move(callback_).Run(false); 
  }

 private:
  CacheStorageDispatcher::DeleteCacheCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(DeleteCacheImpl);
};

class DeleteCacheEntry : public blink::WebServiceWorkerCache::CacheBatchCallbacks {
 public:
  explicit DeleteCacheEntry(CacheStorageDispatcher::DeleteEntryCallback callback)
      : callback_(std::move(callback)) {}
  ~DeleteCacheEntry() override = default;

  void OnSuccess() override { 
    std::move(callback_).Run(true);
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    //DLOG(ERROR) << "Error requesting cache names: " << CacheStorageErrorString(error).data();
    std::move(callback_).Run(false); 
  }

 private:
  CacheStorageDispatcher::DeleteEntryCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(DeleteCacheEntry);
};

class GetCacheForDeleteEntry
    : public blink::WebServiceWorkerCacheStorage::CacheStorageWithCacheCallbacks {
 public:
  GetCacheForDeleteEntry(const String& request_spec,
                         const String& cache_name,
                         CacheStorageDispatcher::DeleteEntryCallback callback)
      : request_spec_(request_spec),
        cache_name_(cache_name),
        callback_(std::move(callback)) {}
  ~GetCacheForDeleteEntry() override = default;

  void OnSuccess(std::unique_ptr<blink::WebServiceWorkerCache> cache) override {
    auto delete_request =
        std::make_unique<DeleteCacheEntry>(std::move(callback_));
    blink::WebServiceWorkerCache::BatchOperation delete_operation;
    delete_operation.operation_type =
        blink::WebServiceWorkerCache::kOperationTypeDelete;
    delete_operation.request.SetURL(blink::KURL(request_spec_));
    Vector<blink::WebServiceWorkerCache::BatchOperation> operations;
    operations.push_back(delete_operation);
    cache.release()->DispatchBatch(std::move(delete_request),
                                   blink::WebVector<blink::WebServiceWorkerCache::BatchOperation>(operations));
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    //DLOG(ERROR) << "Error requesting cache " << cache_name_.Utf8().data() << ": " << CacheStorageErrorString(error).data();
    std::move(callback_).Run(false); 
  }

 private:
  String request_spec_;
  String cache_name_;
  CacheStorageDispatcher::DeleteEntryCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(GetCacheForDeleteEntry);
};

class PutCacheEntry : public blink::WebServiceWorkerCache::CacheBatchCallbacks {
 public:
  explicit PutCacheEntry(CacheStorageDispatcher::PutEntryCallback callback)
      : callback_(std::move(callback)) {}
  ~PutCacheEntry() override {
    //DLOG(INFO) << "~PutCacheEntry";
    if(!callback_.is_null()) {
      std::move(callback_).Run(false); 
    }
  }

  void OnSuccess() override {
    //DLOG(INFO) << "PutCacheEntry::OnSuccess: calling callback";
    if(!callback_.is_null()) {
      std::move(callback_).Run(true);
    }
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    //DLOG(ERROR) << "Error requesting cache names: " << CacheStorageErrorString(error).data();
    if(!callback_.is_null()) {
      std::move(callback_).Run(false); 
    }
  }

 private:
  CacheStorageDispatcher::PutEntryCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(PutCacheEntry);
};

class BlobHandleCallbackForPut final
    : public blink::GarbageCollectedFinalized<BlobHandleCallbackForPut>,
      public blink::FetchDataLoader::Client {
  USING_GARBAGE_COLLECTED_MIXIN(BlobHandleCallbackForPut);

 public:
  BlobHandleCallbackForPut(blink::FetchDataLoader::Client* callback,
                           blink::Request* request,
                           blink::Response* response)
      : callback_(callback) {
    // request->PopulateWebServiceWorkerRequest(web_request_);
    // response->PopulateWebServiceWorkerResponse(web_response_);
  }
  ~BlobHandleCallbackForPut() override = default;

  void DidFetchDataLoadedBlobHandle(
      scoped_refptr<blink::BlobDataHandle> handle) override {
    callback_->DidFetchDataLoadedBlobHandle(handle);
  }

  void DidFetchDataLoadFailed() override {
    callback_->DidFetchDataLoadFailed();
  }

  void Abort() override {
    callback_->Abort();
  }

  void Trace(blink::Visitor* visitor) override {
    blink::FetchDataLoader::Client::Trace(visitor);
  }

 private:
  blink::FetchDataLoader::Client* callback_;

  // blink::WebServiceWorkerRequest web_request_;
  // blink::WebServiceWorkerResponse web_response_;
};

class GetCacheForPutEntry
    : public blink::WebServiceWorkerCacheStorage::CacheStorageWithCacheCallbacks,
      public blink::FetchDataLoader::Client {
 public:
  GetCacheForPutEntry(blink::LocalFrame* frame,
                      const String& request_spec,
                      const String& cache_name,
                      blink::mojom::DataElementPtr data,
                      CacheStorageDispatcher::PutEntryCallback callback)
      : frame_(frame),
        request_spec_(request_spec),
        cache_name_(cache_name),
        data_(std::move(data)),
        callback_(std::move(callback)) {}

  GetCacheForPutEntry(blink::LocalFrame* frame,
                      const String& request_spec,
                      const String& cache_name,
                      //const scoped_refptr<blink::BlobDataHandle>& blob,
                      blink::mojom::SerializedBlobPtr blob,
                      CacheStorageDispatcher::PutEntryCallback callback)
      : frame_(frame),
        request_spec_(request_spec),
        cache_name_(cache_name),
        blob_(std::move(blob)),
        callback_(std::move(callback)) {}

  ~GetCacheForPutEntry() override {
    //DLOG(INFO) << "~GetCacheForPutEntry";
  }

  void OnSuccess(std::unique_ptr<blink::WebServiceWorkerCache> cache) override {
    //DLOG(INFO) << "GetCacheForPutEntry::OnSuccess (application): dispatching PUT operation";
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::HandleScope handleScope(isolate);
    blink::ExceptionState exception_state(isolate, blink::ExceptionState::kExecutionContext, "CacheStorage", "put");
    // FIXME
    String content_type = "text/plain"; 

    //blink::ScriptState* script_state = blink::ToScriptStateForMainWorld(frame_);
    //blink::ExecutionContext* execution_context = blink::ExecutionContext::From(script_state);    
    blink::LocalWindowProxy* proxy = frame_->GetScriptController().WindowProxy(blink::DOMWrapperWorld::MainWorld());
    v8::Local<v8::Context> v8context = proxy->ContextIfInitialized();
    blink::ScriptState* script_state = blink::ScriptState::From(v8context);
    blink::ExecutionContext* execution_context = blink::ExecutionContext::From(script_state);

    v8context->Enter();
    
    // LocalDOMWindow
    // blink::GlobalFetch::ScopedFetcher* fetcher = blink::GlobalFetch::ScopedFetcher::From(*frame_->DomWindow());
    // cache_ = blink::Cache::Create(fetcher, std::move(cache));
    cache_ = std::move(cache);
 
    //auto put_request = std::make_unique<PutCacheEntry>(std::move(callback_));//(blob_ ? std::move(blob_callback_) : std::move(callback_));
    auto data = blink::BlobData::Create();
    //data->Elements().push_back(std::move(data_));
    // FIXME: deal with other cases
    if (data_ && data_->is_bytes()) {
       if (data_->get_bytes()->embedded_data.has_value()) {
         const void* bytes = &data_->get_bytes()->embedded_data.value()[0];
         uint64_t len = data_->get_bytes()->length;
         //DLOG(INFO) << "GetCacheForPutEntry::OnSuccess: data [" << len << "] => '" << (const char*)bytes << "'";
         data->AppendBytes(bytes, len); 
       }
    } else if (data_ && data_->is_file()) {
      data->AppendFile(String::FromUTF8(data_->get_file()->path.value().data()),
                       data_->get_file()->offset,
                       data_->get_file()->length,
                       data_->get_file()->expected_modification_time.has_value() ? 
                        data_->get_file()->expected_modification_time.value().ToInternalValue() : 
                        0);
    } else if (data_ && data_->is_file_filesystem()) {
      data->AppendFileSystemURL(blink::KURL(String::FromUTF8(data_->get_file_filesystem()->url.possibly_invalid_spec().data())),
                                data_->get_file_filesystem()->offset,
                                data_->get_file_filesystem()->length,
                                data_->get_file_filesystem()->expected_modification_time.has_value() ? 
                                  data_->get_file_filesystem()->expected_modification_time.value().ToInternalValue() : 
                                  0);
    } else if (blob_) {
      data->AppendBlob(
        blink::BlobDataHandle::Create(
          String::FromUTF8(blob_->uuid.data()), 
          String::FromUTF8(blob_->content_type.data()), 
          blob_->size, 
          // FIXME: check if tis really work as intended
          blink::mojom::blink::BlobPtrInfo(
            blob_->blob.PassHandle(),
            blink::mojom::blink::Blob::Version_)),
        0,
        blob_->size);
    }
    auto data_size = data->length();
    //DLOG(INFO) << "GetCacheForPutEntry::OnSuccess (application): sending " << data_size << " bytes";
    scoped_refptr<blink::BlobDataHandle> blob_data_handle = blink::BlobDataHandle::Create(std::move(data), data_size);
    blink::BodyStreamBuffer* body_stream_buffer = new blink::BodyStreamBuffer(
      script_state, 
      new blink::BlobBytesConsumer(execution_context, blob_data_handle),
      nullptr);
    request_ = blink::Request::Create(script_state, request_spec_, exception_state);
    response_ = blink::Response::Create(
      script_state,
      body_stream_buffer,
      content_type, 
      blink::ResponseInit(), 
      exception_state);
    if (!request_) {
      //DLOG(ERROR) << "GetCacheForPutEntry::OnSuccess (application): Request::Create() failed returning a new request object";
      Reply(false);
      return;
    }
    if (!response_) {
      //DLOG(ERROR) << "GetCacheForPutEntry::OnSuccess (application): Response::Create() failed returning a new response object";
      Reply(false);
      return;
    }

    blink::FetchDataLoader* loader = blink::FetchDataLoader::CreateLoaderAsBlobHandle(response_->InternalMIMEType());
    body_stream_buffer->StartLoading(loader, new BlobHandleCallbackForPut(this, request_, response_));
    v8context->Exit();
  } 

  void DidFetchDataLoadedBlobHandle(
      scoped_refptr<blink::BlobDataHandle> handle) override {
    blink::WebServiceWorkerCache::BatchOperation batch_operation;
    batch_operation.operation_type = blink::WebServiceWorkerCache::kOperationTypePut;
    request_->PopulateWebServiceWorkerRequest(batch_operation.request);
    response_->PopulateWebServiceWorkerResponse(batch_operation.response);
    //batch_operation.request = web_request_;
    //batch_operation.response = web_response_;
    batch_operation.response.SetBlobDataHandle(std::move(handle));

    Vector<blink::WebServiceWorkerCache::BatchOperation> operations;
    operations.push_back(batch_operation);

    auto put_request = std::make_unique<PutCacheEntry>(std::move(callback_));

    
    cache_->DispatchBatch(
        std::move(put_request),
        blink::WebVector<blink::WebServiceWorkerCache::BatchOperation>(operations)); 
  }

  void DidFetchDataLoadFailed() override {
    std::move(callback_).Run(false);
  }

  void Abort() override {
    std::move(callback_).Run(false);
  }

  // {
  //   ScriptPromiseResolver* resolver = ScriptPromiseResolver::Create(script_state);
  //   const ScriptPromise promise = resolver->Promise();
  //   BarrierCallbackForPut* barrier_callback =
  //       new BarrierCallbackForPut(requests.size(), this, resolver);

  //   for (size_t i = 0; i < requests.size(); ++i) {
  //     KURL url(NullURL(), requests[i]->url());
  //     // if (!url.ProtocolIsInHTTPFamily()) {
  //     //   barrier_callback->OnError("Request scheme '" + url.Protocol() +
  //     //                             "' is unsupported");
  //     //   return promise;
  //     // }
  //     if (requests[i]->method() != HTTPNames::GET) {
  //       barrier_callback->OnError("Request method '" + requests[i]->method() +
  //                                 "' is unsupported");
  //       return promise;
  //     }
  //     DCHECK(!requests[i]->HasBody());

  //     if (VaryHeaderContainsAsterisk(responses[i])) {
  //       barrier_callback->OnError("Vary header contains *");
  //       return promise;
  //     }
  //     if (responses[i]->status() == 206) {
  //       barrier_callback->OnError(
  //           "Partial response (status code 206) is unsupported");
  //       return promise;
  //     }
  //     if (responses[i]->IsBodyLocked() || responses[i]->bodyUsed()) {
  //       barrier_callback->OnError("Response body is already used");
  //       return promise;
  //     }

  //     BodyStreamBuffer* buffer = responses[i]->InternalBodyBuffer();

  //     if (ShouldGenerateV8CodeCache(script_state, responses[i])) {
  //       FetchDataLoader* loader = FetchDataLoader::CreateLoaderAsArrayBuffer();
  //       buffer->StartLoading(loader, new CodeCacheHandleCallbackForPut(
  //                                       script_state, i, barrier_callback,
  //                                       requests[i], responses[i]));
  //       continue;
  //     }

  //     if (buffer) {
  //       // If the response has body, read the all data and create
  //       // the blob handle and dispatch the put batch asynchronously.
  //       FetchDataLoader* loader = FetchDataLoader::CreateLoaderAsBlobHandle(
  //           responses[i]->InternalMIMEType());
  //       buffer->StartLoading(
  //           loader, new BlobHandleCallbackForPut(i, barrier_callback, requests[i],
  //                                               responses[i]));
  //       continue;
  //     }

  //     WebServiceWorkerCache::BatchOperation batch_operation;
  //     batch_operation.operation_type = WebServiceWorkerCache::kOperationTypePut;
  //     requests[i]->PopulateWebServiceWorkerRequest(batch_operation.request);
  //     responses[i]->PopulateWebServiceWorkerResponse(batch_operation.response);
  //     barrier_callback->OnSuccess(i, batch_operation);
  // }

  void OnError(blink::mojom::CacheStorageError error) override {
    //DLOG(ERROR) << "Error requesting cache " << cache_name_.Utf8().data() << ": " << CacheStorageErrorString(error).data();
    Reply(false);
  }

  void Reply(bool result) {
    if(!callback_.is_null()) {
      std::move(callback_).Run(false); 
    }
  }

 private:
  blink::Member<blink::LocalFrame> frame_;
  String request_spec_;
  String cache_name_;
  blink::mojom::DataElementPtr data_;
  //scoped_refptr<blink::BlobDataHandle> blob_;
  blink::mojom::SerializedBlobPtr blob_;
  CacheStorageDispatcher::PutEntryCallback callback_;
  blink::Member<blink::Request> request_;
  blink::Member<blink::Response> response_;
  std::unique_ptr<blink::WebServiceWorkerCache> cache_;
  //blink::Member<blink::Cache> cache_;

  DISALLOW_COPY_AND_ASSIGN(GetCacheForPutEntry);
};


class CachedResponseFileReaderLoaderClient final
    : private blink::FileReaderLoaderClient {
 public:
  static void Load(scoped_refptr<blink::BlobDataHandle> blob,
                   bool base64_encoded,
                   CacheStorageDispatcher::RequestCachedResponseCallback callback) {
    new CachedResponseFileReaderLoaderClient(std::move(blob),
                                             base64_encoded,
                                             std::move(callback));
  }

  void DidStartLoading() override {}

  void DidFinishLoading() override {
    automation::CachedResponsePtr response = automation::CachedResponse::New();
    if (base64_encoded_) {
      String encoded_body = Base64Encode(data_->Data(), data_->size());
      response->body = std::string(encoded_body.Utf8().data(), encoded_body.Utf8().length());
    } else {
      response->body = std::string(data_->Data(), data_->size());
    }
    std::move(callback_).Run(std::move(response));
    dispose();
  }

  void DidFail(blink::FileError::ErrorCode error) override {
    //callback_->sendFailure(ProtocolResponse::Error(String::Format(
    //    "Unable to read the cached response, error code: %d", error)));
    //DLOG(ERROR) << "Unable to read the cached response, error code: " << error;
    dispose();
  }

  void DidReceiveDataForClient(const char* data,
                               unsigned data_length) override {
    data_->Append(data, data_length);
  }

 private:
  CachedResponseFileReaderLoaderClient(
      scoped_refptr<blink::BlobDataHandle>&& blob,
      bool base64_encoded,
      CacheStorageDispatcher::RequestCachedResponseCallback&& callback)
      : loader_(
            blink::FileReaderLoader::Create(blink::FileReaderLoader::kReadByClient, this)),
        callback_(std::move(callback)),
        data_(blink::SharedBuffer::Create()),
        base64_encoded_(base64_encoded) {
    loader_->Start(std::move(blob));
  }

  ~CachedResponseFileReaderLoaderClient() override = default;

  void dispose() { delete this; }

  std::unique_ptr<blink::FileReaderLoader> loader_;
  CacheStorageDispatcher::RequestCachedResponseCallback callback_;
  scoped_refptr<blink::SharedBuffer> data_;
  bool base64_encoded_;

  DISALLOW_COPY_AND_ASSIGN(CachedResponseFileReaderLoaderClient);
};

class CachedResponseMatchCallback
    : public blink::WebServiceWorkerCacheStorage::CacheStorageMatchCallbacks {
 public:
  explicit CachedResponseMatchCallback(
      bool base64_encoded,
      CacheStorageDispatcher::RequestCachedResponseCallback callback)
      : base64_encoded_(base64_encoded),
        callback_(std::move(callback)) {}

  void OnSuccess(const blink::WebServiceWorkerResponse& response) override {
    if (!response.GetBlobDataHandle()) {
      std::move(callback_).Run(automation::CachedResponse::New());
      return;
    }
    CachedResponseFileReaderLoaderClient::Load(
      response.GetBlobDataHandle(),
      base64_encoded_,
      std::move(callback_));
  }

  void OnError(blink::mojom::CacheStorageError error) override {
    // callback_->sendFailure(ProtocolResponse::Error(
    //     String::Format("Unable to read cached response: %s",
    //                    CacheStorageErrorString(error).data())));
    //DLOG(ERROR) << "Unable to read the cached response: " << CacheStorageErrorString(error).data();
    std::move(callback_).Run(automation::CachedResponse::New());
  }

 private:
  bool base64_encoded_;
  CacheStorageDispatcher::RequestCachedResponseCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(CachedResponseMatchCallback);
};

}

// static 
void CacheStorageDispatcher::Create(automation::CacheStorageRequest request, PageInstance* page_instance) {
  new CacheStorageDispatcher(std::move(request), page_instance);
}

CacheStorageDispatcher::CacheStorageDispatcher(automation::CacheStorageRequest request, PageInstance* page_instance_):
  page_instance_(page_instance_),
  application_id_(-1),
  binding_(this),
  enabled_(true) {

}

CacheStorageDispatcher::CacheStorageDispatcher(PageInstance* page_instance_):
  page_instance_(page_instance_),
  application_id_(-1),
  binding_(this),
  enabled_(true) {

}

CacheStorageDispatcher::~CacheStorageDispatcher() {

}

void CacheStorageDispatcher::Init(IPC::SyncChannel* channel) {

}

void CacheStorageDispatcher::Bind(automation::CacheStorageAssociatedRequest request) {
  //DLOG(INFO) << "CacheStorageDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void CacheStorageDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void CacheStorageDispatcher::HasCache(const std::string& id, HasCacheCallback callback) {
  String cache_name;
  String cache_id = String::FromUTF8(id.data());
  blink::WebServiceWorkerCacheStorage* cache_storage = nullptr;
  bool ok = AssertCacheStorageAndNameForId(cache_id, page_instance_->inspected_frames(), &cache_name, &caches_, &cache_storage);
  if (!ok) {
    //callback->sendFailure(response);
    //DLOG(ERROR) << "No cache found for id " << id;
    std::move(callback).Run(false);
    return;
  }
  cache_storage->DispatchHas(
      std::make_unique<HasCacheImpl>(std::move(callback)),
      blink::WebString(cache_name));
}

void CacheStorageDispatcher::OpenCache(const std::string& id, OpenCacheCallback callback) {
  String cache_name;
  String cache_id = String::FromUTF8(id.data());
  blink::WebServiceWorkerCacheStorage* cache_storage = nullptr;
  bool ok = AssertCacheStorageAndNameForId(cache_id, page_instance_->inspected_frames(), &cache_name, &caches_, &cache_storage);
  if (!ok) {
    //callback->sendFailure(response);
    std::move(callback).Run(-1);
    //DLOG(ERROR) << "No cache found for id " << id;
    return;
  }
  cache_storage->DispatchOpen(
      std::make_unique<OpenCacheImpl>(std::move(callback)),
      blink::WebString(cache_name));
}

void CacheStorageDispatcher::DeleteCache(const std::string& id, DeleteCacheCallback callback) {
  String cache_name;
  String cache_id = String::FromUTF8(id.data());
  blink::WebServiceWorkerCacheStorage* cache_storage = nullptr;
  bool ok = AssertCacheStorageAndNameForId(cache_id, page_instance_->inspected_frames(), &cache_name, &caches_, &cache_storage);
  if (!ok) {
    //callback->sendFailure(response);
    std::move(callback).Run(false);
    //DLOG(ERROR) << "No cache found for id " << id;
    return;
  }
  cache_storage->DispatchDelete(
      std::make_unique<DeleteCacheImpl>(std::move(callback)),
      blink::WebString(cache_name));
}

void CacheStorageDispatcher::DeleteEntry(const std::string& id, const std::string& request, DeleteEntryCallback callback) {
  String cache_name;
  String cache_id = String::FromUTF8(id.data());
  blink::WebServiceWorkerCacheStorage* cache_storage = nullptr;
  bool ok = AssertCacheStorageAndNameForId(cache_id, page_instance_->inspected_frames(), &cache_name, &caches_, &cache_storage);
  if (!ok) {
    //callback->sendFailure(response);
    std::move(callback).Run(false);
    //DLOG(ERROR) << "No cache found for id " << id;
    return;
  }
  cache_storage->DispatchOpen(std::make_unique<GetCacheForDeleteEntry>(
                              String::FromUTF8(request.data()), 
                              cache_name, 
                              std::move(callback)),
                              blink::WebString(cache_name));
}

void CacheStorageDispatcher::PutEntry(const std::string& id, const std::string& request, blink::mojom::DataElementPtr data, PutEntryCallback callback) {
  //DLOG(INFO) << "CacheStorageDispatcher::PutEntryData (application): [" << data.size() << "] '" << std::string(data.begin()[0], data.size()) << "'";
  String cache_name;
  String cache_id = String::FromUTF8(id.data());
  blink::WebServiceWorkerCacheStorage* cache_storage = nullptr;
  bool ok = AssertCacheStorageAndNameForId(cache_id, page_instance_->inspected_frames(), &cache_name, &caches_, &cache_storage);
  if (!ok) {
    //callback->sendFailure(response);
    if(!callback.is_null()) {
      std::move(callback).Run(false);
    }
    //DLOG(ERROR) << "No cache found for id " << id;
    return;
  }

  cache_storage->DispatchOpen(std::make_unique<GetCacheForPutEntry>(
                              page_instance()->inspected_frames()->Root(), 
                              String::FromUTF8(request.data()), 
                              cache_name, 
                              std::move(data),
                              std::move(callback)),
                              blink::WebString(cache_name));
}

void CacheStorageDispatcher::PutEntryBlob(const std::string& id, const std::string& request, blink::mojom::SerializedBlobPtr blob, automation::CacheStorage::PutEntryBlobCallback callback) {
  String cache_name;
  String cache_id = String::FromUTF8(id.data());
  blink::WebServiceWorkerCacheStorage* cache_storage = nullptr;
  bool ok = AssertCacheStorageAndNameForId(cache_id, page_instance_->inspected_frames(), &cache_name, &caches_, &cache_storage);
  if (!ok) {
    //callback->sendFailure(response);
    std::move(callback).Run(false);
    //DLOG(ERROR) << "No cache found for id " << id;
    return;
  }
  cache_storage->DispatchOpen(std::make_unique<GetCacheForPutEntry>(
                              page_instance()->inspected_frames()->Root(), 
                              String::FromUTF8(request.data()), 
                              cache_name, 
                              std::move(blob),
                              std::move(callback)),
                              blink::WebString(cache_name));
}

void CacheStorageDispatcher::RequestCacheNames(const std::string& origin, RequestCacheNamesCallback callback) {
  String security_origin = String::FromUTF8(origin.data());
  scoped_refptr<const blink::SecurityOrigin> sec_origin = blink::SecurityOrigin::CreateFromString(security_origin);

  // Cache Storage API is restricted to trustworthy origins.
  // if (!sec_origin->IsPotentiallyTrustworthy()) {
  //   // Don't treat this as an error, just don't attempt to open and enumerate
  //   // the caches.
  //   //callback->sendSuccess(Array<ProtocolCache>::create());
  //   //DLOG(ERROR) << "Origin " << origin << " is not considered potentially trustworthy";
  //   std::move(callback).Run(std::vector<automation::CachePtr>());
  //   return;
  // }

  blink::WebServiceWorkerCacheStorage* cache_storage = nullptr;

  bool ok = AssertCacheStorage(security_origin, page_instance_->inspected_frames(), &caches_, &cache_storage);
  if (!ok) {
    //callback->sendFailure(response);
    std::move(callback).Run(std::vector<automation::CachePtr>());
    //DLOG(ERROR) << "No cache storage found for security origin '" << origin << "'";
    return;
  }

  cache_storage->DispatchKeys(
    std::make_unique<RequestCacheNamesImpl>(
      security_origin, 
      std::move(callback)));
}

void CacheStorageDispatcher::RequestCachedResponse(const std::string& id, const std::string& request_url, bool base64_encoded, RequestCachedResponseCallback callback) {
  String cache_name;
  String cache_id = String::FromUTF8(id.data());
  blink::WebServiceWorkerCacheStorage* cache_storage = nullptr;
  bool ok = AssertCacheStorageAndNameForId(
      cache_id, page_instance_->inspected_frames(), &cache_name, &caches_, &cache_storage);
  if (!ok) {
    //callback->sendFailure(response);
    //DLOG(ERROR) << "No cache found for id " << id;
    std::move(callback).Run(nullptr);
    return;
  }
  blink::WebServiceWorkerRequest request;
  request.SetURL(blink::KURL(request_url.data()));
  cache_storage->DispatchMatch(
      std::make_unique<CachedResponseMatchCallback>(base64_encoded, std::move(callback)),
      request, 
      blink::WebServiceWorkerCache::QueryParams());
}

void CacheStorageDispatcher::RequestEntries(const std::string& id, int32_t skip_count, int32_t page_size, RequestEntriesCallback callback) {
  String cache_name;
  String cache_id = String::FromUTF8(id.data());
  blink::WebServiceWorkerCacheStorage* cache_storage = nullptr;
  bool ok = AssertCacheStorageAndNameForId(
      cache_id, page_instance_->inspected_frames(), &cache_name, &caches_, &cache_storage);
  if (!ok) {
    //DLOG(ERROR) << "No cache found for id " << id;
    std::move(callback).Run(std::vector<automation::DataEntryPtr>(), false);//callback->sendFailure(response);
    return;
  }
  DataRequestParams params;
  params.cache_name = cache_name;
  params.page_size = page_size;
  params.skip_count = skip_count;

  cache_storage->DispatchOpen(
      std::make_unique<GetCacheForRequestData>(params, std::move(callback)),
      blink::WebString(cache_name));
}

void CacheStorageDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  //Enable();
}

}