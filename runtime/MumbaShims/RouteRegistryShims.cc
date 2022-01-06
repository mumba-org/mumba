// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "RouteRegistryShims.h"
#include "EngineHelper.h"

#include "base/sha1.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/domain/route/route_dispatcher.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/application_process.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_status_code.h"
#include "net/http/http_util.h"

struct RouteRegistrySubscriberCallbacks {
  void(*OnRouteHeaderChanged)(void*, const char*);
  void(*OnRouteAdded)(void*, int, int, int, const char*, const char*, const char*);
  void(*OnRouteRemoved)(void*, int, int, int, const char*, const char*, const char*);
  void(*OnRouteChanged)(void*, int, int, int, const char*, const char*, const char*);
};

class RouteRegistrySubscriberImpl : public common::mojom::RouteSubscriber {
public:
 RouteRegistrySubscriberImpl(
  void* state, 
  RouteRegistrySubscriberCallbacks cb,
  common::mojom::RouteSubscriberRequest request): 
  state_(state),
  cb_(std::move(cb)),
  binding_(this) {
  
  binding_.Bind(std::move(request));
 }

 ~RouteRegistrySubscriberImpl() {
   
 }

 void GetUUID(const common::mojom::RouteSubscriber::GetUUIDCallback callback) override {

 }

 void OnRouteHeaderChanged(const network::ResourceResponseHead& head) override {
   // FIXME
   cb_.OnRouteHeaderChanged(state_, nullptr);
 }

 void OnRouteAdded(common::mojom::RouteEntryPtr entry) override {
   cb_.OnRouteAdded(state_, static_cast<int>(entry->type), static_cast<int>(entry->transport_type), static_cast<int>(entry->rpc_method_type), entry->name.c_str(), entry->path.c_str(), entry->url.spec().c_str());
 }
 
 void OnRouteRemoved(common::mojom::RouteEntryPtr entry) override {
   cb_.OnRouteRemoved(state_, static_cast<int>(entry->type), static_cast<int>(entry->transport_type), static_cast<int>(entry->rpc_method_type), entry->name.c_str(), entry->path.c_str(), entry->url.spec().c_str());
 }

 void OnRouteChanged(common::mojom::RouteEntryPtr entry) override {
   cb_.OnRouteChanged(state_, static_cast<int>(entry->type), static_cast<int>(entry->transport_type), static_cast<int>(entry->rpc_method_type), entry->name.c_str(), entry->path.c_str(), entry->url.spec().c_str());
 }

private:
  void* state_;
  RouteRegistrySubscriberCallbacks cb_;
  mojo::Binding<common::mojom::RouteSubscriber> binding_;
};

struct RouteHaveCallbackState {
  void* state;
  void(*cb)(void*, int);
};

struct RouteGetCallbackState {
  void* state;
  void(*cb)(void*, int, int, int, int, const char*, const char*, const char*);
};

struct RouteListCallbackState {
  void* state;
  void(*cb)(void*, int, int, int*, int*, int*, const char**, const char**, const char**);
};

struct SchemeListCallbackState {
  void* state;
  void(*cb)(void*, int, const char**);
};

struct RouteAddSubscriberCallbackState {
  void* state;
  void* watcher_state;
  void(*cb)(void*, int, void*, void*);
  void(*OnRouteHeaderChanged)(void*, const char*);
  void(*OnRouteAdded)(void*, int, int, int, const char*, const char*, const char*);
  void(*OnRouteRemoved)(void*, int, int, int, const char*, const char*, const char*);
  void(*OnRouteChanged)(void*, int, int, int, const char*, const char*, const char*);
  common::mojom::RouteSubscriberPtr watcher_ptr;
};

// struct RouteEntryWrapper {
//   RouteEntryWrapper(common::mojom::RouteEntryPtr e): entry(std::move(e)) {}
//   common::mojom::RouteEntryPtr entry;
// };

void OnAddRouteResult(common::mojom::RouteStatusCode reply) {
  //DLOG(INFO) << "RouteRegistry: AddEntry returned with code " << static_cast<int>(reply);
}

void OnGetRouteResult(RouteGetCallbackState cb_state, common::mojom::RouteStatusCode r, common::mojom::RouteEntryPtr entry) {
  if (r == common::mojom::RouteStatusCode::kROUTE_STATUS_OK) {
    cb_state.cb(cb_state.state, static_cast<int>(r), static_cast<int>(entry->type), static_cast<int>(entry->transport_type), static_cast<int>(entry->rpc_method_type), entry->name.c_str(), entry->path.c_str(), entry->url.spec().c_str());
  } else {
    cb_state.cb(cb_state.state, static_cast<int>(r), -1, -1, -1, nullptr, nullptr, nullptr);
  }
}

void OnHaveRouteResult(RouteHaveCallbackState cb_state, bool r) {
  cb_state.cb(cb_state.state, r ? 1 : 0);
}

void OnCountRoutesResult(RouteHaveCallbackState cb_state, uint32_t count) {
  cb_state.cb(cb_state.state, static_cast<int>(count));
}

void OnListRoutesResult(RouteListCallbackState cb_state, std::vector<common::mojom::RouteEntryPtr> entries) {
  if (entries.size() > 0) {
    size_t count = entries.size();
    int types[count];
    int transportTypes[count];
    int methodTypes[count];
    const char* names[count];
    const char* paths[count];
    const char* urls[count];
    for (size_t i = 0; i < count; ++i) {
      types[i] = static_cast<int>(entries[i]->type);
      transportTypes[i] = static_cast<int>(entries[i]->transport_type);
      methodTypes[i] = static_cast<int>(entries[i]->rpc_method_type);
      names[i] = entries[i]->name.c_str();
      paths[i] = entries[i]->path.c_str();
      urls[i] = entries[i]->url.spec().c_str();
    }
    cb_state.cb(
      cb_state.state, 
      0,
      count,
      types,
      transportTypes,
      methodTypes,
      names,
      paths, 
      urls);
  } else {
    cb_state.cb(cb_state.state, 2, 0, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
  }
}

void OnAddSubscriberResult(
  RouteRegistrySubscriberImpl* watcher,
  RouteAddSubscriberCallbackState cb_state, 
  int32_t id) {
    cb_state.cb(cb_state.state, id, cb_state.watcher_state, watcher);
}


class RouteRequestImpl : public domain::RouteRequest {
public:
  RouteRequestImpl(domain::RouteDispatcher* dispatcher, void* state, const RouteRequestHandlerCallbacks& handler_callbacks, const std::string& url, int request):
   dispatcher_(dispatcher),
   state_(state),
   handler_callbacks_(handler_callbacks),
   request_(request),
   response_headers_filled_(false),
   is_completed_(false),
   completion_status_(-1) {
    url_ = GURL(url);  
  }

  ~RouteRequestImpl() {
    // silence compiler
    dispatcher_ = nullptr;
  }

  int id() override {
    return request_;
  }

  bool is_completed() const override {
    return is_completed_;
  }

  void Complete(int code) override {
    completion_status_ = code;
    is_completed_ = true;
  }

  int status() override {
    //base::AutoLock lock(handle_lock_);
    return handler_callbacks_.GetStatus(state_, request_);
  }

  const GURL& url() override {
    return url_;
  }

  const std::string& method() override {
    //base::AutoLock lock(handle_lock_);
    if (method_.empty())
      method_ = std::string(handler_callbacks_.GetMethod(state_, request_));
    return method_;
  }

  void GetMimeType(std::string* mime_type) override {
    //base::AutoLock lock(handle_lock_);
    const char* cmime_type = handler_callbacks_.GetMimeType(state_, request_);
    *mime_type = std::string(cmime_type);
  }

  void GetCharset(std::string* charset) override {
    //base::AutoLock lock(handle_lock_);
    const char* ccharset = handler_callbacks_.GetMimeType(state_, request_);
    *charset = std::string(ccharset);
  }
  
  base::TimeTicks GetCreationTime() override {
    //base::AutoLock lock(handle_lock_);
    int64_t time = handler_callbacks_.GetCreationTime(state_, request_);
    return base::TimeTicks::FromInternalValue(time);
  }
  
  int64_t GetTotalReceivedBytes() override {
    //base::AutoLock lock(handle_lock_);
    return handler_callbacks_.GetTotalReceivedBytes(state_, request_); 
  }
  
  int64_t GetRawBodyBytes() override {
    //base::AutoLock lock(handle_lock_);
    return handler_callbacks_.GetRawBodyBytes(state_, request_); 
  }
  
  void GetLoadTimingInfo(net::LoadTimingInfo* load_timing_info) override {
    //base::AutoLock lock(handle_lock_);
    handler_callbacks_.GetLoadTimingInfo(state_, request_, load_timing_info); 
  }
  
  int64_t GetExpectedContentSize() override {
    //base::AutoLock lock(handle_lock_);
    return handler_callbacks_.GetExpectedContentSize(state_, request_); 
  }
  
  net::HttpResponseHeaders* GetResponseHeaders() override {
    //base::AutoLock lock(handle_lock_);
    net::HttpResponseHeaders* headers = response_headers_.get();
    if (!headers) {
      int size = 0;
      const char* cheaders = handler_callbacks_.GetResponseHeaders(state_, request_, &size);
      std::string raw_headers(cheaders, (size_t)size);
      response_headers_ = new net::HttpResponseHeaders(raw_headers);
      headers = response_headers_.get();
      response_headers_filled_ = true;
    }
    return headers;
  }
  
  const net::HttpResponseInfo& GetResponseInfo() override {
    //base::AutoLock lock(handle_lock_);
    if (!response_info_filled_) {
      handler_callbacks_.GetResponseInfo(state_, request_, &response_info_); 
    }
    return response_info_;
  }
  
  void Start(base::OnceCallback<void(int)> callback) override {
    //base::AutoLock lock(handle_lock_);
    int r = handler_callbacks_.Start(state_, request_);
    // the start here is async
    std::move(callback).Run(r);
  }
  
  void SetExtraRequestHeaders(const net::HttpRequestHeaders& headers) override {

  }
  
  void FollowDeferredRedirect() override {
    //base::AutoLock lock(handle_lock_);
    handler_callbacks_.FollowDeferredRedirect(state_, request_);
  }
  
  bool Read(net::IOBuffer* buf, int max_bytes, int* bytes_read) override {
    //base::AutoLock lock(handle_lock_);
    int readed = handler_callbacks_.Read(state_, request_, buf->data(), max_bytes, bytes_read);
    return readed >= 0;
  }
  
  int CancelWithError(int error) override {
    //base::AutoLock lock(handle_lock_);
    return handler_callbacks_.CancelWithError(state_, request_, error);  
  }
  
private:
  domain::RouteDispatcher* dispatcher_;
  void* state_;
  RouteRequestHandlerCallbacks handler_callbacks_;
  int request_;
  GURL url_;
  std::string method_;
  scoped_refptr<net::HttpResponseHeaders> response_headers_;
  net::HttpResponseInfo response_info_;
  bool response_headers_filled_;
  bool response_info_filled_;
  bool is_completed_;
  int completion_status_;
  base::Lock handle_lock_;
};

struct RouteRegistryWrapper : public domain::RouteDispatcher::Delegate {

  RouteRegistryWrapper(common::mojom::RouteRegistry* registry,
                       domain::RouteDispatcher* dispatcher, 
                       void* handler_state,
                       RouteRequestHandlerCallbacks handler_callbacks,
                       const scoped_refptr<base::SingleThreadTaskRunner>& task_runner): 
    registry(registry),
    dispatcher(dispatcher),
    handler_state(handler_state),
    handler_callbacks(std::move(handler_callbacks)),
    task_runner(task_runner) {
    if (dispatcher) {
      dispatcher->set_delegate(this);
    }
  }

  common::mojom::RouteRegistry* registry;
  domain::RouteDispatcher* dispatcher;
  void* handler_state;
  RouteRequestHandlerCallbacks handler_callbacks;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner;

  void AddSubscriber(
    std::string scheme,
    RouteAddSubscriberCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::AddSubscriberImpl, 
        base::Unretained(this),
        base::Passed(std::move(scheme)),
        base::Passed(std::move(cb_state))));
  }

  void RemoveSubscriber(int id) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::RemoveSubscriberImpl, 
        base::Unretained(this),
        id));
  }

  void HaveRouteByPath(std::string path, RouteHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::HaveRouteByPathImpl, 
        base::Unretained(this),
        base::Passed(std::move(path)),
        base::Passed(std::move(cb_state))));
  }

  void HaveRouteByUrl(std::string url, RouteHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::HaveRouteByUrlImpl, 
        base::Unretained(this),
        base::Passed(std::move(url)),
        base::Passed(std::move(cb_state))));
  }

  void HaveRouteByUUID(std::string uuid, RouteHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::HaveRouteByUUIDImpl, 
        base::Unretained(this),
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void CountRoutes(RouteHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::CountRoutesImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void LookupRoute(std::string scheme, std::string path, RouteGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::LookupRouteImpl, 
        base::Unretained(this), 
        base::Passed(std::move(scheme)),
        base::Passed(std::move(path)),
        base::Passed(std::move(cb_state))));
  }
  
  void LookupRouteByPath(std::string path, RouteGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::LookupRouteByPathImpl, 
        base::Unretained(this), 
        base::Passed(std::move(path)),
        base::Passed(std::move(cb_state))));
  }

  void LookupRouteByUrl(std::string url, RouteGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::LookupRouteByUrlImpl, 
        base::Unretained(this), 
        base::Passed(std::move(url)),
        base::Passed(std::move(cb_state))));
  }

  void LookupRouteByUUID(std::string uuid, RouteGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::LookupRouteByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void AddRoute(common::mojom::RouteEntryPtr entry, common::mojom::RouteEntryExtrasPtr extras) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::AddRouteImpl, 
        base::Unretained(this),
        base::Passed(std::move(entry)),
        base::Passed(std::move(extras))));
  }

  void RemoveRoute(std::string path) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::RemoveRouteImpl, 
        base::Unretained(this), 
        base::Passed(std::move(path))));
  }

  void RemoveRouteByUrl(std::string url) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::RemoveRouteByUrlImpl, 
        base::Unretained(this), 
        base::Passed(std::move(url))));
  }

  void RemoveRouteByUUID(std::string uuid) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::RemoveRouteByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid))));
  }

  void ListRoutes(std::string scheme, RouteListCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::ListRoutesWithSchemeImpl, 
        base::Unretained(this), 
        base::Passed(std::move(scheme)),
        base::Passed(std::move(cb_state))));
  }

  void ListRoutes(RouteListCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::ListAllRoutesImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void ListSchemes(RouteListCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&RouteRegistryWrapper::ListSchemesImpl, 
        base::Unretained(this), 
        base::Passed(std::move(cb_state))));
  }

  void AddRouteImpl(common::mojom::RouteEntryPtr entry, common::mojom::RouteEntryExtrasPtr extras) {
    registry->AddRoute(
      std::move(entry),
      std::move(extras), 
      base::BindOnce(&OnAddRouteResult));
  }

  void RemoveRouteImpl(std::string path) {
    registry->RemoveRoute(path, base::BindOnce(&OnAddRouteResult));
  }

  void RemoveRouteByUrlImpl(std::string url) {
    registry->RemoveRouteByUrl(GURL(url), base::BindOnce(&OnAddRouteResult));
  }

  void RemoveRouteByUUIDImpl(std::string uuid) {
    registry->RemoveRouteByUUID(uuid, base::BindOnce(&OnAddRouteResult));
  }

  void HaveRouteByPathImpl(std::string path, RouteHaveCallbackState cb_state) {
    registry->HaveRoute(path, base::BindOnce(&OnHaveRouteResult, base::Passed(std::move(cb_state))));
  }

  void HaveRouteByUrlImpl(std::string url, RouteHaveCallbackState cb_state) {
    registry->HaveRouteByUrl(GURL(url), base::BindOnce(&OnHaveRouteResult, base::Passed(std::move(cb_state))));
  }

  void HaveRouteByUUIDImpl(std::string uuid, RouteHaveCallbackState cb_state) {
    registry->HaveRouteByUUID(uuid, base::BindOnce(&OnHaveRouteResult, base::Passed(std::move(cb_state))));
  }

  void CountRoutesImpl(RouteHaveCallbackState cb_state) {
    registry->GetRouteCount(base::BindOnce(&OnCountRoutesResult, base::Passed(std::move(cb_state))));
  }

  void LookupRouteImpl(std::string scheme, std::string path, RouteGetCallbackState cb_state) {
    registry->LookupRoute(scheme, path, base::BindOnce(&OnGetRouteResult, base::Passed(std::move(cb_state))));
  }

  void LookupRouteByPathImpl(std::string path, RouteGetCallbackState cb_state) {
    registry->LookupRouteByPath(path, base::BindOnce(&OnGetRouteResult, base::Passed(std::move(cb_state))));
  }

  void LookupRouteByUrlImpl(std::string url, RouteGetCallbackState cb_state) {
    registry->LookupRouteByUrl(GURL(url), base::BindOnce(&OnGetRouteResult, base::Passed(std::move(cb_state))));
  }

  void LookupRouteByUUIDImpl(std::string uuid, RouteGetCallbackState cb_state) {
    registry->LookupRouteByUUID(uuid, base::BindOnce(&OnGetRouteResult, base::Passed(std::move(cb_state))));
  }

  void ListRoutesWithSchemeImpl(std::string scheme, RouteListCallbackState cb_state) {
    registry->ListRoutesForScheme(scheme, base::BindOnce(&OnListRoutesResult, base::Passed(std::move(cb_state))));
  }

  void ListAllRoutesImpl(RouteListCallbackState cb_state) {
    registry->ListRoutes(base::BindOnce(&OnListRoutesResult, base::Passed(std::move(cb_state))));
  }

  void ListSchemesImpl(RouteListCallbackState cb_state) {
    registry->ListSchemes(base::BindOnce(&OnListRoutesResult, base::Passed(std::move(cb_state))));
  }

  void AddSubscriberImpl(std::string scheme, RouteAddSubscriberCallbackState cb_state) {
    common::mojom::RouteSubscriberPtrInfo url_watcher_info;
    RouteRegistrySubscriberImpl* watcher = new RouteRegistrySubscriberImpl(
      cb_state.watcher_state, 
      RouteRegistrySubscriberCallbacks{cb_state.OnRouteHeaderChanged, cb_state.OnRouteAdded, cb_state.OnRouteRemoved, cb_state.OnRouteChanged},
      mojo::MakeRequest(&url_watcher_info));
    registry->Subscribe(
      scheme,
      common::mojom::RouteSubscriberPtr(std::move(url_watcher_info)),
      base::BindOnce(&OnAddSubscriberResult, 
        base::Unretained(watcher),
        base::Passed(std::move(cb_state))));
  }

  void RemoveSubscriberImpl(int id) {
    registry->Unsubscribe(id);
  }

  // RouteDispatcher::Delegate
  std::unique_ptr<domain::RouteRequest> CreateRequest(domain::RouteDispatcher* dispatcher, const std::string& url, int request_id) override {
    std::unique_ptr<RouteRequestImpl> request = std::make_unique<RouteRequestImpl>(dispatcher, handler_state, handler_callbacks, url, request_id);
    handler_callbacks.OnRequestCreated(handler_state, url.c_str(), request_id);
    return request;
  }

  void OnComplete(domain::RouteDispatcher* dispatcher, int request_id, network::URLLoaderCompletionStatus status) override {
    handler_callbacks.OnComplete(handler_state, request_id, status.error_code);
  }

  void GetRouteHeader(const std::string& url, common::mojom::RouteDispatcher::GetRouteHeaderCallback callback) override {
    network::ResourceResponseHead head;
    int size = 0; 
    const char* header_string = handler_callbacks.GetRouteHeader(handler_state, url.c_str(), &size);
    head.headers =
      new net::HttpResponseHeaders(
        net::HttpUtil::AssembleRawHeaders(
          header_string, size));
    std::move(callback).Run(head);
  }

  
  void LookupRoute(const std::string& query, common::mojom::RouteDispatcher::LookupRouteCallback callback) override {
    // this should not be called. obsolete
    DCHECK(false);
  }
  
  void LookupRouteByPath(const std::string& path, common::mojom::RouteDispatcher::LookupRouteByPathCallback callback) override {
    base::ScopedAllowBlockingForTesting allow_blocking;
    int type;
    int transportType;
    int transportMode;
    char* scheme;
    int schemeSize;
    char* name;
    int nameSize;
    char* pathOut;
    int pathSize;
    char* url;
    int urlSize;
    char* title;
    int titleSize;
    char* contentType;
    int contentSize;
    
    int code = handler_callbacks.LookupRouteByPath(
      handler_state, 
      path.c_str(),
      &type,
      &transportType,
      &transportMode,
      &scheme,
      &schemeSize,
      &name,
      &nameSize,
      &pathOut,
      &pathSize,
      &url,
      &urlSize,
      &title,
      &titleSize,
      &contentType,
      &contentSize);  
    
    if (code != net::OK) {
      std::move(callback).Run(static_cast<common::mojom::RouteStatusCode>(code), nullptr);
      return;
    }
    common::mojom::RouteEntryPtr entry = common::mojom::RouteEntry::New();
    entry->type = static_cast<common::mojom::RouteEntryType>(type);
    entry->transport_type = static_cast<common::mojom::RouteEntryTransportType>(transportType);
    entry->rpc_method_type = static_cast<common::mojom::RouteEntryRPCMethodType>(transportMode);
    entry->name = std::string(name, (size_t)nameSize);
    entry->path = std::string(pathOut, (size_t)pathSize);
    entry->url = GURL(std::string(url, (size_t)urlSize));
    entry->title = base::ASCIIToUTF16(title);
    entry->content_type = std::string(contentType, (size_t)contentSize);

    std::move(callback).Run(static_cast<common::mojom::RouteStatusCode>(code), std::move(entry));

    free(scheme);
    free(name);
    free(pathOut);
    free(url);
    free(title);
    free(contentType);
  }
  
  void LookupRouteByUrl(const GURL& url, common::mojom::RouteDispatcher::LookupRouteByUrlCallback callback) override {
    base::ScopedAllowBlockingForTesting allow_blocking;
    int type;
    int transportType;
    int transportMode;
    char* scheme;
    int schemeSize;
    char* name;
    int nameSize;
    char* path;
    int pathSize;
    char* urlOut;
    int urlSize;
    char* title;
    int titleSize;
    char* contentType;
    int contentSize;

    int code = handler_callbacks.LookupRouteByUrl(
      handler_state, 
      url.spec().c_str(),
      &type,
      &transportType,
      &transportMode,
      &scheme,
      &schemeSize,
      &name,
      &nameSize,
      &path,
      &pathSize,
      &urlOut,
      &urlSize,
      &title,
      &titleSize,
      &contentType,
      &contentSize);  
    if (code != net::OK) {
      std::move(callback).Run(static_cast<common::mojom::RouteStatusCode>(code), nullptr);
      return;
    }
    common::mojom::RouteEntryPtr entry = common::mojom::RouteEntry::New();
    entry->type = static_cast<common::mojom::RouteEntryType>(type);
    entry->transport_type = static_cast<common::mojom::RouteEntryTransportType>(transportType);
    entry->rpc_method_type = static_cast<common::mojom::RouteEntryRPCMethodType>(transportMode);
    entry->name = std::string(name, (size_t)nameSize);
    entry->path = std::string(path, (size_t)pathSize);
    entry->url = GURL(std::string(urlOut, (size_t)urlSize));
    entry->title = base::ASCIIToUTF16(title);
    entry->content_type = std::string(contentType, (size_t)contentSize);


    std::move(callback).Run(static_cast<common::mojom::RouteStatusCode>(code), std::move(entry));

    free(scheme);
    free(name);
    free(path);
    free(urlOut);
    free(title);
    free(contentType);
  }
  
  void LookupRouteByUUID(const std::string& uuid, common::mojom::RouteDispatcher::LookupRouteByUUIDCallback callback) override {
    base::ScopedAllowBlockingForTesting allow_blocking;
    int type;
    int transportType;
    int transportMode;
    char* scheme;
    int schemeSize;
    char* name;
    int nameSize;
    char* path;
    int pathSize;
    char* url;
    int urlSize;
    char* title;
    int titleSize;
    char* contentType;
    int contentSize;

    int code = handler_callbacks.LookupRouteByUUID(
      handler_state, 
      uuid.c_str(),
      &type,
      &transportType,
      &transportMode,
      &scheme,
      &schemeSize,
      &name,
      &nameSize,
      &path,
      &pathSize,
      &url,
      &urlSize,
      &title,
      &titleSize,
      &contentType,
      &contentSize);  
    if (code != net::OK) {
      std::move(callback).Run(static_cast<common::mojom::RouteStatusCode>(code), nullptr);
      return;
    }
    common::mojom::RouteEntryPtr entry = common::mojom::RouteEntry::New();
    entry->type = static_cast<common::mojom::RouteEntryType>(type);
    entry->transport_type = static_cast<common::mojom::RouteEntryTransportType>(transportType);
    entry->rpc_method_type = static_cast<common::mojom::RouteEntryRPCMethodType>(transportMode);
    entry->name = std::string(name, (size_t)nameSize);
    entry->path = std::string(path, (size_t)pathSize);
    entry->url = GURL(std::string(url, (size_t)urlSize));
    entry->title = base::ASCIIToUTF16(title);
    entry->content_type = std::string(contentType, (size_t)contentSize);

    std::move(callback).Run(static_cast<common::mojom::RouteStatusCode>(code), std::move(entry));

    free(scheme);
    free(name);
    free(path);
    free(url);
    free(title);
    free(contentType);
  }
  
  void GetRouteCount(common::mojom::RouteDispatcher::GetRouteCountCallback callback) override {
    int count = handler_callbacks.GetRouteCount(handler_state);  
    std::move(callback).Run(count);
  }
  
  void Subscribe(common::mojom::RouteSubscriberPtr subscriber, common::mojom::RouteDispatcher::SubscribeCallback callback) override {
    int id = handler_callbacks.Subscribe(handler_state);
    std::move(callback).Run(id);
  }

  void Unsubscribe(int32_t subscriber_id) override {
    handler_callbacks.Unsubscribe(handler_state, subscriber_id);  
  }

};

RouteRegistryRef _RouteRegistryCreateFromEngine(EngineInstanceRef handle, void* handler_state, RouteRequestHandlerCallbacks callbacks) {
  domain::ModuleState* module = reinterpret_cast<_EngineInstance *>(handle)->module_state();
  return new RouteRegistryWrapper(module->route_registry(), module->route_dispatcher(), handler_state, std::move(callbacks), module->GetMainTaskRunner());
}

RouteRegistryRef _RouteRegistryCreateFromApp(ApplicationInstanceRef handle) {
  application::ApplicationThread* thread = reinterpret_cast<application::ApplicationProcess *>(handle)->main_thread();
  return new RouteRegistryWrapper(thread->GetRouteRegistry(), nullptr, nullptr, RouteRequestHandlerCallbacks(), thread->main_thread_runner());
}

void _RouteRegistryDestroy(RouteRegistryRef handle) {
  delete reinterpret_cast<RouteRegistryWrapper *>(handle);
}

void _RouteRegistryAddRoute(
  RouteRegistryRef registry,
  int type,
  int transportType,
  int transportMode,
  const char* scheme, 
  const char* name,
  const char* path,
  const char* url,
  const char* title,
  const char* content_type,
  const uint8_t* icon_data,
  int icon_data_size) {
  
  common::mojom::RouteEntryPtr entry = common::mojom::RouteEntry::New();
  entry->type = static_cast<common::mojom::RouteEntryType>(type);
  entry->transport_type = static_cast<common::mojom::RouteEntryTransportType>(transportType);
  entry->rpc_method_type = static_cast<common::mojom::RouteEntryRPCMethodType>(transportMode);
  entry->name = std::string(name);
  entry->path = std::string(path);
  entry->url = GURL(std::string(url));
  entry->title = base::ASCIIToUTF16(title);
  entry->content_type = std::string(content_type);
  
  common::mojom::RouteEntryExtrasPtr extras = common::mojom::RouteEntryExtras::New();
  extras->icon_data_size = 0;
  if (icon_data_size > 0 && icon_data != nullptr) {
    extras->icon_data = mojo::SharedBufferHandle::Create(icon_data_size);
    extras->icon_data_size = icon_data_size;
    mojo::ScopedSharedBufferMapping mapping = extras->icon_data->Map(icon_data_size);
    memcpy(mapping.get(), icon_data, icon_data_size);
  }

  reinterpret_cast<RouteRegistryWrapper *>(registry)->AddRoute(std::move(entry), std::move(extras));
}

void _RouteRegistryRemoveRoute(RouteRegistryRef registry, const char* path) {
  reinterpret_cast<RouteRegistryWrapper *>(registry)->RemoveRoute(std::string(path));
}

void _RouteRegistryRemoveRouteByUrl(RouteRegistryRef registry, const char* url) {
  reinterpret_cast<RouteRegistryWrapper *>(registry)->RemoveRouteByUrl(std::string(url));
}

void _RouteRegistryRemoveRouteByUUID(RouteRegistryRef registry, const char* uuid) {
  reinterpret_cast<RouteRegistryWrapper *>(registry)->RemoveRouteByUUID(std::string(uuid));
}

void _RouteRegistryHaveRouteByPath(RouteRegistryRef registry, const char* path, void* state, void(*cb)(void*, int)) {
  RouteHaveCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->HaveRouteByPath(std::string(path), std::move(cb_state));
}

void _RouteRegistryHaveRouteByUrl(RouteRegistryRef registry, const char* url, void* state, void(*cb)(void*, int)) {
  RouteHaveCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->HaveRouteByUrl(std::string(url), std::move(cb_state));
}

void _RouteRegistryHaveRouteByUUID(RouteRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int)) {
  RouteHaveCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->HaveRouteByUUID(std::string(uuid), std::move(cb_state));
}

void _RouteRegistryLookupRoute(RouteRegistryRef registry, const char* scheme, const char* path, void* state, void(*cb)(void*, int, int, int, int, const char*, const char*, const char*)) {
  RouteGetCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->LookupRoute(std::string(scheme), std::string(path), std::move(cb_state));
}

void _RouteRegistryLookupRouteByPath(RouteRegistryRef registry, const char* path, void* state, void(*cb)(void*, int, int, int, int, const char*, const char*, const char*)) {
  RouteGetCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->LookupRouteByPath(std::string(path), std::move(cb_state));
}

void _RouteRegistryLookupRouteByUrl(RouteRegistryRef registry, const char* url, void* state, void(*cb)(void*, int, int, int, int, const char*, const char*, const char*)) {
  RouteGetCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->LookupRouteByUrl(std::string(url), std::move(cb_state));
}

void _RouteRegistryLookupRouteByUUID(RouteRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int, int, int, int, const char*, const char*, const char*)) {
  RouteGetCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->LookupRouteByUUID(std::string(uuid), std::move(cb_state));
}

void _RouteRegistryListRoutesWithScheme(RouteRegistryRef registry, const char* scheme, void* state, void(*cb)(void*, int, int, int*, int*, int*,const char**, const char**, const char**)) {
  RouteListCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->ListRoutes(std::string(scheme), std::move(cb_state));
}

void _RouteRegistryListAllRoutes(RouteRegistryRef registry, void* state, void(*cb)(void*, int, int, int*, int*, int*, const char**, const char**, const char**)) {
  RouteListCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->ListRoutes(std::move(cb_state));
}

void _RouteRegistryListSchemes(RouteRegistryRef registry, void* state, void(*cb)(void*, int, int, int*, int*, int*,const char**, const char**, const char**)) {
  RouteListCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->ListSchemes(std::move(cb_state));  
}

void _RouteRegistryGetRouteCount(RouteRegistryRef registry, void* state, void(*cb)(void*, int)) {
  RouteHaveCallbackState cb_state{state, cb};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->CountRoutes(std::move(cb_state));
}

void _RouteRegistryAddSubscriber(
  RouteRegistryRef registry, 
  const char* scheme, 
  void* state,
  void* watcher_state, 
  void(*cb)(void*, int, void*, void*),
  void(*OnRouteHeaderChanged)(void*, const char*),
  void(*OnRouteAdded)(void*, int, int, int, const char*, const char*, const char*),
  void(*OnRouteRemoved)(void*, int, int, int, const char*, const char*, const char*),
  void(*OnRouteChanged)(void*, int, int, int, const char*, const char*, const char*)) {
  RouteAddSubscriberCallbackState cb_state{state, watcher_state, cb, OnRouteHeaderChanged, OnRouteAdded, OnRouteRemoved, OnRouteChanged};
  reinterpret_cast<RouteRegistryWrapper *>(registry)->AddSubscriber(
    std::string(scheme), 
    std::move(cb_state)); 
}

void _RouteRegistryRemoveSubscriber(RouteRegistryRef registry, int id) {
  reinterpret_cast<RouteRegistryWrapper *>(registry)->RemoveSubscriber(id); 
}

void _RouteSubscriberDestroy(void* handle) {
  delete reinterpret_cast<RouteRegistrySubscriberImpl *>(handle);
}