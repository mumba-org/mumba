// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_APP_DATA_SOURCE_H_
#define MUMBA_CORE_HOST_APP_DATA_SOURCE_H_

#include <vector>
#include <memory>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/atomic_sequence_num.h"
#include "base/single_thread_task_runner.h"
#include "core/host/application/url_data_source.h"
#include "core/host/rpc/server/host_rpc_service.h"
#include "core/host/rpc/client/rpc_host.h"
#include "core/host/rpc/client/rpc_client.h"
#include "core/host/protocol/protocol.h"
#include "core/host/protocol/protocol_registry.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/url_request_job_factory.h"

namespace net {
class RpcStream;  
}

namespace host {
class Domain;
class Place;
class PlaceRegistry;
class EntryContent;
class URLDataManagerBackend;
// A DataSource for "app://" that binds to Rpc methods URLs.

// TODO: associate Rpc services and protos with the "owner" Domain..
// that way we can only have a reference to the application this data source
// points to
class RpcDataSource : public URLDataSource {
 public:
  // struct ApplicationMethod {
  //   net::RpcService* service;
  //   std::string name;
  //   std::string full_name;
  //   net::RpcMethodType method_type;
  //   std::string mime_type;

  //   ApplicationMethod(
  //     net::RpcService* service,
  //     const std::string& name,
  //     const std::string& full_name,
  //     net::RpcMethodType method_type,
  //     const std::string& mime_type):
  //       service(service),
  //       name(name),
  //       full_name(full_name),
  //       method_type(method_type),
  //       mime_type(mime_type){}
  // };
  RpcDataSource(PlaceRegistry* place_registry, Domain* application);

  // URLDataSource implementation.
  std::string GetSource() const override;
  void SetBackend(URLDataManagerBackend* backend) override;
  void StartDataRequest(
      const GURL& url,
      const std::string& path,
      const ResourceRequestInfo::ApplicationContentsGetter& wc_getter,
      URLDataSource::GotDataCallback callback) override;
  void OnDataSent(int call_id, size_t bytes, URLDataSource::GotDataCallback callback) override;
  bool AllowCaching() const override;
  std::string GetMimeType(const std::string& scheme, const std::string& path) const override;
  scoped_refptr<base::SingleThreadTaskRunner> TaskRunnerForRequestPath(
      const std::string& scheme,
      const std::string& path) override;
  std::string GetAccessControlAllowOriginForOrigin(
      const std::string& origin) const override;
  bool IsGzipped(const std::string& scheme, const std::string& path) const override;
  void SendResponse(
    int request_id,
    int call_id,
    scoped_refptr<base::RefCountedMemory> contents,
    bool should_complete) override;
  scoped_refptr<net::HttpResponseHeaders> GetHeaders(
    const std::string& scheme,
    const std::string& path,
    const std::string& origin) override;

  PlaceRegistry* GetPlaceRegistry() const override;
  void SetPlaceRegistry(PlaceRegistry* place_registry) override;

  bool ShouldServeMimeTypeAsContentTypeHeader() const override;
  bool ShouldCompleteRequest(int call_id) override;

  //ApplicationMethod* GetMethodForPath(const std::string& path) const;

 private:

  enum CallState {
    kCALL_BEGIN,
    kCALL_DATA_SENT,
    kCALL_DATA_RECV,
    kCALL_COMPLETED
  };

  struct CallData {

    CallData(
      int call_id,
      const std::string& path,
      Protocol* proto,
      Place* entry,
      net::RpcMethodType method_type,
      URLDataSource::GotDataCallback callback):
        id(call_id), 
        state(kCALL_BEGIN), 
        path(path), 
        proto(proto),
        entry(entry),
        method_type(method_type),
        callback(std::move(callback)) {}

    int id;
    CallState state;
    std::string path;
    Protocol* proto;
    Place* entry;
    net::RpcMethodType method_type;
    std::unique_ptr<net::RpcStream> caller;
    URLDataSource::GotDataCallback callback;
  };

  //using MethodMap = base::hash_map<std::string, std::unique_ptr<ApplicationMethod>>;
  using CallMap = base::hash_map<int, std::unique_ptr<CallData>>;  

  ~RpcDataSource() override;
  void Init();
  void AddPlace(const std::string& scheme,
                    const std::string& path,
                    HostRpcService* service,
                    const net::RpcDescriptor& descr);
  void ScheduleCall(int call_id);
  void ScheduleCall(CallData* call);
  void OnResourceNotFound(const CallData& call);
  void OnServiceNotFound(const std::string& path, const URLDataSource::GotDataCallback& callback);
  void OnRpcContinuation(net::Error status, void* data, bool should_complete);
  
  CallData* CreateCall(
    const std::string& path,
    Protocol* proto,
    Place* entry,
    net::RpcMethodType method_type,
    URLDataSource::GotDataCallback callback,
    const std::string& host,
    const std::string& port,
    const std::string& method_name,
    const std::string& method_params);
  CallData* GetCall(int call_id);
  void RemoveCall(int call_id);

  void SendResponseOnIOThread(
      int request_id,
      scoped_refptr<base::RefCountedMemory> contents,
      bool should_complete);

  void PopulateAndScheduleEntryCatalogCall();
  void ScheduleEntryCatalogCall(HostRpcService* entry_catalog_service, const net::RpcDescriptor& entry_catalog_method);
  void OnEntryCatalogAvailable(HostRpcService* entry_catalog_service, int status);
  void OnEntryCatalogStreamCreated(HostRpcService* entry_catalog_service, net::Error code, std::unique_ptr<net::RpcStream> stream);
  void OnCallStreamCreated(CallData* call, net::Error code, std::unique_ptr<net::RpcStream> stream);
  void OnEntryCatalogShutdown();

  base::AtomicSequenceNumber call_id_gen_;
  URLDataManagerBackend* backend_;
  PlaceRegistry* place_registry_;
  Domain* application_;
  RpcHost rpc_host_;
  RpcClient* rpc_client_;
  //MethodMap method_map_;
  CallMap call_map_;
  std::unique_ptr<net::RpcStream> entry_catalog_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  base::WeakPtrFactory<RpcDataSource> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RpcDataSource);
};

}  // host

#endif  // MUMBA_CORE_HOST_APP_DATA_SOURCE_H_