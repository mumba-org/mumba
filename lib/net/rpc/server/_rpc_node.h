// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_SERVER_RPC_NODE_H_
#define NET_RPC_SERVER_RPC_NODE_H_

#include <vector>

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/uuid.h"
#include "core/common/url.h"
#include "core/common/rpc.h"
#include "rpc/grpc.h"

namespace net {

// TODO: permission system

// TODO: dont forget to expose these system services

// 'mumba.shell'
// 'mumba.route'
// 'mumba.device'
// 'mumba.log'
// 'mumba.notification'
// 'mumba.identity'
// 'mumba.session'
// 'mumba.registry'
// 'mumba.container'
// 'mumba.workspace'
// 'mumba.module'

// enum class RpcMethodType {
//   kNORMAL_Rpc,
//   kSERVER_STREAMING,
//   kCLIENT_STREAMING,
//   kBIDI_STREAMING
// };

struct RpcMethod {
  RpcTransportType transport_type;
  common::RpcMethodType method_type;
  std::string host;
  int port;
  std::string name;
  void* tag;
  
  RpcMethod(RpcTransportType transport_type, 
    common::RpcMethodType method_type, 
    const std::string& host, 
    const std::string& name, 
    int port);
  
  ~RpcMethod();

  URL url() const {
    return GURL((transport_type == RpcTransportType::kHTTP ? "http://" : "unix://")+host+":"+base::IntToString(port)+name);
  }

  grpc_server_register_method_payload_handling payload_handling() const {
    switch (method_type) {
      case common::RpcMethodType::kNORMAL:
      case common::RpcMethodType::kSERVER_STREAM:
        return GRPC_SRM_PAYLOAD_READ_INITIAL_BYTE_BUFFER;
      case common::RpcMethodType::kCLIENT_STREAM:
      case common::RpcMethodType::kBIDI_STREAM:
        return GRPC_SRM_PAYLOAD_NONE;
    }
    return GRPC_SRM_PAYLOAD_NONE;
  }

  bool has_payload() const {
    return method_type == common::RpcMethodType::kNORMAL || 
      method_type == common::RpcMethodType::kSERVER_STREAM;
  }
};

class RpcNode {
public:

  typedef std::vector<RpcMethod*> Methods;
  typedef Methods::const_iterator ConstIterator;
  typedef Methods::iterator Iterator;
  // The Actor that is evented when something happen
  class Observer {
  public:
    virtual ~Observer() {}
  };

  RpcNode(const base::UUID& uuid, const std::string& host, int port, const std::string& ns, RpcTransportType type);
  ~RpcNode();

  const base::UUID& uuid() const { return uuid_; }

  // '127.0.0.1'
  const std::string& host() const { return host_; }

  int port() const { return port_; }

  // 'twitter'
  const std::string& ns() const { return ns_; }

  // = 'twitter.followers' route id

  RpcTransportType transport_type() const { return transport_type_; }

  Iterator methods_begin() { return methods_.begin(); }
  ConstIterator methods_begin() const { return methods_.begin(); }

  Iterator methods_end() { return methods_.end(); }
  ConstIterator methods_end() const { return methods_.end(); }

  size_t method_count() { return methods_.size(); }

  RpcMethod* AddMethod(const std::string& name, common::RpcMethodType method_type);
  RpcMethod* GetMethod(const std::string& addr) const;

  bool FillDescriptor(const std::string& method_addr, RpcDescriptor* descr) const;
  bool FillDescriptor(RpcMethod* method, RpcDescriptor* descr) const;

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);
  
private:
  
  std::vector<Observer *> observers_;

  base::UUID uuid_;

  std::string host_;

  int port_;

  std::string ns_;
  
  RpcTransportType transport_type_;

  Methods methods_;
  
  DISALLOW_COPY_AND_ASSIGN(RpcNode);
};

}

#endif