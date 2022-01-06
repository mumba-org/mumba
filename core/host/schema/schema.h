// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SCHEMA_SCHEMA_H_
#define MUMBA_HOST_SCHEMA_SCHEMA_H_

#include <memory>

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string_piece.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.pb.h"

namespace host {
class SchemaRegistry;
class ServiceHandler;

class Schema : public Serializable {
public:
  static char kClassName[];
  static std::string CalculateHash(const base::StringPiece& content);
  // changed from base::StringPiece to std::string. as Protobuf is having trouble with it
  static std::unique_ptr<Schema> Deserialize(SchemaRegistry* registry, net::IOBuffer* buffer, int size);
  static std::unique_ptr<Schema> NewFromProtobuf(SchemaRegistry* registry, std::string filename, std::string schema_data);
  
  ~Schema() override;

  const base::UUID& id() const {
    return id_;
  }

  const std::string& package();
  const std::string& name();
  const std::string& filename();

  const std::string& root_hash() const {
    return schema_proto_.root_hash();
  }

  std::string root_hash_hex() const {
    return base::ToLowerASCII(base::HexEncode(root_hash().data(), root_hash().size()));
  }

  const std::string& content() const {
    return schema_proto_.content();
  }

  size_t content_lenght() const {
    return content().size();
  }

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  const google::protobuf::FileDescriptor* file_proto() {
    base::AutoLock lock(file_proto_lock_);
    return file_proto_;
  }

  size_t service_count();
  size_t enum_count();
  size_t message_count();

  const google::protobuf::ServiceDescriptor* service_at(size_t index);
  const google::protobuf::EnumDescriptor* enum_at(size_t index);
  const google::protobuf::Descriptor* message_at(size_t index);

  const google::protobuf::Descriptor* GetMessageDescriptorNamed(const std::string& name);
  const google::protobuf::EnumDescriptor* GetEnumDescriptorNamed(const std::string& name);
  const google::protobuf::ServiceDescriptor* GetServiceDescriptorNamed(const std::string& name);

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;
  std::string CalculateHash() const;

  // services that implements this schema
  void AddServiceHandler(ServiceHandler* service);
  void RemoveServiceHandler(ServiceHandler* service);

  const std::vector<ServiceHandler *>& service_handlers() const {
    return service_handlers_;
  }

  SchemaRegistry* registry() const {
    return registry_;
  }

private:
  Schema(SchemaRegistry* registry);
  Schema(SchemaRegistry* registry, protocol::Protocol schema);

//  size_t GetSchemaEncodedLenght() const;
  SchemaRegistry* registry_;

  base::UUID id_;

  protocol::Protocol schema_proto_;

  //std::string sha256_hash_;

  //std::string content_;
  base::Lock file_proto_lock_;
  const google::protobuf::FileDescriptor* file_proto_;

  bool managed_;

  base::Lock handlers_lock_;
  std::vector<ServiceHandler *> service_handlers_;

  DISALLOW_COPY_AND_ASSIGN(Schema);
};

}

#endif