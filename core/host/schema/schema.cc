// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/schema/schema.h"

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/hash.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "net/base/io_buffer.h"
#include "third_party/protobuf/src/google/protobuf/compiler/parser.h"
#include "third_party/protobuf/src/google/protobuf/io/tokenizer.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl.h"
#include "third_party/protobuf/src/google/protobuf/stubs/strutil.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "third_party/protobuf/src/google/protobuf/arena.h"
#include "third_party/protobuf/src/google/protobuf/arenastring.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_table_driven.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_util.h"
#include "third_party/protobuf/src/google/protobuf/inlined_string_field.h"
#include "third_party/protobuf/src/google/protobuf/metadata.h"
#include "third_party/protobuf/src/google/protobuf/message.h"
#include "core/host/schema/schema_registry.h"
#include "net/rpc/server/rpc_service.h"
#include "core/common/protocol/message_serialization.h"

namespace host {

namespace {
  class SingleFileErrorCollector : public google::protobuf::io::ErrorCollector {
 public:
  SingleFileErrorCollector(const std::string& filename)
    : filename_(filename),
      had_errors_(false) {}
  ~SingleFileErrorCollector() {}

  bool had_errors() { return had_errors_; }

  // implements ErrorCollector ---------------------------------------
  void AddError(int line, int column, const std::string& message) override {
    had_errors_ = true;
    printf("protobuf error %d:%d: %s\n", line, column, message.c_str());
  }

 private:
  std::string filename_;
  bool had_errors_;
};

}

std::string Schema::CalculateHash(const base::StringPiece& content) {
  std::string sha256_hash(crypto::kSHA256Length, 0);
  std::unique_ptr<crypto::SecureHash> ctx = crypto::SecureHash::Create(crypto::SecureHash::SHA256);
  ctx->Update(content.data(), content.size());
  ctx->Finish(const_cast<char *>(sha256_hash.data()), sha256_hash.size());
  return sha256_hash;
}

// std::unique_ptr<Schema> Schema::Deserialize(SchemaRegistry* registry, net::IOBuffer* buffer, int size) {
//   std::unique_ptr<Schema> schema(new Schema());
//   uint8_t const* d = reinterpret_cast<uint8_t const*>(data.data());

//   uint64_t container_len, name_len, hash_len, content_len;

//   //d += csqliteGetVarint(d, (u64*)&container->id_);
//   schema->id_ = base::UUID(d);
//   d += 16; // size of uuid in bytes
  
//   // we save those in the db record for index purposes
//   // but we dont use them here, cause we are using
//   // the ones described in the schema descriptor
//   d += csqliteGetVarint(d, (u64*)&container_len);
//   d += container_len;
//   d += csqliteGetVarint(d, (u64*)&name_len);
//   std::string filename;
//   // copy, so the protobuf lib dont freak out trying to deallocate the buffer
//   filename.assign(reinterpret_cast<char const*>(d), name_len);
//   d += name_len;

//   d += csqliteGetVarint(d, (u64*)&hash_len);
//   schema->sha256_hash_ = std::string(reinterpret_cast<char const*>(d), hash_len);

//   // jump hash
//   d += hash_len;

//   d += csqliteGetVarint(d, (u64*)&content_len);
//   // explicitly copy the content
//   schema->content_.assign(reinterpret_cast<char const*>(d), content_len);

//   // build the FileDescriptor 
//   google::protobuf::io::ArrayInputStream input(schema->content_.data(), schema->content_.size());
//   SingleFileErrorCollector file_error_collector("_");
//   google::protobuf::io::Tokenizer tokenizer(&input, &file_error_collector);
//   google::protobuf::compiler::Parser parser;
 
//   google::protobuf::FileDescriptorProto file_proto;
//   file_proto.set_name(filename);
//   parser.Parse(&tokenizer, &file_proto);

//   schema->file_proto_ = registry->BuildFile(file_proto);
  
//   //printf("Deserialized schema:\n name: %s,\n id: %s,\n hash: %s,\n content: \n%s\n",
//   //  schema->name().c_str(), 
//   //  schema->id_.to_string().c_str(), 
//   //  schema->sha256_hash_hex().c_str(),
//   //  schema->content_.c_str());

//   const google::protobuf::FileDescriptor* file = schema->file_proto_;

//   printf("decoded schema:\n name: %s\n container: %s\n messages: %d\n enums: %d\n services: %d\n", 
//     file->name().c_str(), 
//     file->container().c_str(),
//     file->message_type_count(),
//     file->enum_type_count(),
//     file->service_count());

//   return schema;
// }

char Schema::kClassName[] = "schema";

// static 
std::unique_ptr<Schema> Schema::NewFromProtobuf(SchemaRegistry* registry, std::string filename, std::string schema_data) {
  std::unique_ptr<Schema> schema(new Schema(registry));
  schema->schema_proto_.set_root_hash(Schema::CalculateHash(schema_data));
  std::string name = filename;
  auto offset = name.find(".");
  if (offset != std::string::npos) {
    name = name.substr(0, offset);
  }
  schema->schema_proto_.set_name(name);
   // build the FileDescriptor 
  google::protobuf::io::ArrayInputStream input(schema_data.data(), schema_data.size());
  SingleFileErrorCollector file_error_collector("_");
  google::protobuf::io::Tokenizer tokenizer(&input, &file_error_collector);
  google::protobuf::compiler::Parser parser;
 
  google::protobuf::FileDescriptorProto file_proto;
  //schema->file_proto_.reset(file_proto.New());
  file_proto.set_name(filename); 
  if (!parser.Parse(&tokenizer, &file_proto)) {
    DLOG(ERROR) << "failed to parse '" << filename << "'";
    return std::unique_ptr<Schema>();
  }
  
  schema->schema_proto_.set_content(schema_data);

  schema->file_proto_ = registry->BuildFile(file_proto);

  if (!schema->file_proto_) {
    return std::unique_ptr<Schema>();
  }

  //const google::protobuf::FileDescriptor* file = schema->file_proto_;

  //printf("Schema::NewFromProtobuf: decoded schema:\n name: %s\n container: %s\n messages: %d\n enums: %d\n services: %d\n", 
  //  file->name().c_str(), 
  //  file->container().c_str(),
  //  file->message_type_count(),
  //  file->enum_type_count(),
  //  file->service_count());

  return schema;
}

std::unique_ptr<Schema> Schema::Deserialize(SchemaRegistry* registry, net::IOBuffer* buffer, int size) {
  protocol::Protocol schema_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!schema_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  //bool ok = false;
  base::UUID uuid(reinterpret_cast<const uint8_t *>(schema_proto.uuid().data()));

  auto schema = std::unique_ptr<Schema>(new Schema(registry, std::move(schema_proto)));

  // build the FileDescriptor 
  google::protobuf::io::ArrayInputStream input(schema->content().data(), schema->content().size());
  SingleFileErrorCollector file_error_collector("_");
  google::protobuf::io::Tokenizer tokenizer(&input, &file_error_collector);
  google::protobuf::compiler::Parser parser;
 
  google::protobuf::FileDescriptorProto file_proto;
  file_proto.set_name(uuid.to_string());
  parser.Parse(&tokenizer, &file_proto);
 
  schema->file_proto_ = registry->BuildFile(file_proto);

  return schema;
} 

Schema::Schema(SchemaRegistry* registry, protocol::Protocol schema):
  registry_(registry),
  id_(reinterpret_cast<const uint8_t *>(schema.uuid().data())),
  schema_proto_(std::move(schema)),
  managed_(false) {
}

Schema::Schema(SchemaRegistry* registry):
  registry_(registry),
  managed_(false) {
  id_ = base::UUID::generate();
  schema_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));
}

Schema::~Schema() {
  
}

const std::string& Schema::package() {
  base::AutoLock lock(file_proto_lock_);
  DCHECK(file_proto_);
  return file_proto_->package();
}

const std::string& Schema::name() const {
  return schema_proto_.name();
}

const std::string& Schema::filename() {
  base::AutoLock lock(file_proto_lock_);
  DCHECK(file_proto_);
  return file_proto_->name();
}

size_t Schema::service_count() {
  base::AutoLock lock(file_proto_lock_);
  DCHECK(file_proto_);
  return file_proto_->service_count();
}

size_t Schema::enum_count() {
  base::AutoLock lock(file_proto_lock_);
  DCHECK(file_proto_);
  return file_proto_->enum_type_count();
}

size_t Schema::message_count() {
  base::AutoLock lock(file_proto_lock_);
  DCHECK(file_proto_);
  return file_proto_->message_type_count();
}

const google::protobuf::ServiceDescriptor* Schema::service_at(size_t index) {
  base::AutoLock lock(file_proto_lock_);
  DCHECK(file_proto_);
  return file_proto_->service(index);
}

const google::protobuf::EnumDescriptor* Schema::enum_at(size_t index) {
  base::AutoLock lock(file_proto_lock_);
  DCHECK(file_proto_);
  return file_proto_->enum_type(index);
}

const google::protobuf::Descriptor* Schema::message_at(size_t index) {
  base::AutoLock lock(file_proto_lock_);
  DCHECK(file_proto_);
  return file_proto_->message_type(index);
}

const google::protobuf::Descriptor* Schema::GetMessageDescriptorNamed(const std::string& name) {
  const google::protobuf::Descriptor* result = nullptr;
  for (size_t i = 0; i < message_count(); i++) {
    const google::protobuf::Descriptor* current = message_at(i);
    if (current->name() == name) {
      result = current;
      break;
    }
  }
  return result;
}

const google::protobuf::EnumDescriptor* Schema::GetEnumDescriptorNamed(const std::string& name) {
  const google::protobuf::EnumDescriptor* result = nullptr;
  for (size_t i = 0; i < enum_count(); i++) {
    const google::protobuf::EnumDescriptor* current = enum_at(i);
    if (current->name() == name) {
      result = current;
      break;
    }
  }
  return result; 
}

const google::protobuf::ServiceDescriptor* Schema::GetServiceDescriptorNamed(const std::string& name) {
  const google::protobuf::ServiceDescriptor* result = nullptr;
  for (size_t i = 0; i < service_count(); i++) {
    const google::protobuf::ServiceDescriptor* current = service_at(i);
    if (current->name() == name) {
      result = current;
      break;
    }
  }
  return result;
}

void Schema::AddServiceHandler(ServiceHandler* service) {
  base::AutoLock lock(handlers_lock_);
  service_handlers_.push_back(service);
}

void Schema::RemoveServiceHandler(ServiceHandler* service) {
  base::AutoLock lock(handlers_lock_);
  for (auto it = service_handlers_.begin(); it != service_handlers_.end(); ++it) {
    if (*it == service) {
      service_handlers_.erase(it);
      return;
    }
  }
}

// scoped_refptr<net::IOBufferWithSize> Schema::Serialize() const {
//   scoped_refptr<net::IOBufferWithSize> buffer;
  
//   size_t len = GetSchemaEncodedLenght();
 
//   buffer = new net::IOBufferWithSize(len);
//   uint8_t* buf = reinterpret_cast<uint8_t *>(buffer->data());
//   memset(buf, 0, len);
  
//   // id
//   memcpy(buf, id_.data, 16);
//   buf += 16;//csqlitePutVarint(buf, id_);
  
//   // container
//   buf += csqlitePutVarint(buf, container().size());
//   memcpy(buf, container().data(), container().size());
//   buf += container().size();

//   // name
//   buf += csqlitePutVarint(buf, name().size());
//   memcpy(buf, name().data(), name().size());
//   buf += name().size();

//   // hash
//   buf += csqlitePutVarint(buf, sha256_hash_.size());
//   memcpy(buf, sha256_hash_.data(), sha256_hash_.size());
//   buf += sha256_hash_.size();

//   // content
//   buf += csqlitePutVarint(buf, content_.size());
//   memcpy(buf, content_.data(), content_.size());
//   buf += content_.size();
  
//   return buffer;
// }

scoped_refptr<net::IOBufferWithSize> Schema::Serialize() const {
  return protocol::SerializeMessage(schema_proto_);
}

std::string Schema::CalculateHash() const {
  return Schema::CalculateHash(content());
}

// size_t Schema::GetSchemaEncodedLenght() const {
//   size_t len = 16 + // uuid
//     csqliteVarintLen(container().size()) + 
//     container().size() +
//     csqliteVarintLen(name().size()) + 
//     name().size() +
//     csqliteVarintLen(sha256_hash_.size()) +
//     sha256_hash_.size() +
//     csqliteVarintLen(content_.size()) +
//     content_.size();

//   return len;
// }

}
