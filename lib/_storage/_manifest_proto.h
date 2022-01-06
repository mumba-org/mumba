// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_LIB_STORAGE_MANIFEST_H_
#define MUMBA_LIB_STORAGE_MANIFEST_H_

#include <string>
#include <vector>

#include "base/macros.h"
#include "storage/storage_resource.h"

namespace storage {
class Storage;

class ManifestProto : public StorageResource {
public:
 static std::unique_ptr<ManifestProto> ParseFromXMLString(const std::string& xml);
 static std::unique_ptr<ManifestProto> ParseFromEncodedProtobuf(const std::string& data);
 static bool ParseProtoFromXMLString(const std::string& xml, storage_proto::ManifestProto* out);

 ~ManifestProto() override;

 const std::string& uuid() const {
   return manifest_proto_->resource().uuid();
 }

 storage_proto::StorageProfile profile() const {
  return manifest_proto_->profile();
 }

 const std::string& version() const {
  return manifest_proto_->version();
 }

 const std::string& identifier() const {
  return manifest_proto_->identifier();
 }

 const std::string& scheme() const {
  return manifest_proto_->scheme();
 }

 const std::string& sha256_hash() const {
  return manifest_proto_->resource().sha256_hash();
 }

 size_t size() const {
   return static_cast<size_t>(manifest_proto_->resource().size());
 }

 storage_proto::Signature::Kind signature_type() const {
  return manifest_proto_->signature().kind();
 }

 const std::string& signature() const {
  return manifest_proto_->signature().data();
 }

 const std::string& address() const {
  return manifest_proto_->address();
 }

 storage_proto::ResourceKind resource_type() const override;
 const base::FilePath& path() const override;

private:
  friend class Storage;
  
  ManifestProto(std::unique_ptr<storage_proto::ManifestProto> manifest_proto);

  std::unique_ptr<storage_proto::ManifestProto> manifest_proto_;

  base::FilePath path_;

  DISALLOW_COPY_AND_ASSIGN(ManifestProto);
};

class ManifestProtoBuilder {
public:
  ManifestProtoBuilder();
  ~ManifestProtoBuilder() = default;
  
  std::unique_ptr<storage_proto::ManifestProto> BuildProtoFromXML(const std::string& xml_string);
  bool SerializeProtoFromXML(const std::string xml_string, storage_proto::ManifestProto* manifest);

private:
  
  bool ParseFromXMLString(const std::string& xml_string, storage_proto::ManifestProto* manifest);

  DISALLOW_COPY_AND_ASSIGN(ManifestProtoBuilder);
};

}

#endif
